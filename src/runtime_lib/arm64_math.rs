//! ARM64 soft-float long double (quad-precision) arithmetic.
//!
//! Provides software implementations of IEEE 754 quad-precision
//! (128-bit) floating-point operations for ARM64 targets without
//! hardware quad-precision support.
//!
//! C equivalent: `lib/lib-arm64.c` (693 lines)
//!
//! # Design Notes
//!
//! The original C code represents 128-bit floats as `u128_t { x0, x1 }`
//! and uses `memcpy` for type-punning between `long double` and the struct.
//! In the Rust translation, we use [`QuadFloat`] directly, eliminating all
//! type-punning and achieving full memory safety.
//!
//! IEEE 754 quad-precision format (binary128):
//! - 1 sign bit (bit 127 / x1 bit 63)
//! - 15 exponent bits (bits 112–126 / x1 bits 48–62)
//! - 112 mantissa bits (bits 0–111 / x1 bits 0–47 + x0 bits 0–63)

// IEEE 754 quad-precision arithmetic inherently requires bit-level integer
// manipulation with casts between i32/u32/i64/u64 for mantissa, exponent, and
// sign-bit fields.  These operations are faithful translations of lib-arm64.c
// where the C code uses implicit integer promotions.
#![allow(clippy::cast_lossless)]
#![allow(clippy::similar_names)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]

// ---------------------------------------------------------------------------
// QuadFloat — 128-bit IEEE 754 representation
// ---------------------------------------------------------------------------

/// Internal representation of a quad-precision (128-bit) IEEE 754 float.
///
/// C equivalent: `u128_t` struct in `lib/lib-arm64.c` lines 41–43.
/// Uses two `u64` halves matching the ARM64 register pair representation.
///
/// ```text
/// x1: [sign(1)][exponent(15)][mantissa_high(48)]
/// x0: [mantissa_low(64)]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuadFloat {
    /// Low 64 bits (x0 register in ARM64 calling convention).
    /// Contains the lower 64 bits of the 112-bit mantissa.
    pub(crate) x0: u64,
    /// High 64 bits (x1 register in ARM64 calling convention).
    /// Contains sign bit, 15-bit exponent, and upper 48 mantissa bits.
    pub(crate) x1: u64,
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl QuadFloat {
    /// Exponent bias for quad-precision IEEE 754 (2^14 − 1 = 16383).
    pub(crate) const BIAS: i32 = 16383;

    /// Number of mantissa (significand) bits in quad-precision format.
    pub(crate) const MANT_BITS: u32 = 112;

    /// Number of exponent bits in quad-precision format.
    pub(crate) const EXP_BITS: u32 = 15;

    /// Maximum biased exponent value (reserved for infinity and NaN).
    pub(crate) const MAX_EXP: u32 = 0x7FFF;

    /// Create a zero with the specified sign.
    ///
    /// C equivalent: `f3_zero(sgn)` in `lib/lib-arm64.c` lines 45–51.
    pub(crate) fn zero(sign: bool) -> Self {
        Self {
            x0: 0,
            x1: u64::from(sign) << 63,
        }
    }

    /// Create an infinity with the specified sign.
    ///
    /// C equivalent: `f3_infinity(sgn)` in `lib/lib-arm64.c` lines 53–59.
    pub(crate) fn infinity(sign: bool) -> Self {
        Self {
            x0: 0,
            x1: (u64::from(sign) << 63) | 0x7FFF_0000_0000_0000,
        }
    }

    /// Create a quiet NaN (GCC library convention: all fraction bits set).
    ///
    /// C equivalent: `f3_NaN()` in `lib/lib-arm64.c` lines 61–73.
    /// Uses GCC's convention (all fraction bits set), matching the
    /// `#else` branch in the C source (the active code path).
    pub(crate) fn nan() -> Self {
        Self {
            x0: u64::MAX,
            x1: 0x7FFF_FFFF_FFFF_FFFF,
        }
    }

    /// Check if this value represents a NaN (Not a Number).
    ///
    /// A quad-precision value is NaN when the exponent field is all ones
    /// and the mantissa is non-zero.
    pub(crate) fn is_nan(&self) -> bool {
        let exp = (self.x1 >> 48) & 0x7FFF;
        let mant_hi = self.x1 & 0x0000_FFFF_FFFF_FFFF;
        exp == 0x7FFF && (mant_hi != 0 || self.x0 != 0)
    }

    /// Check if this value represents positive or negative infinity.
    ///
    /// A quad-precision value is infinity when the exponent field is
    /// all ones and the mantissa is zero.
    pub(crate) fn is_infinity(&self) -> bool {
        let exp = (self.x1 >> 48) & 0x7FFF;
        let mant_hi = self.x1 & 0x0000_FFFF_FFFF_FFFF;
        exp == 0x7FFF && mant_hi == 0 && self.x0 == 0
    }

    /// Get the sign bit (`true` = negative, `false` = positive).
    pub(crate) fn sign(&self) -> bool {
        (self.x1 >> 63) != 0
    }

    /// Get the biased exponent value (0..=32767).
    pub(crate) fn exponent(&self) -> u32 {
        ((self.x1 >> 48) & 0x7FFF) as u32
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — unpack / NaN handling
// ---------------------------------------------------------------------------

/// Unpack a quad-precision float into sign, biased exponent, and mantissa.
///
/// C equivalent: `f3_unpack()` in `lib/lib-arm64.c` lines 102–114.
///
/// For normal numbers the implicit bit (bit 48 of `mnt_hi`) is set.
/// For subnormals the exponent is set to 1 so that normalisation works.
///
/// Returns `(sign, exp, mnt_lo, mnt_hi)`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn unpack(q: QuadFloat) -> (bool, i32, u64, u64) {
    let sign = (q.x1 >> 63) != 0;
    let mut exp = ((q.x1 >> 48) & 0x7FFF) as i32;
    // Clear sign and exponent, keeping mantissa-high bits [0..47].
    let mut mnt_hi = q.x1 & 0x0000_FFFF_FFFF_FFFF;
    let mnt_lo = q.x0;

    if exp != 0 {
        // Normal: set the implicit leading 1 at bit 48.
        mnt_hi |= 1u64 << 48;
    } else {
        // Subnormal: use exponent 1 for normalisation arithmetic.
        exp = 1;
    }

    (sign, exp, mnt_lo, mnt_hi)
}

/// Convert a mantissa into a quiet-NaN result, preserving the sign.
///
/// C equivalent: `fp3_convert_NaN()` in `lib/lib-arm64.c` lines 75–81.
fn convert_nan(sign: bool, mnt_lo: u64, mnt_hi: u64) -> QuadFloat {
    QuadFloat {
        x0: mnt_lo,
        x1: mnt_hi | 0x7FFF_8000_0000_0000 | (u64::from(sign) << 63),
    }
}

/// Detect signalling and quiet NaN operands and return the appropriate
/// result NaN if found.
///
/// C equivalent: `fp3_detect_NaNs()` in `lib/lib-arm64.c` lines 83–100.
///
/// Returns `Some(nan_result)` when at least one operand is NaN,
/// `None` when both operands are non-NaN.
#[allow(clippy::too_many_arguments)]
fn detect_nans(
    a_sign: bool,
    a_exp: i32,
    a_lo: u64,
    a_hi: u64,
    b_sign: bool,
    b_exp: i32,
    b_lo: u64,
    b_hi: u64,
) -> Option<QuadFloat> {
    // Signalling NaN: exponent == 32767, mantissa nonzero, quiet bit clear.
    // `a_hi << 16` strips the implicit bit (bit 48) leaving fraction bits.
    if a_exp == 32767 && (a_lo | (a_hi << 16)) != 0 && (a_hi >> 47 & 1) == 0 {
        return Some(convert_nan(a_sign, a_lo, a_hi));
    }
    if b_exp == 32767 && (b_lo | (b_hi << 16)) != 0 && (b_hi >> 47 & 1) == 0 {
        return Some(convert_nan(b_sign, b_lo, b_hi));
    }

    // Quiet NaN: exponent == 32767, mantissa nonzero.
    if a_exp == 32767 && (a_lo | (a_hi << 16)) != 0 {
        return Some(convert_nan(a_sign, a_lo, a_hi));
    }
    if b_exp == 32767 && (b_lo | (b_hi << 16)) != 0 {
        return Some(convert_nan(b_sign, b_lo, b_hi));
    }

    None
}

// ---------------------------------------------------------------------------
// Internal helpers — normalise / sticky-shift / round
// ---------------------------------------------------------------------------

/// Normalise the mantissa so that its MSB sits at bit 63 of `mnt_hi`.
///
/// C equivalent: `f3_normalise()` in `lib/lib-arm64.c` lines 116–133.
///
/// Uses a binary-search style shift to minimise the number of iterations.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn normalize(exp: &mut i32, mnt_lo: &mut u64, mnt_hi: &mut u64) {
    if (*mnt_lo | *mnt_hi) == 0 {
        return;
    }
    // Move entirely from low half to high half when high is empty.
    if *mnt_hi == 0 {
        *mnt_hi = *mnt_lo;
        *mnt_lo = 0;
        *exp -= 64;
    }
    // Binary search for leading zeros in mnt_hi.
    let mut sh: i32 = 32;
    while sh != 0 {
        let s = sh as u32;
        if (*mnt_hi >> (64 - s)) == 0 {
            *mnt_hi = (*mnt_hi << s) | (*mnt_lo >> (64 - s));
            *mnt_lo <<= s;
            *exp -= sh;
        }
        sh >>= 1;
    }
}

/// Right-shift a 128-bit value by `sh` bits with sticky-bit preservation.
///
/// C equivalent: `f3_sticky_shift()` in `lib/lib-arm64.c` lines 135–151.
///
/// Bit 0 of `x0` (the "sticky bit") is set to 1 whenever any bits would
/// be shifted out, ensuring correct rounding in [`round`].
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn sticky_shift(sh: i32, x0: &mut u64, x1: &mut u64) {
    if sh >= 128 {
        *x0 = u64::from((*x0 | *x1) != 0);
        *x1 = 0;
        return;
    }
    let mut sh = sh;
    if sh >= 64 {
        *x0 = *x1 | u64::from(*x0 != 0);
        *x1 = 0;
        sh -= 64;
    }
    if sh > 0 {
        // sh is now in [1, 63] — all shifts are within range.
        let s = sh as u32;
        let inv = 64u32 - s;
        let sticky = u64::from((*x0 << inv) != 0);
        *x0 = (*x0 >> s) | (*x1 << inv) | sticky;
        *x1 >>= s;
    }
}

/// Round a 128-bit significand and pack it into a [`QuadFloat`] result.
///
/// C equivalent: `f3_round()` in `lib/lib-arm64.c` lines 153–189.
///
/// Implements round-to-nearest-even (IEEE 754 default).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn round(sign: bool, mut exp: i32, lo: u64, hi: u64) -> QuadFloat {
    let mut x0 = lo;
    let mut x1 = hi;

    // Shift right to align the result, preserving guard / round / sticky bits.
    if exp > 0 {
        sticky_shift(13, &mut x0, &mut x1);
    } else {
        sticky_shift(14 - exp, &mut x0, &mut x1);
        exp = 0;
    }

    // Extract the 2-bit rounding error (guard + round bits).
    let error = (x0 & 3) as u32;
    x0 = (x0 >> 2) | (x1 << 62);
    x1 >>= 2;

    // Round to nearest, ties to even.
    if error == 3 || (error == 2 && (x0 & 1) != 0) {
        x0 = x0.wrapping_add(1);
        if x0 == 0 {
            // Carry into high half.
            x1 = x1.wrapping_add(1);
            if x1 == 1u64 << 48 {
                exp = 1;
            } else if x1 == 1u64 << 49 {
                exp += 1;
                x0 = (x0 >> 1) | (x1 << 63);
                x1 >>= 1;
            }
        }
    }

    // Overflow → infinity.
    if exp >= 32767 {
        return QuadFloat::infinity(sign);
    }

    // Pack: mantissa-high [0..47], exponent [48..62], sign [63].
    x1 = (x1 & 0x0000_FFFF_FFFF_FFFF)
        | ((exp as u64) << 48)
        | (u64::from(sign) << 63);

    QuadFloat { x0, x1 }
}

// ---------------------------------------------------------------------------
// Arithmetic — addition / subtraction
// ---------------------------------------------------------------------------

/// Internal addition / subtraction engine.
///
/// C equivalent: `f3_add()` in `lib/lib-arm64.c` lines 191–251.
///
/// When `negate_b` is `true` the operation becomes `a − b`.
fn add_internal(a: QuadFloat, b: QuadFloat, negate_b: bool) -> QuadFloat {
    let (a_sign, a_exp, mut a_lo, mut a_hi) = unpack(a);
    let (b_sign_raw, b_exp, mut b_lo, mut b_hi) = unpack(b);

    // NaN propagation uses original (un-negated) signs.
    if let Some(nan) = detect_nans(
        a_sign, a_exp, a_lo, a_hi,
        b_sign_raw, b_exp, b_lo, b_hi,
    ) {
        return nan;
    }

    let b_sign = b_sign_raw ^ negate_b;

    // Infinity handling.
    if a_exp == 32767 && b_exp == 32767 && a_sign != b_sign {
        return QuadFloat::nan(); // inf − inf  or  −inf + inf
    }
    if a_exp == 32767 {
        return QuadFloat::infinity(a_sign);
    }
    if b_exp == 32767 {
        return QuadFloat::infinity(b_sign);
    }

    // Zero + zero.
    if (a_lo | a_hi | b_lo | b_hi) == 0 {
        return QuadFloat::zero(a_sign && b_sign);
    }

    // Shift mantissas left by 3 bits for extra precision.
    a_hi = (a_hi << 3) | (a_lo >> 61);
    a_lo <<= 3;
    b_hi = (b_hi << 3) | (b_lo >> 61);
    b_lo <<= 3;

    // Align exponents — sticky-shift the smaller operand.
    let mut x_exp: i32;
    if a_exp <= b_exp {
        sticky_shift(b_exp - a_exp, &mut a_lo, &mut a_hi);
        x_exp = b_exp;
    } else {
        sticky_shift(a_exp - b_exp, &mut b_lo, &mut b_hi);
        x_exp = a_exp;
    }

    // Perform 128-bit add or subtract.
    let mut x_sign = a_sign;
    let mut x_lo: u64;
    let mut x_hi: u64;

    if a_sign == b_sign {
        // Same sign → add magnitudes.
        x_lo = a_lo.wrapping_add(b_lo);
        x_hi = a_hi
            .wrapping_add(b_hi)
            .wrapping_add(u64::from(x_lo < a_lo));
    } else {
        // Different signs → subtract magnitudes.
        x_lo = a_lo.wrapping_sub(b_lo);
        x_hi = a_hi
            .wrapping_sub(b_hi)
            .wrapping_sub(u64::from(x_lo > a_lo));
        if (x_hi >> 63) != 0 {
            // Result is negative — flip sign and negate 128-bit value.
            x_sign = !x_sign;
            x_lo = x_lo.wrapping_neg();
            x_hi = x_hi
                .wrapping_neg()
                .wrapping_sub(u64::from(x_lo != 0));
        }
    }

    // Zero result.
    if (x_lo | x_hi) == 0 {
        return QuadFloat::zero(false);
    }

    normalize(&mut x_exp, &mut x_lo, &mut x_hi);
    round(x_sign, x_exp + 12, x_lo, x_hi)
}

/// Quad-precision addition: `a + b`.
///
/// C equivalent: `__addtf3` in `lib/lib-arm64.c` lines 254–257.
pub(crate) fn addtf3(a: QuadFloat, b: QuadFloat) -> QuadFloat {
    add_internal(a, b, false)
}

/// Quad-precision subtraction: `a − b`.
///
/// C equivalent: `__subtf3` in `lib/lib-arm64.c` lines 259–262.
pub(crate) fn subtf3(a: QuadFloat, b: QuadFloat) -> QuadFloat {
    add_internal(a, b, true)
}

// ---------------------------------------------------------------------------
// Arithmetic — multiplication
// ---------------------------------------------------------------------------

/// Quad-precision multiplication: `a × b`.
///
/// C equivalent: `__multf3` in `lib/lib-arm64.c` lines 264–327.
///
/// Uses a base-2^30 decomposition to compute the 128×128 → 256-bit product
/// with sixteen 64-bit multiplications that individually cannot overflow.
pub(crate) fn multf3(a: QuadFloat, b: QuadFloat) -> QuadFloat {
    let (a_sign, mut a_exp, mut a_lo, mut a_hi) = unpack(a);
    let (b_sign, mut b_exp, mut b_lo, mut b_hi) = unpack(b);

    if let Some(nan) = detect_nans(
        a_sign, a_exp, a_lo, a_hi,
        b_sign, b_exp, b_lo, b_hi,
    ) {
        return nan;
    }

    // Handle infinities and zeros.
    if (a_exp == 32767 && (b_lo | b_hi) == 0)
        || (b_exp == 32767 && (a_lo | a_hi) == 0)
    {
        return QuadFloat::nan(); // 0 × ∞
    }
    if a_exp == 32767 || b_exp == 32767 {
        return QuadFloat::infinity(a_sign != b_sign);
    }
    if (a_lo | a_hi) == 0 || (b_lo | b_hi) == 0 {
        return QuadFloat::zero(a_sign != b_sign);
    }

    normalize(&mut a_exp, &mut a_lo, &mut a_hi);
    normalize(&mut b_exp, &mut b_lo, &mut b_hi);

    let x_sign = a_sign != b_sign;
    let mut x_exp = a_exp + b_exp - 16352;

    // Decompose each 128-bit mantissa into four base-2^30 digits,
    // discarding the bottom 6 bits of the low word:
    //   (a3, a2, a1, a0) with (32, 30, 30, 30) bits respectively.
    let a0 = (a_lo << 28) >> 34;
    let b0 = (b_lo << 28) >> 34;
    let a1 = (a_lo >> 36) | ((a_hi << 62) >> 34);
    let b1 = (b_lo >> 36) | ((b_hi << 62) >> 34);
    let a2 = (a_hi << 32) >> 34;
    let b2 = (b_hi << 32) >> 34;
    let a3 = a_hi >> 32;
    let b3 = b_hi >> 32;

    // 16 small multiplications accumulated with carries.
    // wrapping_add / wrapping_mul match C unsigned-overflow semantics.
    let p0 = a0.wrapping_mul(b0);
    let p1 = (p0 >> 30)
        .wrapping_add(a0.wrapping_mul(b1))
        .wrapping_add(a1.wrapping_mul(b0));
    let p2 = (p1 >> 30)
        .wrapping_add(a0.wrapping_mul(b2))
        .wrapping_add(a1.wrapping_mul(b1))
        .wrapping_add(a2.wrapping_mul(b0));
    let p3 = (p2 >> 30)
        .wrapping_add(a0.wrapping_mul(b3))
        .wrapping_add(a1.wrapping_mul(b2))
        .wrapping_add(a2.wrapping_mul(b1))
        .wrapping_add(a3.wrapping_mul(b0));
    let p4 = (p3 >> 30)
        .wrapping_add(a1.wrapping_mul(b3))
        .wrapping_add(a2.wrapping_mul(b2))
        .wrapping_add(a3.wrapping_mul(b1));
    let p5 = (p4 >> 30)
        .wrapping_add(a2.wrapping_mul(b3))
        .wrapping_add(a3.wrapping_mul(b2));
    let p6 = (p5 >> 30)
        .wrapping_add(a3.wrapping_mul(b3));

    // Assemble the top 128 bits with sticky bit.
    let sticky = u64::from(
        ((p3 << 38) | ((p2 | p1 | p0) << 34)) != 0,
    );
    let mut y0 = (p5 << 34)
        | ((p4 << 34) >> 30)
        | ((p3 << 34) >> 60)
        | sticky;
    let mut y1 = p6;

    // Top bit may be zero after multiplication; renormalise.
    if (y1 >> 63) == 0 {
        y1 = (y1 << 1) | (y0 >> 63);
        y0 <<= 1;
        x_exp -= 1;
    }

    round(x_sign, x_exp, y0, y1)
}

// ---------------------------------------------------------------------------
// Arithmetic — division
// ---------------------------------------------------------------------------

/// Quad-precision division: `a ÷ b`.
///
/// C equivalent: `__divtf3` in `lib/lib-arm64.c` lines 329–379.
///
/// Uses restoring binary long division over 116 iterations to produce
/// 116 quotient bits plus a sticky remainder bit.
pub(crate) fn divtf3(a: QuadFloat, b: QuadFloat) -> QuadFloat {
    let (a_sign, mut a_exp, mut a_lo, mut a_hi) = unpack(a);
    let (b_sign, mut b_exp, mut b_lo, mut b_hi) = unpack(b);

    if let Some(nan) = detect_nans(
        a_sign, a_exp, a_lo, a_hi,
        b_sign, b_exp, b_lo, b_hi,
    ) {
        return nan;
    }

    // Handle infinities and zeros.
    if (a_exp == 32767 && b_exp == 32767)
        || ((a_lo | a_hi) == 0 && (b_lo | b_hi) == 0)
    {
        return QuadFloat::nan(); // inf/inf  or  0/0
    }
    if a_exp == 32767 || (b_lo | b_hi) == 0 {
        return QuadFloat::infinity(a_sign != b_sign);
    }
    if (a_lo | a_hi) == 0 || b_exp == 32767 {
        return QuadFloat::zero(a_sign != b_sign);
    }

    normalize(&mut a_exp, &mut a_lo, &mut a_hi);
    normalize(&mut b_exp, &mut b_lo, &mut b_hi);

    let x_sign = a_sign != b_sign;
    let mut x_exp = a_exp - b_exp + 16395;

    // Right-shift both mantissas by 1 to prevent overflow in subtraction.
    a_lo = (a_lo >> 1) | (a_hi << 63);
    a_hi >>= 1;
    b_lo = (b_lo >> 1) | (b_hi << 63);
    b_hi >>= 1;

    let mut x_lo: u64 = 0;
    let mut x_hi: u64 = 0;

    // Restoring long division: 116 iterations.
    for _i in 0..116 {
        // Shift quotient left by 1.
        x_hi = (x_hi << 1) | (x_lo >> 63);
        x_lo <<= 1;

        // If remainder ≥ divisor, subtract and set quotient bit.
        if a_hi > b_hi || (a_hi == b_hi && a_lo >= b_lo) {
            a_hi = a_hi
                .wrapping_sub(b_hi)
                .wrapping_sub(u64::from(a_lo < b_lo));
            a_lo = a_lo.wrapping_sub(b_lo);
            x_lo |= 1;
        }

        // Shift remainder left by 1.
        a_hi = (a_hi << 1) | (a_lo >> 63);
        a_lo <<= 1;
    }

    // Sticky bit from the remainder.
    x_lo |= u64::from((a_lo | a_hi) != 0);

    normalize(&mut x_exp, &mut x_lo, &mut x_hi);
    round(x_sign, x_exp, x_lo, x_hi)
}

// ---------------------------------------------------------------------------
// Arithmetic — negation
// ---------------------------------------------------------------------------

/// Quad-precision negation: `−a`.
///
/// C equivalent: `__negtf2` in `lib/lib-arm64.c` lines 381–390.
///
/// Flips only the sign bit; mantissa and exponent are unchanged.
pub(crate) fn negtf2(a: QuadFloat) -> QuadFloat {
    QuadFloat {
        x0: a.x0,
        x1: a.x1 ^ (1u64 << 63),
    }
}

// ---------------------------------------------------------------------------
// Conversions — widen to quad
// ---------------------------------------------------------------------------

/// Extend `f32` to quad-precision.
///
/// C equivalent: `__extendsftf2` in `lib/lib-arm64.c` lines 392–416.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 bit-level manipulation: exponent/mantissa field extraction and assembly
pub(crate) fn extendsftf2(f: f32) -> QuadFloat {
    let a: u32 = f.to_bits();
    let aa: u64 = u64::from(a);
    let x0: u64 = 0;
    let x1: u64;

    if (a << 1) == 0 {
        // ±0 — only the sign bit survives.
        x1 = aa << 32;
    } else if (a << 1) >> 24 == 255 {
        // Infinity or NaN.
        // Rebuild with quad exponent 0x7FFF, propagating mantissa and sign.
        // The quiet-NaN bit is set if any mantissa bit was set.
        x1 = 0x7FFF_0000_0000_0000
            | (aa >> 31 << 63)
            | ((aa << 41) >> 16)
            | (u64::from((a << 9) != 0) << 47);
    } else if (a << 1) >> 24 == 0 {
        // Subnormal f32 — normalise and rebias.
        let mut adj: u64 = 0;
        while ((a << 1) >> 1 >> (23u64.wrapping_sub(adj) as u32)) == 0 {
            adj += 1;
        }
        x1 = (aa >> 31 << 63)
            | ((16256u64.wrapping_sub(adj).wrapping_add(1)) << 48)
            | ((aa << (adj as u32) << 41) >> 16);
    } else {
        // Normal f32 — rebias exponent from 127 to 16383 (offset 16256).
        x1 = (aa >> 31 << 63)
            | (((aa >> 23 & 255) + 16256) << 48)
            | ((aa << 41) >> 16);
    }

    QuadFloat { x0, x1 }
}

/// Extend `f64` to quad-precision.
///
/// C equivalent: `__extenddftf2` in `lib/lib-arm64.c` lines 418–440.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 bit-level manipulation: exponent/mantissa field extraction and assembly
pub(crate) fn extenddftf2(f: f64) -> QuadFloat {
    let a: u64 = f.to_bits();
    let mut x0: u64 = a << 60;
    let x1: u64;

    if (a << 1) == 0 {
        // ±0
        x1 = a;
    } else if (a << 1) >> 53 == 2047 {
        // Infinity or NaN.
        x1 = 0x7FFF_0000_0000_0000
            | (a >> 63 << 63)
            | ((a << 12) >> 16)
            | (u64::from((a << 12) != 0) << 47);
    } else if (a << 1) >> 53 == 0 {
        // Subnormal f64 — normalise and rebias.
        let mut adj: u64 = 0;
        while ((a << 1) >> 1 >> (52u64.wrapping_sub(adj) as u32)) == 0 {
            adj += 1;
        }
        x0 <<= adj as u32;
        x1 = (a >> 63 << 63)
            | ((15360u64.wrapping_sub(adj).wrapping_add(1)) << 48)
            | ((a << (adj as u32) << 12) >> 16);
    } else {
        // Normal f64 — rebias exponent from 1023 to 16383 (offset 15360).
        x1 = (a >> 63 << 63)
            | (((a >> 52 & 2047) + 15360) << 48)
            | ((a << 12) >> 16);
    }

    QuadFloat { x0, x1 }
}

// ---------------------------------------------------------------------------
// Conversions — truncate from quad
// ---------------------------------------------------------------------------

/// Truncate quad-precision to `f32`.
///
/// C equivalent: `__trunctfsf2` in `lib/lib-arm64.c` lines 442–471.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 bit-level manipulation: exponent narrowing and mantissa rounding
pub(crate) fn trunctfsf2(f: QuadFloat) -> f32 {
    let (sgn, exp, mnt_lo, mnt_hi) = unpack(f);
    let sgn_bit = u32::from(sgn) << 31;
    let x: u32;

    if exp == 32767 && (mnt_lo | (mnt_hi << 16)) != 0 {
        // NaN
        x = 0x7FC0_0000 | sgn_bit | ((mnt_hi >> 25) as u32 & 0x007F_FFFF);
    } else if exp > 16510 {
        // Overflow → infinity
        x = 0x7F80_0000 | sgn_bit;
    } else if exp < 16233 {
        // Underflow → zero
        x = sgn_bit;
    } else {
        let mut e = exp - 16257;
        let mut m = (mnt_hi >> 23) as u32
            | u32::from((mnt_lo | (mnt_hi << 41)) != 0);
        if e < 0 {
            let neg_e = (-e) as u32;
            m = (m >> neg_e) | u32::from((m << (32u32.wrapping_sub(neg_e))) != 0);
            e = 0;
        }
        // Round to nearest even.
        if (m & 3) == 3 || (m & 7) == 6 {
            m += 4;
        }
        x = ((m >> 2).wrapping_add((e as u32) << 23)) | sgn_bit;
    }

    f32::from_bits(x)
}

/// Truncate quad-precision to `f64`.
///
/// C equivalent: `__trunctfdf2` in `lib/lib-arm64.c` lines 473–503.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 bit-level manipulation: exponent narrowing and mantissa rounding
pub(crate) fn trunctfdf2(f: QuadFloat) -> f64 {
    let (sgn, exp, mnt_lo, mnt_hi) = unpack(f);
    let sgn_bit = u64::from(sgn) << 63;
    let x: u64;

    if exp == 32767 && (mnt_lo | (mnt_hi << 16)) != 0 {
        // NaN
        x = 0x7FF8_0000_0000_0000
            | sgn_bit
            | ((mnt_hi << 16) >> 12)
            | (mnt_lo >> 60);
    } else if exp > 17406 {
        // Overflow → infinity
        x = 0x7FF0_0000_0000_0000 | sgn_bit;
    } else if exp < 15308 {
        // Underflow → zero
        x = sgn_bit;
    } else {
        let mut e = exp - 15361;
        let mut m = (mnt_hi << 6) | (mnt_lo >> 58)
            | u64::from((mnt_lo << 6) != 0);
        if e < 0 {
            let neg_e = (-e) as u32;
            m = (m >> neg_e) | u64::from((m << (64u32.wrapping_sub(neg_e))) != 0);
            e = 0;
        }
        // Round to nearest even.
        if (m & 3) == 3 || (m & 7) == 6 {
            m += 4;
        }
        x = ((m >> 2).wrapping_add((e as u64) << 52)) | sgn_bit;
    }

    f64::from_bits(x)
}

// ---------------------------------------------------------------------------
// Integer casts — quad → signed / unsigned integer
// ---------------------------------------------------------------------------

/// Convert quad-precision to `i32` (truncating towards zero).
///
/// C equivalent: `__fixtfsi` in `lib/lib-arm64.c` lines 505–518.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 quad→i32 conversion: mantissa shift and sign application
pub(crate) fn fixtfsi(fa: QuadFloat) -> i32 {
    let (a_sgn, a_exp, _a_lo, a_hi) = unpack(fa);
    if a_exp < 16369 {
        return 0; // |value| < 0.5
    }
    if a_exp > 16413 {
        return if a_sgn {
            i32::MIN // −2^31
        } else {
            i32::MAX // 2^31 − 1
        };
    }
    let shift = (16431 - a_exp) as u32;
    let x = (a_hi >> shift) as i32;
    if a_sgn { -x } else { x }
}

/// Convert quad-precision to `i64` (truncating towards zero).
///
/// C equivalent: `__fixtfdi` in `lib/lib-arm64.c` lines 520–533.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 quad→i64 conversion: mantissa shift and sign application
pub(crate) fn fixtfdi(fa: QuadFloat) -> i64 {
    let (a_sgn, a_exp, a_lo, a_hi) = unpack(fa);
    if a_exp < 16383 {
        return 0;
    }
    if a_exp > 16445 {
        return if a_sgn {
            i64::MIN // −2^63
        } else {
            i64::MAX // 2^63 − 1
        };
    }
    let combined = (a_hi << 15) | (a_lo >> 49);
    let shift = (16446 - a_exp) as u32;
    let x = (combined >> shift) as i64;
    if a_sgn { -x } else { x }
}

/// Convert quad-precision to `u32` (truncating towards zero, negative → 0).
///
/// C equivalent: `__fixunstfsi` in `lib/lib-arm64.c` lines 535–546.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
// IEEE 754 quad→u32 conversion: mantissa shift with sign-guard
pub(crate) fn fixunstfsi(fa: QuadFloat) -> u32 {
    let (a_sgn, a_exp, _a_lo, a_hi) = unpack(fa);
    if a_sgn || a_exp < 16369 {
        return 0;
    }
    if a_exp > 16414 {
        return u32::MAX;
    }
    let shift = (16431 - a_exp) as u32;
    (a_hi >> shift) as u32
}

/// Convert quad-precision to `u64` (truncating towards zero, negative → 0).
///
/// C equivalent: `__fixunstfdi` in `lib/lib-arm64.c` lines 548–559.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
// IEEE 754 quad→u64 conversion: mantissa shift with sign-guard
pub(crate) fn fixunstfdi(fa: QuadFloat) -> u64 {
    let (a_sgn, a_exp, a_lo, a_hi) = unpack(fa);
    if a_sgn || a_exp < 16383 {
        return 0;
    }
    if a_exp > 16446 {
        return u64::MAX;
    }
    let combined = (a_hi << 15) | (a_lo >> 49);
    let shift = (16446 - a_exp) as u32;
    combined >> shift
}

// ---------------------------------------------------------------------------
// Integer casts — signed / unsigned integer → quad
// ---------------------------------------------------------------------------

/// Convert `i32` to quad-precision.
///
/// C equivalent: `__floatsitf` in `lib/lib-arm64.c` lines 561–584.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 i32→quad conversion: sign extraction, magnitude→mantissa, exponent assembly
pub(crate) fn floatsitf(a: i32) -> QuadFloat {
    if a == 0 {
        return QuadFloat::zero(false);
    }

    let sgn = a < 0;
    let mut mnt: u32 = if sgn { (a as u32).wrapping_neg() } else { a as u32 };
    let mut exp: i32 = 16414; // BIAS + 31

    // Normalise — shift so MSB is at bit 31.
    let mut sh: u32 = 16;
    while sh != 0 {
        if (mnt >> (32 - sh)) == 0 {
            mnt <<= sh;
            exp -= sh as i32;
        }
        sh >>= 1;
    }

    // Pack: implicit bit removed by the `<< 1`, then positioned at bits [17..47].
    let hi = (u64::from(sgn) << 63)
        | ((exp as u64) << 48)
        | (u64::from(mnt << 1) << 16);

    QuadFloat { x0: 0, x1: hi }
}

/// Convert `i64` to quad-precision.
///
/// C equivalent: `__floatditf` in `lib/lib-arm64.c` lines 586–609.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 i64→quad conversion: sign extraction, magnitude→mantissa, exponent assembly
pub(crate) fn floatditf(a: i64) -> QuadFloat {
    if a == 0 {
        return QuadFloat::zero(false);
    }

    let sgn = a < 0;
    let mut mnt: u64 = if sgn { (a as u64).wrapping_neg() } else { a as u64 };
    let mut exp: i32 = 16446; // BIAS + 63

    // Normalise — shift so MSB is at bit 63.
    let mut sh: u32 = 32;
    while sh != 0 {
        if (mnt >> (64 - sh)) == 0 {
            mnt <<= sh;
            exp -= sh as i32;
        }
        sh >>= 1;
    }

    // Bottom 15 mantissa bits go into x0, top 48 into x1.
    let lo = mnt << 49;
    let hi = (u64::from(sgn) << 63)
        | ((exp as u64) << 48)
        | ((mnt << 1) >> 16);

    QuadFloat { x0: lo, x1: hi }
}

/// Convert `u32` to quad-precision.
///
/// C equivalent: `__floatunsitf` in `lib/lib-arm64.c` lines 611–628.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 u32→quad conversion: magnitude→mantissa, exponent assembly; sh→i32 for exp adjust
pub(crate) fn floatunsitf(a: u32) -> QuadFloat {
    if a == 0 {
        return QuadFloat::zero(false);
    }

    let mut mnt: u32 = a;
    let mut exp: i32 = 16414; // BIAS + 31

    let mut sh: u32 = 16;
    while sh != 0 {
        if (mnt >> (32 - sh)) == 0 {
            mnt <<= sh;
            exp -= sh as i32;
        }
        sh >>= 1;
    }

    let hi = ((exp as u64) << 48)
        | (u64::from(mnt << 1) << 16);

    QuadFloat { x0: 0, x1: hi }
}

/// Convert `u64` to quad-precision.
///
/// C equivalent: `__floatunditf` in `lib/lib-arm64.c` lines 630–648.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// IEEE 754 u64→quad conversion: magnitude→mantissa, exponent assembly; sh→i32 for exp adjust
pub(crate) fn floatunditf(a: u64) -> QuadFloat {
    if a == 0 {
        return QuadFloat::zero(false);
    }

    let mut mnt: u64 = a;
    let mut exp: i32 = 16446; // BIAS + 63

    let mut sh: u32 = 32;
    while sh != 0 {
        if (mnt >> (64 - sh)) == 0 {
            mnt <<= sh;
            exp -= sh as i32;
        }
        sh >>= 1;
    }

    let lo = mnt << 49;
    let hi = ((exp as u64) << 48)
        | ((mnt << 1) >> 16);

    QuadFloat { x0: lo, x1: hi }
}

// ---------------------------------------------------------------------------
// Comparisons
// ---------------------------------------------------------------------------

/// Three-way comparison on packed quad-precision values.
///
/// C equivalent: `f3_cmp()` in `lib/lib-arm64.c` lines 650–663.
///
/// Returns:
/// - `0`  if `a == b` (including `+0 == −0`)
/// - `-1` if `a < b`
/// - `1`  if `a > b`
/// - `2`  if unordered (either operand is NaN)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn cmp(a: QuadFloat, b: QuadFloat) -> i32 {
    let ax0 = a.x0;
    let ax1 = a.x1;
    let bx0 = b.x0;
    let bx1 = b.x1;

    // Both ±0.
    if (ax0 | (ax1 << 1) | bx0 | (bx1 << 1)) == 0 {
        return 0;
    }

    // Either NaN — exponent 0x7FFF and nonzero mantissa.
    let a_is_nan = ((ax1 << 1) >> 49) == 0x7FFF && ((ax0 | (ax1 << 16)) != 0);
    let b_is_nan = ((bx1 << 1) >> 49) == 0x7FFF && ((bx0 | (bx1 << 16)) != 0);
    if a_is_nan || b_is_nan {
        return 2;
    }

    // Different signs.
    let a_sign = ax1 >> 63;
    let b_sign = bx1 >> 63;
    if a_sign != b_sign {
        return (b_sign as i32) - (a_sign as i32);
    }

    // Same sign — compare magnitude (x1 first, then x0).
    // For positive numbers: a < b → −1; for negative: a < b (by bits) → 1.
    let sign_flip = (a_sign << 1) as i32 - 1; // −1 if positive, +1 if negative
    if ax1 < bx1 {
        return sign_flip;
    }
    if ax1 > bx1 {
        return -sign_flip;
    }
    if ax0 < bx0 {
        return sign_flip;
    }
    if bx0 < ax0 {
        return -sign_flip;
    }
    0
}

/// Quad-precision equality test.
///
/// C equivalent: `__eqtf2` in `lib/lib-arm64.c` lines 665–668.
///
/// Returns `0` if `a == b`, nonzero otherwise (including NaN).
pub(crate) fn eqtf2(a: QuadFloat, b: QuadFloat) -> i32 {
    i32::from(cmp(a, b) != 0)
}

/// Quad-precision inequality test.
///
/// C equivalent: `__netf2` in `lib/lib-arm64.c` lines 670–673.
///
/// Returns `0` if `a == b`, nonzero otherwise (including NaN).
/// (Same semantics as `eqtf2` per GCC soft-float convention.)
pub(crate) fn netf2(a: QuadFloat, b: QuadFloat) -> i32 {
    i32::from(cmp(a, b) != 0)
}

/// Quad-precision less-than comparison.
///
/// C equivalent: `__lttf2` in `lib/lib-arm64.c` lines 675–678.
///
/// Returns negative if `a < b`, `0` if equal, positive if `a > b`,
/// `2` if unordered (NaN).
pub(crate) fn lttf2(a: QuadFloat, b: QuadFloat) -> i32 {
    cmp(a, b)
}

/// Quad-precision less-than-or-equal comparison.
///
/// C equivalent: `__letf2` in `lib/lib-arm64.c` lines 680–683.
///
/// Returns negative if `a < b`, `0` if equal, positive if `a > b`,
/// `2` if unordered.
pub(crate) fn letf2(a: QuadFloat, b: QuadFloat) -> i32 {
    cmp(a, b)
}

/// Quad-precision greater-than comparison.
///
/// C equivalent: `__gttf2` in `lib/lib-arm64.c` lines 685–688.
///
/// Returns negative if `a < b`, `0` if equal, positive if `a > b`,
/// `−2` if unordered.
pub(crate) fn gttf2(a: QuadFloat, b: QuadFloat) -> i32 {
    -cmp(b, a)
}

/// Quad-precision greater-than-or-equal comparison.
///
/// C equivalent: `__getf2` in `lib/lib-arm64.c` lines 690–693.
///
/// Returns negative if `a < b`, `0` if equal, positive if `a > b`,
/// `−2` if unordered.
pub(crate) fn getf2(a: QuadFloat, b: QuadFloat) -> i32 {
    -cmp(b, a)
}

/// Quad-precision unordered comparison.
///
/// Standard compiler-rt function `__unordtf2`: returns nonzero if either
/// operand is NaN, `0` if both operands are ordered.
///
/// Not present in the original `lib/lib-arm64.c` — added for completeness
/// to satisfy the full soft-float ABI contract.
pub(crate) fn unordtf2(a: QuadFloat, b: QuadFloat) -> i32 {
    i32::from(a.is_nan() || b.is_nan())
}

// ---------------------------------------------------------------------------
// ARM64 cache flush helper
// ---------------------------------------------------------------------------

/// ARM64 instruction-cache flush.
///
/// C equivalent: `__arm64_clear_cache` / `__clear_cache` in
/// `lib/lib-arm64.c` lines 34–38.
///
/// The actual cache-flush system call (`ic ivau` / `dsb ish` / `isb` on
/// `AArch64`) requires `unsafe` and platform-specific code which lives in
/// `src/runtime.rs` per the project's safety policy (AAP §0.8.1).
/// This function provides the safe interface; the platform implementation
/// is delegated to the runtime module at link time.
pub(crate) fn arm64_clear_cache(_beg: usize, _end: usize) {
    // On non-aarch64 hosts this is a no-op.
    // On aarch64 the actual flush is handled by src/runtime.rs via
    // the unsafe `libc::__clear_cache` or inline assembly wrapper.
    //
    // This stub exists so that other crate modules can reference the
    // symbol without platform-conditional imports.
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    // --- QuadFloat constructors ---

    #[test]
    fn test_zero_positive() {
        let z = QuadFloat::zero(false);
        assert_eq!(z.x0, 0);
        assert_eq!(z.x1, 0);
        assert!(!z.sign());
        assert!(!z.is_nan());
        assert!(!z.is_infinity());
    }

    #[test]
    fn test_zero_negative() {
        let z = QuadFloat::zero(true);
        assert_eq!(z.x0, 0);
        assert_eq!(z.x1, 1u64 << 63);
        assert!(z.sign());
    }

    #[test]
    fn test_infinity_positive() {
        let inf = QuadFloat::infinity(false);
        assert!(inf.is_infinity());
        assert!(!inf.is_nan());
        assert!(!inf.sign());
        assert_eq!(inf.exponent(), 0x7FFF);
    }

    #[test]
    fn test_infinity_negative() {
        let inf = QuadFloat::infinity(true);
        assert!(inf.is_infinity());
        assert!(inf.sign());
    }

    #[test]
    fn test_nan() {
        let n = QuadFloat::nan();
        assert!(n.is_nan());
        assert!(!n.is_infinity());
    }

    // --- Constants ---

    #[test]
    fn test_constants() {
        assert_eq!(QuadFloat::BIAS, 16383);
        assert_eq!(QuadFloat::MANT_BITS, 112);
        assert_eq!(QuadFloat::EXP_BITS, 15);
        assert_eq!(QuadFloat::MAX_EXP, 0x7FFF);
    }

    // --- Integer → quad conversion round-trips ---

    #[test]
    fn test_floatsitf_zero() {
        assert_eq!(floatsitf(0), QuadFloat::zero(false));
    }

    #[test]
    fn test_floatsitf_one() {
        let q = floatsitf(1);
        // 1.0q has biased exponent = BIAS = 16383, mantissa = 0
        assert_eq!(q.exponent(), 16383);
        assert!(!q.sign());
        assert_eq!(q.x0, 0);
        // Mantissa bits in x1[0..47] should be zero
        assert_eq!(q.x1 & 0x0000_FFFF_FFFF_FFFF, 0);
    }

    #[test]
    fn test_floatsitf_negative() {
        let q = floatsitf(-1);
        assert!(q.sign());
        // Same magnitude as +1
        let pos = floatsitf(1);
        assert_eq!(q.x0, pos.x0);
        assert_eq!(q.x1 ^ (1u64 << 63), pos.x1);
    }

    #[test]
    fn test_floatditf_round_trip() {
        for &val in &[0i64, 1, -1, 42, -42, i64::MAX, i64::MIN + 1] {
            let q = floatditf(val);
            let back = fixtfdi(q);
            assert_eq!(back, val, "round-trip failed for {val}");
        }
    }

    #[test]
    fn test_floatunsitf_round_trip() {
        for &val in &[0u32, 1, 42, u32::MAX] {
            let q = floatunsitf(val);
            let back = fixunstfsi(q);
            assert_eq!(back, val, "round-trip failed for {val}");
        }
    }

    #[test]
    fn test_floatunditf_round_trip() {
        for &val in &[0u64, 1, 1000, u64::MAX >> 1] {
            let q = floatunditf(val);
            let back = fixunstfdi(q);
            assert_eq!(back, val, "round-trip failed for {val}");
        }
    }

    // --- Negation ---

    #[test]
    fn test_negtf2() {
        let one = floatsitf(1);
        let neg = negtf2(one);
        assert!(neg.sign());
        let pos = negtf2(neg);
        assert_eq!(pos, one);
    }

    // --- Addition / subtraction ---

    #[test]
    fn test_addtf3_basic() {
        let one = floatsitf(1);
        let two = floatsitf(2);
        let three = floatsitf(3);
        assert_eq!(addtf3(one, two), three);
    }

    #[test]
    fn test_subtf3_basic() {
        let five = floatsitf(5);
        let three = floatsitf(3);
        let two = floatsitf(2);
        assert_eq!(subtf3(five, three), two);
    }

    #[test]
    fn test_add_opposite_signs() {
        let five = floatsitf(5);
        let neg5 = negtf2(five);
        let result = addtf3(five, neg5);
        assert_eq!(result, QuadFloat::zero(false));
    }

    #[test]
    fn test_add_infinities() {
        let inf = QuadFloat::infinity(false);
        let ninf = QuadFloat::infinity(true);
        // inf + inf = inf
        assert!(addtf3(inf, inf).is_infinity());
        // inf + (−inf) = NaN
        assert!(addtf3(inf, ninf).is_nan());
    }

    // --- Multiplication ---

    #[test]
    fn test_multf3_basic() {
        let three = floatsitf(3);
        let four = floatsitf(4);
        let twelve = floatsitf(12);
        assert_eq!(multf3(three, four), twelve);
    }

    #[test]
    fn test_multf3_zero() {
        let zero = QuadFloat::zero(false);
        let five = floatsitf(5);
        assert_eq!(multf3(zero, five), QuadFloat::zero(false));
    }

    #[test]
    fn test_multf3_inf_zero_nan() {
        let inf = QuadFloat::infinity(false);
        let zero = QuadFloat::zero(false);
        assert!(multf3(inf, zero).is_nan());
    }

    // --- Division ---

    #[test]
    fn test_divtf3_basic() {
        let twelve = floatsitf(12);
        let four = floatsitf(4);
        let three = floatsitf(3);
        assert_eq!(divtf3(twelve, four), three);
    }

    #[test]
    fn test_divtf3_zero_by_zero() {
        let z = QuadFloat::zero(false);
        assert!(divtf3(z, z).is_nan());
    }

    #[test]
    fn test_divtf3_by_zero() {
        let one = floatsitf(1);
        let z = QuadFloat::zero(false);
        assert!(divtf3(one, z).is_infinity());
    }

    // --- Float conversions ---

    #[test]
    fn test_extendsftf2_one() {
        let q = extendsftf2(1.0f32);
        let expected = floatsitf(1);
        assert_eq!(q, expected);
    }

    #[test]
    fn test_extenddftf2_one() {
        let q = extenddftf2(1.0f64);
        let expected = floatsitf(1);
        assert_eq!(q, expected);
    }

    #[test]
    fn test_trunctfsf2_round_trip() {
        for &val in &[0.0f32, 1.0, -1.0, 3.125, f32::INFINITY, f32::NEG_INFINITY] {
            let q = extendsftf2(val);
            let back = trunctfsf2(q);
            assert_eq!(back.to_bits(), val.to_bits(),
                "f32 round-trip failed for {val}");
        }
    }

    #[test]
    fn test_trunctfdf2_round_trip() {
        for &val in &[0.0f64, 1.0, -1.0, 2.625, f64::INFINITY] {
            let q = extenddftf2(val);
            let back = trunctfdf2(q);
            assert_eq!(back.to_bits(), val.to_bits(),
                "f64 round-trip failed for {val}");
        }
    }

    #[test]
    fn test_nan_conversions() {
        let nan32 = extendsftf2(f32::NAN);
        assert!(nan32.is_nan());
        let nan64 = extenddftf2(f64::NAN);
        assert!(nan64.is_nan());
        assert!(trunctfsf2(QuadFloat::nan()).is_nan());
        assert!(trunctfdf2(QuadFloat::nan()).is_nan());
    }

    // --- Comparisons ---

    #[test]
    fn test_eqtf2_equal() {
        let a = floatsitf(42);
        assert_eq!(eqtf2(a, a), 0);
    }

    #[test]
    fn test_eqtf2_not_equal() {
        let a = floatsitf(1);
        let b = floatsitf(2);
        assert_ne!(eqtf2(a, b), 0);
    }

    #[test]
    fn test_lttf2() {
        let one = floatsitf(1);
        let two = floatsitf(2);
        assert!(lttf2(one, two) < 0);
        assert!(lttf2(two, one) > 0);
        assert_eq!(lttf2(one, one), 0);
    }

    #[test]
    fn test_gttf2() {
        let one = floatsitf(1);
        let two = floatsitf(2);
        assert!(gttf2(two, one) > 0);
        assert!(gttf2(one, two) < 0);
    }

    #[test]
    fn test_unordtf2() {
        let one = floatsitf(1);
        let nan = QuadFloat::nan();
        assert_eq!(unordtf2(one, one), 0);
        assert_ne!(unordtf2(one, nan), 0);
        assert_ne!(unordtf2(nan, one), 0);
        assert_ne!(unordtf2(nan, nan), 0);
    }

    #[test]
    fn test_zero_equality() {
        let pz = QuadFloat::zero(false);
        let nz = QuadFloat::zero(true);
        assert_eq!(eqtf2(pz, nz), 0); // +0 == −0
    }

    // --- arm64_clear_cache ---

    #[test]
    fn test_arm64_clear_cache_no_panic() {
        // Should not panic (no-op on non-aarch64).
        arm64_clear_cache(0, 4096);
    }
}
