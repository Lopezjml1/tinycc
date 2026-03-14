//! Compiler builtin functions implementation.
//!
//! Provides De Bruijn table-based implementations of common compiler
//! builtins: ffs, clz, ctz, clrsb, popcount, and parity for 32-bit
//! and 64-bit integers. Platform-sized "long" variants delegate to
//! the correct width based on `std::mem::size_of::<isize>()`.
//!
//! C equivalent: `lib/builtin.c` (164 lines)
//!
//! ## Safety
//!
//! This module contains zero `unsafe` blocks. All operations are pure
//! arithmetic on integer types using De Bruijn multiplication sequences
//! and standard bit-manipulation algorithms.
//!
//! ## Integer Cast Policy
//!
//! Several functions require reinterpretation of signed integers as
//! unsigned bit patterns (e.g., `i32` → `u32`) for De Bruijn table
//! lookups. These casts are intentional and mathematically correct.
//! Targeted `#[allow(clippy::cast_*)]` attributes are applied at the
//! function level with justification comments.

use std::mem;

// ---------------------------------------------------------------------------
// De Bruijn lookup tables — exact values from lib/builtin.c lines 21-40
// ---------------------------------------------------------------------------

/// De Bruijn table for 32-bit ffs/ctz (isolate lowest set bit).
///
/// C equivalent: `table_1_32` in `builtin.c:21-24`
const TABLE_1_32: [u8; 32] = [
     0,  1, 28,  2, 29, 14, 24,  3, 30, 22, 20, 15, 25, 17,  4,  8,
    31, 27, 13, 23, 21, 19, 16,  7, 26, 12, 18,  6, 11,  5, 10,  9,
];

/// De Bruijn table for 32-bit clz (fill and count leading zeros).
///
/// C equivalent: `table_2_32` in `builtin.c:25-28`
const TABLE_2_32: [u8; 32] = [
    31, 22, 30, 21, 18, 10, 29,  2, 20, 17, 15, 13,  9,  6, 28,  1,
    23, 19, 11,  3, 16, 14,  7, 24, 12,  4,  8, 25,  5, 26, 27,  0,
];

/// De Bruijn table for 64-bit ffs/ctz (isolate lowest set bit).
///
/// C equivalent: `table_1_64` in `builtin.c:29-34`
const TABLE_1_64: [u8; 64] = [
     0,  1,  2, 53,  3,  7, 54, 27,  4, 38, 41,  8, 34, 55, 48, 28,
    62,  5, 39, 46, 44, 42, 22,  9, 24, 35, 59, 56, 49, 18, 29, 11,
    63, 52,  6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
    51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12,
];

/// De Bruijn table for 64-bit clz (fill and count leading zeros).
///
/// C equivalent: `table_2_64` in `builtin.c:35-40`
const TABLE_2_64: [u8; 64] = [
    63, 16, 62,  7, 15, 36, 61,  3,  6, 14, 22, 26, 35, 47, 60,  2,
     9,  5, 28, 11, 13, 21, 42, 19, 25, 31, 34, 40, 46, 52, 59,  1,
    17,  8, 37,  4, 23, 27, 48, 10, 29, 12, 43, 20, 32, 41, 53, 18,
    38, 24, 49, 30, 44, 33, 54, 39, 50, 45, 55, 51, 56, 57, 58,  0,
];

// ---------------------------------------------------------------------------
// ffs — find first set (least significant 1-bit)
// ---------------------------------------------------------------------------

/// Returns one plus the index of the least significant 1-bit of `x`,
/// or if `x` is zero, returns zero.
///
/// C equivalent: `__builtin_ffs()` in `builtin.c:78`
///
/// Uses De Bruijn multiplication on the isolated lowest set bit
/// (`x & -x`) to compute the bit index in O(1).
#[allow(clippy::cast_sign_loss)] // Intentional: reinterpret i32 bit pattern as u32
pub(crate) fn builtin_ffs(x: i32) -> i32 {
    let xu = x as u32;
    let isolated = xu.wrapping_neg() & xu;
    let idx = (isolated.wrapping_mul(0x077C_B531_u32) >> 27) as usize;
    i32::from(TABLE_1_32[idx]) + i32::from(xu != 0)
}

/// Returns one plus the index of the least significant 1-bit of `x`,
/// or if `x` is zero, returns zero. 64-bit variant.
///
/// C equivalent: `__builtin_ffsll()` in `builtin.c:79`
#[allow(clippy::cast_sign_loss)] // Intentional: reinterpret i64 bit pattern as u64
#[allow(clippy::cast_possible_truncation)] // Index is at most 63, always fits in usize
pub(crate) fn builtin_ffsll(x: i64) -> i32 {
    let xu = x as u64;
    let isolated = xu.wrapping_neg() & xu;
    let idx = (isolated.wrapping_mul(0x022F_DD63_CC95_386D_u64) >> 58) as usize;
    i32::from(TABLE_1_64[idx]) + i32::from(xu != 0)
}

/// Platform-sized `long` variant of `ffs`.
///
/// Routes to [`builtin_ffs`] on 32-bit platforms or [`builtin_ffsll`] on
/// 64-bit platforms, matching the C `__builtin_ffsl()` alias behavior
/// controlled by `__SIZEOF_LONG__`.
///
/// C equivalent: `__builtin_ffsl()` in `builtin.c:80-84`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; isize == i32 on 32-bit
pub(crate) fn builtin_ffsl(x: isize) -> i32 {
    if mem::size_of::<isize>() == 4 {
        builtin_ffs(x as i32)
    } else {
        builtin_ffsll(x as i64)
    }
}

// ---------------------------------------------------------------------------
// clz — count leading zeros
// ---------------------------------------------------------------------------

/// Returns the number of leading 0-bits in `x`, starting at the most
/// significant bit position. If `x` is 0, the result is undefined
/// (matches GCC `__builtin_clz` semantics).
///
/// C equivalent: `__builtin_clz()` in `builtin.c:88`
///
/// Algorithm: fill all bits below the highest set bit via cascading OR,
/// then use De Bruijn multiplication to look up the position.
pub(crate) fn builtin_clz(mut x: u32) -> i32 {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    let idx = (x.wrapping_mul(0x07C4_ACDD_u32) >> 27) as usize;
    i32::from(TABLE_2_32[idx])
}

/// Returns the number of leading 0-bits in `x`. 64-bit variant.
///
/// C equivalent: `__builtin_clzll()` in `builtin.c:89`
#[allow(clippy::cast_possible_truncation)] // Index is at most 63, always fits in usize
pub(crate) fn builtin_clzll(mut x: u64) -> i32 {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    let idx = (x.wrapping_mul(0x03F7_9D71_B4CB_0A89_u64) >> 58) as usize;
    i32::from(TABLE_2_64[idx])
}

/// Platform-sized `long` variant of `clz`.
///
/// C equivalent: `__builtin_clzl()` in `builtin.c:90-94`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; usize == u32 on 32-bit
pub(crate) fn builtin_clzl(x: usize) -> i32 {
    if mem::size_of::<usize>() == 4 {
        builtin_clz(x as u32)
    } else {
        builtin_clzll(x as u64)
    }
}

// ---------------------------------------------------------------------------
// ctz — count trailing zeros
// ---------------------------------------------------------------------------

/// Returns the number of trailing 0-bits in `x`, starting at the least
/// significant bit position. If `x` is 0, the result is undefined
/// (matches GCC `__builtin_ctz` semantics).
///
/// C equivalent: `__builtin_ctz()` in `builtin.c:98`
///
/// Uses the same De Bruijn technique as `ffs` but without the +1 offset.
pub(crate) fn builtin_ctz(x: u32) -> i32 {
    let isolated = x.wrapping_neg() & x;
    let idx = (isolated.wrapping_mul(0x077C_B531_u32) >> 27) as usize;
    i32::from(TABLE_1_32[idx])
}

/// Returns the number of trailing 0-bits in `x`. 64-bit variant.
///
/// C equivalent: `__builtin_ctzll()` in `builtin.c:99`
#[allow(clippy::cast_possible_truncation)] // Index is at most 63, always fits in usize
pub(crate) fn builtin_ctzll(x: u64) -> i32 {
    let isolated = x.wrapping_neg() & x;
    let idx = (isolated.wrapping_mul(0x022F_DD63_CC95_386D_u64) >> 58) as usize;
    i32::from(TABLE_1_64[idx])
}

/// Platform-sized `long` variant of `ctz`.
///
/// C equivalent: `__builtin_ctzl()` in `builtin.c:100-104`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; usize == u32 on 32-bit
pub(crate) fn builtin_ctzl(x: usize) -> i32 {
    if mem::size_of::<usize>() == 4 {
        builtin_ctz(x as u32)
    } else {
        builtin_ctzll(x as u64)
    }
}

// ---------------------------------------------------------------------------
// clrsb — count leading redundant sign bits
// ---------------------------------------------------------------------------

/// Returns the number of leading redundant sign bits in `x`, i.e. the
/// number of bits following the most significant bit that are identical
/// to it. There are no special cases for 0 or other values.
///
/// C equivalent: `__builtin_clrsb()` in `builtin.c:109`
///
/// Algorithm: if negative, bitwise-NOT to get the magnitude; shift left
/// by 1 to exclude the sign bit itself; then count leading zeros.
#[allow(clippy::cast_sign_loss)] // Intentional: after conditional NOT, value is non-negative
pub(crate) fn builtin_clrsb(x: i32) -> i32 {
    let magnitude = if x < 0 { !x } else { x } as u32;
    let shifted = magnitude << 1;
    builtin_clz(shifted)
}

/// Returns the number of leading redundant sign bits. 64-bit variant.
///
/// C equivalent: `__builtin_clrsbll()` in `builtin.c:110`
#[allow(clippy::cast_sign_loss)] // Intentional: after conditional NOT, value is non-negative
pub(crate) fn builtin_clrsbll(x: i64) -> i32 {
    let magnitude = if x < 0 { !x } else { x } as u64;
    let shifted = magnitude << 1;
    builtin_clzll(shifted)
}

/// Platform-sized `long` variant of `clrsb`.
///
/// C equivalent: `__builtin_clrsbl()` in `builtin.c:111-115`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; isize == i32 on 32-bit
pub(crate) fn builtin_clrsbl(x: isize) -> i32 {
    if mem::size_of::<isize>() == 4 {
        builtin_clrsb(x as i32)
    } else {
        builtin_clrsbll(x as i64)
    }
}

// ---------------------------------------------------------------------------
// popcount — population count (number of 1-bits)
// ---------------------------------------------------------------------------

/// Returns the number of 1-bits in `x`.
///
/// C equivalent: `__builtin_popcount()` in `builtin.c:118`
///
/// Uses the standard sideways-addition algorithm: pairs → nibbles →
/// bytes, then multiply-and-shift to sum all bytes into the top byte.
#[allow(clippy::cast_possible_wrap)] // Result is 0..=32, always fits in i32
pub(crate) fn builtin_popcount(mut x: u32) -> i32 {
    x -= (x >> 1) & 0x5555_5555;
    x = (x & 0x3333_3333) + ((x >> 2) & 0x3333_3333);
    x = (x + (x >> 4)) & 0x0F0F_0F0F;
    ((x.wrapping_mul(0x0101_0101)) >> 24) as i32 & 0x3F
}

/// Returns the number of 1-bits in `x`. 64-bit variant.
///
/// C equivalent: `__builtin_popcountll()` in `builtin.c:119`
#[allow(clippy::cast_possible_truncation)] // Result of >> 56 is at most 255, fits in i32
#[allow(clippy::cast_possible_wrap)] // Result is 0..=64, always fits in i32
pub(crate) fn builtin_popcountll(mut x: u64) -> i32 {
    x -= (x >> 1) & 0x5555_5555_5555_5555_u64;
    x = (x & 0x3333_3333_3333_3333_u64) + ((x >> 2) & 0x3333_3333_3333_3333_u64);
    x = (x + (x >> 4)) & 0x0F0F_0F0F_0F0F_0F0F_u64;
    ((x.wrapping_mul(0x0101_0101_0101_0101_u64)) >> 56) as i32 & 0x7F
}

/// Platform-sized `long` variant of `popcount`.
///
/// C equivalent: `__builtin_popcountl()` in `builtin.c:120-124`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; usize == u32 on 32-bit
pub(crate) fn builtin_popcountl(x: usize) -> i32 {
    if mem::size_of::<usize>() == 4 {
        builtin_popcount(x as u32)
    } else {
        builtin_popcountll(x as u64)
    }
}

// ---------------------------------------------------------------------------
// parity — bit parity (popcount mod 2)
// ---------------------------------------------------------------------------

/// Returns the parity of `x`, i.e. the number of 1-bits in `x` modulo 2.
///
/// C equivalent: `__builtin_parity()` in `builtin.c:127`
///
/// Uses the same sideways-addition as popcount but masks the final
/// result to a single bit.
#[allow(clippy::cast_possible_wrap)] // Result is 0 or 1, always fits in i32
pub(crate) fn builtin_parity(mut x: u32) -> i32 {
    x -= (x >> 1) & 0x5555_5555;
    x = (x & 0x3333_3333) + ((x >> 2) & 0x3333_3333);
    x = (x + (x >> 4)) & 0x0F0F_0F0F;
    ((x.wrapping_mul(0x0101_0101)) >> 24) as i32 & 0x01
}

/// Returns the parity of `x`. 64-bit variant.
///
/// C equivalent: `__builtin_parityll()` in `builtin.c:128`
#[allow(clippy::cast_possible_truncation)] // Result of >> 56 is at most 255, fits in i32
#[allow(clippy::cast_possible_wrap)] // Result is 0 or 1, always fits in i32
pub(crate) fn builtin_parityll(mut x: u64) -> i32 {
    x -= (x >> 1) & 0x5555_5555_5555_5555_u64;
    x = (x & 0x3333_3333_3333_3333_u64) + ((x >> 2) & 0x3333_3333_3333_3333_u64);
    x = (x + (x >> 4)) & 0x0F0F_0F0F_0F0F_0F0F_u64;
    ((x.wrapping_mul(0x0101_0101_0101_0101_u64)) >> 56) as i32 & 0x01
}

/// Platform-sized `long` variant of `parity`.
///
/// C equivalent: `__builtin_parityl()` in `builtin.c:129-133`
#[allow(clippy::cast_possible_truncation)] // Guarded by size_of check; usize == u32 on 32-bit
pub(crate) fn builtin_parityl(x: usize) -> i32 {
    if mem::size_of::<usize>() == 4 {
        builtin_parity(x as u32)
    } else {
        builtin_parityll(x as u64)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ffs tests --

    #[test]
    fn test_ffs_zero() {
        assert_eq!(builtin_ffs(0), 0);
    }

    #[test]
    fn test_ffs_one() {
        assert_eq!(builtin_ffs(1), 1);
    }

    #[test]
    fn test_ffs_powers_of_two() {
        for i in 0..31 {
            assert_eq!(builtin_ffs(1_i32 << i), i + 1);
        }
    }

    #[test]
    fn test_ffs_negative() {
        assert_eq!(builtin_ffs(-1), 1);
        assert_eq!(builtin_ffs(-128), 8); // -128 = 0xFFFFFF80, lowest set bit at position 7
    }

    #[test]
    fn test_ffsll_zero() {
        assert_eq!(builtin_ffsll(0), 0);
    }

    #[test]
    fn test_ffsll_powers_of_two() {
        for i in 0..63 {
            assert_eq!(builtin_ffsll(1_i64 << i), i + 1);
        }
    }

    #[test]
    fn test_ffsl_delegates_correctly() {
        assert_eq!(builtin_ffsl(0), 0);
        assert_eq!(builtin_ffsl(1), 1);
        assert_eq!(builtin_ffsl(-1), 1);
    }

    // -- clz tests --

    #[test]
    fn test_clz_one() {
        assert_eq!(builtin_clz(1), 31);
    }

    #[test]
    fn test_clz_max() {
        assert_eq!(builtin_clz(u32::MAX), 0);
    }

    #[test]
    fn test_clz_powers_of_two() {
        for i in 0..32_u32 {
            assert_eq!(builtin_clz(1_u32 << i), (31 - i) as i32);
        }
    }

    #[test]
    fn test_clzll_one() {
        assert_eq!(builtin_clzll(1), 63);
    }

    #[test]
    fn test_clzll_max() {
        assert_eq!(builtin_clzll(u64::MAX), 0);
    }

    #[test]
    fn test_clzll_powers_of_two() {
        for i in 0..64_u64 {
            assert_eq!(builtin_clzll(1_u64 << i), (63 - i) as i32);
        }
    }

    #[test]
    fn test_clzl_delegates_correctly() {
        assert_eq!(builtin_clzl(1), (mem::size_of::<usize>() * 8 - 1) as i32);
    }

    // -- ctz tests --

    #[test]
    fn test_ctz_one() {
        assert_eq!(builtin_ctz(1), 0);
    }

    #[test]
    fn test_ctz_powers_of_two() {
        for i in 0..32_u32 {
            assert_eq!(builtin_ctz(1_u32 << i), i as i32);
        }
    }

    #[test]
    fn test_ctzll_one() {
        assert_eq!(builtin_ctzll(1), 0);
    }

    #[test]
    fn test_ctzll_powers_of_two() {
        for i in 0..64_u64 {
            assert_eq!(builtin_ctzll(1_u64 << i), i as i32);
        }
    }

    #[test]
    fn test_ctzl_delegates_correctly() {
        assert_eq!(builtin_ctzl(1), 0);
        assert_eq!(builtin_ctzl(4), 2);
    }

    // -- clrsb tests --

    #[test]
    fn test_clrsb_zero() {
        assert_eq!(builtin_clrsb(0), 31);
    }

    #[test]
    fn test_clrsb_minus_one() {
        assert_eq!(builtin_clrsb(-1), 31);
    }

    #[test]
    fn test_clrsb_one() {
        assert_eq!(builtin_clrsb(1), 30);
    }

    #[test]
    fn test_clrsb_min() {
        assert_eq!(builtin_clrsb(i32::MIN), 0);
    }

    #[test]
    fn test_clrsb_max() {
        assert_eq!(builtin_clrsb(i32::MAX), 0);
    }

    #[test]
    fn test_clrsbll_zero() {
        assert_eq!(builtin_clrsbll(0), 63);
    }

    #[test]
    fn test_clrsbll_minus_one() {
        assert_eq!(builtin_clrsbll(-1), 63);
    }

    #[test]
    fn test_clrsbl_delegates_correctly() {
        assert_eq!(builtin_clrsbl(0), (mem::size_of::<isize>() * 8 - 1) as i32);
        assert_eq!(builtin_clrsbl(-1), (mem::size_of::<isize>() * 8 - 1) as i32);
    }

    // -- popcount tests --

    #[test]
    fn test_popcount_zero() {
        assert_eq!(builtin_popcount(0), 0);
    }

    #[test]
    fn test_popcount_one() {
        assert_eq!(builtin_popcount(1), 1);
    }

    #[test]
    fn test_popcount_max() {
        assert_eq!(builtin_popcount(u32::MAX), 32);
    }

    #[test]
    fn test_popcount_alternating() {
        assert_eq!(builtin_popcount(0xAAAA_AAAA), 16);
        assert_eq!(builtin_popcount(0x5555_5555), 16);
    }

    #[test]
    fn test_popcountll_zero() {
        assert_eq!(builtin_popcountll(0), 0);
    }

    #[test]
    fn test_popcountll_max() {
        assert_eq!(builtin_popcountll(u64::MAX), 64);
    }

    #[test]
    fn test_popcountl_delegates_correctly() {
        assert_eq!(builtin_popcountl(0), 0);
        assert_eq!(builtin_popcountl(1), 1);
        assert_eq!(builtin_popcountl(usize::MAX), (mem::size_of::<usize>() * 8) as i32);
    }

    // -- parity tests --

    #[test]
    fn test_parity_zero() {
        assert_eq!(builtin_parity(0), 0);
    }

    #[test]
    fn test_parity_one() {
        assert_eq!(builtin_parity(1), 1);
    }

    #[test]
    fn test_parity_three() {
        assert_eq!(builtin_parity(3), 0); // 2 bits set → even parity
    }

    #[test]
    fn test_parity_max() {
        assert_eq!(builtin_parity(u32::MAX), 0); // 32 bits set → even parity
    }

    #[test]
    fn test_parityll_zero() {
        assert_eq!(builtin_parityll(0), 0);
    }

    #[test]
    fn test_parityll_max() {
        assert_eq!(builtin_parityll(u64::MAX), 0); // 64 bits set → even parity
    }

    #[test]
    fn test_parityll_one() {
        assert_eq!(builtin_parityll(1), 1);
    }

    #[test]
    fn test_parityl_delegates_correctly() {
        assert_eq!(builtin_parityl(0), 0);
        assert_eq!(builtin_parityl(1), 1);
        assert_eq!(builtin_parityl(3), 0);
    }

    // -- cross-validation against Rust intrinsics --

    #[test]
    fn test_cross_validate_popcount_with_intrinsic() {
        for val in [0_u32, 1, 2, 7, 15, 255, 0xDEAD_BEEF, u32::MAX] {
            assert_eq!(
                builtin_popcount(val),
                val.count_ones() as i32,
                "popcount mismatch for 0x{val:08X}"
            );
        }
    }

    #[test]
    fn test_cross_validate_clz_with_intrinsic() {
        for val in [1_u32, 2, 7, 15, 255, 0x8000_0000, u32::MAX] {
            assert_eq!(
                builtin_clz(val),
                val.leading_zeros() as i32,
                "clz mismatch for 0x{val:08X}"
            );
        }
    }

    #[test]
    fn test_cross_validate_ctz_with_intrinsic() {
        for val in [1_u32, 2, 4, 8, 0x80, 0x8000_0000, u32::MAX] {
            assert_eq!(
                builtin_ctz(val),
                val.trailing_zeros() as i32,
                "ctz mismatch for 0x{val:08X}"
            );
        }
    }
}
