//! x86 PIC (Position Independent Code) thunk helpers.
//!
//! Provides the four `__x86.get_pc_thunk.*` helpers used by i386 PIC
//! sequences to capture the program counter non-destructively. These
//! are only needed on 32-bit x86 targets.
//!
//! # C/ASM equivalent
//!
//! `lib/pic86.S` (39 lines)
//!
//! The original assembly defines four global hidden symbols, each executing:
//!
//! ```text
//! mov (%esp), %REG
//! ret
//! ```
//!
//! This captures the return address (which equals the program counter at the
//! call site) into a general-purpose register, enabling position-independent
//! code to compute base addresses on i386 where there is no `RIP`-relative
//! addressing.
//!
//! # Rust translation strategy
//!
//! Rather than using `global_asm!`, the thunk machine code is represented as
//! constant byte arrays. When the linker backend needs to emit a PIC thunk
//! symbol, it copies these bytes into the `.text` section directly. This
//! avoids any `unsafe` blocks while remaining byte-accurate with the original
//! assembly.
//!
//! # Platform gating
//!
//! All items in this module are relevant only for i386 targets. Consumers
//! should gate usage with `#[cfg(feature = "i386")]` as appropriate.

// ---------------------------------------------------------------------------
// x86 instruction encoding reference for `mov (%esp), %REG`:
//
//   Opcode:  0x8B  — MOV r32, r/m32
//   ModR/M:  mod=00, r/m=100 (SIB follows)
//            reg field selects destination:
//              000 (eax) → 0x04
//              011 (ebx) → 0x1C
//              001 (ecx) → 0x0C
//              010 (edx) → 0x14
//   SIB:     0x24 — base=ESP (100), index=none (100), scale=00
//
//   Total: 3 bytes per MOV instruction.
//   Followed by 0xC3 (RET) for a 4-byte thunk.
// ---------------------------------------------------------------------------

/// Enumerates the four general-purpose registers that can serve as PIC
/// thunk destinations on i386.
///
/// Each variant corresponds to one of the `__x86.get_pc_thunk.*` symbols
/// defined in the original `lib/pic86.S`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PicThunkReg {
    /// `%eax` — `__x86.get_pc_thunk.ax`
    Ax,
    /// `%ebx` — `__x86.get_pc_thunk.bx`
    Bx,
    /// `%ecx` — `__x86.get_pc_thunk.cx`
    Cx,
    /// `%edx` — `__x86.get_pc_thunk.dx`
    Dx,
}

impl PicThunkReg {
    /// Returns an iterator over all four thunk register variants.
    ///
    /// The iteration order matches the declaration order in the original
    /// `lib/pic86.S`: ax, bx, cx, dx.
    pub const fn all() -> [PicThunkReg; 4] {
        [
            PicThunkReg::Ax,
            PicThunkReg::Bx,
            PicThunkReg::Cx,
            PicThunkReg::Dx,
        ]
    }

    /// Returns the symbol name for this thunk register.
    ///
    /// The returned name does NOT include a leading underscore; callers
    /// targeting platforms that mangle C symbols with a leading `_` must
    /// prepend it themselves (matching the `#ifdef __leading_underscore`
    /// guard in the original assembly).
    pub const fn symbol_name(self) -> &'static str {
        match self {
            PicThunkReg::Ax => THUNK_NAMES[0],
            PicThunkReg::Bx => THUNK_NAMES[1],
            PicThunkReg::Cx => THUNK_NAMES[2],
            PicThunkReg::Dx => THUNK_NAMES[3],
        }
    }

    /// Returns the 3-byte `mov (%esp), %REG` instruction bytes for this
    /// register (without the trailing `ret`).
    pub const fn mov_bytes(self) -> [u8; 3] {
        match self {
            PicThunkReg::Ax => THUNK_AX,
            PicThunkReg::Bx => THUNK_BX,
            PicThunkReg::Cx => THUNK_CX,
            PicThunkReg::Dx => THUNK_DX,
        }
    }
}

impl core::fmt::Display for PicThunkReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            PicThunkReg::Ax => "ax",
            PicThunkReg::Bx => "bx",
            PicThunkReg::Cx => "cx",
            PicThunkReg::Dx => "dx",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// Machine-code constants
// ---------------------------------------------------------------------------

/// Machine code for `mov (%esp), %eax` — opcode `8B`, ModR/M `04`, SIB `24`.
///
/// C/ASM equivalent: line 16 of `lib/pic86.S`
pub const THUNK_AX: [u8; 3] = [0x8B, 0x04, 0x24];

/// Machine code for `mov (%esp), %ebx` — opcode `8B`, ModR/M `1C`, SIB `24`.
///
/// C/ASM equivalent: line 23 of `lib/pic86.S`
pub const THUNK_BX: [u8; 3] = [0x8B, 0x1C, 0x24];

/// Machine code for `mov (%esp), %ecx` — opcode `8B`, ModR/M `0C`, SIB `24`.
///
/// C/ASM equivalent: line 29 of `lib/pic86.S`
pub const THUNK_CX: [u8; 3] = [0x8B, 0x0C, 0x24];

/// Machine code for `mov (%esp), %edx` — opcode `8B`, ModR/M `14`, SIB `24`.
///
/// C/ASM equivalent: line 37 of `lib/pic86.S`
pub const THUNK_DX: [u8; 3] = [0x8B, 0x14, 0x24];

/// The x86 `RET` (near return) instruction byte.
///
/// Appended after each `mov (%esp), %REG` to complete the thunk. Together
/// the 3-byte MOV + 1-byte RET form a 4-byte thunk that is identical in
/// layout to the original assembly in `lib/pic86.S`.
pub const RET_BYTE: u8 = 0xC3;

/// The complete set of PIC thunk symbol names.
///
/// These names do NOT include a leading underscore. Platforms that require
/// underscore-prefixed C symbols (e.g., macOS) must prepend `_` at the
/// call site — mirroring the `#ifdef __leading_underscore` preprocessor
/// guard from the original `lib/pic86.S`.
///
/// Index mapping:
/// - `[0]` → `__x86.get_pc_thunk.ax`
/// - `[1]` → `__x86.get_pc_thunk.bx`
/// - `[2]` → `__x86.get_pc_thunk.cx`
/// - `[3]` → `__x86.get_pc_thunk.dx`
pub const THUNK_NAMES: [&str; 4] = [
    "__x86.get_pc_thunk.ax",
    "__x86.get_pc_thunk.bx",
    "__x86.get_pc_thunk.cx",
    "__x86.get_pc_thunk.dx",
];

// ---------------------------------------------------------------------------
// Thunk byte generation functions
// ---------------------------------------------------------------------------

/// Returns the complete 4-byte thunk code for the given register.
///
/// The returned `Vec<u8>` contains exactly 4 bytes:
///
/// | Offset | Byte(s)        | Instruction            |
/// |--------|----------------|------------------------|
/// | 0–2    | `8B xx 24`     | `mov (%esp), %REG`     |
/// | 3      | `C3`           | `ret`                  |
///
/// # Example
///
/// ```ignore
/// use tcc::runtime_lib::pic86::{get_thunk_bytes, PicThunkReg};
///
/// let bytes = get_thunk_bytes(PicThunkReg::Bx);
/// assert_eq!(bytes, vec![0x8B, 0x1C, 0x24, 0xC3]);
/// ```
///
/// C/ASM equivalent: each `__x86.get_pc_thunk.*` function body in
/// `lib/pic86.S`.
pub fn get_thunk_bytes(reg: PicThunkReg) -> Vec<u8> {
    let mov = reg.mov_bytes();
    vec![mov[0], mov[1], mov[2], RET_BYTE]
}

/// Emits all four PIC thunk code sequences for the i386 runtime library.
///
/// Returns a `Vec` of `(symbol_name, code_bytes)` pairs — one for each of
/// the four thunk registers (ax, bx, cx, dx). Each `code_bytes` vector is
/// 4 bytes long (3-byte `mov` + 1-byte `ret`).
///
/// All symbols should be emitted with **hidden visibility** and appropriate
/// `.size` metadata in the output object, matching the `.hidden` and `.size`
/// directives in the original `lib/pic86.S`.
///
/// # Example
///
/// ```ignore
/// use tcc::runtime_lib::pic86::emit_all_pic_thunks;
///
/// let thunks = emit_all_pic_thunks();
/// assert_eq!(thunks.len(), 4);
/// assert_eq!(thunks[0].0, "__x86.get_pc_thunk.ax");
/// assert_eq!(thunks[0].1, vec![0x8B, 0x04, 0x24, 0xC3]);
/// ```
///
/// C/ASM equivalent: the entirety of `lib/pic86.S`.
pub fn emit_all_pic_thunks() -> Vec<(&'static str, Vec<u8>)> {
    PicThunkReg::all()
        .iter()
        .map(|&reg| (reg.symbol_name(), get_thunk_bytes(reg)))
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thunk_ax_bytes() {
        let bytes = get_thunk_bytes(PicThunkReg::Ax);
        assert_eq!(bytes, vec![0x8B, 0x04, 0x24, 0xC3]);
    }

    #[test]
    fn test_thunk_bx_bytes() {
        let bytes = get_thunk_bytes(PicThunkReg::Bx);
        assert_eq!(bytes, vec![0x8B, 0x1C, 0x24, 0xC3]);
    }

    #[test]
    fn test_thunk_cx_bytes() {
        let bytes = get_thunk_bytes(PicThunkReg::Cx);
        assert_eq!(bytes, vec![0x8B, 0x0C, 0x24, 0xC3]);
    }

    #[test]
    fn test_thunk_dx_bytes() {
        let bytes = get_thunk_bytes(PicThunkReg::Dx);
        assert_eq!(bytes, vec![0x8B, 0x14, 0x24, 0xC3]);
    }

    #[test]
    fn test_thunk_length_is_four() {
        for reg in PicThunkReg::all() {
            let bytes = get_thunk_bytes(reg);
            assert_eq!(bytes.len(), 4, "thunk for {reg} should be exactly 4 bytes");
        }
    }

    #[test]
    fn test_all_thunks_end_with_ret() {
        for reg in PicThunkReg::all() {
            let bytes = get_thunk_bytes(reg);
            assert_eq!(
                *bytes.last().expect("thunk bytes should not be empty"),
                RET_BYTE,
                "thunk for {reg} should end with RET (0xC3)"
            );
        }
    }

    #[test]
    fn test_all_thunks_start_with_mov_opcode() {
        for reg in PicThunkReg::all() {
            let bytes = get_thunk_bytes(reg);
            assert_eq!(
                bytes[0], 0x8B,
                "thunk for {reg} should start with MOV opcode 0x8B"
            );
        }
    }

    #[test]
    fn test_all_thunks_use_esp_sib() {
        // The SIB byte for (%esp) is always 0x24
        for reg in PicThunkReg::all() {
            let bytes = get_thunk_bytes(reg);
            assert_eq!(
                bytes[2], 0x24,
                "thunk for {reg} should use SIB byte 0x24 for (%esp)"
            );
        }
    }

    #[test]
    fn test_thunk_names_count() {
        assert_eq!(THUNK_NAMES.len(), 4);
    }

    #[test]
    fn test_thunk_names_content() {
        assert_eq!(THUNK_NAMES[0], "__x86.get_pc_thunk.ax");
        assert_eq!(THUNK_NAMES[1], "__x86.get_pc_thunk.bx");
        assert_eq!(THUNK_NAMES[2], "__x86.get_pc_thunk.cx");
        assert_eq!(THUNK_NAMES[3], "__x86.get_pc_thunk.dx");
    }

    #[test]
    fn test_symbol_name_matches_thunk_names() {
        for (i, reg) in PicThunkReg::all().iter().enumerate() {
            assert_eq!(
                reg.symbol_name(),
                THUNK_NAMES[i],
                "symbol_name() for variant {i} should match THUNK_NAMES[{i}]"
            );
        }
    }

    #[test]
    fn test_emit_all_pic_thunks_returns_four() {
        let thunks = emit_all_pic_thunks();
        assert_eq!(thunks.len(), 4);
    }

    #[test]
    fn test_emit_all_pic_thunks_names_and_bytes() {
        let thunks = emit_all_pic_thunks();

        assert_eq!(thunks[0].0, "__x86.get_pc_thunk.ax");
        assert_eq!(thunks[0].1, vec![0x8B, 0x04, 0x24, 0xC3]);

        assert_eq!(thunks[1].0, "__x86.get_pc_thunk.bx");
        assert_eq!(thunks[1].1, vec![0x8B, 0x1C, 0x24, 0xC3]);

        assert_eq!(thunks[2].0, "__x86.get_pc_thunk.cx");
        assert_eq!(thunks[2].1, vec![0x8B, 0x0C, 0x24, 0xC3]);

        assert_eq!(thunks[3].0, "__x86.get_pc_thunk.dx");
        assert_eq!(thunks[3].1, vec![0x8B, 0x14, 0x24, 0xC3]);
    }

    #[test]
    fn test_ret_byte_value() {
        assert_eq!(RET_BYTE, 0xC3);
    }

    #[test]
    fn test_pic_thunk_reg_display() {
        assert_eq!(format!("{}", PicThunkReg::Ax), "ax");
        assert_eq!(format!("{}", PicThunkReg::Bx), "bx");
        assert_eq!(format!("{}", PicThunkReg::Cx), "cx");
        assert_eq!(format!("{}", PicThunkReg::Dx), "dx");
    }

    #[test]
    fn test_pic_thunk_reg_clone_copy() {
        let reg = PicThunkReg::Bx;
        let cloned = reg;
        assert_eq!(reg, cloned);
    }

    #[test]
    fn test_pic_thunk_reg_debug() {
        // Ensure Debug is implemented and produces meaningful output
        let debug_str = format!("{:?}", PicThunkReg::Ax);
        assert!(debug_str.contains("Ax"));
    }

    #[test]
    fn test_mov_bytes_consistency() {
        // Verify that mov_bytes() matches the THUNK_* constants exactly
        assert_eq!(PicThunkReg::Ax.mov_bytes(), THUNK_AX);
        assert_eq!(PicThunkReg::Bx.mov_bytes(), THUNK_BX);
        assert_eq!(PicThunkReg::Cx.mov_bytes(), THUNK_CX);
        assert_eq!(PicThunkReg::Dx.mov_bytes(), THUNK_DX);
    }

    #[test]
    fn test_all_variants_are_distinct() {
        let all = PicThunkReg::all();
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "variants at index {i} and {j} should be distinct"
                );
                assert_ne!(
                    get_thunk_bytes(all[i]),
                    get_thunk_bytes(all[j]),
                    "thunk bytes for index {i} and {j} should differ"
                );
            }
        }
    }
}
