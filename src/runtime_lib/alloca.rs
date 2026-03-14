//! Stack allocation helpers (alloca) for compiled programs.
//!
//! Provides `alloca`, `__alloca`, and `__bound_alloca` implementations that get
//! linked into programs compiled by tinycc-rs. These are architecture-specific
//! stack allocation routines with optional bounds-checking instrumentation.
//!
//! C/ASM equivalent: `lib/alloca.S` (148 lines) + `lib/alloca-bt.S` (200 lines)
//!
//! # Strategy
//!
//! For the runtime library linked into compiled programs, the alloca
//! implementation is provided as raw machine code bytes for each target
//! architecture. This preserves the exact assembly semantics while keeping
//! the compiler itself free of `global_asm!` or `unsafe` blocks.
//!
//! The code generator emits these bytes into the compiled output's text
//! section, adding relocations for bounds-checking call targets as needed.
//!
//! # Architecture Coverage
//!
//! | Architecture | Standard alloca | Bounds-check alloca | Windows guard page probing |
//! |---|---|---|---|
//! | i386 | ✓ | ✓ | ✓ |
//! | x86_64 | ✓ | ✓ | ✓ |
//! | ARM | ✓ | ✓ | — |
//! | AArch64 | ✓ | ✓ | ✓ |
//! | RISC-V 64 | ✓ | ✓ | — |

// ---------------------------------------------------------------------------
// Alloca code template returned by `get_alloca_code`
// ---------------------------------------------------------------------------

/// Alloca machine code template with optional relocation metadata.
///
/// The `code` field contains raw machine code bytes ready to be copied into
/// a compiled program's text section. If the alloca variant includes a call
/// to `__bound_new_region` (bounds-checking mode), the `relocations` field
/// describes where the linker must patch in the call target.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AllocaCode {
    /// Raw machine code bytes for the alloca implementation.
    pub(crate) code: &'static [u8],
    /// Relocations required within `code`.
    ///
    /// Each entry is `(byte_offset, symbol_name)`:
    /// - For x86/x86_64: `byte_offset` points to the 4-byte displacement
    ///   immediately after the `0xE8` (CALL) opcode.
    /// - For ARM (32-bit): `byte_offset` points to the 4-byte BL instruction
    ///   whose 24-bit offset field must be patched.
    /// - For AArch64: `byte_offset` points to the 4-byte BL instruction
    ///   whose 26-bit offset field must be patched (R_AARCH64_CALL26).
    /// - For RISC-V: `byte_offset` points to the 4-byte JAL instruction
    ///   whose 20-bit offset field must be patched.
    pub(crate) relocations: &'static [AllocaRelocation],
}

/// A single relocation entry within an alloca code template.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AllocaRelocation {
    /// Byte offset within the code template where the relocation applies.
    pub(crate) offset: usize,
    /// Name of the target symbol (e.g., `"__bound_new_region"`).
    pub(crate) symbol: &'static str,
}

// ---------------------------------------------------------------------------
// i386 machine code (from alloca.S lines 11-37, alloca-bt.S lines 11-51)
// ---------------------------------------------------------------------------

/// Alloca machine code for i386 (32-bit x86).
///
/// Assembly sequence (non-Windows):
/// ```asm
/// pop %edx; pop %eax; add $3,%eax; and $-4,%eax; jz p3;
/// sub %eax,%esp; mov %esp,%eax;
/// p3: push %edx; push %edx; ret
/// ```
///
/// The Windows variant includes a guard-page probing loop that touches each
/// 4 KiB page before allocating, preventing stack overflow past the guard page.
#[cfg(feature = "i386")]
pub(crate) mod i386 {
    use super::{AllocaCode, AllocaRelocation};

    // -- Standard alloca (alloca.S lines 14-37, non-Windows) ------------------

    /// Standard alloca for i386, non-Windows.
    ///
    /// Verified against `as --32` + `objdump -d` output.
    pub(crate) const ALLOCA_CODE: &[u8] = &[
        0x5A,                   // pop    %edx          (save return address)
        0x58,                   // pop    %eax          (get requested size)
        0x83, 0xC0, 0x03,      // add    $3,%eax       (round up …)
        0x83, 0xE0, 0xFC,      // and    $-4,%eax      (… to 4-byte alignment)
        0x74, 0x04,             // jz     p3            (skip if size == 0)
        0x29, 0xC4,             // sub    %eax,%esp     (allocate on stack)
        0x89, 0xE0,             // mov    %esp,%eax     (return pointer)
        // p3:
        0x52,                   // push   %edx          (restore return address)
        0x52,                   // push   %edx          (second push for alignment)
        0xC3,                   // ret
    ];

    /// Standard alloca for i386, Windows (with guard-page probing).
    ///
    /// Probes each 4 KiB page with `test %eax,-4096(%esp)` before adjusting
    /// `%esp`, ensuring the OS commits pages incrementally.
    pub(crate) const ALLOCA_WIN_CODE: &[u8] = &[
        0x5A,                   // pop    %edx
        0x58,                   // pop    %eax
        0x83, 0xC0, 0x03,      // add    $3,%eax
        0x83, 0xE0, 0xFC,      // and    $-4,%eax
        0x74, 0x1F,             // jz     p3
        // p1 (probe loop):
        0x3D, 0x00, 0x10, 0x00, 0x00,  // cmp $4096,%eax
        0x72, 0x14,                      // jb  p2
        0x85, 0x84, 0x24, 0x00, 0xF0, 0xFF, 0xFF, // test %eax,-4096(%esp)
        0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,        // sub  $4096,%esp
        0x2D, 0x00, 0x10, 0x00, 0x00,              // sub  $4096,%eax
        0xEB, 0xE5,                                  // jmp  p1
        // p2:
        0x29, 0xC4,             // sub    %eax,%esp
        0x89, 0xE0,             // mov    %esp,%eax
        // p3:
        0x52,                   // push   %edx
        0x52,                   // push   %edx
        0xC3,                   // ret
    ];

    // -- Bounds-checking alloca (alloca-bt.S lines 13-51) ---------------------

    /// Bounds-checking alloca for i386, non-Windows.
    ///
    /// After stack adjustment, calls `__bound_new_region(ptr, size)` to
    /// register the allocated region with the bounds checker.
    ///
    /// The `call __bound_new_region` at offset 0x16 needs a R_386_PC32 relocation.
    /// Bytes 0x17..0x1B contain a placeholder 4-byte displacement (all zeros).
    pub(crate) const ALLOCA_BT_CODE: &[u8] = &[
        0x5A,                   // pop    %edx          (save return address)
        0x58,                   // pop    %eax          (get requested size)
        0x89, 0xC1,             // mov    %eax,%ecx     (save original size)
        0x85, 0xC0,             // test   %eax,%eax     (check for zero)
        0x74, 0x18,             // jz     p6            (skip if zero)
        0x83, 0xC0, 0x04,      // add    $4,%eax       (+1 extra to separate regions)
        0x83, 0xE0, 0xFC,      // and    $-4,%eax      (4-byte alignment)
        0x29, 0xC4,             // sub    %eax,%esp     (allocate)
        0x89, 0xE0,             // mov    %esp,%eax     (pointer to region)
        0x52,                   // push   %edx          (save return addr)
        0x50,                   // push   %eax          (save result)
        0x51,                   // push   %ecx          (arg2: size)
        0x50,                   // push   %eax          (arg1: ptr)
        0xE8, 0x00, 0x00, 0x00, 0x00, // call __bound_new_region (RELOC)
        0x83, 0xC4, 0x08,      // add    $8,%esp       (clean up args)
        0x58,                   // pop    %eax          (restore result)
        0x5A,                   // pop    %edx          (restore return addr)
        // p6:
        0x52,                   // push   %edx
        0x52,                   // push   %edx
        0xC3,                   // ret
    ];

    /// Relocation for i386 bounds-checking alloca: call displacement at offset 0x17.
    pub(crate) const ALLOCA_BT_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 0x17, symbol: "__bound_new_region" },
    ];

    /// Bounds-checking alloca for i386, Windows (with guard-page probing).
    pub(crate) const ALLOCA_BT_WIN_CODE: &[u8] = &[
        0x5A,                   // pop    %edx
        0x58,                   // pop    %eax
        0x89, 0xC1,             // mov    %eax,%ecx
        0x85, 0xC0,             // test   %eax,%eax
        0x74, 0x33,             // jz     p6
        0x83, 0xC0, 0x04,      // add    $4,%eax
        0x83, 0xE0, 0xFC,      // and    $-4,%eax
        // p4 (probe loop):
        0x3D, 0x00, 0x10, 0x00, 0x00,  // cmp $4096,%eax
        0x72, 0x14,                      // jb  p5
        0x85, 0x84, 0x24, 0x00, 0xF0, 0xFF, 0xFF, // test %eax,-4096(%esp)
        0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,        // sub  $4096,%esp
        0x2D, 0x00, 0x10, 0x00, 0x00,              // sub  $4096,%eax
        0xEB, 0xE5,                                  // jmp  p4
        // p5:
        0x29, 0xC4,             // sub    %eax,%esp
        0x89, 0xE0,             // mov    %esp,%eax
        0x52,                   // push   %edx
        0x50,                   // push   %eax
        0x51,                   // push   %ecx
        0x50,                   // push   %eax
        0xE8, 0x00, 0x00, 0x00, 0x00, // call __bound_new_region (RELOC)
        0x83, 0xC4, 0x08,      // add    $8,%esp
        0x58,                   // pop    %eax
        0x5A,                   // pop    %edx
        // p6:
        0x52,                   // push   %edx
        0x52,                   // push   %edx
        0xC3,                   // ret
    ];

    /// Relocation for i386 bounds-checking alloca (Windows): call at offset 0x32.
    pub(crate) const ALLOCA_BT_WIN_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 0x32, symbol: "__bound_new_region" },
    ];

    /// Get i386 alloca code template.
    pub(crate) fn get_code(bounds_check: bool, windows: bool) -> AllocaCode {
        match (bounds_check, windows) {
            (false, false) => AllocaCode { code: ALLOCA_CODE, relocations: &[] },
            (false, true) => AllocaCode { code: ALLOCA_WIN_CODE, relocations: &[] },
            (true, false) => AllocaCode { code: ALLOCA_BT_CODE, relocations: ALLOCA_BT_RELOCS },
            (true, true) => AllocaCode { code: ALLOCA_BT_WIN_CODE, relocations: ALLOCA_BT_WIN_RELOCS },
        }
    }
}

// ---------------------------------------------------------------------------
// x86_64 machine code (from alloca.S lines 40-68, alloca-bt.S lines 53-93)
// ---------------------------------------------------------------------------

/// Alloca machine code for x86_64.
///
/// The x86_64 variant uses the System V AMD64 ABI where the size argument
/// is passed in `%rdi` (non-Windows) or `%rcx` (Windows).
/// Alignment is 16 bytes (matching the ABI stack alignment requirement).
#[cfg(feature = "x86_64")]
pub(crate) mod x86_64 {
    use super::{AllocaCode, AllocaRelocation};

    // -- Standard alloca (alloca.S lines 42-68, non-Windows) ------------------

    /// Standard alloca for x86_64, non-Windows (System V ABI).
    ///
    /// Verified against `as -64` + `objdump -d` output.
    pub(crate) const ALLOCA_CODE: &[u8] = &[
        0x5A,                         // pop    %rdx          (save return address)
        0x48, 0x89, 0xF8,             // mov    %rdi,%rax     (get size from arg1)
        0x48, 0x83, 0xC0, 0x0F,       // add    $15,%rax      (round up …)
        0x48, 0x83, 0xE0, 0xF0,       // and    $-16,%rax     (… to 16-byte alignment)
        0x74, 0x06,                    // jz     p3            (skip if size == 0)
        0x48, 0x29, 0xC4,             // sub    %rax,%rsp     (allocate on stack)
        0x48, 0x89, 0xE0,             // mov    %rsp,%rax     (return pointer)
        // p3:
        0x52,                          // push   %rdx          (restore return address)
        0xC3,                          // ret
    ];

    /// Standard alloca for x86_64, Windows (with guard-page probing).
    ///
    /// Uses `%rcx` for the size argument per the Windows x64 calling convention.
    pub(crate) const ALLOCA_WIN_CODE: &[u8] = &[
        0x5A,                         // pop    %rdx
        0x48, 0x89, 0xC8,             // mov    %rcx,%rax     (size in %rcx on Windows)
        0x48, 0x83, 0xC0, 0x0F,       // add    $15,%rax
        0x48, 0x83, 0xE0, 0xF0,       // and    $-16,%rax
        0x74, 0x25,                    // jz     p3
        // p1 (probe loop):
        0x48, 0x3D, 0x00, 0x10, 0x00, 0x00,             // cmp $4096,%rax
        0x72, 0x17,                                       // jb  p2
        0x48, 0x85, 0x84, 0x24, 0x00, 0xF0, 0xFF, 0xFF, // test %rax,-4096(%rsp)
        0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,       // sub  $4096,%rsp
        0x48, 0x2D, 0x00, 0x10, 0x00, 0x00,             // sub  $4096,%rax
        0xEB, 0xE1,                                       // jmp  p1
        // p2:
        0x48, 0x29, 0xC4,             // sub    %rax,%rsp
        0x48, 0x89, 0xE0,             // mov    %rsp,%rax
        // p3:
        0x52,                          // push   %rdx
        0xC3,                          // ret
    ];

    // -- Bounds-checking alloca (alloca-bt.S lines 55-92, non-Windows) --------

    /// Bounds-checking alloca for x86_64, non-Windows.
    ///
    /// After stack adjustment, calls `__bound_new_region(ptr, size)` using
    /// System V ABI (ptr in `%rdi`, size in `%rsi`).
    ///
    /// The `call __bound_new_region` at offset 0x1E needs a R_X86_64_PC32 relocation.
    /// Bytes 0x1F..0x23 contain a placeholder 4-byte displacement (all zeros).
    pub(crate) const ALLOCA_BT_CODE: &[u8] = &[
        0x5A,                         // pop    %rdx          (save return address)
        0x48, 0x89, 0xF8,             // mov    %rdi,%rax     (get size)
        0x21, 0xC0,                    // and    %eax,%eax     (zero-extend & test)
        0x74, 0x1D,                    // jz     p3            (skip if zero)
        0x48, 0x89, 0xC6,             // mov    %rax,%rsi     (size → arg2)
        0x48, 0x83, 0xC0, 0x10,       // add    $16,%rax      (+1 extra, 16-byte align)
        0x48, 0x83, 0xE0, 0xF0,       // and    $-16,%rax
        0x48, 0x29, 0xC4,             // sub    %rax,%rsp     (allocate)
        0x48, 0x89, 0xE7,             // mov    %rsp,%rdi     (ptr → arg1)
        0x48, 0x89, 0xE0,             // mov    %rsp,%rax     (save result)
        0x52,                          // push   %rdx          (save return addr)
        0x50,                          // push   %rax          (save result)
        0xE8, 0x00, 0x00, 0x00, 0x00, // call __bound_new_region (RELOC)
        0x58,                          // pop    %rax          (restore result)
        0x5A,                          // pop    %rdx          (restore return addr)
        // p3:
        0x52,                          // push   %rdx
        0xC3,                          // ret
    ];

    /// Relocation for x86_64 bounds-checking alloca: call displacement at offset 0x1F.
    pub(crate) const ALLOCA_BT_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 0x1F, symbol: "__bound_new_region" },
    ];

    /// Bounds-checking alloca for x86_64, Windows.
    ///
    /// The Windows variant increments the size by 1 (to separate regions),
    /// jumps to `alloca` for the actual allocation, then a secondary entry
    /// point `__bound_alloca_nr` registers the region. This requires two
    /// relocations: one for the `jmp alloca` and one for the
    /// `call __bound_new_region`.
    ///
    /// Combined code: `__bound_alloca` (inc+jmp) + `__bound_alloca_nr` (register).
    pub(crate) const ALLOCA_BT_WIN_CODE: &[u8] = &[
        // __bound_alloca:
        0x48, 0xFF, 0xC1,             // inc    %rcx          (add one extra)
        0xE9, 0x00, 0x00, 0x00, 0x00, // jmp    alloca        (RELOC #0)
        // __bound_alloca_nr:
        0x48, 0xFF, 0xC9,             // dec    %rcx          (restore original size)
        0x50,                          // push   %rax          (save alloca result)
        0x48, 0x89, 0xCA,             // mov    %rcx,%rdx     (size → arg2)
        0x48, 0x89, 0xC1,             // mov    %rax,%rcx     (ptr → arg1)
        0x48, 0x83, 0xEC, 0x20,       // sub    $32,%rsp      (shadow space)
        0xE8, 0x00, 0x00, 0x00, 0x00, // call __bound_new_region (RELOC #1)
        0x48, 0x83, 0xC4, 0x20,       // add    $32,%rsp      (clean shadow space)
        0x58,                          // pop    %rax          (restore result)
        0xC3,                          // ret
    ];

    /// Relocations for x86_64 bounds-checking alloca (Windows).
    /// Two relocations: `jmp alloca` and `call __bound_new_region`.
    pub(crate) const ALLOCA_BT_WIN_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 0x04, symbol: "alloca" },
        AllocaRelocation { offset: 0x15, symbol: "__bound_new_region" },
    ];

    /// Offset of the `__bound_alloca_nr` entry point within `ALLOCA_BT_WIN_CODE`.
    ///
    /// The linker must export this as a separate symbol so that the alloca
    /// return path can call it.
    pub(crate) const ALLOCA_BT_WIN_NR_OFFSET: usize = 0x08;

    /// Get x86_64 alloca code template.
    pub(crate) fn get_code(bounds_check: bool, windows: bool) -> AllocaCode {
        match (bounds_check, windows) {
            (false, false) => AllocaCode { code: ALLOCA_CODE, relocations: &[] },
            (false, true) => AllocaCode { code: ALLOCA_WIN_CODE, relocations: &[] },
            (true, false) => AllocaCode { code: ALLOCA_BT_CODE, relocations: ALLOCA_BT_RELOCS },
            (true, true) => AllocaCode { code: ALLOCA_BT_WIN_CODE, relocations: ALLOCA_BT_WIN_RELOCS },
        }
    }
}

// ---------------------------------------------------------------------------
// ARM machine code (from alloca.S lines 71-78, alloca-bt.S lines 96-109)
// ---------------------------------------------------------------------------

/// Alloca machine code for ARM (32-bit).
///
/// ARM alloca subtracts the requested size from SP, aligns to 8 bytes,
/// and returns the new SP in r0. The bounds-checking variant calls
/// `__bound_new_region` before returning.
#[cfg(feature = "arm")]
pub(crate) mod arm {
    use super::{AllocaCode, AllocaRelocation};

    /// Standard alloca for ARM (alloca.S lines 74-78).
    ///
    /// ```asm
    /// rsb sp, r0, sp      @ sp = sp - r0
    /// bic sp, sp, #7      @ align to 8 bytes
    /// mov r0, sp          @ return new SP
    /// mov pc, lr          @ return
    /// ```
    pub(crate) const ALLOCA_CODE: &[u8] = &[
        0x0D, 0xD0, 0x60, 0xE0, // rsb sp, r0, sp      (0xE060D00D)
        0x07, 0xD0, 0xCD, 0xE3, // bic sp, sp, #7       (0xE3CDD007)
        0x0D, 0x00, 0xA0, 0xE1, // mov r0, sp           (0xE1A0000D)
        0x0E, 0xF0, 0xA0, 0xE1, // mov pc, lr           (0xE1A0F00E)
    ];

    /// Bounds-checking alloca for ARM (alloca-bt.S lines 99-109).
    ///
    /// ```asm
    /// mov r1, r0                  @ save original size
    /// add r0, r0, #1              @ +1 to separate regions
    /// rsb sp, r0, sp              @ sp = sp - r0
    /// bic sp, sp, #7              @ align to 8 bytes
    /// mov r0, sp                  @ pointer to region
    /// push { lr }                 @ save link register
    /// bl __bound_new_region       @ register region (RELOC)
    /// pop { lr }                  @ restore link register
    /// mov r0, sp                  @ return new SP
    /// mov pc, lr                  @ return
    /// ```
    ///
    /// The `bl __bound_new_region` at offset 20 needs a R_ARM_CALL relocation.
    pub(crate) const ALLOCA_BT_CODE: &[u8] = &[
        0x00, 0x10, 0xA0, 0xE1, // mov r1, r0           (0xE1A01000)
        0x01, 0x00, 0x80, 0xE2, // add r0, r0, #1       (0xE2800001)
        0x0D, 0xD0, 0x60, 0xE0, // rsb sp, r0, sp       (0xE060D00D)
        0x07, 0xD0, 0xCD, 0xE3, // bic sp, sp, #7       (0xE3CDD007)
        0x0D, 0x00, 0xA0, 0xE1, // mov r0, sp           (0xE1A0000D)
        0x00, 0x40, 0x2D, 0xE9, // push {lr}             (0xE92D4000)
        0x00, 0x00, 0x00, 0xEB, // bl __bound_new_region (0xEB000000, RELOC)
        0x00, 0x40, 0xBD, 0xE8, // pop {lr}              (0xE8BD4000)
        0x0D, 0x00, 0xA0, 0xE1, // mov r0, sp           (0xE1A0000D)
        0x0E, 0xF0, 0xA0, 0xE1, // mov pc, lr           (0xE1A0F00E)
    ];

    /// Relocation for ARM bounds-checking alloca: BL instruction at offset 24.
    pub(crate) const ALLOCA_BT_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 24, symbol: "__bound_new_region" },
    ];

    /// Get ARM alloca code template.
    ///
    /// ARM does not have a separate Windows variant (no guard-page probing).
    pub(crate) fn get_code(bounds_check: bool, _windows: bool) -> AllocaCode {
        if bounds_check {
            AllocaCode { code: ALLOCA_BT_CODE, relocations: ALLOCA_BT_RELOCS }
        } else {
            AllocaCode { code: ALLOCA_CODE, relocations: &[] }
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 machine code (from alloca.S lines 81-135, alloca-bt.S lines 112-177)
// ---------------------------------------------------------------------------

/// Alloca machine code for AArch64 (ARM 64-bit).
///
/// Instruction encodings taken directly from the `.int` values in alloca.S
/// and alloca-bt.S (the `__TINYC__` path), which provide pre-encoded
/// instruction words.
///
/// AArch64 alloca aligns to 16 bytes (matching the ABI requirement).
#[cfg(feature = "arm64")]
pub(crate) mod arm64 {
    use super::{AllocaCode, AllocaRelocation};

    /// Standard alloca for AArch64, non-Windows (alloca.S __TINYC__ path).
    ///
    /// ```asm
    /// add  x0, x0, #15       // round up to 16-byte boundary
    /// and  x0, x0, #-16      // ensure 16-byte alignment
    /// sub  sp, sp, x0        // allocate space on stack
    /// mov  x0, sp            // return allocated address
    /// ret                    // return to caller
    /// ```
    pub(crate) const ALLOCA_CODE: &[u8] = &[
        0x00, 0x3C, 0x00, 0x91, // add  x0, x0, #15       (0x91003C00)
        0x00, 0xEC, 0x7C, 0x92, // and  x0, x0, #-16      (0x927CEC00)
        0xFF, 0x63, 0x20, 0xCB, // sub  sp, sp, x0        (0xCB2063FF)
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp            (0x910003E0)
        0xC0, 0x03, 0x5F, 0xD6, // ret                    (0xD65F03C0)
    ];

    /// Standard alloca for AArch64, Windows (with guard-page probing).
    ///
    /// Uses a loop to probe each 4 KiB page before allocating.
    pub(crate) const ALLOCA_WIN_CODE: &[u8] = &[
        0x00, 0x3C, 0x00, 0x91, // add  x0, x0, #15       (0x91003C00)
        0x00, 0xEC, 0x7C, 0x92, // and  x0, x0, #-16      (0x927CEC00)
        0x60, 0x01, 0x00, 0xB4, // cbz  x0, p100          (0xB4000160)
        0x01, 0x00, 0x82, 0xD2, // mov  x1, #4096         (0xD2820001)
        // p101:
        0x1F, 0x00, 0x01, 0xEB, // cmp  x0, x1            (0xEB01001F)
        0xC3, 0x00, 0x00, 0x54, // b.lo p102              (0x540000C3)
        0xE2, 0x63, 0x21, 0xCB, // sub  x2, sp, x1        (0xCB2163E2)
        0x5F, 0x00, 0x40, 0xF9, // ldr  xzr, [x2]         (0xF940005F)
        0xFF, 0x63, 0x21, 0xCB, // sub  sp, sp, x1        (0xCB2163FF)
        0x00, 0x00, 0x01, 0xCB, // sub  x0, x0, x1        (0xCB010000)
        0xFA, 0xFF, 0xFF, 0x17, // b    p101              (0x17FFFFFA)
        // p102:
        0x40, 0x00, 0x00, 0xB4, // cbz  x0, p100          (0xB4000040)
        0xFF, 0x63, 0x20, 0xCB, // sub  sp, sp, x0        (0xCB2063FF)
        // p100:
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp            (0x910003E0)
        0xC0, 0x03, 0x5F, 0xD6, // ret                    (0xD65F03C0)
    ];

    /// Bounds-checking alloca for AArch64, non-Windows.
    ///
    /// After stack adjustment, saves frame pointer and link register,
    /// calls `__bound_new_region(ptr, size)`, then restores and returns.
    ///
    /// The `bl __bound_new_region` at offset 24 needs a R_AARCH64_CALL26 relocation.
    pub(crate) const ALLOCA_BT_CODE: &[u8] = &[
        0xE1, 0x03, 0x00, 0xAA, // mov  x1, x0            (0xAA0003E1)
        0x00, 0x40, 0x00, 0x91, // add  x0, x0, #16       (0x91004000)
        0x00, 0xEC, 0x7C, 0x92, // and  x0, x0, #-16      (0x927CEC00)
        0xFF, 0x63, 0x20, 0xCB, // sub  sp, sp, x0        (0xCB2063FF)
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp            (0x910003E0)
        0xFD, 0x7B, 0xBF, 0xA9, // stp  x29, x30, [sp, #-16]! (0xA9BF7BFD)
        0x00, 0x00, 0x00, 0x94, // bl   __bound_new_region (0x94000000, RELOC)
        0xFD, 0x7B, 0xC1, 0xA8, // ldp  x29, x30, [sp], #16  (0xA8C17BFD)
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp            (0x910003E0)
        0xC0, 0x03, 0x5F, 0xD6, // ret                    (0xD65F03C0)
    ];

    /// Relocation for AArch64 bounds-checking alloca: BL at offset 24.
    pub(crate) const ALLOCA_BT_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 24, symbol: "__bound_new_region" },
    ];

    /// Bounds-checking alloca for AArch64, Windows (with guard-page probing).
    pub(crate) const ALLOCA_BT_WIN_CODE: &[u8] = &[
        0xE1, 0x03, 0x00, 0xAA, // mov  x1, x0            (0xAA0003E1)
        0x00, 0x40, 0x00, 0x91, // add  x0, x0, #16       (0x91004000)
        0x00, 0xEC, 0x7C, 0x92, // and  x0, x0, #-16      (0x927CEC00)
        // Windows probe loop:
        0x60, 0x01, 0x00, 0xB4, // cbz  x0, p100          (0xB4000160)
        0x02, 0x00, 0x82, 0xD2, // mov  x2, #4096         (0xD2820002)
        // p101:
        0x1F, 0x00, 0x02, 0xEB, // cmp  x0, x2            (0xEB02001F)
        0xC3, 0x00, 0x00, 0x54, // b.lo p102              (0x540000C3)
        0xE3, 0x63, 0x22, 0xCB, // sub  x3, sp, x2        (0xCB2263E3)
        0x7F, 0x00, 0x40, 0xF9, // ldr  xzr, [x3]         (0xF940007F)
        0xFF, 0x63, 0x22, 0xCB, // sub  sp, sp, x2        (0xCB2263FF)
        0x00, 0x00, 0x02, 0xCB, // sub  x0, x0, x2        (0xCB020000)
        0xFA, 0xFF, 0xFF, 0x17, // b    p101              (0x17FFFFFA)
        // p102:
        0x40, 0x00, 0x00, 0xB4, // cbz  x0, p100          (0xB4000040)
        0xFF, 0x63, 0x20, 0xCB, // sub  sp, sp, x0        (0xCB2063FF)
        // p100:
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp            (0x910003E0)
        0xFD, 0x7B, 0xBF, 0xA9, // stp  x29, x30, [sp, #-16]!
        0x00, 0x00, 0x00, 0x94, // bl   __bound_new_region (RELOC)
        0xFD, 0x7B, 0xC1, 0xA8, // ldp  x29, x30, [sp], #16
        0xE0, 0x03, 0x00, 0x91, // mov  x0, sp
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ];

    /// Relocation for AArch64 bounds-checking alloca (Windows): BL at offset 68.
    pub(crate) const ALLOCA_BT_WIN_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 68, symbol: "__bound_new_region" },
    ];

    /// Get AArch64 alloca code template.
    pub(crate) fn get_code(bounds_check: bool, windows: bool) -> AllocaCode {
        match (bounds_check, windows) {
            (false, false) => AllocaCode { code: ALLOCA_CODE, relocations: &[] },
            (false, true) => AllocaCode { code: ALLOCA_WIN_CODE, relocations: &[] },
            (true, false) => AllocaCode { code: ALLOCA_BT_CODE, relocations: ALLOCA_BT_RELOCS },
            (true, true) => AllocaCode { code: ALLOCA_BT_WIN_CODE, relocations: ALLOCA_BT_WIN_RELOCS },
        }
    }
}

// ---------------------------------------------------------------------------
// RISC-V 64 machine code (from alloca.S lines 138-148, alloca-bt.S lines 180-197)
// ---------------------------------------------------------------------------

/// Alloca machine code for RISC-V 64-bit.
///
/// RISC-V alloca subtracts the requested size (in `a0`) from SP, aligns
/// to 16 bytes, and returns the new SP in `a0`.
#[cfg(feature = "riscv64")]
pub(crate) mod riscv64 {
    use super::{AllocaCode, AllocaRelocation};

    /// Standard alloca for RISC-V 64 (alloca.S lines 141-147).
    ///
    /// ```asm
    /// sub    sp, sp, a0      # subtract requested size
    /// addi   sp, sp, -15     # round down …
    /// andi   sp, sp, -16     # … to 16-byte alignment
    /// add    a0, sp, zero    # return new SP (mv a0, sp)
    /// ret                    # return
    /// ```
    pub(crate) const ALLOCA_CODE: &[u8] = &[
        0x33, 0x01, 0xA1, 0x40, // sub  sp, sp, a0       (0x40A10133)
        0x13, 0x01, 0x11, 0xFF, // addi sp, sp, -15      (0xFF110113)
        0x13, 0x71, 0x01, 0xFF, // andi sp, sp, -16      (0xFF017113)
        0x33, 0x05, 0x01, 0x00, // add  a0, sp, zero     (0x00010533)
        0x67, 0x80, 0x00, 0x00, // ret                   (0x00008067)
    ];

    /// Bounds-checking alloca for RISC-V 64 (alloca-bt.S lines 183-197).
    ///
    /// ```asm
    /// mv     a1, a0          # save original size for __bound_new_region
    /// sub    sp, sp, a0      # subtract size
    /// addi   sp, sp, -16     # round down …
    /// andi   sp, sp, -16     # … to 16-byte alignment
    /// add    a0, sp, zero    # pointer to region
    /// addi   sp, sp, -16     # allocate stack frame
    /// sd     s0, 0(sp)       # save s0
    /// sd     ra, 8(sp)       # save return address
    /// jal    ra, __bound_new_region  # register region (RELOC)
    /// ld     s0, 0(sp)       # restore s0
    /// ld     ra, 8(sp)       # restore return address
    /// addi   sp, sp, 16      # deallocate stack frame
    /// add    a0, sp, zero    # return new SP
    /// ret                    # return
    /// ```
    ///
    /// The `jal __bound_new_region` at offset 32 needs a R_RISCV_JAL relocation.
    pub(crate) const ALLOCA_BT_CODE: &[u8] = &[
        0xB3, 0x05, 0x05, 0x00, // mv   a1, a0           (0x000505B3)
        0x33, 0x01, 0xA1, 0x40, // sub  sp, sp, a0       (0x40A10133)
        0x13, 0x01, 0x01, 0xFF, // addi sp, sp, -16      (0xFF010113)
        0x13, 0x71, 0x01, 0xFF, // andi sp, sp, -16      (0xFF017113)
        0x33, 0x05, 0x01, 0x00, // add  a0, sp, zero     (0x00010533)
        0x13, 0x01, 0x01, 0xFF, // addi sp, sp, -16      (0xFF010113)
        0x23, 0x30, 0x81, 0x00, // sd   s0, 0(sp)        (0x00813023)
        0x23, 0x34, 0x11, 0x00, // sd   ra, 8(sp)        (0x00113423)
        0xEF, 0x00, 0x00, 0x00, // jal  ra, __bound_new_region (0x000000EF, RELOC)
        0x03, 0x34, 0x01, 0x00, // ld   s0, 0(sp)        (0x00013403)
        0x83, 0x30, 0x81, 0x00, // ld   ra, 8(sp)        (0x00813083)
        0x13, 0x01, 0x01, 0x01, // addi sp, sp, 16       (0x01010113)
        0x33, 0x05, 0x01, 0x00, // add  a0, sp, zero     (0x00010533)
        0x67, 0x80, 0x00, 0x00, // ret                   (0x00008067)
    ];

    /// Relocation for RISC-V bounds-checking alloca: JAL at offset 32.
    pub(crate) const ALLOCA_BT_RELOCS: &[AllocaRelocation] = &[
        AllocaRelocation { offset: 32, symbol: "__bound_new_region" },
    ];

    /// Get RISC-V 64 alloca code template.
    ///
    /// RISC-V does not have separate Windows variants.
    pub(crate) fn get_code(bounds_check: bool, _windows: bool) -> AllocaCode {
        if bounds_check {
            AllocaCode { code: ALLOCA_BT_CODE, relocations: ALLOCA_BT_RELOCS }
        } else {
            AllocaCode { code: ALLOCA_CODE, relocations: &[] }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Symbol names for the alloca functions emitted into the runtime library.
///
/// Standard alloca uses `alloca` (and `__alloca` on i386 for cdecl compat).
/// Bounds-checking alloca uses `__bound_alloca`.
pub(crate) const ALLOCA_SYMBOL: &str = "alloca";

/// Alternative symbol name for i386 (cdecl calling convention).
pub(crate) const ALLOCA_ALT_SYMBOL: &str = "__alloca";

/// Bounds-checking alloca symbol name.
pub(crate) const BOUND_ALLOCA_SYMBOL: &str = "__bound_alloca";

/// Windows x86_64 bounds-checking alloca secondary entry point.
pub(crate) const BOUND_ALLOCA_NR_SYMBOL: &str = "__bound_alloca_nr";

/// Get the alloca code bytes for a target architecture.
///
/// Returns an [`AllocaCode`] containing the raw machine code bytes and any
/// relocations that must be applied when linking the code into a compiled
/// program's text section.
///
/// # Arguments
///
/// * `bounds_check` — If `true`, returns the bounds-checking variant that
///   calls `__bound_new_region` after stack adjustment (from `alloca-bt.S`).
///   If `false`, returns the standard alloca (from `alloca.S`).
///
/// # Target Selection
///
/// The target architecture is selected at compile time via Cargo feature
/// flags (`x86_64`, `i386`, `arm`, `arm64`, `riscv64`). If multiple
/// features are enabled, `x86_64` takes priority.
///
/// # Examples
///
/// ```ignore
/// let code = get_alloca_code(false);
/// // Copy code.code into the text section at the alloca symbol offset
/// // Apply relocations from code.relocations via the linker
/// ```
pub(crate) fn get_alloca_code(bounds_check: bool) -> AllocaCode {
    get_alloca_code_for_target(bounds_check, cfg!(target_os = "windows"))
}

/// Get alloca code for a specific target platform combination.
///
/// This is the full-control variant allowing explicit specification of
/// the Windows flag (useful for cross-compilation where the host OS
/// differs from the target OS).
pub(crate) fn get_alloca_code_for_target(bounds_check: bool, windows: bool) -> AllocaCode {
    // Priority: x86_64 > i386 > arm64 > arm > riscv64
    // This matches TCC's default target selection order.

    #[cfg(feature = "x86_64")]
    {
        return x86_64::get_code(bounds_check, windows);
    }

    #[cfg(feature = "i386")]
    {
        return i386::get_code(bounds_check, windows);
    }

    #[cfg(feature = "arm64")]
    {
        return arm64::get_code(bounds_check, windows);
    }

    #[cfg(feature = "arm")]
    {
        return arm::get_code(bounds_check, windows);
    }

    #[cfg(feature = "riscv64")]
    {
        return riscv64::get_code(bounds_check, windows);
    }

    // Fallback: no architecture feature enabled — return empty code.
    // The compiler will report an error if alloca is needed but no backend
    // is configured.
    #[allow(unreachable_code)]
    AllocaCode { code: &[], relocations: &[] }
}

/// Pure Rust alloca-equivalent for stack frame management.
///
/// Computes the aligned allocation size for a dynamic stack allocation.
/// Used by the code generator to calculate the size argument before
/// emitting the architecture-specific alloca call sequence.
///
/// # Arguments
///
/// * `requested_size` — The number of bytes requested by the program.
/// * `alignment` — The required alignment in bytes (must be a power of 2).
///
/// # Returns
///
/// The smallest value ≥ `requested_size` that is a multiple of `alignment`.
/// Returns 0 if `alignment` is 0 (invalid, but handled gracefully).
///
/// # C Equivalent
///
/// This replaces the inline alignment logic in each architecture's alloca:
/// - i386: `add $3,%eax; and $-4,%eax` (4-byte alignment)
/// - x86_64: `add $15,%rax; and $-16,%rax` (16-byte alignment)
/// - ARM: `bic sp, sp, #7` (8-byte alignment)
/// - AArch64: `and x0, x0, #-16` (16-byte alignment)
/// - RISC-V: `andi sp, sp, -16` (16-byte alignment)
///
/// # Examples
///
/// ```ignore
/// assert_eq!(compute_alloca_adjustment(1, 16), 16);
/// assert_eq!(compute_alloca_adjustment(16, 16), 16);
/// assert_eq!(compute_alloca_adjustment(17, 16), 32);
/// assert_eq!(compute_alloca_adjustment(0, 16), 0);
/// ```
pub(crate) fn compute_alloca_adjustment(requested_size: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return requested_size;
    }
    // alignment must be a power of 2 for the bitmask trick to work.
    // This matches the assembly: `add (alignment-1); and -alignment`.
    let mask = alignment.wrapping_sub(1);
    requested_size.checked_add(mask).map_or(usize::MAX, |v| v & !mask)
}

/// Get the default alignment for alloca on a given architecture.
///
/// Returns the stack alignment requirement that the alloca code enforces:
/// - i386: 4 bytes
/// - x86_64: 16 bytes
/// - ARM: 8 bytes
/// - AArch64: 16 bytes
/// - RISC-V 64: 16 bytes
///
/// Falls back to 16 if no architecture feature is enabled.
pub(crate) fn default_alloca_alignment() -> usize {
    #[cfg(feature = "x86_64")]
    { return 16; }

    #[cfg(feature = "i386")]
    { return 4; }

    #[cfg(feature = "arm64")]
    { return 16; }

    #[cfg(feature = "arm")]
    { return 8; }

    #[cfg(feature = "riscv64")]
    { return 16; }

    #[allow(unreachable_code)]
    16
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_alloca_adjustment_basic() {
        // Zero size → zero
        assert_eq!(compute_alloca_adjustment(0, 16), 0);
        // Exact alignment → unchanged
        assert_eq!(compute_alloca_adjustment(16, 16), 16);
        assert_eq!(compute_alloca_adjustment(32, 16), 32);
        // Round up
        assert_eq!(compute_alloca_adjustment(1, 16), 16);
        assert_eq!(compute_alloca_adjustment(15, 16), 16);
        assert_eq!(compute_alloca_adjustment(17, 16), 32);
        assert_eq!(compute_alloca_adjustment(31, 16), 32);
        assert_eq!(compute_alloca_adjustment(33, 16), 48);
    }

    #[test]
    fn test_compute_alloca_adjustment_4_byte_alignment() {
        // i386 uses 4-byte alignment
        assert_eq!(compute_alloca_adjustment(0, 4), 0);
        assert_eq!(compute_alloca_adjustment(1, 4), 4);
        assert_eq!(compute_alloca_adjustment(3, 4), 4);
        assert_eq!(compute_alloca_adjustment(4, 4), 4);
        assert_eq!(compute_alloca_adjustment(5, 4), 8);
    }

    #[test]
    fn test_compute_alloca_adjustment_8_byte_alignment() {
        // ARM uses 8-byte alignment
        assert_eq!(compute_alloca_adjustment(0, 8), 0);
        assert_eq!(compute_alloca_adjustment(1, 8), 8);
        assert_eq!(compute_alloca_adjustment(7, 8), 8);
        assert_eq!(compute_alloca_adjustment(8, 8), 8);
        assert_eq!(compute_alloca_adjustment(9, 8), 16);
    }

    #[test]
    fn test_compute_alloca_adjustment_edge_cases() {
        // Zero alignment → passthrough
        assert_eq!(compute_alloca_adjustment(42, 0), 42);
        // Large size near usize::MAX → saturates
        assert_eq!(compute_alloca_adjustment(usize::MAX, 16), usize::MAX);
        assert_eq!(compute_alloca_adjustment(usize::MAX - 1, 16), usize::MAX);
        // Alignment of 1 → unchanged
        assert_eq!(compute_alloca_adjustment(42, 1), 42);
        assert_eq!(compute_alloca_adjustment(0, 1), 0);
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_alloca_code_not_empty() {
        assert!(!x86_64::ALLOCA_CODE.is_empty());
        assert!(!x86_64::ALLOCA_WIN_CODE.is_empty());
        assert!(!x86_64::ALLOCA_BT_CODE.is_empty());
        assert!(!x86_64::ALLOCA_BT_WIN_CODE.is_empty());
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_alloca_code_starts_with_pop_rdx() {
        // All x86_64 alloca variants start with pop %rdx (0x5A)
        // except the Windows BT variant which starts with inc %rcx
        assert_eq!(x86_64::ALLOCA_CODE[0], 0x5A);
        assert_eq!(x86_64::ALLOCA_WIN_CODE[0], 0x5A);
        assert_eq!(x86_64::ALLOCA_BT_CODE[0], 0x5A);
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_alloca_code_ends_with_ret() {
        // All x86_64 alloca code ends with 0xC3 (ret)
        assert_eq!(*x86_64::ALLOCA_CODE.last().expect("non-empty"), 0xC3);
        assert_eq!(*x86_64::ALLOCA_WIN_CODE.last().expect("non-empty"), 0xC3);
        assert_eq!(*x86_64::ALLOCA_BT_CODE.last().expect("non-empty"), 0xC3);
        assert_eq!(*x86_64::ALLOCA_BT_WIN_CODE.last().expect("non-empty"), 0xC3);
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_bt_has_call_instruction() {
        // The non-Windows BT code must contain 0xE8 (CALL near)
        assert!(
            x86_64::ALLOCA_BT_CODE.contains(&0xE8),
            "bounds-checking alloca must contain a CALL instruction"
        );
        // And have exactly one relocation
        assert_eq!(x86_64::ALLOCA_BT_RELOCS.len(), 1);
        assert_eq!(x86_64::ALLOCA_BT_RELOCS[0].symbol, "__bound_new_region");
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_get_alloca_code_standard() {
        let code = get_alloca_code_for_target(false, false);
        assert!(!code.code.is_empty());
        assert!(code.relocations.is_empty());
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_get_alloca_code_bounds_check() {
        let code = get_alloca_code_for_target(true, false);
        assert!(!code.code.is_empty());
        assert!(!code.relocations.is_empty());
        assert_eq!(code.relocations[0].symbol, "__bound_new_region");
    }

    #[cfg(feature = "i386")]
    #[test]
    fn test_i386_alloca_code_not_empty() {
        assert!(!i386::ALLOCA_CODE.is_empty());
        assert!(!i386::ALLOCA_WIN_CODE.is_empty());
        assert!(!i386::ALLOCA_BT_CODE.is_empty());
        assert!(!i386::ALLOCA_BT_WIN_CODE.is_empty());
    }

    #[cfg(feature = "i386")]
    #[test]
    fn test_i386_alloca_code_starts_correctly() {
        // i386 alloca starts with pop %edx (0x5A), pop %eax (0x58)
        assert_eq!(i386::ALLOCA_CODE[0], 0x5A);
        assert_eq!(i386::ALLOCA_CODE[1], 0x58);
    }

    #[cfg(feature = "arm64")]
    #[test]
    fn test_arm64_alloca_code_not_empty() {
        assert!(!arm64::ALLOCA_CODE.is_empty());
        assert!(!arm64::ALLOCA_WIN_CODE.is_empty());
        assert!(!arm64::ALLOCA_BT_CODE.is_empty());
        assert!(!arm64::ALLOCA_BT_WIN_CODE.is_empty());
    }

    #[cfg(feature = "arm64")]
    #[test]
    fn test_arm64_alloca_code_size_is_word_aligned() {
        // AArch64 instructions are always 4 bytes
        assert_eq!(arm64::ALLOCA_CODE.len() % 4, 0);
        assert_eq!(arm64::ALLOCA_WIN_CODE.len() % 4, 0);
        assert_eq!(arm64::ALLOCA_BT_CODE.len() % 4, 0);
        assert_eq!(arm64::ALLOCA_BT_WIN_CODE.len() % 4, 0);
    }

    #[cfg(feature = "riscv64")]
    #[test]
    fn test_riscv64_alloca_code_not_empty() {
        assert!(!riscv64::ALLOCA_CODE.is_empty());
        assert!(!riscv64::ALLOCA_BT_CODE.is_empty());
    }

    #[cfg(feature = "riscv64")]
    #[test]
    fn test_riscv64_alloca_code_size_is_word_aligned() {
        // RISC-V instructions are 4 bytes (32-bit base ISA)
        assert_eq!(riscv64::ALLOCA_CODE.len() % 4, 0);
        assert_eq!(riscv64::ALLOCA_BT_CODE.len() % 4, 0);
    }

    #[test]
    fn test_default_alloca_alignment() {
        let align = default_alloca_alignment();
        // Alignment must be a power of 2
        assert!(align > 0);
        assert_eq!(align & (align - 1), 0);
    }
}
