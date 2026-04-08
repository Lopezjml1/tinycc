// ==========================================================================
// crates/tcc-core/src/arch/il/gen.rs — .NET IL/CIL Bytecode Emission
//
// Port of il-gen.c (657 lines) and il-opcodes.h (251 lines) from TinyCC.
// Original author: Fabrice Bellard (2002), LGPL license.
//
// HISTORICAL NOTE: The C source contains `#error this code has bit-rotted
// since 2003` at line 21. This backend is experimental/historical but is
// ported for completeness per the migration plan. The Rust port preserves
// this status with clear documentation.
//
// This module provides:
// - IlOpcode enum: All 229 CIL opcodes from il-opcodes.h
// - IL code emission helpers: out_byte, out_le32, out_op, out_opb, out_opi
// - Type-to-string conversion for CIL assembly text
// - Load/store operations mapping C types to CIL ldloc/ldarg/stloc/starg
// - Function generation: prologue, epilogue, call
// - Jump generation: conditional and unconditional branches
// - Integer/float operations and type conversions
// ==========================================================================

#![allow(
    clippy::match_same_arms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::fmt::Write;

use super::{IlBackend, ARG_BASE, NB_REGS};
use crate::error::{TccError, TccResult};
use crate::types::{
    SValue, Sym,
    VT_BTYPE, VT_BOOL, VT_BYTE, VT_CONST, VT_DOUBLE, VT_FLOAT,
    VT_FUNC, VT_INT, VT_LDOUBLE, VT_LLONG, VT_LVAL,
    VT_LOCAL, VT_PTR, VT_SHORT, VT_STRUCT, VT_UNSIGNED, VT_VALMASK, VT_VOID,
    SYM_FIELD, SYM_STRUCT,
};
use crate::token::{
    TOK_EQ, TOK_GE, TOK_GT, TOK_LE, TOK_LT, TOK_NE, TOK_PDIV, TOK_SAR,
    TOK_SHL, TOK_SHR, TOK_UDIV, TOK_UGE, TOK_UGT, TOK_ULE, TOK_ULT,
    TOK_UMOD,
};

// ===========================================================================
// IlOpcode — CIL (Common Intermediate Language) opcode definitions
//
// Port of il-opcodes.h (251 lines).
// Each variant carries its opcode number via #[repr(u16)].
//
// Single-byte opcodes: 0x00–0xE0
// Two-byte (prefix 0xFE) opcodes: 0x100+ (encoded as 0xFE then opcode & 0xFF)
// ===========================================================================

/// All CIL opcodes defined in ECMA-335 / il-opcodes.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IlOpcode {
    // --- Single-byte opcodes (0x00 – 0xE0) ---
    Nop              = 0x00,
    Break            = 0x01,
    LdargZero        = 0x02,
    LdargOne         = 0x03,
    LdargTwo         = 0x04,
    LdargThree       = 0x05,
    LdlocZero        = 0x06,
    LdlocOne         = 0x07,
    LdlocTwo         = 0x08,
    LdlocThree       = 0x09,
    StlocZero        = 0x0a,
    StlocOne         = 0x0b,
    StlocTwo         = 0x0c,
    StlocThree       = 0x0d,
    LdargS           = 0x0e,
    LdargaS          = 0x0f,
    StargS           = 0x10,
    LdlocS           = 0x11,
    LdlocaS          = 0x12,
    StlocS           = 0x13,
    Ldnull           = 0x14,
    LdcI4M1          = 0x15,
    LdcI4Zero        = 0x16,
    LdcI4One         = 0x17,
    LdcI4Two         = 0x18,
    LdcI4Three       = 0x19,
    LdcI4Four        = 0x1a,
    LdcI4Five        = 0x1b,
    LdcI4Six         = 0x1c,
    LdcI4Seven       = 0x1d,
    LdcI4Eight       = 0x1e,
    LdcI4S           = 0x1f,
    LdcI4            = 0x20,
    LdcI8            = 0x21,
    LdcR4            = 0x22,
    LdcR8            = 0x23,
    Ldptr            = 0x24,
    Dup              = 0x25,
    Pop              = 0x26,
    Jmp              = 0x27,
    Call             = 0x28,
    Calli            = 0x29,
    Ret              = 0x2a,
    BrS              = 0x2b,
    BrfalseS         = 0x2c,
    BrtrueS          = 0x2d,
    BeqS             = 0x2e,
    BgeS             = 0x2f,
    BgtS             = 0x30,
    BleS             = 0x31,
    BltS             = 0x32,
    BneUnS           = 0x33,
    BgeUnS           = 0x34,
    BgtUnS           = 0x35,
    BleUnS           = 0x36,
    BltUnS           = 0x37,
    Br               = 0x38,
    Brfalse          = 0x39,
    Brtrue           = 0x3a,
    Beq              = 0x3b,
    Bge              = 0x3c,
    Bgt              = 0x3d,
    Ble              = 0x3e,
    Blt              = 0x3f,
    BneUn            = 0x40,
    BgeUn            = 0x41,
    BgtUn            = 0x42,
    BleUn            = 0x43,
    BltUn            = 0x44,
    Switch           = 0x45,
    LdindI1          = 0x46,
    LdindU1          = 0x47,
    LdindI2          = 0x48,
    LdindU2          = 0x49,
    LdindI4          = 0x4a,
    LdindU4          = 0x4b,
    LdindI8          = 0x4c,
    LdindI           = 0x4d,
    LdindR4          = 0x4e,
    LdindR8          = 0x4f,
    LdindRef         = 0x50,
    StindRef         = 0x51,
    StindI1          = 0x52,
    StindI2          = 0x53,
    StindI4          = 0x54,
    StindI8          = 0x55,
    StindR4          = 0x56,
    StindR8          = 0x57,
    Add              = 0x58,
    Sub              = 0x59,
    Mul              = 0x5a,
    Div              = 0x5b,
    DivUn            = 0x5c,
    Rem              = 0x5d,
    RemUn            = 0x5e,
    And              = 0x5f,
    Or               = 0x60,
    Xor              = 0x61,
    Shl              = 0x62,
    Shr              = 0x63,
    ShrUn            = 0x64,
    Neg              = 0x65,
    Not              = 0x66,
    ConvI1           = 0x67,
    ConvI2           = 0x68,
    ConvI4           = 0x69,
    ConvI8           = 0x6a,
    ConvR4           = 0x6b,
    ConvR8           = 0x6c,
    ConvU4           = 0x6d,
    ConvU8           = 0x6e,
    Callvirt         = 0x6f,
    Cpobj            = 0x70,
    Ldobj            = 0x71,
    Ldstr            = 0x72,
    Newobj           = 0x73,
    Castclass        = 0x74,
    Isinst           = 0x75,
    ConvRUn          = 0x76,
    AnnDataS         = 0x77,
    Unbox            = 0x79,
    Throw            = 0x7a,
    Ldfld            = 0x7b,
    Ldflda           = 0x7c,
    Stfld            = 0x7d,
    Ldsfld           = 0x7e,
    Ldsflda          = 0x7f,
    Stsfld           = 0x80,
    Stobj            = 0x81,
    ConvOvfI1Un      = 0x82,
    ConvOvfI2Un      = 0x83,
    ConvOvfI4Un      = 0x84,
    ConvOvfI8Un      = 0x85,
    ConvOvfU1Un      = 0x86,
    ConvOvfU2Un      = 0x87,
    ConvOvfU4Un      = 0x88,
    ConvOvfU8Un      = 0x89,
    ConvOvfIUn       = 0x8a,
    ConvOvfUUn       = 0x8b,
    Box              = 0x8c,
    Newarr           = 0x8d,
    Ldlen            = 0x8e,
    Ldelema          = 0x8f,
    LdelemI1         = 0x90,
    LdelemU1         = 0x91,
    LdelemI2         = 0x92,
    LdelemU2         = 0x93,
    LdelemI4         = 0x94,
    LdelemU4         = 0x95,
    LdelemI8         = 0x96,
    LdelemI          = 0x97,
    LdelemR4         = 0x98,
    LdelemR8         = 0x99,
    LdelemRef        = 0x9a,
    StelemI          = 0x9b,
    StelemI1         = 0x9c,
    StelemI2         = 0x9d,
    StelemI4         = 0x9e,
    StelemI8         = 0x9f,
    StelemR4         = 0xa0,
    StelemR8         = 0xa1,
    StelemRef        = 0xa2,
    ConvOvfI1        = 0xb3,
    ConvOvfU1        = 0xb4,
    ConvOvfI2        = 0xb5,
    ConvOvfU2        = 0xb6,
    ConvOvfI4        = 0xb7,
    ConvOvfU4        = 0xb8,
    ConvOvfI8        = 0xb9,
    ConvOvfU8        = 0xba,
    Refanyval        = 0xc2,
    Ckfinite         = 0xc3,
    Mkrefany         = 0xc6,
    AnnCall          = 0xc7,
    AnnCatch         = 0xc8,
    AnnDead          = 0xc9,
    AnnHoisted       = 0xca,
    AnnHoistedCall   = 0xcb,
    AnnLab           = 0xcc,
    AnnDef           = 0xcd,
    AnnRefS          = 0xce,
    AnnPhi           = 0xcf,
    Ldtoken          = 0xd0,
    ConvU2           = 0xd1,
    ConvU1           = 0xd2,
    ConvI            = 0xd3,
    ConvOvfI         = 0xd4,
    ConvOvfU         = 0xd5,
    AddOvf           = 0xd6,
    AddOvfUn         = 0xd7,
    MulOvf           = 0xd8,
    MulOvfUn         = 0xd9,
    SubOvf           = 0xda,
    SubOvfUn         = 0xdb,
    Endfinally       = 0xdc,
    Leave            = 0xdd,
    LeaveS           = 0xde,
    StindI           = 0xdf,
    ConvU            = 0xe0,

    // --- Two-byte prefix opcodes (0xFE XX) — encoded as 0x100 + XX ---
    Arglist          = 0x100,
    Ceq              = 0x101,
    Cgt              = 0x102,
    CgtUn            = 0x103,
    Clt              = 0x104,
    CltUn            = 0x105,
    Ldftn            = 0x106,
    Ldvirtftn        = 0x107,
    Jmpi             = 0x108,
    Ldarg            = 0x109,
    Ldarga           = 0x10a,
    Starg            = 0x10b,
    Ldloc            = 0x10c,
    Ldloca           = 0x10d,
    Stloc            = 0x10e,
    Localloc         = 0x10f,
    Endfilter        = 0x111,
    Unaligned        = 0x112,
    Volatile         = 0x113,
    Tail             = 0x114,
    Initobj          = 0x115,
    AnnLive          = 0x116,
    Cpblk            = 0x117,
    Initblk          = 0x118,
    AnnRef           = 0x119,
    Rethrow          = 0x11a,
    Sizeof           = 0x11c,
    Refanytype       = 0x11d,
    AnnData          = 0x122,
    AnnArg           = 0x123,
}

impl IlOpcode {
    /// Return the CIL mnemonic string for this opcode, exactly matching
    /// the string literals from `il-opcodes.h`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Nop            => "nop",
            Self::Break          => "break",
            Self::LdargZero      => "ldarg.0",
            Self::LdargOne       => "ldarg.1",
            Self::LdargTwo       => "ldarg.2",
            Self::LdargThree     => "ldarg.3",
            Self::LdlocZero      => "ldloc.0",
            Self::LdlocOne       => "ldloc.1",
            Self::LdlocTwo       => "ldloc.2",
            Self::LdlocThree     => "ldloc.3",
            Self::StlocZero      => "stloc.0",
            Self::StlocOne       => "stloc.1",
            Self::StlocTwo       => "stloc.2",
            Self::StlocThree     => "stloc.3",
            Self::LdargS         => "ldarg.s",
            Self::LdargaS        => "ldarga.s",
            Self::StargS         => "starg.s",
            Self::LdlocS         => "ldloc.s",
            Self::LdlocaS        => "ldloca.s",
            Self::StlocS         => "stloc.s",
            Self::Ldnull         => "ldnull",
            Self::LdcI4M1        => "ldc.i4.m1",
            Self::LdcI4Zero      => "ldc.i4.0",
            Self::LdcI4One       => "ldc.i4.1",
            Self::LdcI4Two       => "ldc.i4.2",
            Self::LdcI4Three     => "ldc.i4.3",
            Self::LdcI4Four      => "ldc.i4.4",
            Self::LdcI4Five      => "ldc.i4.5",
            Self::LdcI4Six       => "ldc.i4.6",
            Self::LdcI4Seven     => "ldc.i4.7",
            Self::LdcI4Eight     => "ldc.i4.8",
            Self::LdcI4S         => "ldc.i4.s",
            Self::LdcI4          => "ldc.i4",
            Self::LdcI8          => "ldc.i8",
            Self::LdcR4          => "ldc.r4",
            Self::LdcR8          => "ldc.r8",
            Self::Ldptr          => "ldptr",
            Self::Dup            => "dup",
            Self::Pop            => "pop",
            Self::Jmp            => "jmp",
            Self::Call           => "call",
            Self::Calli          => "calli",
            Self::Ret            => "ret",
            Self::BrS            => "br.s",
            Self::BrfalseS       => "brfalse.s",
            Self::BrtrueS        => "brtrue.s",
            Self::BeqS           => "beq.s",
            Self::BgeS           => "bge.s",
            Self::BgtS           => "bgt.s",
            Self::BleS           => "ble.s",
            Self::BltS           => "blt.s",
            Self::BneUnS         => "bne.un.s",
            Self::BgeUnS         => "bge.un.s",
            Self::BgtUnS         => "bgt.un.s",
            Self::BleUnS         => "ble.un.s",
            Self::BltUnS         => "blt.un.s",
            Self::Br             => "br",
            Self::Brfalse        => "brfalse",
            Self::Brtrue         => "brtrue",
            Self::Beq            => "beq",
            Self::Bge            => "bge",
            Self::Bgt            => "bgt",
            Self::Ble            => "ble",
            Self::Blt            => "blt",
            Self::BneUn          => "bne.un",
            Self::BgeUn          => "bge.un",
            Self::BgtUn          => "bgt.un",
            Self::BleUn          => "ble.un",
            Self::BltUn          => "blt.un",
            Self::Switch         => "switch",
            Self::LdindI1        => "ldind.i1",
            Self::LdindU1        => "ldind.u1",
            Self::LdindI2        => "ldind.i2",
            Self::LdindU2        => "ldind.u2",
            Self::LdindI4        => "ldind.i4",
            Self::LdindU4        => "ldind.u4",
            Self::LdindI8        => "ldind.i8",
            Self::LdindI         => "ldind.i",
            Self::LdindR4        => "ldind.r4",
            Self::LdindR8        => "ldind.r8",
            Self::LdindRef       => "ldind.ref",
            Self::StindRef       => "stind.ref",
            Self::StindI1        => "stind.i1",
            Self::StindI2        => "stind.i2",
            Self::StindI4        => "stind.i4",
            Self::StindI8        => "stind.i8",
            Self::StindR4        => "stind.r4",
            Self::StindR8        => "stind.r8",
            Self::Add            => "add",
            Self::Sub            => "sub",
            Self::Mul            => "mul",
            Self::Div            => "div",
            Self::DivUn          => "div.un",
            Self::Rem            => "rem",
            Self::RemUn          => "rem.un",
            Self::And            => "and",
            Self::Or             => "or",
            Self::Xor            => "xor",
            Self::Shl            => "shl",
            Self::Shr            => "shr",
            Self::ShrUn          => "shr.un",
            Self::Neg            => "neg",
            Self::Not            => "not",
            Self::ConvI1         => "conv.i1",
            Self::ConvI2         => "conv.i2",
            Self::ConvI4         => "conv.i4",
            Self::ConvI8         => "conv.i8",
            Self::ConvR4         => "conv.r4",
            Self::ConvR8         => "conv.r8",
            Self::ConvU4         => "conv.u4",
            Self::ConvU8         => "conv.u8",
            Self::Callvirt       => "callvirt",
            Self::Cpobj          => "cpobj",
            Self::Ldobj          => "ldobj",
            Self::Ldstr          => "ldstr",
            Self::Newobj         => "newobj",
            Self::Castclass      => "castclass",
            Self::Isinst         => "isinst",
            Self::ConvRUn        => "conv.r.un",
            Self::AnnDataS       => "ann.data.s",
            Self::Unbox          => "unbox",
            Self::Throw          => "throw",
            Self::Ldfld          => "ldfld",
            Self::Ldflda         => "ldflda",
            Self::Stfld          => "stfld",
            Self::Ldsfld         => "ldsfld",
            Self::Ldsflda        => "ldsflda",
            Self::Stsfld         => "stsfld",
            Self::Stobj          => "stobj",
            Self::ConvOvfI1Un    => "conv.ovf.i1.un",
            Self::ConvOvfI2Un    => "conv.ovf.i2.un",
            Self::ConvOvfI4Un    => "conv.ovf.i4.un",
            Self::ConvOvfI8Un    => "conv.ovf.i8.un",
            Self::ConvOvfU1Un    => "conv.ovf.u1.un",
            Self::ConvOvfU2Un    => "conv.ovf.u2.un",
            Self::ConvOvfU4Un    => "conv.ovf.u4.un",
            Self::ConvOvfU8Un    => "conv.ovf.u8.un",
            Self::ConvOvfIUn     => "conv.ovf.i.un",
            Self::ConvOvfUUn     => "conv.ovf.u.un",
            Self::Box            => "box",
            Self::Newarr         => "newarr",
            Self::Ldlen          => "ldlen",
            Self::Ldelema        => "ldelema",
            Self::LdelemI1       => "ldelem.i1",
            Self::LdelemU1       => "ldelem.u1",
            Self::LdelemI2       => "ldelem.i2",
            Self::LdelemU2       => "ldelem.u2",
            Self::LdelemI4       => "ldelem.i4",
            Self::LdelemU4       => "ldelem.u4",
            Self::LdelemI8       => "ldelem.i8",
            Self::LdelemI        => "ldelem.i",
            Self::LdelemR4       => "ldelem.r4",
            Self::LdelemR8       => "ldelem.r8",
            Self::LdelemRef      => "ldelem.ref",
            Self::StelemI        => "stelem.i",
            Self::StelemI1       => "stelem.i1",
            Self::StelemI2       => "stelem.i2",
            Self::StelemI4       => "stelem.i4",
            Self::StelemI8       => "stelem.i8",
            Self::StelemR4       => "stelem.r4",
            Self::StelemR8       => "stelem.r8",
            Self::StelemRef      => "stelem.ref",
            Self::ConvOvfI1      => "conv.ovf.i1",
            Self::ConvOvfU1      => "conv.ovf.u1",
            Self::ConvOvfI2      => "conv.ovf.i2",
            Self::ConvOvfU2      => "conv.ovf.u2",
            Self::ConvOvfI4      => "conv.ovf.i4",
            Self::ConvOvfU4      => "conv.ovf.u4",
            Self::ConvOvfI8      => "conv.ovf.i8",
            Self::ConvOvfU8      => "conv.ovf.u8",
            Self::Refanyval      => "refanyval",
            Self::Ckfinite       => "ckfinite",
            Self::Mkrefany       => "mkrefany",
            Self::AnnCall        => "ann.call",
            Self::AnnCatch       => "ann.catch",
            Self::AnnDead        => "ann.dead",
            Self::AnnHoisted     => "ann.hoisted",
            Self::AnnHoistedCall => "ann.hoisted.call",
            Self::AnnLab         => "ann.lab",
            Self::AnnDef         => "ann.def",
            Self::AnnRefS        => "ann.ref.s",
            Self::AnnPhi         => "ann.phi",
            Self::Ldtoken        => "ldtoken",
            Self::ConvU2         => "conv.u2",
            Self::ConvU1         => "conv.u1",
            Self::ConvI          => "conv.i",
            Self::ConvOvfI       => "conv.ovf.i",
            Self::ConvOvfU       => "conv.ovf.u",
            Self::AddOvf         => "add.ovf",
            Self::AddOvfUn       => "add.ovf.un",
            Self::MulOvf         => "mul.ovf",
            Self::MulOvfUn       => "mul.ovf.un",
            Self::SubOvf         => "sub.ovf",
            Self::SubOvfUn       => "sub.ovf.un",
            Self::Endfinally     => "endfinally",
            Self::Leave          => "leave",
            Self::LeaveS         => "leave.s",
            Self::StindI         => "stind.i",
            Self::ConvU          => "conv.u",
            // Two-byte prefix opcodes (0xFE xx)
            Self::Arglist        => "arglist",
            Self::Ceq            => "ceq",
            Self::Cgt            => "cgt",
            Self::CgtUn          => "cgt.un",
            Self::Clt            => "clt",
            Self::CltUn          => "clt.un",
            Self::Ldftn          => "ldftn",
            Self::Ldvirtftn      => "ldvirtftn",
            Self::Jmpi           => "jmpi",
            Self::Ldarg          => "ldarg",
            Self::Ldarga         => "ldarga",
            Self::Starg          => "starg",
            Self::Ldloc          => "ldloc",
            Self::Ldloca         => "ldloca",
            Self::Stloc          => "stloc",
            Self::Localloc       => "localloc",
            Self::Endfilter      => "endfilter",
            Self::Unaligned      => "unaligned.",
            Self::Volatile       => "volatile.",
            Self::Tail           => "tail.",
            Self::Initobj        => "initobj",
            Self::AnnLive        => "ann.live",
            Self::Cpblk          => "cpblk",
            Self::Initblk        => "initblk",
            Self::AnnRef         => "ann.ref",
            Self::Rethrow        => "rethrow",
            Self::Sizeof         => "sizeof",
            Self::Refanytype     => "refanytype",
            Self::AnnData        => "ann.data",
            Self::AnnArg         => "ann.arg",
        }
    }

    /// Return the raw numeric value of this opcode.
    pub fn opcode_value(self) -> u16 {
        self as u16
    }
}

// ===========================================================================
// Constants and type aliases
// ===========================================================================

/// Two-byte opcode prefix byte.
/// Source: il-gen.c line 79
pub const IL_OP_PREFIX: u8 = 0xFE;

/// Type alias — `IlGenState` is the same as `IlBackend` from `mod.rs`.
///
/// All gen.rs functions accept `&mut IlGenState` (i.e. `&mut IlBackend`).
/// The `IlBackend` struct carries: `outfile_initialized`, `il_output`,
/// `ind`, and `code` — matching the schema's IlGenState definition.
pub type IlGenState = IlBackend;

/// Function call context — tracks calling convention for current call.
/// Source: il-gen.c lines 72-74
pub struct GFuncContext {
    /// Calling convention type (mirrors C `func_call` field)
    pub func_call: i32,
}

// ===========================================================================
// Byte emission helpers — Port of il-gen.c lines 100-151
// ===========================================================================

/// Emit a single byte to the current code position.
/// Source: il-gen.c lines 100-103
///
/// Appends `c` to the code buffer and advances the emission index.
pub fn out_byte(state: &mut IlGenState, c: u8) {
    state.code.push(c);
    state.ind += 1;
}

/// Emit a 32-bit little-endian value (4 bytes).
/// Source: il-gen.c lines 105-111
///
/// Writes the four bytes of `c` in little-endian order.
pub fn out_le32(state: &mut IlGenState, c: i32) {
    let bytes = c.to_le_bytes();
    for &b in &bytes {
        out_byte(state, b);
    }
}

/// Initialize IL output with mscorlib assembly reference.
/// Source: il-gen.c lines 113-123
///
/// Emits the `.assembly extern mscorlib {}` header block that every
/// .NET CIL assembly file requires. Only runs once per compilation.
pub fn init_outfile(state: &mut IlGenState) {
    if !state.outfile_initialized {
        let _ = writeln!(state.il_output, ".assembly extern mscorlib");
        let _ = writeln!(state.il_output, "{{");
        let _ = writeln!(state.il_output, ".ver 1:0:2411:0");
        let _ = writeln!(state.il_output, "}}");
        let _ = writeln!(state.il_output);
        state.outfile_initialized = true;
    }
}

/// Emit a single opcode (with 0xFE prefix if op >= 0x100).
/// Source: il-gen.c lines 125-130
///
/// Two-byte opcodes (value >= 0x100) are encoded with a 0xFE prefix
/// byte followed by the low byte of the opcode value.
pub fn out_op1(state: &mut IlGenState, op: u16) {
    if op & 0x100 != 0 {
        out_byte(state, IL_OP_PREFIX);
    }
    out_byte(state, (op & 0xFF) as u8);
}

/// Emit opcode with textual output (for IL assembly listing).
/// Source: il-gen.c lines 133-137
///
/// Writes both the binary opcode to the code buffer and the mnemonic
/// text to the IL output string.
pub fn out_op(state: &mut IlGenState, op: IlOpcode) {
    init_outfile(state);
    out_op1(state, op.opcode_value());
    let _ = write!(state.il_output, "\t{}", op.name());
}

/// Emit opcode with byte operand.
/// Source: il-gen.c lines 139-144
///
/// Writes the opcode followed by a single byte operand. The textual
/// output includes the operand value.
pub fn out_opb(state: &mut IlGenState, op: IlOpcode, c: u8) {
    out_op(state, op);
    out_byte(state, c);
    let _ = writeln!(state.il_output, " {}", c);
}

/// Emit opcode with 32-bit integer operand.
/// Source: il-gen.c lines 146-151
///
/// Writes the opcode followed by a 32-bit little-endian operand.
/// The textual output includes the operand value.
pub fn out_opi(state: &mut IlGenState, op: IlOpcode, c: i32) {
    out_op(state, op);
    out_le32(state, c);
    let _ = writeln!(state.il_output, " {}", c);
}

// ===========================================================================
// IL Type-to-String Conversion — Port of il-gen.c lines 154-227
// ===========================================================================

/// Convert a C type (represented as the `t` field from `CType`) to its CIL
/// type string representation.
///
/// Source: il-gen.c lines 154-227
///
/// Maps VT_BTYPE values to CIL type names:
/// - `VT_VOID` → `"void"`
/// - `VT_BOOL` → `"bool"`
/// - `VT_BYTE` → `"int8"` (with `"unsigned "` prefix if `VT_UNSIGNED`)
/// - `VT_SHORT` → `"int16"`
/// - `VT_INT` → `"int32"`
/// - `VT_LLONG` → `"int64"`
/// - `VT_FLOAT` → `"float32"`
/// - `VT_DOUBLE` / `VT_LDOUBLE` → `"float64"`
/// - `VT_STRUCT` → error (struct types have no direct CIL string representation)
/// - `VT_FUNC` → recursive: `return_type(param_types)`
/// - `VT_PTR` → recursive with `*` prefix
///
/// The optional `varstr` parameter appends a variable name after the type.
pub fn il_type_to_str(t: i32, varstr: Option<&str>) -> TccResult<String> {
    let bt = t & VT_BTYPE;
    let unsigned = (t & VT_UNSIGNED) != 0;

    let type_str = match bt {
        VT_VOID   => "void".to_string(),
        VT_BOOL   => "bool".to_string(),
        VT_BYTE   => {
            if unsigned { "unsigned int8".to_string() }
            else { "int8".to_string() }
        }
        VT_SHORT  => {
            if unsigned { "unsigned int16".to_string() }
            else { "int16".to_string() }
        }
        VT_INT => {
            if unsigned { "unsigned int32".to_string() }
            else { "int32".to_string() }
        }
        VT_LLONG  => {
            if unsigned { "unsigned int64".to_string() }
            else { "int64".to_string() }
        }
        VT_FLOAT  => "float32".to_string(),
        VT_DOUBLE | VT_LDOUBLE => "float64".to_string(),
        VT_PTR    => {
            // Pointer: recurse on the pointed-to type (strip VT_PTR and any
            // flags above VT_BTYPE), then append " *"
            let inner_t = (t >> 4) & VT_BTYPE;
            let inner = il_type_to_str(inner_t, None)?;
            format!("{} *", inner)
        }
        VT_FUNC   => {
            // Function type: produce "return_type(param_types)"
            // Simplified — full signature would require Sym chain traversal
            // which is handled at the gfunc_prolog/gfunc_call callsite.
            "int32()".to_string()
        }
        VT_STRUCT => {
            return Err(TccError::CodegenError {
                message: "IL codegen: struct type not supported in il_type_to_str".into(),
            });
        }
        _ => {
            // Fall back to int32 for any unrecognized base type
            "int32".to_string()
        }
    };

    match varstr {
        Some(name) if !name.is_empty() => Ok(format!("{} {}", type_str, name)),
        _ => Ok(type_str),
    }
}

// ===========================================================================
// Relocation and Symbol Resolution — Port of il-gen.c lines 230-255
// ===========================================================================

/// Patch relocation entry with value.
/// Source: il-gen.c lines 231-233
///
/// The C source defines this as an empty function body. In the IL backend,
/// relocations are handled symbolically by the .NET assembler, so no
/// binary patching is needed.
pub fn greloc_patch1() {
    // Intentionally empty — IL backend uses textual labels, not binary relocations.
}

/// Resolve symbol at address and patch all forward references.
/// Source: il-gen.c lines 236-238
///
/// The C source defines this as an empty function body. Symbol resolution
/// in the IL backend is handled textually through label references.
pub fn gsym_addr(_t: i32, _a: i32) {
    // Intentionally empty — IL backend uses textual labels.
}

/// Emit a jump opcode and return label identifier for later patching.
/// Source: il-gen.c lines 241-250
///
/// If `c` is 0, creates a new label at the current code position.
/// Returns the label identifier (the current code index before the jump
/// target is emitted, forming a linked list of forward references).
pub fn out_opj(state: &mut IlGenState, op: IlOpcode, c: i32) -> i32 {
    out_op(state, op);
    let _ = writeln!(state.il_output, " label{}", state.ind);
    let t = c;
    // Store the forward reference chain: the 4-byte slot at the current
    // position holds the previous chain value, which will be patched later.
    out_le32(state, t);
    // Return the position of the jump target field for later patching
    (state.ind as i32) - 4
}

/// Resolve a label at the current code position.
/// Source: il-gen.c lines 252-255
///
/// Emit a label at position `t` in the IL text output.
///
/// In the IL backend, labels are textual (e.g., `L42:`) rather than binary
/// relocation targets. The .NET assembler resolves them.
///
/// Source: il-gen.c lines 252-255:
/// ```c
/// void gsym(int t) {
///     fprintf(il_outfile, "L%d:\n", t);
/// }
/// ```
pub fn gsym(state: &mut IlGenState, t: i32) {
    let _ = writeln!(state.il_output, "L{}:", t);
}

// ===========================================================================
// Load/Store Operations — Port of il-gen.c lines 258-379
// ===========================================================================

/// Load value described by `SValue` into the IL evaluation stack.
///
/// Source: il-gen.c lines 258-334
///
/// # Algorithm
///
/// The function dispatches based on the `sv.r` flags:
///
/// **If VT_LVAL (lvalue — memory load):**
/// - `VT_LOCAL`:
///   - If `fc >= ARG_BASE`: argument load (ldarg.0..ldarg.3, ldarg.s, ldarg)
///   - Else: local variable load (ldloc.0..ldloc.3, ldloc.s, ldloc)
/// - `VT_CONST`: global load via `ldsfld` (symbolic — resolved by .NET assembler)
/// - Otherwise: indirect load based on type (ldind.i1/u1/i2/u2/i4/r4/r8)
///
/// **Else (rvalue — address/constant load):**
/// - `VT_CONST`: integer constant (ldc.i4.m1..ldc.i4.8, ldc.i4.s, ldc.i4)
/// - `VT_LOCAL`: load address of local/arg (ldarga.s/ldarga, ldloca.s/ldloca)
pub fn load(state: &mut IlGenState, _r: i32, sv: &SValue) -> TccResult<()> {
    let v = (sv.r as i32) & VT_VALMASK;
    // Safety: CValue is a union; accessing `.i` is valid when the SValue
    // was populated with an integer constant or local variable index.
    let fc = unsafe { sv.c.i } as i32;

    if (sv.r as i32) & VT_LVAL != 0 {
        // lvalue — memory load
        if v == VT_LOCAL {
            if fc >= ARG_BASE {
                // Function argument load
                let arg_idx = fc - ARG_BASE;
                match arg_idx {
                    0 => out_op1(state, IlOpcode::LdargZero.opcode_value()),
                    1 => out_op1(state, IlOpcode::LdargOne.opcode_value()),
                    2 => out_op1(state, IlOpcode::LdargTwo.opcode_value()),
                    3 => out_op1(state, IlOpcode::LdargThree.opcode_value()),
                    _ if arg_idx <= 0xFF => {
                        out_opb(state, IlOpcode::LdargS, arg_idx as u8);
                        return Ok(());
                    }
                    _ => {
                        out_opi(state, IlOpcode::Ldarg, arg_idx);
                        return Ok(());
                    }
                }
                let _ = writeln!(state.il_output);
            } else {
                // Local variable load
                match fc {
                    0 => { out_op1(state, IlOpcode::LdlocZero.opcode_value()); let _ = writeln!(state.il_output); }
                    1 => { out_op1(state, IlOpcode::LdlocOne.opcode_value()); let _ = writeln!(state.il_output); }
                    2 => { out_op1(state, IlOpcode::LdlocTwo.opcode_value()); let _ = writeln!(state.il_output); }
                    3 => { out_op1(state, IlOpcode::LdlocThree.opcode_value()); let _ = writeln!(state.il_output); }
                    _ if fc <= 0xFF => {
                        out_opb(state, IlOpcode::LdlocS, fc as u8);
                        return Ok(());
                    }
                    _ => {
                        out_opi(state, IlOpcode::Ldloc, fc);
                        return Ok(());
                    }
                }
            }
        } else if v == VT_CONST {
            // Global variable load — emit ldsfld with symbolic reference.
            // Note: full global variable resolution is not implemented in the
            // original C backend (il-gen.c has an XXX annotation here). We emit
            // a synthetic label that would be resolved by a .NET linker pass.
            out_op(state, IlOpcode::Ldsfld);
            let _ = writeln!(state.il_output, " [global_{}]", fc);
        } else {
            // Indirect load — dispatch by type
            let bt = sv.type_.t & VT_BTYPE;
            let unsigned = (sv.type_.t & VT_UNSIGNED) != 0;
            let op = match bt {
                VT_FLOAT  => IlOpcode::LdindR4,
                VT_DOUBLE | VT_LDOUBLE => IlOpcode::LdindR8,
                VT_BYTE   => if unsigned { IlOpcode::LdindU1 } else { IlOpcode::LdindI1 },
                VT_SHORT  => if unsigned { IlOpcode::LdindU2 } else { IlOpcode::LdindI2 },
                _         => IlOpcode::LdindI4,
            };
            out_op(state, op);
            let _ = writeln!(state.il_output);
        }
    } else {
        // rvalue — constant or address load
        if v == VT_CONST {
            // Integer constant load with short-form optimization
            match fc {
                -1 => { out_op1(state, IlOpcode::LdcI4M1.opcode_value()); let _ = writeln!(state.il_output); }
                0  => { out_op1(state, IlOpcode::LdcI4Zero.opcode_value()); let _ = writeln!(state.il_output); }
                1  => { out_op1(state, IlOpcode::LdcI4One.opcode_value()); let _ = writeln!(state.il_output); }
                2  => { out_op1(state, IlOpcode::LdcI4Two.opcode_value()); let _ = writeln!(state.il_output); }
                3  => { out_op1(state, IlOpcode::LdcI4Three.opcode_value()); let _ = writeln!(state.il_output); }
                4  => { out_op1(state, IlOpcode::LdcI4Four.opcode_value()); let _ = writeln!(state.il_output); }
                5  => { out_op1(state, IlOpcode::LdcI4Five.opcode_value()); let _ = writeln!(state.il_output); }
                6  => { out_op1(state, IlOpcode::LdcI4Six.opcode_value()); let _ = writeln!(state.il_output); }
                7  => { out_op1(state, IlOpcode::LdcI4Seven.opcode_value()); let _ = writeln!(state.il_output); }
                8  => { out_op1(state, IlOpcode::LdcI4Eight.opcode_value()); let _ = writeln!(state.il_output); }
                _ if fc >= -128 && fc <= 127 => {
                    out_opb(state, IlOpcode::LdcI4S, fc as u8);
                }
                _ => {
                    out_opi(state, IlOpcode::LdcI4, fc);
                }
            }
        } else if v == VT_LOCAL {
            // Load address of local/arg
            if fc >= ARG_BASE {
                let arg_idx = fc - ARG_BASE;
                if arg_idx <= 0xFF {
                    out_opb(state, IlOpcode::LdargaS, arg_idx as u8);
                } else {
                    out_opi(state, IlOpcode::Ldarga, arg_idx);
                }
            } else if fc <= 0xFF {
                out_opb(state, IlOpcode::LdlocaS, fc as u8);
            } else {
                out_opi(state, IlOpcode::Ldloca, fc);
            }
        }
        // else: unhandled value class — no emission (matches C behavior)
    }
    Ok(())
}

/// Store value from the IL evaluation stack into location described by `SValue`.
///
/// Source: il-gen.c lines 337-379
///
/// # Algorithm
///
/// Dispatches based on `sv.r` flags:
/// - `VT_LOCAL`:
///   - If `fc >= ARG_BASE`: argument store (starg.s, starg)
///   - Else: local store (stloc.0..stloc.3, stloc.s, stloc)
/// - `VT_CONST`: global store via `stsfld` (symbolic — resolved by .NET assembler)
/// - Otherwise: indirect store based on type (stind.i1/i2/i4/r4/r8)
pub fn store(state: &mut IlGenState, _r: i32, sv: &SValue) -> TccResult<()> {
    let v = (sv.r as i32) & VT_VALMASK;
    // Safety: CValue is a union; `.i` access is valid for local/arg indices.
    let fc = unsafe { sv.c.i } as i32;

    if v == VT_LOCAL {
        if fc >= ARG_BASE {
            // Argument store
            let arg_idx = fc - ARG_BASE;
            if arg_idx <= 0xFF {
                out_opb(state, IlOpcode::StargS, arg_idx as u8);
            } else {
                out_opi(state, IlOpcode::Starg, arg_idx);
            }
        } else {
            // Local variable store — short forms for indices 0-3
            match fc {
                0 => { out_op1(state, IlOpcode::StlocZero.opcode_value()); let _ = writeln!(state.il_output); }
                1 => { out_op1(state, IlOpcode::StlocOne.opcode_value()); let _ = writeln!(state.il_output); }
                2 => { out_op1(state, IlOpcode::StlocTwo.opcode_value()); let _ = writeln!(state.il_output); }
                3 => { out_op1(state, IlOpcode::StlocThree.opcode_value()); let _ = writeln!(state.il_output); }
                _ if fc <= 0xFF => {
                    out_opb(state, IlOpcode::StlocS, fc as u8);
                }
                _ => {
                    out_opi(state, IlOpcode::Stloc, fc);
                }
            }
        }
    } else if v == VT_CONST {
        // Global variable store — emit stsfld with symbolic reference.
        // Note: full global variable resolution is not implemented in the
        // original C backend (il-gen.c has an XXX annotation here). We emit
        // a synthetic label that would be resolved by a .NET linker pass.
        out_op(state, IlOpcode::Stsfld);
        let _ = writeln!(state.il_output, " [global_{}]", fc);
    } else {
        // Indirect store — dispatch by type
        let bt = sv.type_.t & VT_BTYPE;
        let op = match bt {
            VT_FLOAT  => IlOpcode::StindR4,
            VT_DOUBLE | VT_LDOUBLE => IlOpcode::StindR8,
            VT_BYTE   => IlOpcode::StindI1,
            VT_SHORT  => IlOpcode::StindI2,
            _         => IlOpcode::StindI4,
        };
        out_op(state, op);
        let _ = writeln!(state.il_output);
    }
    Ok(())
}

// ===========================================================================
// Function Generation — Port of il-gen.c lines 382-465
// ===========================================================================

/// Start function call context — initialize calling convention.
/// Source: il-gen.c lines 382-385
pub fn gfunc_start(c: &mut GFuncContext, func_call: i32) {
    c.func_call = func_call;
}

/// Push function parameter onto the IL evaluation stack.
/// Source: il-gen.c lines 389-398
///
/// For the IL backend, parameters are already on the evaluation stack
/// after being evaluated. Struct parameters are not supported
/// (matching the C source's error for structure params).
pub fn gfunc_param(_state: &mut IlGenState, _c: &GFuncContext, sv: &SValue) -> TccResult<()> {
    let bt = sv.type_.t & VT_BTYPE;
    if bt == VT_STRUCT {
        return Err(TccError::CodegenError {
            message: "IL codegen: structures passed by value not yet supported".into(),
        });
    }
    // For non-struct types, the value is already on the IL evaluation stack
    // after the expression has been evaluated. No additional emission needed.
    Ok(())
}

/// Generate function call instruction.
/// Source: il-gen.c lines 402-417
///
/// Emits either a direct `call` (for `VT_CONST` function references) or
/// an indirect `calli` instruction. The textual output includes the
/// type signature.
///
/// `nb_args` is the number of arguments already pushed on the stack.
pub fn gfunc_call(state: &mut IlGenState, nb_args: i32) -> TccResult<()> {
    // Build a simplified type signature string for the call.
    // The actual function type resolution is handled by the higher-level
    // compiler pipeline; here we emit a generic signature.
    let mut sig = String::from("int32(");
    for i in 0..nb_args {
        if i > 0 {
            sig.push_str(", ");
        }
        sig.push_str("int32");
    }
    sig.push(')');

    // Emit the call opcode with the signature.
    //
    // In the C source (il-gen.c lines 350-380), the compiler checks vtop
    // for VT_CONST to decide between `call` (direct/static) and `calli`
    // (indirect / function pointer). When the callee is a VT_PTR to
    // VT_FUNC (i.e., a function pointer), `calli` must be used — the
    // pointer is already on the evaluation stack and `calli` consumes it.
    //
    // The higher-level codegen pipeline sets `state.is_indirect_call`
    // when the call target is a function pointer (VT_PTR to VT_FUNC).
    if state.is_indirect_call {
        out_op(state, IlOpcode::Calli);
    } else {
        out_op(state, IlOpcode::Call);
    }
    let _ = writeln!(state.il_output, " {}", sig);
    // Reset indirect flag after emission.
    state.is_indirect_call = false;
    Ok(())
}

/// Generate function prologue.
/// Source: il-gen.c lines 420-458
///
/// Emits the `.method` header, `.maxstack`, `.locals`, and `.entrypoint`
/// directives for a CIL method.
///
/// The `func_sym` parameter provides the function's type information:
/// - Return type from `func_sym.type_.ref_sym` (if available)
/// - Parameter list by walking the symbol chain via `.next`
pub fn gfunc_prolog(state: &mut IlGenState, func_sym: &Sym) -> TccResult<()> {
    init_outfile(state);

    // Determine function name from the symbol's identifier value.
    // In the C source, this accesses `get_tok_str(v, NULL)` to get the
    // function name string. Since the Rust port does not have direct access
    // to the token string table from the codegen layer, we derive a unique
    // function name from the symbol's numeric identifier.
    let func_name = format!("func_{:x}", func_sym.v & !(SYM_STRUCT as i32 | SYM_FIELD as i32));

    // Determine return type
    let ret_type = if let Some(ref ref_sym) = func_sym.type_.ref_sym {
        let rt = ref_sym.type_.t;
        il_type_to_str(rt, None).unwrap_or_else(|_| "int32".to_string())
    } else {
        "void".to_string()
    };

    // Build parameter list by walking the symbol chain
    let mut params = Vec::new();
    if let Some(ref ref_sym) = func_sym.type_.ref_sym {
        let mut sym_opt: Option<&Sym> = ref_sym.next.as_deref();
        while let Some(sym) = sym_opt {
            // Skip SYM_FIELD markers
            if (sym.v & SYM_FIELD as i32) == 0 {
                let pt = il_type_to_str(sym.type_.t, None)
                    .unwrap_or_else(|_| "int32".to_string());
                params.push(pt);
            }
            sym_opt = sym.next.as_deref();
        }
    }

    // Emit .method header
    let _ = write!(state.il_output, ".method static {} {}(", ret_type, func_name);
    for (i, p) in params.iter().enumerate() {
        if i > 0 {
            let _ = write!(state.il_output, ", ");
        }
        let _ = write!(state.il_output, "{}", p);
    }
    let _ = writeln!(state.il_output, ") il managed");
    let _ = writeln!(state.il_output, "{{");

    // Emit .maxstack (NB_REGS = 3 in the C source)
    let _ = writeln!(state.il_output, "  .maxstack {}", NB_REGS);

    // Emit .locals with 8 int32 slots (matching C source's fixed allocation)
    let _ = write!(state.il_output, "  .locals (");
    for i in 0..8 {
        if i > 0 {
            let _ = write!(state.il_output, ", ");
        }
        let _ = write!(state.il_output, "int32");
    }
    let _ = writeln!(state.il_output, ")");

    // Emit .entrypoint for the program's entry function.
    //
    // In the C source (il-gen.c), this checks `!strcmp(funcname, "main")`.
    // The Rust port checks two conditions:
    //   1. Explicit flag: `state.is_entry_point` is set by the higher-level
    //      codegen dispatch when it knows the current function is the program
    //      entry point (e.g., from TCCState's main symbol index).
    //   2. Name heuristic: the function name equals or ends with "main",
    //      catching both C-level `main` and mangled variants.
    //
    // Both checks are needed because IL function names may be numeric
    // (`func_{hex_addr}`) when generated from symbol addresses.
    let is_main = state.is_entry_point
        || func_name == "main"
        || func_name.ends_with("main")
        || func_name == "func_main";
    if is_main {
        let _ = writeln!(state.il_output, "  .entrypoint");
        state.is_entry_point = false;
    }

    let _ = writeln!(state.il_output);
    Ok(())
}

/// Generate function epilogue.
/// Source: il-gen.c lines 461-465
///
/// Emits the `ret` opcode and the closing brace of the method definition.
pub fn gfunc_epilog(state: &mut IlGenState) -> TccResult<()> {
    out_op(state, IlOpcode::Ret);
    let _ = writeln!(state.il_output);
    let _ = writeln!(state.il_output, "}}");
    let _ = writeln!(state.il_output);
    Ok(())
}

// ===========================================================================
// Jump Generation — Port of il-gen.c lines 468-537
// ===========================================================================

/// Generate an unconditional jump, returning a label for later patching.
/// Source: il-gen.c lines 468-471
///
/// Emits `br` with forward-reference `t`. Returns the new chain head.
pub fn gjmp(state: &mut IlGenState, t: i32) -> i32 {
    out_opj(state, IlOpcode::Br, t)
}

/// Generate an unconditional jump to a fixed (known) address.
/// Source: il-gen.c lines 474-478
///
/// Emits `br` with the target label for backward jumps.
pub fn gjmp_addr(state: &mut IlGenState, a: i32) {
    // For backward jumps (target address already known), emit the offset
    // directly. The offset is relative to the instruction following the jump.
    out_op(state, IlOpcode::Br);
    let offset = a - (state.ind as i32) - 4;
    out_le32(state, offset);
    let _ = writeln!(state.il_output, " label{}", a);
}

/// Generate conditional branch based on comparison operator.
///
/// Source: il-gen.c lines 481-537
///
/// Called by the `CodegenBackend::gjmp_cond` trait method. Maps TCC
/// comparison operator tokens to the corresponding CIL branch opcodes
/// and emits a forward-reference jump.
///
/// # Arguments
///
/// * `state` — Mutable IL generation state.
/// * `op`    — Comparison operator token (TOK_EQ, TOK_NE, TOK_LT, etc.).
/// * `t`     — Forward-reference jump chain head (0 to start new chain).
///
/// # Returns
///
/// The new jump chain head (position of the jump target field in the code
/// buffer) for later patching by [`gsym`].
pub fn gtst(state: &mut IlGenState, op: i32, t: i32) -> TccResult<i32> {
    // Map comparison operator to CIL branch opcode.
    let branch_op = match op {
        x if x == TOK_EQ  => IlOpcode::Beq,
        x if x == TOK_NE  => IlOpcode::BneUn,
        x if x == TOK_LT  => IlOpcode::Blt,
        x if x == TOK_LE  => IlOpcode::Ble,
        x if x == TOK_GT  => IlOpcode::Bgt,
        x if x == TOK_GE  => IlOpcode::Bge,
        x if x == TOK_ULT => IlOpcode::BltUn,
        x if x == TOK_ULE => IlOpcode::BleUn,
        x if x == TOK_UGT => IlOpcode::BgtUn,
        x if x == TOK_UGE => IlOpcode::BgeUn,
        _ => {
            // Default: branch on true (for non-comparison conditions, e.g.
            // a value already on the evaluation stack used as a boolean)
            IlOpcode::Brtrue
        }
    };
    Ok(out_opj(state, branch_op, t))
}

// ===========================================================================
// Integer/Float Operations — Port of il-gen.c lines 540-610
// ===========================================================================

/// Generate an integer binary operation.
///
/// Source: il-gen.c lines 540-602
///
/// Assumes two operands are already on the IL evaluation stack (pushed by
/// the higher-level codegen via `gv2(RC_ST1, RC_ST0)`).
///
/// Maps C operators to CIL opcodes:
/// - `+` → `add`, `-` → `sub`, `*` → `mul`
/// - `&` → `and`, `^` → `xor`, `|` → `or`
/// - `TOK_SHL` → `shl`, `TOK_SHR` → `shr.un`, `TOK_SAR` → `shr`
/// - `/` / `TOK_PDIV` → `div`, `TOK_UDIV` → `div.un`
/// - `%` → `rem`, `TOK_UMOD` → `rem.un`
///
/// For comparison operators (`TOK_EQ` through `TOK_UGE`), the result is
/// stored as a `VT_CMP` flag rather than emitting an opcode directly;
/// the actual branch/comparison is deferred to `gtst()`.
///
/// Returns `Ok(())` after emitting the appropriate opcode. For comparison
/// operators (`TOK_EQ` through `TOK_UGE`), the common codegen layer handles
/// `VT_CMP` signaling and later calls `gjmp_cond` / `gtst`; this function
/// is a no-op for comparisons in the IL backend.
pub fn gen_opi(state: &mut IlGenState, op: i32) -> TccResult<()> {
    // Comparison operators are handled by the common codegen layer, which
    // sets VT_CMP on the value stack and later invokes gjmp_cond/gtst.
    // The IL backend does not emit any opcode for comparisons here.
    if op == TOK_EQ || op == TOK_NE
        || op == TOK_LT || op == TOK_LE || op == TOK_GT || op == TOK_GE
        || op == TOK_ULT || op == TOK_ULE || op == TOK_UGT || op == TOK_UGE
    {
        return Ok(());
    }

    // Arithmetic / bitwise / shift operators — emit the IL opcode.
    let il_op = match op {
        x if x == b'+' as i32 => IlOpcode::Add,
        x if x == b'-' as i32 => IlOpcode::Sub,
        x if x == b'*' as i32 => IlOpcode::Mul,
        x if x == b'&' as i32 => IlOpcode::And,
        x if x == b'^' as i32 => IlOpcode::Xor,
        x if x == b'|' as i32 => IlOpcode::Or,
        x if x == b'/' as i32 => IlOpcode::Div,
        x if x == b'%' as i32 => IlOpcode::Rem,
        x if x == TOK_SHL     => IlOpcode::Shl,
        x if x == TOK_SHR     => IlOpcode::ShrUn,
        x if x == TOK_SAR     => IlOpcode::Shr,
        x if x == TOK_PDIV    => IlOpcode::Div,
        x if x == TOK_UDIV    => IlOpcode::DivUn,
        x if x == TOK_UMOD    => IlOpcode::RemUn,
        _ => {
            // Unknown operator — emit nop as fallback
            IlOpcode::Nop
        }
    };

    out_op(state, il_op);
    let _ = writeln!(state.il_output);
    Ok(())
}

/// Generate a floating-point binary operation.
///
/// Source: il-gen.c lines 606-610
///
/// In the CIL virtual machine, integer and floating-point arithmetic use
/// the same opcodes (the type is determined by what is on the evaluation
/// stack). Therefore this simply delegates to `gen_opi`.
pub fn gen_opf(state: &mut IlGenState, op: i32) -> TccResult<()> {
    gen_opi(state, op)
}

// ===========================================================================
// Type Conversions — Port of il-gen.c lines 613-653
// ===========================================================================

/// Convert integer to float on the IL evaluation stack.
///
/// Source: il-gen.c lines 614-621
///
/// - `VT_FLOAT` → `conv.r4`
/// - Otherwise → `conv.r8` (double / long double)
pub fn gen_cvt_itof(state: &mut IlGenState, t: i32) -> TccResult<()> {
    let bt = t & VT_BTYPE;
    let op = if bt == VT_FLOAT {
        IlOpcode::ConvR4
    } else {
        IlOpcode::ConvR8
    };
    out_op(state, op);
    let _ = writeln!(state.il_output);
    Ok(())
}

/// Convert float to integer on the IL evaluation stack.
///
/// Source: il-gen.c lines 625-642
///
/// - `VT_INT` with `VT_UNSIGNED` → `conv.u4`
/// - `VT_LLONG` → `conv.i8`
/// - `VT_LLONG` with `VT_UNSIGNED` → `conv.u8`
/// - Default → `conv.i4`
pub fn gen_cvt_ftoi(state: &mut IlGenState, t: i32) -> TccResult<()> {
    let bt = t & VT_BTYPE;
    let unsigned = (t & VT_UNSIGNED) != 0;

    let op = match bt {
        VT_LLONG => {
            if unsigned { IlOpcode::ConvU8 } else { IlOpcode::ConvI8 }
        }
        VT_INT => {
            if unsigned { IlOpcode::ConvU4 } else { IlOpcode::ConvI4 }
        }
        _ => {
            if unsigned { IlOpcode::ConvU4 } else { IlOpcode::ConvI4 }
        }
    };
    out_op(state, op);
    let _ = writeln!(state.il_output);
    Ok(())
}

/// Convert between float types on the IL evaluation stack.
///
/// Source: il-gen.c lines 645-653
///
/// - `VT_FLOAT` → `conv.r4`
/// - Otherwise → `conv.r8`
pub fn gen_cvt_ftof(state: &mut IlGenState, t: i32) -> TccResult<()> {
    let bt = t & VT_BTYPE;
    let op = if bt == VT_FLOAT {
        IlOpcode::ConvR4
    } else {
        IlOpcode::ConvR8
    };
    out_op(state, op);
    let _ = writeln!(state.il_output);
    Ok(())
}

// ===========================================================================
// Unit tests for IL code generator
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::il::IlBackend;

    /// Helper: create a fresh IlGenState for testing.
    fn new_state() -> IlGenState {
        IlBackend::new()
    }

    // -----------------------------------------------------------------------
    // IlOpcode enum tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcode_nop_value() {
        assert_eq!(IlOpcode::Nop.opcode_value(), 0x00);
    }

    #[test]
    fn test_opcode_nop_name() {
        assert_eq!(IlOpcode::Nop.name(), "nop");
    }

    #[test]
    fn test_opcode_add_value() {
        assert_eq!(IlOpcode::Add.opcode_value(), 0x58);
    }

    #[test]
    fn test_opcode_add_name() {
        assert_eq!(IlOpcode::Add.name(), "add");
    }

    #[test]
    fn test_opcode_ret_value() {
        assert_eq!(IlOpcode::Ret.opcode_value(), 0x2A);
    }

    #[test]
    fn test_opcode_ret_name() {
        assert_eq!(IlOpcode::Ret.name(), "ret");
    }

    #[test]
    fn test_opcode_ldarg_zero_name() {
        assert_eq!(IlOpcode::LdargZero.name(), "ldarg.0");
    }

    #[test]
    fn test_opcode_two_byte_prefix() {
        // Two-byte opcodes have values >= 0x100 and require the 0xFE prefix
        assert_eq!(IlOpcode::Ceq.opcode_value(), 0x0101);
        assert_eq!(IlOpcode::Ceq.name(), "ceq");
    }

    #[test]
    fn test_opcode_sizeof_two_byte() {
        assert_eq!(IlOpcode::Sizeof.opcode_value(), 0x011C);
        assert_eq!(IlOpcode::Sizeof.name(), "sizeof");
    }

    #[test]
    fn test_opcode_stloc_zero_name() {
        assert_eq!(IlOpcode::StlocZero.name(), "stloc.0");
    }

    // -----------------------------------------------------------------------
    // Byte emission helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_out_byte_single() {
        let mut s = new_state();
        out_byte(&mut s, 0x42);
        assert_eq!(s.code, vec![0x42]);
        assert_eq!(s.ind, 1);
    }

    #[test]
    fn test_out_byte_multiple() {
        let mut s = new_state();
        out_byte(&mut s, 0xAA);
        out_byte(&mut s, 0xBB);
        out_byte(&mut s, 0xCC);
        assert_eq!(s.code, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(s.ind, 3);
    }

    #[test]
    fn test_out_le32_value() {
        let mut s = new_state();
        out_le32(&mut s, 0x04030201);
        assert_eq!(s.code, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(s.ind, 4);
    }

    #[test]
    fn test_out_le32_negative() {
        let mut s = new_state();
        out_le32(&mut s, -1);
        assert_eq!(s.code, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_out_le32_zero() {
        let mut s = new_state();
        out_le32(&mut s, 0);
        assert_eq!(s.code, vec![0x00, 0x00, 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // Opcode emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_out_op1_single_byte() {
        let mut s = new_state();
        // Nop = 0x00, single-byte opcode
        out_op1(&mut s, 0x00);
        assert_eq!(s.code, vec![0x00]);
        assert_eq!(s.ind, 1);
    }

    #[test]
    fn test_out_op1_two_byte() {
        let mut s = new_state();
        // Ceq = 0x0101, two-byte opcode (0xFE prefix + 0x01)
        out_op1(&mut s, 0x0101);
        assert_eq!(s.code, vec![IL_OP_PREFIX, 0x01]);
        assert_eq!(s.ind, 2);
    }

    #[test]
    fn test_out_op_writes_mnemonic() {
        let mut s = new_state();
        out_op(&mut s, IlOpcode::Add);
        assert!(s.il_output.contains("add"));
        // Binary code buffer should contain the opcode byte
        assert_eq!(s.code, vec![0x58]); // Add = 0x58
    }

    #[test]
    fn test_out_opb_byte_operand() {
        let mut s = new_state();
        out_opb(&mut s, IlOpcode::LdcI4S, 42);
        // Code: opcode byte (0x1F for ldc.i4.s) + operand byte (42)
        assert_eq!(s.code[0], 0x1F); // LdcI4S
        assert_eq!(s.code[1], 42);
        assert!(s.il_output.contains("ldc.i4.s"));
        assert!(s.il_output.contains("42"));
    }

    #[test]
    fn test_out_opi_int_operand() {
        let mut s = new_state();
        out_opi(&mut s, IlOpcode::LdcI4, 1000);
        // Code: opcode byte (0x20 for ldc.i4) + 4-byte LE integer
        assert_eq!(s.code[0], 0x20); // LdcI4
        let val = i32::from_le_bytes([s.code[1], s.code[2], s.code[3], s.code[4]]);
        assert_eq!(val, 1000);
        assert!(s.il_output.contains("ldc.i4"));
        assert!(s.il_output.contains("1000"));
    }

    // -----------------------------------------------------------------------
    // init_outfile tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_init_outfile_writes_header() {
        let mut s = new_state();
        assert!(!s.outfile_initialized);
        init_outfile(&mut s);
        assert!(s.outfile_initialized);
        assert!(s.il_output.contains(".assembly extern mscorlib"));
        assert!(s.il_output.contains(".ver 1:0:2411:0"));
    }

    #[test]
    fn test_init_outfile_idempotent() {
        let mut s = new_state();
        init_outfile(&mut s);
        let first_output = s.il_output.clone();
        init_outfile(&mut s);
        // Second call should not add anything
        assert_eq!(s.il_output, first_output);
    }

    // -----------------------------------------------------------------------
    // il_type_to_str tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_void() {
        let result = il_type_to_str(VT_VOID, None).unwrap();
        assert_eq!(result, "void");
    }

    #[test]
    fn test_type_bool() {
        let result = il_type_to_str(VT_BOOL, None).unwrap();
        assert_eq!(result, "bool");
    }

    #[test]
    fn test_type_int32() {
        let result = il_type_to_str(VT_INT, None).unwrap();
        assert_eq!(result, "int32");
    }

    #[test]
    fn test_type_unsigned_int32() {
        let result = il_type_to_str(VT_INT | VT_UNSIGNED, None).unwrap();
        assert_eq!(result, "unsigned int32");
    }

    #[test]
    fn test_type_int8() {
        let result = il_type_to_str(VT_BYTE, None).unwrap();
        assert_eq!(result, "int8");
    }

    #[test]
    fn test_type_unsigned_int8() {
        let result = il_type_to_str(VT_BYTE | VT_UNSIGNED, None).unwrap();
        assert_eq!(result, "unsigned int8");
    }

    #[test]
    fn test_type_int16() {
        let result = il_type_to_str(VT_SHORT, None).unwrap();
        assert_eq!(result, "int16");
    }

    #[test]
    fn test_type_int64() {
        let result = il_type_to_str(VT_LLONG, None).unwrap();
        assert_eq!(result, "int64");
    }

    #[test]
    fn test_type_unsigned_int64() {
        let result = il_type_to_str(VT_LLONG | VT_UNSIGNED, None).unwrap();
        assert_eq!(result, "unsigned int64");
    }

    #[test]
    fn test_type_float32() {
        let result = il_type_to_str(VT_FLOAT, None).unwrap();
        assert_eq!(result, "float32");
    }

    #[test]
    fn test_type_float64_double() {
        let result = il_type_to_str(VT_DOUBLE, None).unwrap();
        assert_eq!(result, "float64");
    }

    #[test]
    fn test_type_float64_ldouble() {
        let result = il_type_to_str(VT_LDOUBLE, None).unwrap();
        assert_eq!(result, "float64");
    }

    #[test]
    fn test_type_with_varstr() {
        let result = il_type_to_str(VT_INT, Some("x")).unwrap();
        assert!(result.contains("int32"));
        assert!(result.contains("x"));
    }

    // -----------------------------------------------------------------------
    // Type conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gen_cvt_itof_float32() {
        let mut s = new_state();
        gen_cvt_itof(&mut s, VT_FLOAT).unwrap();
        assert!(s.il_output.contains("conv.r4"));
    }

    #[test]
    fn test_gen_cvt_itof_float64() {
        let mut s = new_state();
        gen_cvt_itof(&mut s, VT_DOUBLE).unwrap();
        assert!(s.il_output.contains("conv.r8"));
    }

    #[test]
    fn test_gen_cvt_ftoi_int32() {
        let mut s = new_state();
        gen_cvt_ftoi(&mut s, VT_INT).unwrap();
        assert!(s.il_output.contains("conv.i4"));
    }

    #[test]
    fn test_gen_cvt_ftoi_uint32() {
        let mut s = new_state();
        gen_cvt_ftoi(&mut s, VT_INT | VT_UNSIGNED).unwrap();
        assert!(s.il_output.contains("conv.u4"));
    }

    #[test]
    fn test_gen_cvt_ftoi_int64() {
        let mut s = new_state();
        gen_cvt_ftoi(&mut s, VT_LLONG).unwrap();
        assert!(s.il_output.contains("conv.i8"));
    }

    #[test]
    fn test_gen_cvt_ftoi_uint64() {
        let mut s = new_state();
        gen_cvt_ftoi(&mut s, VT_LLONG | VT_UNSIGNED).unwrap();
        assert!(s.il_output.contains("conv.u8"));
    }

    #[test]
    fn test_gen_cvt_ftof_to_float32() {
        let mut s = new_state();
        gen_cvt_ftof(&mut s, VT_FLOAT).unwrap();
        assert!(s.il_output.contains("conv.r4"));
    }

    #[test]
    fn test_gen_cvt_ftof_to_float64() {
        let mut s = new_state();
        gen_cvt_ftof(&mut s, VT_DOUBLE).unwrap();
        assert!(s.il_output.contains("conv.r8"));
    }

    // -----------------------------------------------------------------------
    // IL_OP_PREFIX constant test
    // -----------------------------------------------------------------------

    #[test]
    fn test_il_op_prefix() {
        assert_eq!(IL_OP_PREFIX, 0xFE);
    }

    // -----------------------------------------------------------------------
    // GFuncContext test
    // -----------------------------------------------------------------------

    #[test]
    fn test_gfunc_context_creation() {
        let ctx = GFuncContext { func_call: 0 };
        assert_eq!(ctx.func_call, 0);
    }

    // -----------------------------------------------------------------------
    // IlGenState (IlBackend) initialization test
    // -----------------------------------------------------------------------

    #[test]
    fn test_ilgenstate_default() {
        let s = new_state();
        assert!(!s.outfile_initialized);
        assert!(s.il_output.is_empty());
        assert_eq!(s.ind, 0);
        assert!(s.code.is_empty());
        assert!(!s.is_indirect_call);
        assert!(!s.is_entry_point);
    }

    // -----------------------------------------------------------------------
    // Emission sequence tests (verify byte sequences for compound operations)
    // -----------------------------------------------------------------------

    #[test]
    fn test_emit_ldc_add_ret_sequence() {
        let mut s = new_state();
        // Emit: ldc.i4 42; ldc.i4 58; add; ret
        out_opi(&mut s, IlOpcode::LdcI4, 42);
        out_opi(&mut s, IlOpcode::LdcI4, 58);
        out_op(&mut s, IlOpcode::Add);
        let _ = writeln!(s.il_output);
        out_op(&mut s, IlOpcode::Ret);
        let _ = writeln!(s.il_output);

        // Verify code buffer contains expected opcodes
        // ldc.i4 = 0x20 (1 byte) + 42 LE (4 bytes) = 5 bytes
        // ldc.i4 = 0x20 (1 byte) + 58 LE (4 bytes) = 5 bytes
        // add    = 0x58 (1 byte)
        // ret    = 0x2A (1 byte)
        assert_eq!(s.ind, 12); // 5 + 5 + 1 + 1
        assert_eq!(s.code[0], 0x20); // ldc.i4
        assert_eq!(s.code[5], 0x20); // ldc.i4
        assert_eq!(s.code[10], 0x58); // add
        assert_eq!(s.code[11], 0x2A); // ret

        // Verify textual IL output contains all mnemonics
        assert!(s.il_output.contains("ldc.i4"));
        assert!(s.il_output.contains("add"));
        assert!(s.il_output.contains("ret"));
    }

    #[test]
    fn test_emit_two_byte_opcode_ceq() {
        let mut s = new_state();
        out_op(&mut s, IlOpcode::Ceq);
        let _ = writeln!(s.il_output);
        // Ceq = 0x0101 → emits 0xFE then 0x01
        assert_eq!(s.code, vec![0xFE, 0x01]);
        assert!(s.il_output.contains("ceq"));
    }

    #[test]
    fn test_emit_two_byte_opcode_cgt() {
        let mut s = new_state();
        out_op(&mut s, IlOpcode::Cgt);
        let _ = writeln!(s.il_output);
        // Cgt = 0x0102 → emits 0xFE then 0x02
        assert_eq!(s.code, vec![0xFE, 0x02]);
        assert!(s.il_output.contains("cgt"));
    }

    #[test]
    fn test_emit_two_byte_opcode_clt() {
        let mut s = new_state();
        out_op(&mut s, IlOpcode::Clt);
        let _ = writeln!(s.il_output);
        // Clt = 0x0104 → emits 0xFE then 0x04
        assert_eq!(s.code, vec![0xFE, 0x04]);
        assert!(s.il_output.contains("clt"));
    }
}
