// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tcctok.h and tcc.h to Rust as part of the TCC C-to-Rust migration.
//
// Allow non-upper-case constant names to preserve C naming convention
// compatibility (e.g., TOK___fixsfdi matches C's TOK___fixsfdi exactly).
#![allow(non_upper_case_globals)]
//
//! Token definitions and keyword tables for the TCC compiler.
//!
//! This module defines the complete token set used by the lexer, preprocessor,
//! and parser, including C keywords, operators, built-in identifiers, GCC
//! extensions, assembler directives, and atomic operations.
//!
//! Ported from:
//! - `tcctok.h` (430 lines) — Token definitions via `DEF()` macro
//! - `tcc.h` — Token-related constants (`TOK_HASH_SIZE`, operator codes, etc.)
//!
//! # Design Decisions
//!
//! - **Rust enum**: Type-safe token representation instead of C integer constants.
//! - **HashMap keyword lookup**: O(1) lookup instead of linear search (OPT-02).
//! - **GCC alternative keywords**: `__const`, `__volatile__`, `__inline__` etc.
//!   map to the same canonical tokens as their standard C counterparts.
//! - **FEAT-02**: `__builtin_expect` token included.
//! - **FEAT-04**: `_Complex` keyword included for C99 complex type support.

use std::collections::HashMap;

use crate::types::TokenSym;

// ===========================================================================
// Token Enum
// ===========================================================================

/// Complete set of tokens recognized by the TCC compiler.
///
/// This enum covers:
/// - C language keywords (C89/C99/C11)
/// - GCC extension keywords and builtins
/// - Operators and punctuation
/// - Assignment operators
/// - Literal/value token categories
/// - Preprocessor-specific tokens
/// - Special internal tokens
///
/// The `#[repr(i32)]` attribute ensures layout compatibility with the original
/// C `enum tcc_token` (tcc.h lines 1198-1203).
///
/// # Variant Naming Convention
/// Variants use PascalCase for keywords (e.g., `If`, `Else`, `While`) and
/// operator names (e.g., `Arrow`, `Inc`, `Shl`). GCC alternative spellings
/// (`__const`, `__const__`) are mapped to the same canonical variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Token {
    // =======================================================================
    // C Keywords (tcctok.h lines 2-69)
    // =======================================================================

    // --- Control Flow ---
    /// `if` keyword
    If = 256,       // TOK_IDENT = 256; first keyword follows
    /// `else` keyword
    Else,
    /// `while` keyword
    While,
    /// `for` keyword
    For,
    /// `do` keyword
    Do,
    /// `continue` keyword
    Continue,
    /// `break` keyword
    Break,
    /// `return` keyword
    Return,
    /// `goto` keyword
    Goto,
    /// `switch` keyword
    Switch,
    /// `case` keyword
    Case,
    /// `default` keyword
    Default,
    /// `asm` / `__asm` / `__asm__` keyword
    Asm,

    // --- Storage Class and Qualifiers ---
    /// `extern` storage class specifier
    Extern,
    /// `static` storage class specifier
    Static,
    /// `unsigned` type specifier
    Unsigned,
    /// `_Atomic` qualifier (C11)
    Atomic,
    /// `const` / `__const` / `__const__` qualifier
    Const,
    /// `volatile` / `__volatile` / `__volatile__` qualifier
    Volatile,
    /// `register` storage class specifier
    Register,
    /// `signed` / `__signed` / `__signed__` specifier
    Signed,
    /// `auto` storage class specifier
    Auto,
    /// `inline` / `__inline` / `__inline__` specifier
    Inline,
    /// `restrict` / `__restrict` / `__restrict__` qualifier
    Restrict,
    /// `__extension__` (GCC extension marker)
    Extension,
    /// `_Thread_local` (C11 thread-local storage)
    ThreadLocal,
    /// `_Generic` (C11 generic selection)
    Generic,
    /// `_Static_assert` (C11 static assertion)
    StaticAssert,

    // --- Type Keywords ---
    /// `void` type
    Void,
    /// `char` type
    Char,
    /// `int` type
    Int,
    /// `float` type
    Float,
    /// `double` type
    Double,
    /// `_Bool` type (C99)
    Bool,
    /// `_Complex` type (C99, FEAT-04)
    Complex,
    /// `short` type
    Short,
    /// `long` type modifier
    Long,
    /// `struct` keyword
    Struct,
    /// `union` keyword
    Union,
    /// `typedef` keyword
    Typedef,
    /// `enum` keyword
    Enum,
    /// `sizeof` operator
    Sizeof,

    // --- Attribute and Type-Query Keywords ---
    /// `__attribute` / `__attribute__`
    Attribute,
    /// `_Alignof` / `__alignof` / `__alignof__`
    Alignof,
    /// `_Alignas` (C11 alignment specifier)
    Alignas,
    /// `typeof` / `__typeof` / `__typeof__`
    Typeof,
    /// `__label__` (GCC local label declaration)
    Label,
    /// `__declspec` (MSVC attribute)
    Declspec,
    /// `_Noreturn` / `noreturn` / `__noreturn__` (C11)
    Noreturn,

    // =======================================================================
    // Preprocessor Identifiers (tcctok.h lines 74-95)
    // Not keywords per se, but interned for fast lookup.
    // =======================================================================

    /// `define` (preprocessor directive name)
    Define,
    /// `include` (preprocessor directive name)
    Include,
    /// `include_next` (GCC extension)
    IncludeNext,
    /// `ifdef` (preprocessor directive name)
    Ifdef,
    /// `ifndef` (preprocessor directive name)
    Ifndef,
    /// `elif` (preprocessor directive name)
    Elif,
    /// `endif` (preprocessor directive name)
    Endif,
    /// `defined` (preprocessor operator)
    Defined,
    /// `undef` (preprocessor directive name)
    Undef,
    /// `error` (preprocessor directive name)
    Error,
    /// `warning` (preprocessor directive name, GCC extension)
    Warning,
    /// `line` (preprocessor directive name)
    Line,
    /// `pragma` (preprocessor directive name)
    Pragma,

    // --- Predefined Macros ---
    /// `__LINE__`
    LineMacro,
    /// `__FILE__`
    FileMacro,
    /// `__DATE__`
    DateMacro,
    /// `__TIME__`
    TimeMacro,
    /// `__FUNCTION__`
    FunctionMacro,
    /// `__VA_ARGS__`
    VaArgs,
    /// `__COUNTER__`
    CounterMacro,
    /// `__has_include`
    HasInclude,
    /// `__has_include_next`
    HasIncludeNext,

    // =======================================================================
    // Special Identifiers (tcctok.h lines 97-103)
    // =======================================================================

    /// `__func__` (C99 predefined identifier)
    Func,
    /// `__nan__` (special floating point NaN)
    Nan,
    /// `__snan__` (signaling NaN)
    Snan,
    /// `__inf__` (infinity)
    Inf,

    // =======================================================================
    // Attribute Identifiers (tcctok.h lines 105-165)
    // =======================================================================

    /// `section` / `__section__`
    Section,
    /// `aligned` / `__aligned__`
    Aligned,
    /// `packed` / `__packed__`
    Packed,
    /// `weak` / `__weak__` (attribute, not assembler directive)
    WeakAttr,
    /// `alias` / `__alias__`
    Alias,
    /// `used` / `__used__`
    Used,
    /// `unused` / `__unused__`
    Unused,
    /// `format` / `__format__`
    Format,
    /// `nodebug` / `__nodebug__`
    Nodebug,
    /// `cdecl` / `__cdecl` / `__cdecl__`
    Cdecl,
    /// `stdcall` / `__stdcall` / `__stdcall__`
    Stdcall,
    /// `fastcall` / `__fastcall` / `__fastcall__`
    Fastcall,
    /// `thiscall` / `__thiscall` / `__thiscall__`
    Thiscall,
    /// `regparm` / `__regparm__`
    Regparm,
    /// `cleanup` / `__cleanup__`
    Cleanup,
    /// `constructor` / `__constructor__`
    Constructor,
    /// `destructor` / `__destructor__`
    Destructor,
    /// `always_inline` / `__always_inline__`
    AlwaysInline,
    /// `__noinline__`
    Noinline,
    /// `pure` / `__pure__`
    Pure,
    /// `__mode__`
    Mode,
    /// `__QI__`
    ModeQI,
    /// `__DI__`
    ModeDI,
    /// `__HI__`
    ModeHI,
    /// `__SI__`
    ModeSI,
    /// `__word__`
    ModeWord,
    /// `dllexport`
    Dllexport,
    /// `dllimport`
    Dllimport,
    /// `nodecorate`
    Nodecorate,
    /// `visibility` / `__visibility__`
    Visibility,

    // =======================================================================
    // GCC Builtins (tcctok.h lines 167-184)
    // =======================================================================

    /// `__builtin_types_compatible_p`
    BuiltinTypes,
    /// `__builtin_choose_expr`
    BuiltinChooseExpr,
    /// `__builtin_constant_p`
    BuiltinConstantP,
    /// `__builtin_frame_address`
    BuiltinFrameAddress,
    /// `__builtin_return_address`
    BuiltinReturnAddress,
    /// `__builtin_expect` (FEAT-02: branch prediction hint)
    BuiltinExpect,
    /// `__builtin_unreachable`
    BuiltinUnreachable,
    /// `__builtin_va_start` (target-specific)
    BuiltinVaStart,
    /// `__builtin_va_arg` (target-specific, ARM64)
    BuiltinVaArg,
    /// `__builtin_va_arg_types` (target-specific, x86_64)
    BuiltinVaArgTypes,

    // =======================================================================
    // Atomic Operations (tcctok.h lines 186-203)
    // =======================================================================

    /// `__atomic_store`
    AtomicStore,
    /// `__atomic_load`
    AtomicLoad,
    /// `__atomic_exchange`
    AtomicExchange,
    /// `__atomic_compare_exchange`
    AtomicCompareExchange,
    /// `__atomic_fetch_add`
    AtomicFetchAdd,
    /// `__atomic_fetch_sub`
    AtomicFetchSub,
    /// `__atomic_fetch_or`
    AtomicFetchOr,
    /// `__atomic_fetch_xor`
    AtomicFetchXor,
    /// `__atomic_fetch_and`
    AtomicFetchAnd,
    /// `__atomic_fetch_nand`
    AtomicFetchNand,
    /// `__atomic_add_fetch`
    AtomicAddFetch,
    /// `__atomic_sub_fetch`
    AtomicSubFetch,
    /// `__atomic_or_fetch`
    AtomicOrFetch,
    /// `__atomic_xor_fetch`
    AtomicXorFetch,
    /// `__atomic_and_fetch`
    AtomicAndFetch,
    /// `__atomic_nand_fetch`
    AtomicNandFetch,

    // =======================================================================
    // Pragma Tokens (tcctok.h lines 205-219)
    // =======================================================================

    /// `pack` (pragma name)
    Pack,
    /// `push` (pragma argument — conditional on target)
    AsmPush,
    /// `pop` (pragma argument — conditional on target)
    AsmPop,
    /// `comment` (pragma name)
    Comment,
    /// `lib` (pragma name)
    Lib,
    /// `push_macro` (pragma name)
    PushMacro,
    /// `pop_macro` (pragma name)
    PopMacro,
    /// `once` (pragma name)
    Once,
    /// `option` (pragma name)
    Option,

    // =======================================================================
    // Built-in Runtime Functions (tcctok.h lines 221-363)
    // Platform/target-conditional; all included for cross-compilation.
    // =======================================================================

    /// `memcpy` / `__aeabi_memcpy`
    Memcpy,
    /// `memmove` / `__aeabi_memmove`
    Memmove,
    /// `memset` / `__aeabi_memset`
    Memset,
    /// `__aeabi_memmove4` (ARM EABI)
    Memmove4,
    /// `__aeabi_memmove8` (ARM EABI)
    Memmove8,
    /// `__divdi3` / `__aeabi_ldivmod` (64-bit division)
    Divdi3,
    /// `__moddi3` (64-bit modulo)
    Moddi3,
    /// `__udivdi3` / `__aeabi_uldivmod` (unsigned 64-bit division)
    Udivdi3,
    /// `__umoddi3` (unsigned 64-bit modulo)
    Umoddi3,
    /// `__ashrdi3` / `__aeabi_lasr` (arithmetic right shift 64-bit)
    Ashrdi3,
    /// `__lshrdi3` / `__aeabi_llsr` (logical right shift 64-bit)
    Lshrdi3,
    /// `__ashldi3` / `__aeabi_llsl` (left shift 64-bit)
    Ashldi3,
    /// `__floatundisf` / `__aeabi_ul2f`
    Floatundisf,
    /// `__floatundidf` / `__aeabi_ul2d`
    Floatundidf,
    /// `__floatundixf`
    Floatundixf,
    /// `__fixunsxfdi`
    Fixunsxfdi,
    /// `__fixunssfdi` / `__aeabi_f2ulz`
    Fixunssfdi,
    /// `__fixunsdfdi` / `__aeabi_d2ulz`
    Fixunsdfdi,
    /// `__aeabi_idivmod` (ARM EABI signed int divmod)
    AeabiIdivmod,
    /// `__aeabi_uidivmod` (ARM EABI unsigned int divmod)
    AeabiUidivmod,
    /// `__divsi3` / `__aeabi_idiv` (signed 32-bit division)
    Divsi3,
    /// `__udivsi3` / `__aeabi_uidiv` (unsigned 32-bit division)
    Udivsi3,
    /// `__floatdisf` / `__aeabi_l2f`
    Floatdisf,
    /// `__floatdidf` / `__aeabi_l2d`
    Floatdidf,
    /// `__fixsfdi` / `__aeabi_f2lz`
    Fixsfdi,
    /// `__fixdfdi` / `__aeabi_d2lz`
    Fixdfdi,
    /// `__modsi3` (ARM non-EABI signed 32-bit modulo)
    Modsi3,
    /// `__umodsi3` (ARM non-EABI unsigned 32-bit modulo)
    Umodsi3,
    /// `__floatdixf`
    Floatdixf,
    /// `__fixunssfsi`
    Fixunssfsi,
    /// `__fixunsdfsi`
    Fixunsdfsi,
    /// `__fixunsxfsi`
    Fixunsxfsi,
    /// `__fixxfdi`
    Fixxfdi,

    // --- C67 (TMS320) ---
    /// `_divi` (C67)
    C67Divi,
    /// `_divu` (C67)
    C67Divu,
    /// `_divf` (C67)
    C67Divf,
    /// `_divd` (C67)
    C67Divd,
    /// `_remi` (C67)
    C67Remi,
    /// `_remu` (C67)
    C67Remu,

    /// `alloca`
    Alloca,

    /// `__chkstk` (Windows PE stack probing)
    Chkstk,

    // --- ARM64/RISC-V 128-bit float helpers ---
    /// `__arm64_clear_cache`
    Arm64ClearCache,
    /// `__addtf3`
    Addtf3,
    /// `__subtf3`
    Subtf3,
    /// `__multf3`
    Multf3,
    /// `__divtf3`
    Divtf3,
    /// `__extendsftf2`
    Extendsftf2,
    /// `__extenddftf2`
    Extenddftf2,
    /// `__trunctfsf2`
    Trunctfsf2,
    /// `__trunctfdf2`
    Trunctfdf2,
    /// `__negtf2`
    Negtf2,
    /// `__fixtfsi`
    Fixtfsi,
    /// `__fixtfdi`
    Fixtfdi,
    /// `__fixunstfsi`
    Fixunstfsi,
    /// `__fixunstfdi`
    Fixunstfdi,
    /// `__floatsitf`
    Floatsitf,
    /// `__floatditf`
    Floatditf,
    /// `__floatunsitf`
    Floatunsitf,
    /// `__floatunditf`
    Floatunditf,
    /// `__eqtf2`
    Eqtf2,
    /// `__netf2`
    Netf2,
    /// `__lttf2`
    Lttf2,
    /// `__letf2`
    Letf2,
    /// `__gttf2`
    Gttf2,
    /// `__getf2`
    Getf2,

    // =======================================================================
    // Bounds Checking Symbols (tcctok.h lines 336-363)
    // =======================================================================

    /// `__bound_ptr_add`
    BoundPtrAdd,
    /// `__bound_ptr_indir1`
    BoundPtrIndir1,
    /// `__bound_ptr_indir2`
    BoundPtrIndir2,
    /// `__bound_ptr_indir4`
    BoundPtrIndir4,
    /// `__bound_ptr_indir8`
    BoundPtrIndir8,
    /// `__bound_ptr_indir12`
    BoundPtrIndir12,
    /// `__bound_ptr_indir16`
    BoundPtrIndir16,
    /// `__bound_main_arg`
    BoundMainArg,
    /// `__bound_local_new`
    BoundLocalNew,
    /// `__bound_local_delete`
    BoundLocalDelete,
    /// `__bound_setjmp`
    BoundSetjmp,
    /// `__bound_longjmp`
    BoundLongjmp,
    /// `__bound_new_region`
    BoundNewRegion,
    /// `__bound_alloca_nr` (PE x86_64 only)
    BoundAllocaNr,
    /// `sigsetjmp`
    Sigsetjmp,
    /// `__sigsetjmp`
    SigsetjmpInternal,
    /// `siglongjmp`
    Siglongjmp,
    /// `setjmp`
    Setjmp,
    /// `_setjmp`
    SetjmpInternal,
    /// `longjmp`
    Longjmp,

    // =======================================================================
    // GCC Builtin Functions (additional)
    // =======================================================================

    /// `__builtin_offsetof`
    BuiltinOffsetof,
    /// `__builtin_ffs`
    BuiltinFfs,
    /// `__builtin_clz`
    BuiltinClz,
    /// `__builtin_ctz`
    BuiltinCtz,
    /// `__builtin_popcount`
    BuiltinPopcount,

    // =======================================================================
    // Operator/Punctuation Tokens (these use fixed numeric codes in tcc.h)
    // These are NOT stored in the enum's discriminant range but are matched
    // symbolically. The actual numeric codes are in the TOK_* constants below.
    // =======================================================================

    /// `->` operator
    Arrow,
    /// `++` increment
    Inc,
    /// `--` decrement
    Dec,
    /// `<<` left shift
    Shl,
    /// `>>` right shift
    Shr,
    /// `<=` less-or-equal
    Le,
    /// `>=` greater-or-equal
    Ge,
    /// `==` equality
    Eq,
    /// `!=` inequality
    Ne,
    /// `&&` logical AND
    Land,
    /// `||` logical OR
    Lor,
    /// `...` ellipsis
    Dots,
    /// `##` token pasting
    Twosharps,

    // --- Assignment Operators ---
    /// `+=`
    AddAssign,
    /// `-=`
    SubAssign,
    /// `*=`
    MulAssign,
    /// `/=`
    DivAssign,
    /// `%=`
    ModAssign,
    /// `<<=`
    ShlAssign,
    /// `>>=`
    ShrAssign,
    /// `&=`
    AndAssign,
    /// `|=`
    OrAssign,
    /// `^=`
    XorAssign,

    // --- Special Tokens ---
    /// Line feed token (in preprocessor mode) — numeric value 10
    LineFeed,
    /// End of file — numeric value -1
    Eof,

    // --- Literal/Value Tokens ---
    /// Integer constant (value in tokc)
    IntConst,
    /// Unsigned integer constant
    UintConst,
    /// Long long constant
    LlongConst,
    /// Unsigned long long constant
    UllongConst,
    /// Long constant
    LongConst,
    /// Unsigned long constant
    UlongConst,
    /// Float constant
    FloatConst,
    /// Double constant
    DoubleConst,
    /// Long double constant
    LdoubleConst,
    /// Character constant
    CharConst,
    /// Wide character constant
    LcharConst,
    /// String literal
    StringLiteral,
    /// Wide string literal
    LstringLiteral,
    /// Preprocessor number (not yet converted)
    PpNum,
    /// Preprocessor string (not yet converted)
    PpStr,
    /// Line number info
    LineNum,
    /// Identifier (user-defined name)
    Identifier,
}

// ===========================================================================
// Token Numeric Constants (from tcc.h lines 1113-1193)
// These are the raw numeric codes used internally by the compiler.
// ===========================================================================

// --- Operator Codes ---
/// `--` decrement operator code
pub const TOK_DEC: i32 = 0x80;
/// Increment/decrement to void constant (internal)
pub const TOK_MID: i32 = 0x81;
/// `++` increment operator code
pub const TOK_INC: i32 = 0x82;
/// Unsigned division
pub const TOK_UDIV: i32 = 0x83;
/// Unsigned modulo
pub const TOK_UMOD: i32 = 0x84;
/// Fast division with undefined rounding for pointers
pub const TOK_PDIV: i32 = 0x85;
/// Unsigned 32×32 → 64 multiply
pub const TOK_UMULL: i32 = 0x86;
/// Add with carry generation
pub const TOK_ADDC1: i32 = 0x87;
/// Add with carry use
pub const TOK_ADDC2: i32 = 0x88;
/// Subtract with carry generation
pub const TOK_SUBC1: i32 = 0x89;
/// Subtract with carry use
pub const TOK_SUBC2: i32 = 0x8a;
/// Unsigned shift right
pub const TOK_SHR: i32 = 0x8b;

/// Shift left (same as `'<'`)
pub const TOK_SHL: i32 = b'<' as i32;
/// Signed arithmetic shift right (same as `'>'`)
pub const TOK_SAR: i32 = b'>' as i32;
/// Unary minus for floats (alias of TOK_MID)
pub const TOK_NEG: i32 = TOK_MID;

// --- Conditional/Comparison Operators ---
/// Logical AND `&&`
pub const TOK_LAND: i32 = 0x90;
/// Logical OR `||`
pub const TOK_LOR: i32 = 0x91;
/// Unsigned less than
pub const TOK_ULT: i32 = 0x92;
/// Unsigned greater or equal
pub const TOK_UGE: i32 = 0x93;
/// Equality `==`
pub const TOK_EQ: i32 = 0x94;
/// Inequality `!=`
pub const TOK_NE: i32 = 0x95;
/// Unsigned less or equal
pub const TOK_ULE: i32 = 0x96;
/// Unsigned greater than
pub const TOK_UGT: i32 = 0x97;
/// Signed less than `<`
pub const TOK_LT: i32 = 0x9c;
/// Signed greater or equal `>=`
pub const TOK_GE: i32 = 0x9d;
/// Signed less or equal `<=`
pub const TOK_LE: i32 = 0x9e;
/// Signed greater than `>`
pub const TOK_GT: i32 = 0x9f;

// --- Multi-char Operators ---
/// `->` arrow operator
pub const TOK_ARROW: i32 = 0xa0;
/// `...` ellipsis
pub const TOK_DOTS: i32 = 0xa1;
/// `..` two dots (C++ token, reserved)
pub const TOK_TWODOTS: i32 = 0xa2;
/// `##` token pasting
pub const TOK_TWOSHARPS: i32 = 0xa3;
/// Placeholder token (C99)
pub const TOK_PLCHLDR: i32 = 0xa4;
/// Alias of `(` for parsing `sizeof(type)`
pub const TOK_SOTYPE: i32 = 0xa7;

// --- Assignment Operators ---
/// `+=`
pub const TOK_A_ADD: i32 = 0xb0;
/// `-=`
pub const TOK_A_SUB: i32 = 0xb1;
/// `*=`
pub const TOK_A_MUL: i32 = 0xb2;
/// `/=`
pub const TOK_A_DIV: i32 = 0xb3;
/// `%=`
pub const TOK_A_MOD: i32 = 0xb4;
/// `&=`
pub const TOK_A_AND: i32 = 0xb5;
/// `|=`
pub const TOK_A_OR: i32 = 0xb6;
/// `^=`
pub const TOK_A_XOR: i32 = 0xb7;
/// `<<=`
pub const TOK_A_SHL: i32 = 0xb8;
/// `>>=` (signed)
pub const TOK_A_SAR: i32 = 0xb9;

// --- Value-carrying Token Codes ---
/// Character constant
pub const TOK_CCHAR: i32 = 0xc0;
/// Wide character constant
pub const TOK_LCHAR: i32 = 0xc1;
/// Signed int constant
pub const TOK_CINT: i32 = 0xc2;
/// Unsigned int constant
pub const TOK_CUINT: i32 = 0xc3;
/// Long long constant
pub const TOK_CLLONG: i32 = 0xc4;
/// Unsigned long long constant
pub const TOK_CULLONG: i32 = 0xc5;
/// Long constant
pub const TOK_CLONG: i32 = 0xc6;
/// Unsigned long constant
pub const TOK_CULONG: i32 = 0xc7;
/// String literal
pub const TOK_STR: i32 = 0xc8;
/// Wide string literal
pub const TOK_LSTR: i32 = 0xc9;
/// Float constant
pub const TOK_CFLOAT: i32 = 0xca;
/// Double constant
pub const TOK_CDOUBLE: i32 = 0xcb;
/// Long double constant
pub const TOK_CLDOUBLE: i32 = 0xcc;
/// Preprocessor number
pub const TOK_PPNUM: i32 = 0xcd;
/// Preprocessor string
pub const TOK_PPSTR: i32 = 0xce;
/// Line number info
pub const TOK_LINENUM: i32 = 0xcf;

// --- Special Token Codes ---
/// End of file
pub const TOK_EOF: i32 = -1;
/// Line feed (in preprocessor mode)
pub const TOK_LINEFEED: i32 = 10;

/// Base value for identifiers. All keywords and identifiers have token >= TOK_IDENT.
pub const TOK_IDENT: i32 = 256;

// --- Token Flags ---
/// Beginning of line before this token
pub const TOK_FLAG_BOL: i32 = 0x0001;
/// Beginning of file before this token
pub const TOK_FLAG_BOF: i32 = 0x0002;
/// An `#endif` was found matching starting `#ifdef`
pub const TOK_FLAG_ENDIF: i32 = 0x0004;

// --- Parse Flags ---
/// Activate preprocessing
pub const PARSE_FLAG_PREPROCESS: i32 = 0x0001;
/// Return numbers instead of `TOK_PPNUM`
pub const PARSE_FLAG_TOK_NUM: i32 = 0x0002;
/// Line feed is returned as a token; also returned at EOF
pub const PARSE_FLAG_LINEFEED: i32 = 0x0004;
/// Processing an assembly file: `#` can be used for line comments
pub const PARSE_FLAG_ASM_FILE: i32 = 0x0008;
/// `next()` returns space tokens (for `-E`)
pub const PARSE_FLAG_SPACES: i32 = 0x0010;
/// `next()` returns `\\` stray tokens
pub const PARSE_FLAG_ACCEPT_STRAYS: i32 = 0x0020;
/// Return parsed strings instead of `TOK_PPSTR`
pub const PARSE_FLAG_TOK_STR: i32 = 0x0040;

// ===========================================================================
// Token Hash Table and Allocation Constants
// (from tcc.h lines 439-441; also re-exported from types.rs for convenience)
// ===========================================================================

/// Size of the token hash table (must be power of two).
pub const TOK_HASH_SIZE: usize = 16384;
/// Token allocation increment (must be power of two).
pub const TOK_ALLOC_INCR: usize = 512;
/// Token maximum size in `i32` units when stored in a string.
pub const TOK_MAX_SIZE: usize = 4;

// ===========================================================================
// Internal Operation Token Constants
// These are runtime/codegen helper function tokens (from tcctok.h)
// that map to compiler-generated calls. They are represented as string
// constants so the linker can resolve them by name.
// ===========================================================================

/// `__fixsfdi` — float-to-signed-long-long conversion
pub const TOK___fixsfdi: &str = "__fixsfdi";
/// `__fixdfdi` — double-to-signed-long-long conversion
pub const TOK___fixdfdi: &str = "__fixdfdi";
/// `__fixxfdi` — long-double-to-signed-long-long conversion
pub const TOK___fixxfdi: &str = "__fixxfdi";
/// `__chkstk` — Windows stack probing
pub const TOK___chkstk: &str = "__chkstk";
/// `__bound_local_new` — bounds checking: register new local (BOUND-03 fix)
pub const TOK___bound_local_new: &str = "__bound_local_new";
/// `__bound_local_delete` — bounds checking: deregister local
pub const TOK___bound_local_delete: &str = "__bound_local_delete";
/// `alloca` — dynamic stack allocation
pub const TOK_alloca: &str = "alloca";
/// `__bound_new_region` — bounds checking: register memory region
pub const TOK___bound_new_region: &str = "__bound_new_region";

// --- 128-bit Float (quad precision) Helper Functions ---
/// `__multf3`
pub const TOK___multf3: &str = "__multf3";
/// `__addtf3`
pub const TOK___addtf3: &str = "__addtf3";
/// `__subtf3`
pub const TOK___subtf3: &str = "__subtf3";
/// `__divtf3`
pub const TOK___divtf3: &str = "__divtf3";
/// `__eqtf2`
pub const TOK___eqtf2: &str = "__eqtf2";
/// `__netf2`
pub const TOK___netf2: &str = "__netf2";
/// `__lttf2`
pub const TOK___lttf2: &str = "__lttf2";
/// `__getf2`
pub const TOK___getf2: &str = "__getf2";
/// `__letf2`
pub const TOK___letf2: &str = "__letf2";
/// `__gttf2`
pub const TOK___gttf2: &str = "__gttf2";
/// `__floatunditf`
pub const TOK___floatunditf: &str = "__floatunditf";
/// `__floatditf`
pub const TOK___floatditf: &str = "__floatditf";
/// `__fixunstfdi`
pub const TOK___fixunstfdi: &str = "__fixunstfdi";
/// `__fixtfdi`
pub const TOK___fixtfdi: &str = "__fixtfdi";
/// `__extendsftf2`
pub const TOK___extendsftf2: &str = "__extendsftf2";
/// `__extenddftf2`
pub const TOK___extenddftf2: &str = "__extenddftf2";
/// `__trunctfsf2`
pub const TOK___trunctfsf2: &str = "__trunctfsf2";
/// `__trunctfdf2`
pub const TOK___trunctfdf2: &str = "__trunctfdf2";
/// `__floatunsitf`
pub const TOK___floatunsitf: &str = "__floatunsitf";
/// `__floatsitf`
pub const TOK___floatsitf: &str = "__floatsitf";
/// `__fixunstfsi`
pub const TOK___fixunstfsi: &str = "__fixunstfsi";
/// `__fixtfsi`
pub const TOK___fixtfsi: &str = "__fixtfsi";
/// `__negtf2`
pub const TOK___negtf2: &str = "__negtf2";

// ===========================================================================
// Keyword Lookup Table (OPT-02: O(1) HashMap instead of linear search)
// ===========================================================================

/// Static array of all keyword and special-identifier string-to-token mappings.
///
/// Each entry maps a string representation to its corresponding `Token` variant.
/// GCC alternative spellings (`__const`, `__const__`, etc.) are included as
/// separate entries mapping to the same canonical token.
///
/// This array backs the `build_keyword_table()` function for O(1) lookup.
pub static KEYWORDS: &[(&str, Token)] = &[
    // --- C Keywords ---
    ("if", Token::If),
    ("else", Token::Else),
    ("while", Token::While),
    ("for", Token::For),
    ("do", Token::Do),
    ("continue", Token::Continue),
    ("break", Token::Break),
    ("return", Token::Return),
    ("goto", Token::Goto),
    ("switch", Token::Switch),
    ("case", Token::Case),
    ("default", Token::Default),
    ("asm", Token::Asm),
    ("__asm", Token::Asm),
    ("__asm__", Token::Asm),
    // Storage class and qualifiers
    ("extern", Token::Extern),
    ("static", Token::Static),
    ("unsigned", Token::Unsigned),
    ("_Atomic", Token::Atomic),
    ("const", Token::Const),
    ("__const", Token::Const),
    ("__const__", Token::Const),
    ("volatile", Token::Volatile),
    ("__volatile", Token::Volatile),
    ("__volatile__", Token::Volatile),
    ("register", Token::Register),
    ("signed", Token::Signed),
    ("__signed", Token::Signed),
    ("__signed__", Token::Signed),
    ("auto", Token::Auto),
    ("inline", Token::Inline),
    ("__inline", Token::Inline),
    ("__inline__", Token::Inline),
    ("restrict", Token::Restrict),
    ("__restrict", Token::Restrict),
    ("__restrict__", Token::Restrict),
    ("__extension__", Token::Extension),
    ("_Thread_local", Token::ThreadLocal),
    ("_Generic", Token::Generic),
    ("_Static_assert", Token::StaticAssert),
    // Type keywords
    ("void", Token::Void),
    ("char", Token::Char),
    ("int", Token::Int),
    ("float", Token::Float),
    ("double", Token::Double),
    ("_Bool", Token::Bool),
    ("_Complex", Token::Complex),
    ("short", Token::Short),
    ("long", Token::Long),
    ("struct", Token::Struct),
    ("union", Token::Union),
    ("typedef", Token::Typedef),
    ("enum", Token::Enum),
    ("sizeof", Token::Sizeof),
    ("__attribute", Token::Attribute),
    ("__attribute__", Token::Attribute),
    ("__alignof", Token::Alignof),
    ("__alignof__", Token::Alignof),
    ("_Alignof", Token::Alignof),
    ("_Alignas", Token::Alignas),
    ("typeof", Token::Typeof),
    ("__typeof", Token::Typeof),
    ("__typeof__", Token::Typeof),
    ("__label__", Token::Label),
    ("__declspec", Token::Declspec),
    ("_Noreturn", Token::Noreturn),
    ("noreturn", Token::Noreturn),
    ("__noreturn__", Token::Noreturn),
    // --- Preprocessor directives ---
    ("define", Token::Define),
    ("include", Token::Include),
    ("include_next", Token::IncludeNext),
    ("ifdef", Token::Ifdef),
    ("ifndef", Token::Ifndef),
    ("elif", Token::Elif),
    ("endif", Token::Endif),
    ("defined", Token::Defined),
    ("undef", Token::Undef),
    ("error", Token::Error),
    ("warning", Token::Warning),
    ("line", Token::Line),
    ("pragma", Token::Pragma),
    ("__LINE__", Token::LineMacro),
    ("__FILE__", Token::FileMacro),
    ("__DATE__", Token::DateMacro),
    ("__TIME__", Token::TimeMacro),
    ("__FUNCTION__", Token::FunctionMacro),
    ("__VA_ARGS__", Token::VaArgs),
    ("__COUNTER__", Token::CounterMacro),
    ("__has_include", Token::HasInclude),
    ("__has_include_next", Token::HasIncludeNext),
    // --- Special identifiers ---
    ("__func__", Token::Func),
    ("__nan__", Token::Nan),
    ("__snan__", Token::Snan),
    ("__inf__", Token::Inf),
    // --- Attribute identifiers (with GCC __xxx__ alternatives) ---
    ("section", Token::Section),
    ("__section__", Token::Section),
    ("aligned", Token::Aligned),
    ("__aligned__", Token::Aligned),
    ("packed", Token::Packed),
    ("__packed__", Token::Packed),
    ("weak", Token::WeakAttr),
    ("__weak__", Token::WeakAttr),
    ("alias", Token::Alias),
    ("__alias__", Token::Alias),
    ("used", Token::Used),
    ("__used__", Token::Used),
    ("unused", Token::Unused),
    ("__unused__", Token::Unused),
    ("format", Token::Format),
    ("__format__", Token::Format),
    ("nodebug", Token::Nodebug),
    ("__nodebug__", Token::Nodebug),
    ("cdecl", Token::Cdecl),
    ("__cdecl", Token::Cdecl),
    ("__cdecl__", Token::Cdecl),
    ("stdcall", Token::Stdcall),
    ("__stdcall", Token::Stdcall),
    ("__stdcall__", Token::Stdcall),
    ("fastcall", Token::Fastcall),
    ("__fastcall", Token::Fastcall),
    ("__fastcall__", Token::Fastcall),
    ("thiscall", Token::Thiscall),
    ("__thiscall", Token::Thiscall),
    ("__thiscall__", Token::Thiscall),
    ("regparm", Token::Regparm),
    ("__regparm__", Token::Regparm),
    ("cleanup", Token::Cleanup),
    ("__cleanup__", Token::Cleanup),
    ("constructor", Token::Constructor),
    ("__constructor__", Token::Constructor),
    ("destructor", Token::Destructor),
    ("__destructor__", Token::Destructor),
    ("always_inline", Token::AlwaysInline),
    ("__always_inline__", Token::AlwaysInline),
    ("__noinline__", Token::Noinline),
    ("pure", Token::Pure),
    ("__pure__", Token::Pure),
    ("__mode__", Token::Mode),
    ("__QI__", Token::ModeQI),
    ("__DI__", Token::ModeDI),
    ("__HI__", Token::ModeHI),
    ("__SI__", Token::ModeSI),
    ("__word__", Token::ModeWord),
    ("dllexport", Token::Dllexport),
    ("dllimport", Token::Dllimport),
    ("nodecorate", Token::Nodecorate),
    ("visibility", Token::Visibility),
    ("__visibility__", Token::Visibility),
    // --- GCC builtins ---
    ("__builtin_types_compatible_p", Token::BuiltinTypes),
    ("__builtin_choose_expr", Token::BuiltinChooseExpr),
    ("__builtin_constant_p", Token::BuiltinConstantP),
    ("__builtin_frame_address", Token::BuiltinFrameAddress),
    ("__builtin_return_address", Token::BuiltinReturnAddress),
    ("__builtin_expect", Token::BuiltinExpect),
    ("__builtin_unreachable", Token::BuiltinUnreachable),
    ("__builtin_va_start", Token::BuiltinVaStart),
    ("__builtin_va_arg", Token::BuiltinVaArg),
    ("__builtin_va_arg_types", Token::BuiltinVaArgTypes),
    ("__builtin_offsetof", Token::BuiltinOffsetof),
    ("__builtin_ffs", Token::BuiltinFfs),
    ("__builtin_clz", Token::BuiltinClz),
    ("__builtin_ctz", Token::BuiltinCtz),
    ("__builtin_popcount", Token::BuiltinPopcount),
    // --- Atomic operations ---
    ("__atomic_store", Token::AtomicStore),
    ("__atomic_load", Token::AtomicLoad),
    ("__atomic_exchange", Token::AtomicExchange),
    ("__atomic_compare_exchange", Token::AtomicCompareExchange),
    ("__atomic_fetch_add", Token::AtomicFetchAdd),
    ("__atomic_fetch_sub", Token::AtomicFetchSub),
    ("__atomic_fetch_or", Token::AtomicFetchOr),
    ("__atomic_fetch_xor", Token::AtomicFetchXor),
    ("__atomic_fetch_and", Token::AtomicFetchAnd),
    ("__atomic_fetch_nand", Token::AtomicFetchNand),
    ("__atomic_add_fetch", Token::AtomicAddFetch),
    ("__atomic_sub_fetch", Token::AtomicSubFetch),
    ("__atomic_or_fetch", Token::AtomicOrFetch),
    ("__atomic_xor_fetch", Token::AtomicXorFetch),
    ("__atomic_and_fetch", Token::AtomicAndFetch),
    ("__atomic_nand_fetch", Token::AtomicNandFetch),
    // --- Pragma tokens ---
    ("pack", Token::Pack),
    ("push", Token::AsmPush),
    ("pop", Token::AsmPop),
    ("comment", Token::Comment),
    ("lib", Token::Lib),
    ("push_macro", Token::PushMacro),
    ("pop_macro", Token::PopMacro),
    ("once", Token::Once),
    ("option", Token::Option),
    // --- Runtime function identifiers ---
    ("memcpy", Token::Memcpy),
    ("memmove", Token::Memmove),
    ("memset", Token::Memset),
    ("__divdi3", Token::Divdi3),
    ("__moddi3", Token::Moddi3),
    ("__udivdi3", Token::Udivdi3),
    ("__umoddi3", Token::Umoddi3),
    ("__ashrdi3", Token::Ashrdi3),
    ("__lshrdi3", Token::Lshrdi3),
    ("__ashldi3", Token::Ashldi3),
    ("__floatundisf", Token::Floatundisf),
    ("__floatundidf", Token::Floatundidf),
    ("__floatundixf", Token::Floatundixf),
    ("__fixunsxfdi", Token::Fixunsxfdi),
    ("__fixunssfdi", Token::Fixunssfdi),
    ("__fixunsdfdi", Token::Fixunsdfdi),
    ("__fixsfdi", Token::Fixsfdi),
    ("__fixdfdi", Token::Fixdfdi),
    ("__fixxfdi", Token::Fixxfdi),
    ("__divsi3", Token::Divsi3),
    ("__udivsi3", Token::Udivsi3),
    ("__modsi3", Token::Modsi3),
    ("__umodsi3", Token::Umodsi3),
    ("__floatdisf", Token::Floatdisf),
    ("__floatdidf", Token::Floatdidf),
    ("__floatdixf", Token::Floatdixf),
    ("__fixunssfsi", Token::Fixunssfsi),
    ("__fixunsdfsi", Token::Fixunsdfsi),
    ("__fixunsxfsi", Token::Fixunsxfsi),
    ("alloca", Token::Alloca),
    ("__chkstk", Token::Chkstk),
    ("__arm64_clear_cache", Token::Arm64ClearCache),
    ("__addtf3", Token::Addtf3),
    ("__subtf3", Token::Subtf3),
    ("__multf3", Token::Multf3),
    ("__divtf3", Token::Divtf3),
    ("__extendsftf2", Token::Extendsftf2),
    ("__extenddftf2", Token::Extenddftf2),
    ("__trunctfsf2", Token::Trunctfsf2),
    ("__trunctfdf2", Token::Trunctfdf2),
    ("__negtf2", Token::Negtf2),
    ("__fixtfsi", Token::Fixtfsi),
    ("__fixtfdi", Token::Fixtfdi),
    ("__fixunstfsi", Token::Fixunstfsi),
    ("__fixunstfdi", Token::Fixunstfdi),
    ("__floatsitf", Token::Floatsitf),
    ("__floatditf", Token::Floatditf),
    ("__floatunsitf", Token::Floatunsitf),
    ("__floatunditf", Token::Floatunditf),
    ("__eqtf2", Token::Eqtf2),
    ("__netf2", Token::Netf2),
    ("__lttf2", Token::Lttf2),
    ("__letf2", Token::Letf2),
    ("__gttf2", Token::Gttf2),
    ("__getf2", Token::Getf2),
    // --- ARM EABI alternative names ---
    ("__aeabi_memcpy", Token::Memcpy),
    ("__aeabi_memmove", Token::Memmove),
    ("__aeabi_memmove4", Token::Memmove4),
    ("__aeabi_memmove8", Token::Memmove8),
    ("__aeabi_memset", Token::Memset),
    ("__aeabi_ldivmod", Token::Divdi3),
    ("__aeabi_uldivmod", Token::Udivdi3),
    ("__aeabi_idivmod", Token::AeabiIdivmod),
    ("__aeabi_uidivmod", Token::AeabiUidivmod),
    ("__aeabi_idiv", Token::Divsi3),
    ("__aeabi_uidiv", Token::Udivsi3),
    ("__aeabi_l2f", Token::Floatdisf),
    ("__aeabi_l2d", Token::Floatdidf),
    ("__aeabi_f2lz", Token::Fixsfdi),
    ("__aeabi_d2lz", Token::Fixdfdi),
    ("__aeabi_lasr", Token::Ashrdi3),
    ("__aeabi_llsr", Token::Lshrdi3),
    ("__aeabi_llsl", Token::Ashldi3),
    ("__aeabi_ul2f", Token::Floatundisf),
    ("__aeabi_ul2d", Token::Floatundidf),
    ("__aeabi_f2ulz", Token::Fixunssfdi),
    ("__aeabi_d2ulz", Token::Fixunsdfdi),
    // --- C67 (TMS320) ---
    ("_divi", Token::C67Divi),
    ("_divu", Token::C67Divu),
    ("_divf", Token::C67Divf),
    ("_divd", Token::C67Divd),
    ("_remi", Token::C67Remi),
    ("_remu", Token::C67Remu),
    // --- Bounds checking ---
    ("__bound_ptr_add", Token::BoundPtrAdd),
    ("__bound_ptr_indir1", Token::BoundPtrIndir1),
    ("__bound_ptr_indir2", Token::BoundPtrIndir2),
    ("__bound_ptr_indir4", Token::BoundPtrIndir4),
    ("__bound_ptr_indir8", Token::BoundPtrIndir8),
    ("__bound_ptr_indir12", Token::BoundPtrIndir12),
    ("__bound_ptr_indir16", Token::BoundPtrIndir16),
    ("__bound_main_arg", Token::BoundMainArg),
    ("__bound_local_new", Token::BoundLocalNew),
    ("__bound_local_delete", Token::BoundLocalDelete),
    ("__bound_setjmp", Token::BoundSetjmp),
    ("__bound_longjmp", Token::BoundLongjmp),
    ("__bound_new_region", Token::BoundNewRegion),
    ("__bound_alloca_nr", Token::BoundAllocaNr),
    ("sigsetjmp", Token::Sigsetjmp),
    ("__sigsetjmp", Token::SigsetjmpInternal),
    ("siglongjmp", Token::Siglongjmp),
    ("setjmp", Token::Setjmp),
    ("_setjmp", Token::SetjmpInternal),
    ("longjmp", Token::Longjmp),
];

/// Build a keyword hash map for O(1) lookup from string to `Token`.
///
/// Replaces C's linear search through the token hash table for keyword
/// identification, addressing OPT-02 (more parse optimizations).
///
/// # Returns
///
/// A `HashMap` mapping keyword strings to their `Token` variants. GCC
/// alternative spellings (e.g., `__const__`) map to the same token as
/// the standard spelling (e.g., `const`).
pub fn build_keyword_table() -> HashMap<&'static str, Token> {
    let mut map = HashMap::new();
    for &(s, tok) in KEYWORDS.iter() {
        map.insert(s, tok);
    }
    map
}

// ===========================================================================
// Token Helper Methods
// ===========================================================================

impl Token {
    /// Returns `true` if this token is a type specifier keyword.
    ///
    /// Type specifiers determine the base type: `void`, `char`, `short`,
    /// `int`, `long`, `float`, `double`, `_Bool`, `_Complex`, `signed`,
    /// `unsigned`, `struct`, `union`, `enum`, `typeof`.
    #[inline]
    pub fn is_type_specifier(&self) -> bool {
        matches!(
            self,
            Token::Void
                | Token::Char
                | Token::Short
                | Token::Int
                | Token::Long
                | Token::Float
                | Token::Double
                | Token::Bool
                | Token::Complex
                | Token::Signed
                | Token::Unsigned
                | Token::Struct
                | Token::Union
                | Token::Enum
                | Token::Typeof
        )
    }

    /// Returns `true` if this token is a storage class specifier.
    ///
    /// Storage class specifiers: `extern`, `static`, `auto`, `register`,
    /// `typedef`, `inline`, `_Thread_local`.
    #[inline]
    pub fn is_storage_class(&self) -> bool {
        matches!(
            self,
            Token::Extern
                | Token::Static
                | Token::Auto
                | Token::Register
                | Token::Typedef
                | Token::Inline
                | Token::ThreadLocal
        )
    }

    /// Returns `true` if this token is a type qualifier.
    ///
    /// Type qualifiers: `const`, `volatile`, `restrict`, `_Atomic`.
    #[inline]
    pub fn is_type_qualifier(&self) -> bool {
        matches!(
            self,
            Token::Const | Token::Volatile | Token::Restrict | Token::Atomic
        )
    }

    /// Returns `true` if this token is an assignment operator.
    ///
    /// Assignment operators: `+=`, `-=`, `*=`, `/=`, `%=`, `<<=`, `>>=`,
    /// `&=`, `|=`, `^=`.
    #[inline]
    pub fn is_assignment_op(&self) -> bool {
        matches!(
            self,
            Token::AddAssign
                | Token::SubAssign
                | Token::MulAssign
                | Token::DivAssign
                | Token::ModAssign
                | Token::ShlAssign
                | Token::ShrAssign
                | Token::AndAssign
                | Token::OrAssign
                | Token::XorAssign
        )
    }

    /// Returns the canonical string representation of this token.
    ///
    /// For keywords, returns the standard C spelling (e.g., `"const"` not
    /// `"__const__"`). For operators, returns the symbolic form.
    pub fn as_str(&self) -> &'static str {
        match self {
            // --- Keywords ---
            Token::If => "if",
            Token::Else => "else",
            Token::While => "while",
            Token::For => "for",
            Token::Do => "do",
            Token::Continue => "continue",
            Token::Break => "break",
            Token::Return => "return",
            Token::Goto => "goto",
            Token::Switch => "switch",
            Token::Case => "case",
            Token::Default => "default",
            Token::Asm => "asm",
            Token::Extern => "extern",
            Token::Static => "static",
            Token::Unsigned => "unsigned",
            Token::Atomic => "_Atomic",
            Token::Const => "const",
            Token::Volatile => "volatile",
            Token::Register => "register",
            Token::Signed => "signed",
            Token::Auto => "auto",
            Token::Inline => "inline",
            Token::Restrict => "restrict",
            Token::Extension => "__extension__",
            Token::ThreadLocal => "_Thread_local",
            Token::Generic => "_Generic",
            Token::StaticAssert => "_Static_assert",
            Token::Void => "void",
            Token::Char => "char",
            Token::Int => "int",
            Token::Float => "float",
            Token::Double => "double",
            Token::Bool => "_Bool",
            Token::Complex => "_Complex",
            Token::Short => "short",
            Token::Long => "long",
            Token::Struct => "struct",
            Token::Union => "union",
            Token::Typedef => "typedef",
            Token::Enum => "enum",
            Token::Sizeof => "sizeof",
            Token::Attribute => "__attribute__",
            Token::Alignof => "_Alignof",
            Token::Alignas => "_Alignas",
            Token::Typeof => "typeof",
            Token::Label => "__label__",
            Token::Declspec => "__declspec",
            Token::Noreturn => "_Noreturn",
            // Preprocessor
            Token::Define => "define",
            Token::Include => "include",
            Token::IncludeNext => "include_next",
            Token::Ifdef => "ifdef",
            Token::Ifndef => "ifndef",
            Token::Elif => "elif",
            Token::Endif => "endif",
            Token::Defined => "defined",
            Token::Undef => "undef",
            Token::Error => "error",
            Token::Warning => "warning",
            Token::Line => "line",
            Token::Pragma => "pragma",
            Token::LineMacro => "__LINE__",
            Token::FileMacro => "__FILE__",
            Token::DateMacro => "__DATE__",
            Token::TimeMacro => "__TIME__",
            Token::FunctionMacro => "__FUNCTION__",
            Token::VaArgs => "__VA_ARGS__",
            Token::CounterMacro => "__COUNTER__",
            Token::HasInclude => "__has_include",
            Token::HasIncludeNext => "__has_include_next",
            // Special identifiers
            Token::Func => "__func__",
            Token::Nan => "__nan__",
            Token::Snan => "__snan__",
            Token::Inf => "__inf__",
            // Attribute identifiers
            Token::Section => "section",
            Token::Aligned => "aligned",
            Token::Packed => "packed",
            Token::WeakAttr => "weak",
            Token::Alias => "alias",
            Token::Used => "used",
            Token::Unused => "unused",
            Token::Format => "format",
            Token::Nodebug => "nodebug",
            Token::Cdecl => "cdecl",
            Token::Stdcall => "stdcall",
            Token::Fastcall => "fastcall",
            Token::Thiscall => "thiscall",
            Token::Regparm => "regparm",
            Token::Cleanup => "cleanup",
            Token::Constructor => "constructor",
            Token::Destructor => "destructor",
            Token::AlwaysInline => "always_inline",
            Token::Noinline => "__noinline__",
            Token::Pure => "pure",
            Token::Mode => "__mode__",
            Token::ModeQI => "__QI__",
            Token::ModeDI => "__DI__",
            Token::ModeHI => "__HI__",
            Token::ModeSI => "__SI__",
            Token::ModeWord => "__word__",
            Token::Dllexport => "dllexport",
            Token::Dllimport => "dllimport",
            Token::Nodecorate => "nodecorate",
            Token::Visibility => "visibility",
            // GCC builtins
            Token::BuiltinTypes => "__builtin_types_compatible_p",
            Token::BuiltinChooseExpr => "__builtin_choose_expr",
            Token::BuiltinConstantP => "__builtin_constant_p",
            Token::BuiltinFrameAddress => "__builtin_frame_address",
            Token::BuiltinReturnAddress => "__builtin_return_address",
            Token::BuiltinExpect => "__builtin_expect",
            Token::BuiltinUnreachable => "__builtin_unreachable",
            Token::BuiltinVaStart => "__builtin_va_start",
            Token::BuiltinVaArg => "__builtin_va_arg",
            Token::BuiltinVaArgTypes => "__builtin_va_arg_types",
            Token::BuiltinOffsetof => "__builtin_offsetof",
            Token::BuiltinFfs => "__builtin_ffs",
            Token::BuiltinClz => "__builtin_clz",
            Token::BuiltinCtz => "__builtin_ctz",
            Token::BuiltinPopcount => "__builtin_popcount",
            // Atomic operations
            Token::AtomicStore => "__atomic_store",
            Token::AtomicLoad => "__atomic_load",
            Token::AtomicExchange => "__atomic_exchange",
            Token::AtomicCompareExchange => "__atomic_compare_exchange",
            Token::AtomicFetchAdd => "__atomic_fetch_add",
            Token::AtomicFetchSub => "__atomic_fetch_sub",
            Token::AtomicFetchOr => "__atomic_fetch_or",
            Token::AtomicFetchXor => "__atomic_fetch_xor",
            Token::AtomicFetchAnd => "__atomic_fetch_and",
            Token::AtomicFetchNand => "__atomic_fetch_nand",
            Token::AtomicAddFetch => "__atomic_add_fetch",
            Token::AtomicSubFetch => "__atomic_sub_fetch",
            Token::AtomicOrFetch => "__atomic_or_fetch",
            Token::AtomicXorFetch => "__atomic_xor_fetch",
            Token::AtomicAndFetch => "__atomic_and_fetch",
            Token::AtomicNandFetch => "__atomic_nand_fetch",
            // Pragma
            Token::Pack => "pack",
            Token::AsmPush => "push",
            Token::AsmPop => "pop",
            Token::Comment => "comment",
            Token::Lib => "lib",
            Token::PushMacro => "push_macro",
            Token::PopMacro => "pop_macro",
            Token::Once => "once",
            Token::Option => "option",
            // Runtime
            Token::Memcpy => "memcpy",
            Token::Memmove => "memmove",
            Token::Memset => "memset",
            Token::Memmove4 => "__aeabi_memmove4",
            Token::Memmove8 => "__aeabi_memmove8",
            Token::Divdi3 => "__divdi3",
            Token::Moddi3 => "__moddi3",
            Token::Udivdi3 => "__udivdi3",
            Token::Umoddi3 => "__umoddi3",
            Token::Ashrdi3 => "__ashrdi3",
            Token::Lshrdi3 => "__lshrdi3",
            Token::Ashldi3 => "__ashldi3",
            Token::Floatundisf => "__floatundisf",
            Token::Floatundidf => "__floatundidf",
            Token::Floatundixf => "__floatundixf",
            Token::Fixunsxfdi => "__fixunsxfdi",
            Token::Fixunssfdi => "__fixunssfdi",
            Token::Fixunsdfdi => "__fixunsdfdi",
            Token::AeabiIdivmod => "__aeabi_idivmod",
            Token::AeabiUidivmod => "__aeabi_uidivmod",
            Token::Divsi3 => "__divsi3",
            Token::Udivsi3 => "__udivsi3",
            Token::Floatdisf => "__floatdisf",
            Token::Floatdidf => "__floatdidf",
            Token::Fixsfdi => "__fixsfdi",
            Token::Fixdfdi => "__fixdfdi",
            Token::Modsi3 => "__modsi3",
            Token::Umodsi3 => "__umodsi3",
            Token::Floatdixf => "__floatdixf",
            Token::Fixunssfsi => "__fixunssfsi",
            Token::Fixunsdfsi => "__fixunsdfsi",
            Token::Fixunsxfsi => "__fixunsxfsi",
            Token::Fixxfdi => "__fixxfdi",
            Token::C67Divi => "_divi",
            Token::C67Divu => "_divu",
            Token::C67Divf => "_divf",
            Token::C67Divd => "_divd",
            Token::C67Remi => "_remi",
            Token::C67Remu => "_remu",
            Token::Alloca => "alloca",
            Token::Chkstk => "__chkstk",
            Token::Arm64ClearCache => "__arm64_clear_cache",
            Token::Addtf3 => "__addtf3",
            Token::Subtf3 => "__subtf3",
            Token::Multf3 => "__multf3",
            Token::Divtf3 => "__divtf3",
            Token::Extendsftf2 => "__extendsftf2",
            Token::Extenddftf2 => "__extenddftf2",
            Token::Trunctfsf2 => "__trunctfsf2",
            Token::Trunctfdf2 => "__trunctfdf2",
            Token::Negtf2 => "__negtf2",
            Token::Fixtfsi => "__fixtfsi",
            Token::Fixtfdi => "__fixtfdi",
            Token::Fixunstfsi => "__fixunstfsi",
            Token::Fixunstfdi => "__fixunstfdi",
            Token::Floatsitf => "__floatsitf",
            Token::Floatditf => "__floatditf",
            Token::Floatunsitf => "__floatunsitf",
            Token::Floatunditf => "__floatunditf",
            Token::Eqtf2 => "__eqtf2",
            Token::Netf2 => "__netf2",
            Token::Lttf2 => "__lttf2",
            Token::Letf2 => "__letf2",
            Token::Gttf2 => "__gttf2",
            Token::Getf2 => "__getf2",
            // Bounds checking
            Token::BoundPtrAdd => "__bound_ptr_add",
            Token::BoundPtrIndir1 => "__bound_ptr_indir1",
            Token::BoundPtrIndir2 => "__bound_ptr_indir2",
            Token::BoundPtrIndir4 => "__bound_ptr_indir4",
            Token::BoundPtrIndir8 => "__bound_ptr_indir8",
            Token::BoundPtrIndir12 => "__bound_ptr_indir12",
            Token::BoundPtrIndir16 => "__bound_ptr_indir16",
            Token::BoundMainArg => "__bound_main_arg",
            Token::BoundLocalNew => "__bound_local_new",
            Token::BoundLocalDelete => "__bound_local_delete",
            Token::BoundSetjmp => "__bound_setjmp",
            Token::BoundLongjmp => "__bound_longjmp",
            Token::BoundNewRegion => "__bound_new_region",
            Token::BoundAllocaNr => "__bound_alloca_nr",
            Token::Sigsetjmp => "sigsetjmp",
            Token::SigsetjmpInternal => "__sigsetjmp",
            Token::Siglongjmp => "siglongjmp",
            Token::Setjmp => "setjmp",
            Token::SetjmpInternal => "_setjmp",
            Token::Longjmp => "longjmp",
            // Operators
            Token::Arrow => "->",
            Token::Inc => "++",
            Token::Dec => "--",
            Token::Shl => "<<",
            Token::Shr => ">>",
            Token::Le => "<=",
            Token::Ge => ">=",
            Token::Eq => "==",
            Token::Ne => "!=",
            Token::Land => "&&",
            Token::Lor => "||",
            Token::Dots => "...",
            Token::Twosharps => "##",
            Token::AddAssign => "+=",
            Token::SubAssign => "-=",
            Token::MulAssign => "*=",
            Token::DivAssign => "/=",
            Token::ModAssign => "%=",
            Token::ShlAssign => "<<=",
            Token::ShrAssign => ">>=",
            Token::AndAssign => "&=",
            Token::OrAssign => "|=",
            Token::XorAssign => "^=",
            Token::LineFeed => "\\n",
            Token::Eof => "<eof>",
            // Literals
            Token::IntConst => "<int>",
            Token::UintConst => "<uint>",
            Token::LlongConst => "<llong>",
            Token::UllongConst => "<ullong>",
            Token::LongConst => "<long>",
            Token::UlongConst => "<ulong>",
            Token::FloatConst => "<float>",
            Token::DoubleConst => "<double>",
            Token::LdoubleConst => "<ldouble>",
            Token::CharConst => "<char>",
            Token::LcharConst => "<wchar>",
            Token::StringLiteral => "<string>",
            Token::LstringLiteral => "<wstring>",
            Token::PpNum => "<ppnum>",
            Token::PpStr => "<ppstr>",
            Token::LineNum => "<linenum>",
            Token::Identifier => "<identifier>",
        }
    }

    /// Returns the C operator precedence for this token, if applicable.
    ///
    /// Higher numbers mean higher precedence. Returns `None` for tokens
    /// that are not binary operators.
    ///
    /// Precedence levels (from C standard):
    /// - 1: `||` (logical OR)
    /// - 2: `&&` (logical AND)
    /// - 3: `|` (bitwise OR)
    /// - 4: `^` (bitwise XOR)
    /// - 5: `&` (bitwise AND)
    /// - 6: `==`, `!=`
    /// - 7: `<`, `>`, `<=`, `>=`
    /// - 8: `<<`, `>>`
    /// - 9: `+`, `-`
    /// - 10: `*`, `/`, `%`
    pub fn precedence(&self) -> Option<u8> {
        match self {
            Token::Lor => Some(1),
            Token::Land => Some(2),
            // Bitwise OR, XOR, AND are single characters in the source
            // and are handled by the parser at their raw values.
            // The following are for multi-character tokens:
            Token::Eq | Token::Ne => Some(6),
            Token::Le | Token::Ge => Some(7),
            Token::Shl | Token::Shr => Some(8),
            _ => None,
        }
    }

    /// Returns `true` if the token is a condition/comparison operator.
    ///
    /// Equivalent to C macro `TOK_ISCOND(t)` — tokens in the range
    /// `TOK_LAND` through `TOK_GT`.
    #[inline]
    pub fn is_condition(&self) -> bool {
        matches!(
            self,
            Token::Land
                | Token::Lor
                | Token::Eq
                | Token::Ne
                | Token::Le
                | Token::Ge
        )
    }

    /// Returns `true` if the token carries a constant value in `tokc`.
    ///
    /// Equivalent to C macro `TOK_HAS_VALUE(t)`.
    #[inline]
    pub fn has_value(&self) -> bool {
        matches!(
            self,
            Token::CharConst
                | Token::LcharConst
                | Token::IntConst
                | Token::UintConst
                | Token::LlongConst
                | Token::UllongConst
                | Token::LongConst
                | Token::UlongConst
                | Token::StringLiteral
                | Token::LstringLiteral
                | Token::FloatConst
                | Token::DoubleConst
                | Token::LdoubleConst
                | Token::PpNum
                | Token::PpStr
                | Token::LineNum
        )
    }
}

// ===========================================================================
// AsmDirective Enum — Assembler Directives (tcctok.h lines 367-418)
// ===========================================================================

/// Assembler directives recognized by TCC's built-in assembler.
///
/// These correspond to the `DEF_ASMDIR(x)` entries in `tcctok.h`,
/// representing GAS-syntax assembly directives (`.byte`, `.word`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsmDirective {
    /// `.byte` — emit byte value (must be first directive)
    Byte,
    /// `.word` — emit word value
    Word,
    /// `.align` — align to boundary
    Align,
    /// `.balign` — byte-align to boundary
    Balign,
    /// `.p2align` — power-of-2 align
    P2align,
    /// `.set` — set symbol value
    Set,
    /// `.skip` — skip bytes
    Skip,
    /// `.space` — emit space
    Space,
    /// `.string` — emit NUL-terminated string
    String,
    /// `.asciz` — emit NUL-terminated string (alias)
    Asciz,
    /// `.ascii` — emit string without NUL
    Ascii,
    /// `.file` — set file name
    File,
    /// `.globl` — declare global symbol
    Globl,
    /// `.global` — declare global symbol (alias)
    Global,
    /// `.weak` — declare weak symbol
    Weak,
    /// `.hidden` — set symbol visibility to hidden
    Hidden,
    /// `.ident` — emit identification string
    Ident,
    /// `.size` — set symbol size
    Size,
    /// `.type` — set symbol type
    Type,
    /// `.text` — switch to text section
    Text,
    /// `.data` — switch to data section
    Data,
    /// `.bss` — switch to BSS section
    Bss,
    /// `.previous` — switch to previous section
    Previous,
    /// `.pushsection` — push and switch section
    Pushsection,
    /// `.popsection` — pop section stack
    Popsection,
    /// `.fill` — fill with repeated value
    Fill,
    /// `.rept` — begin repeat block
    Rept,
    /// `.endr` — end repeat block
    Endr,
    /// `.org` — set location counter
    Org,
    /// `.quad` — emit 8-byte value
    Quad,
    /// `.short` — emit 2-byte value
    Short,
    /// `.long` — emit 4-byte value
    Long,
    /// `.int` — emit 4-byte value (alias)
    Int,
    /// `.symver` — set symbol version
    Symver,
    /// `.reloc` — emit relocation
    Reloc,
    /// `.section` — define section (must be last directive)
    Section,
    /// `.code16` — switch to 16-bit mode (i386 only)
    Code16,
    /// `.code32` — switch to 32-bit mode (i386 only)
    Code32,
    /// `.code64` — switch to 64-bit mode (x86_64 only)
    Code64,
    /// `.option` — assembler option (RISC-V only)
    RiscvOption,
}

impl AsmDirective {
    /// Returns the assembly directive string (with leading dot).
    pub fn as_str(&self) -> &'static str {
        match self {
            AsmDirective::Byte => ".byte",
            AsmDirective::Word => ".word",
            AsmDirective::Align => ".align",
            AsmDirective::Balign => ".balign",
            AsmDirective::P2align => ".p2align",
            AsmDirective::Set => ".set",
            AsmDirective::Skip => ".skip",
            AsmDirective::Space => ".space",
            AsmDirective::String => ".string",
            AsmDirective::Asciz => ".asciz",
            AsmDirective::Ascii => ".ascii",
            AsmDirective::File => ".file",
            AsmDirective::Globl => ".globl",
            AsmDirective::Global => ".global",
            AsmDirective::Weak => ".weak",
            AsmDirective::Hidden => ".hidden",
            AsmDirective::Ident => ".ident",
            AsmDirective::Size => ".size",
            AsmDirective::Type => ".type",
            AsmDirective::Text => ".text",
            AsmDirective::Data => ".data",
            AsmDirective::Bss => ".bss",
            AsmDirective::Previous => ".previous",
            AsmDirective::Pushsection => ".pushsection",
            AsmDirective::Popsection => ".popsection",
            AsmDirective::Fill => ".fill",
            AsmDirective::Rept => ".rept",
            AsmDirective::Endr => ".endr",
            AsmDirective::Org => ".org",
            AsmDirective::Quad => ".quad",
            AsmDirective::Short => ".short",
            AsmDirective::Long => ".long",
            AsmDirective::Int => ".int",
            AsmDirective::Symver => ".symver",
            AsmDirective::Reloc => ".reloc",
            AsmDirective::Section => ".section",
            AsmDirective::Code16 => ".code16",
            AsmDirective::Code32 => ".code32",
            AsmDirective::Code64 => ".code64",
            AsmDirective::RiscvOption => ".option",
        }
    }

    /// Parse an assembler directive from its string name (without leading dot).
    ///
    /// Returns `None` if the string does not match any known directive.
    pub fn from_str_name(name: &str) -> Option<AsmDirective> {
        match name {
            "byte" => Some(AsmDirective::Byte),
            "word" => Some(AsmDirective::Word),
            "align" => Some(AsmDirective::Align),
            "balign" => Some(AsmDirective::Balign),
            "p2align" => Some(AsmDirective::P2align),
            "set" => Some(AsmDirective::Set),
            "skip" => Some(AsmDirective::Skip),
            "space" => Some(AsmDirective::Space),
            "string" => Some(AsmDirective::String),
            "asciz" => Some(AsmDirective::Asciz),
            "ascii" => Some(AsmDirective::Ascii),
            "file" => Some(AsmDirective::File),
            "globl" => Some(AsmDirective::Globl),
            "global" => Some(AsmDirective::Global),
            "weak" => Some(AsmDirective::Weak),
            "hidden" => Some(AsmDirective::Hidden),
            "ident" => Some(AsmDirective::Ident),
            "size" => Some(AsmDirective::Size),
            "type" => Some(AsmDirective::Type),
            "text" => Some(AsmDirective::Text),
            "data" => Some(AsmDirective::Data),
            "bss" => Some(AsmDirective::Bss),
            "previous" => Some(AsmDirective::Previous),
            "pushsection" => Some(AsmDirective::Pushsection),
            "popsection" => Some(AsmDirective::Popsection),
            "fill" => Some(AsmDirective::Fill),
            "rept" => Some(AsmDirective::Rept),
            "endr" => Some(AsmDirective::Endr),
            "org" => Some(AsmDirective::Org),
            "quad" => Some(AsmDirective::Quad),
            "short" => Some(AsmDirective::Short),
            "long" => Some(AsmDirective::Long),
            "int" => Some(AsmDirective::Int),
            "symver" => Some(AsmDirective::Symver),
            "reloc" => Some(AsmDirective::Reloc),
            "section" => Some(AsmDirective::Section),
            "code16" => Some(AsmDirective::Code16),
            "code32" => Some(AsmDirective::Code32),
            "code64" => Some(AsmDirective::Code64),
            "option" => Some(AsmDirective::RiscvOption),
            _ => None,
        }
    }
}

// ===========================================================================
// AtomicOp Enum — Atomic Operation Identifiers
// ===========================================================================

/// Atomic operation types corresponding to C11/GCC `__atomic_*` builtins.
///
/// Used by the codegen module to dispatch atomic operation code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtomicOp {
    /// `__atomic_store`
    Store,
    /// `__atomic_load`
    Load,
    /// `__atomic_exchange`
    Exchange,
    /// `__atomic_compare_exchange`
    CompareExchange,
    /// `__atomic_fetch_add`
    FetchAdd,
    /// `__atomic_fetch_sub`
    FetchSub,
    /// `__atomic_fetch_or`
    FetchOr,
    /// `__atomic_fetch_xor`
    FetchXor,
    /// `__atomic_fetch_and`
    FetchAnd,
    /// `__atomic_fetch_nand`
    FetchNand,
    /// `__atomic_add_fetch`
    AddFetch,
    /// `__atomic_sub_fetch`
    SubFetch,
    /// `__atomic_or_fetch`
    OrFetch,
    /// `__atomic_xor_fetch`
    XorFetch,
    /// `__atomic_and_fetch`
    AndFetch,
    /// `__atomic_nand_fetch`
    NandFetch,
}

impl AtomicOp {
    /// Convert a `Token` to an `AtomicOp`, if applicable.
    pub fn from_token(tok: Token) -> Option<AtomicOp> {
        match tok {
            Token::AtomicStore => Some(AtomicOp::Store),
            Token::AtomicLoad => Some(AtomicOp::Load),
            Token::AtomicExchange => Some(AtomicOp::Exchange),
            Token::AtomicCompareExchange => Some(AtomicOp::CompareExchange),
            Token::AtomicFetchAdd => Some(AtomicOp::FetchAdd),
            Token::AtomicFetchSub => Some(AtomicOp::FetchSub),
            Token::AtomicFetchOr => Some(AtomicOp::FetchOr),
            Token::AtomicFetchXor => Some(AtomicOp::FetchXor),
            Token::AtomicFetchAnd => Some(AtomicOp::FetchAnd),
            Token::AtomicFetchNand => Some(AtomicOp::FetchNand),
            Token::AtomicAddFetch => Some(AtomicOp::AddFetch),
            Token::AtomicSubFetch => Some(AtomicOp::SubFetch),
            Token::AtomicOrFetch => Some(AtomicOp::OrFetch),
            Token::AtomicXorFetch => Some(AtomicOp::XorFetch),
            Token::AtomicAndFetch => Some(AtomicOp::AndFetch),
            Token::AtomicNandFetch => Some(AtomicOp::NandFetch),
            _ => None,
        }
    }

    /// Returns the C function name for this atomic operation.
    pub fn as_str(&self) -> &'static str {
        match self {
            AtomicOp::Store => "__atomic_store",
            AtomicOp::Load => "__atomic_load",
            AtomicOp::Exchange => "__atomic_exchange",
            AtomicOp::CompareExchange => "__atomic_compare_exchange",
            AtomicOp::FetchAdd => "__atomic_fetch_add",
            AtomicOp::FetchSub => "__atomic_fetch_sub",
            AtomicOp::FetchOr => "__atomic_fetch_or",
            AtomicOp::FetchXor => "__atomic_fetch_xor",
            AtomicOp::FetchAnd => "__atomic_fetch_and",
            AtomicOp::FetchNand => "__atomic_fetch_nand",
            AtomicOp::AddFetch => "__atomic_add_fetch",
            AtomicOp::SubFetch => "__atomic_sub_fetch",
            AtomicOp::OrFetch => "__atomic_or_fetch",
            AtomicOp::XorFetch => "__atomic_xor_fetch",
            AtomicOp::AndFetch => "__atomic_and_fetch",
            AtomicOp::NandFetch => "__atomic_nand_fetch",
        }
    }
}

// ===========================================================================
// Token Hash Function (Phase 5: TokenSym Management)
// From tcc.h / tccpp.c — the hash function used for the token symbol table
// ===========================================================================

/// Compute a hash value for a token string, for use in the token symbol table.
///
/// This is a faithful port of TCC's `tok_hash()` function. It produces a
/// hash in the range `[0, TOK_HASH_SIZE)` suitable for indexing into the
/// token hash table.
///
/// The hash algorithm is a simple byte-by-byte multiply-and-accumulate
/// using the constant `TOK_HASH_INIT` (1) and `TOK_HASH_FUNC`.
///
/// # Arguments
///
/// * `key` - The byte slice containing the token string.
///
/// # Returns
///
/// A hash value in `[0, TOK_HASH_SIZE)`.
pub fn tok_hash(key: &[u8]) -> usize {
    // Port of TCC's hash function from tccpp.c:
    //   h = TOK_HASH_INIT;
    //   while (len--) h = (h * 263 + *(unsigned char *)p++);
    //   return h & (TOK_HASH_SIZE - 1);
    let mut h: u32 = 1; // TOK_HASH_INIT = 1
    for &b in key {
        h = h.wrapping_mul(263).wrapping_add(b as u32);
    }
    (h as usize) & (TOK_HASH_SIZE - 1)
}

/// Allocate a constant token symbol entry from a static string.
///
/// Creates a new `TokenSym` for a known token string with the given token ID.
/// Used during compiler initialization to populate the keyword hash table
/// with all predefined tokens.
///
/// # Arguments
///
/// * `s` - The token string (keyword text, identifier, etc.).
/// * `tok_id` - The integer token ID to assign.
///
/// # Returns
///
/// A new `TokenSym` with the string data and token ID set, all symbol
/// pointers initialized to `None`, and `hash_next` set to `-1`.
pub fn tok_alloc_const(s: &str, tok_id: i32) -> TokenSym {
    TokenSym {
        hash_next: -1,
        sym_define: None,
        sym_label: None,
        sym_struct: None,
        sym_identifier: None,
        tok: tok_id,
        len: s.len() as i32,
        str_data: s.to_string(),
    }
}

/// Returns `true` if the given raw integer token code is an assignment operator.
///
/// Equivalent to C macro `TOK_ASSIGN(t)`: `t >= TOK_A_ADD && t <= TOK_A_SAR`.
#[inline]
pub fn tok_is_assign(t: i32) -> bool {
    (TOK_A_ADD..=TOK_A_SAR).contains(&t)
}

/// Returns the base operator character for an assignment operator token code.
///
/// Equivalent to C macro `TOK_ASSIGN_OP(t)`: indexes into `"+-*/%&|^<>"`.
/// Returns `None` if the token is not an assignment operator.
pub fn tok_assign_op(t: i32) -> Option<u8> {
    if tok_is_assign(t) {
        let ops = b"+-*/%&|^<>";
        let idx = (t - TOK_A_ADD) as usize;
        ops.get(idx).copied()
    } else {
        None
    }
}

/// Returns `true` if the given raw integer token code is a condition/comparison
/// operator (TOK_LAND through TOK_GT).
///
/// Equivalent to C macro `TOK_ISCOND(t)`.
#[inline]
pub fn tok_is_cond(t: i32) -> bool {
    (TOK_LAND..=TOK_GT).contains(&t)
}

/// Returns `true` if the given raw integer token code carries a value payload.
///
/// Equivalent to C macro `TOK_HAS_VALUE(t)`.
#[inline]
pub fn tok_has_value(t: i32) -> bool {
    (TOK_CCHAR..=TOK_LINENUM).contains(&t)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_table_build() {
        let table = build_keyword_table();
        assert_eq!(table.get("if"), Some(&Token::If));
        assert_eq!(table.get("else"), Some(&Token::Else));
        assert_eq!(table.get("__const"), Some(&Token::Const));
        assert_eq!(table.get("__const__"), Some(&Token::Const));
        assert_eq!(table.get("const"), Some(&Token::Const));
        assert_eq!(table.get("_Atomic"), Some(&Token::Atomic));
        assert_eq!(table.get("__builtin_expect"), Some(&Token::BuiltinExpect));
        assert_eq!(table.get("_Complex"), Some(&Token::Complex));
        assert_eq!(table.get("nonexistent"), None);
    }

    #[test]
    fn test_token_type_specifier() {
        assert!(Token::Void.is_type_specifier());
        assert!(Token::Int.is_type_specifier());
        assert!(Token::Struct.is_type_specifier());
        assert!(Token::Complex.is_type_specifier());
        assert!(!Token::If.is_type_specifier());
        assert!(!Token::Extern.is_type_specifier());
    }

    #[test]
    fn test_token_storage_class() {
        assert!(Token::Extern.is_storage_class());
        assert!(Token::Static.is_storage_class());
        assert!(Token::Typedef.is_storage_class());
        assert!(Token::ThreadLocal.is_storage_class());
        assert!(!Token::Const.is_storage_class());
        assert!(!Token::If.is_storage_class());
    }

    #[test]
    fn test_token_type_qualifier() {
        assert!(Token::Const.is_type_qualifier());
        assert!(Token::Volatile.is_type_qualifier());
        assert!(Token::Restrict.is_type_qualifier());
        assert!(Token::Atomic.is_type_qualifier());
        assert!(!Token::Static.is_type_qualifier());
    }

    #[test]
    fn test_token_assignment_op() {
        assert!(Token::AddAssign.is_assignment_op());
        assert!(Token::XorAssign.is_assignment_op());
        assert!(!Token::Eq.is_assignment_op());
        assert!(!Token::Arrow.is_assignment_op());
    }

    #[test]
    fn test_token_as_str() {
        assert_eq!(Token::If.as_str(), "if");
        assert_eq!(Token::Arrow.as_str(), "->");
        assert_eq!(Token::AddAssign.as_str(), "+=");
        assert_eq!(Token::Eof.as_str(), "<eof>");
        assert_eq!(Token::BuiltinExpect.as_str(), "__builtin_expect");
        assert_eq!(Token::Noreturn.as_str(), "_Noreturn");
    }

    #[test]
    fn test_token_precedence() {
        assert_eq!(Token::Lor.precedence(), Some(1));
        assert_eq!(Token::Land.precedence(), Some(2));
        assert_eq!(Token::Eq.precedence(), Some(6));
        assert_eq!(Token::Ne.precedence(), Some(6));
        assert_eq!(Token::Le.precedence(), Some(7));
        assert_eq!(Token::Shl.precedence(), Some(8));
        assert_eq!(Token::If.precedence(), None);
    }

    #[test]
    fn test_tok_hash_consistency() {
        // Same input produces same hash
        let h1 = tok_hash(b"hello");
        let h2 = tok_hash(b"hello");
        assert_eq!(h1, h2);
        // Hash is within range
        assert!(h1 < TOK_HASH_SIZE);
        // Different inputs should (usually) produce different hashes
        let h3 = tok_hash(b"world");
        assert!(h3 < TOK_HASH_SIZE);
    }

    #[test]
    fn test_tok_alloc_const() {
        let ts = tok_alloc_const("test_token", 42);
        assert_eq!(ts.tok, 42);
        assert_eq!(ts.len, 10);
        assert_eq!(ts.str_data, "test_token");
        assert_eq!(ts.hash_next, -1);
        assert!(ts.sym_define.is_none());
        assert!(ts.sym_label.is_none());
        assert!(ts.sym_struct.is_none());
        assert!(ts.sym_identifier.is_none());
    }

    #[test]
    fn test_tok_is_assign() {
        assert!(tok_is_assign(TOK_A_ADD));
        assert!(tok_is_assign(TOK_A_SAR));
        assert!(tok_is_assign(TOK_A_MUL));
        assert!(!tok_is_assign(TOK_ARROW));
        assert!(!tok_is_assign(0));
    }

    #[test]
    fn test_tok_assign_op() {
        assert_eq!(tok_assign_op(TOK_A_ADD), Some(b'+'));
        assert_eq!(tok_assign_op(TOK_A_SUB), Some(b'-'));
        assert_eq!(tok_assign_op(TOK_A_MUL), Some(b'*'));
        assert_eq!(tok_assign_op(TOK_A_DIV), Some(b'/'));
        assert_eq!(tok_assign_op(TOK_A_MOD), Some(b'%'));
        assert_eq!(tok_assign_op(TOK_A_AND), Some(b'&'));
        assert_eq!(tok_assign_op(TOK_A_OR), Some(b'|'));
        assert_eq!(tok_assign_op(TOK_A_XOR), Some(b'^'));
        assert_eq!(tok_assign_op(TOK_A_SHL), Some(b'<'));
        assert_eq!(tok_assign_op(TOK_A_SAR), Some(b'>'));
        assert_eq!(tok_assign_op(0), None);
    }

    #[test]
    fn test_tok_is_cond() {
        assert!(tok_is_cond(TOK_LAND));
        assert!(tok_is_cond(TOK_LOR));
        assert!(tok_is_cond(TOK_EQ));
        assert!(tok_is_cond(TOK_GT));
        assert!(!tok_is_cond(TOK_DEC));
        assert!(!tok_is_cond(0));
    }

    #[test]
    fn test_tok_has_value() {
        assert!(tok_has_value(TOK_CCHAR));
        assert!(tok_has_value(TOK_CINT));
        assert!(tok_has_value(TOK_STR));
        assert!(tok_has_value(TOK_CFLOAT));
        assert!(tok_has_value(TOK_LINENUM));
        assert!(!tok_has_value(TOK_ARROW));
        assert!(!tok_has_value(0));
    }

    #[test]
    fn test_token_has_value_method() {
        assert!(Token::IntConst.has_value());
        assert!(Token::FloatConst.has_value());
        assert!(Token::StringLiteral.has_value());
        assert!(Token::CharConst.has_value());
        assert!(!Token::If.has_value());
        assert!(!Token::Arrow.has_value());
    }

    #[test]
    fn test_asm_directive_roundtrip() {
        // Every directive should parse from its name
        let directives = [
            ("byte", AsmDirective::Byte),
            ("word", AsmDirective::Word),
            ("align", AsmDirective::Align),
            ("section", AsmDirective::Section),
            ("text", AsmDirective::Text),
            ("data", AsmDirective::Data),
            ("bss", AsmDirective::Bss),
            ("quad", AsmDirective::Quad),
        ];
        for (name, expected) in &directives {
            assert_eq!(AsmDirective::from_str_name(name), Some(*expected));
        }
        assert_eq!(AsmDirective::from_str_name("invalid"), None);
    }

    #[test]
    fn test_atomic_op_from_token() {
        assert_eq!(
            AtomicOp::from_token(Token::AtomicStore),
            Some(AtomicOp::Store)
        );
        assert_eq!(
            AtomicOp::from_token(Token::AtomicFetchAdd),
            Some(AtomicOp::FetchAdd)
        );
        assert_eq!(
            AtomicOp::from_token(Token::AtomicNandFetch),
            Some(AtomicOp::NandFetch)
        );
        assert_eq!(AtomicOp::from_token(Token::If), None);
    }

    #[test]
    fn test_constants_match_c_values() {
        // Verify key constants match their C counterparts
        assert_eq!(TOK_HASH_SIZE, 16384);
        assert_eq!(TOK_ALLOC_INCR, 512);
        assert_eq!(TOK_MAX_SIZE, 4);
        assert_eq!(TOK_EOF, -1);
        assert_eq!(TOK_LINEFEED, 10);
        assert_eq!(TOK_IDENT, 256);
        assert_eq!(TOK_DEC, 0x80);
        assert_eq!(TOK_INC, 0x82);
        assert_eq!(TOK_UDIV, 0x83);
        assert_eq!(TOK_LAND, 0x90);
        assert_eq!(TOK_LOR, 0x91);
        assert_eq!(TOK_ULT, 0x92);
        assert_eq!(TOK_EQ, 0x94);
        assert_eq!(TOK_NE, 0x95);
        assert_eq!(TOK_LT, 0x9c);
        assert_eq!(TOK_GT, 0x9f);
        assert_eq!(TOK_ARROW, 0xa0);
        assert_eq!(TOK_DOTS, 0xa1);
        assert_eq!(TOK_TWOSHARPS, 0xa3);
        assert_eq!(TOK_A_ADD, 0xb0);
        assert_eq!(TOK_A_SAR, 0xb9);
        assert_eq!(TOK_CCHAR, 0xc0);
        assert_eq!(TOK_STR, 0xc8);
        assert_eq!(TOK_CFLOAT, 0xca);
        assert_eq!(TOK_LINENUM, 0xcf);
        assert_eq!(TOK_SHL, b'<' as i32);
        assert_eq!(TOK_SAR, b'>' as i32);
        assert_eq!(TOK_NEG, TOK_MID);
    }

    #[test]
    fn test_keyword_table_comprehensive() {
        let table = build_keyword_table();
        // Verify the table has a reasonable number of entries
        // (more entries than unique tokens since alternatives map to same token)
        assert!(table.len() >= 100, "table.len() = {} < 100", table.len());

        // Check all KEYWORDS entries exist in the table
        for &(s, tok) in KEYWORDS.iter() {
            assert_eq!(
                table.get(s),
                Some(&tok),
                "Keyword '{}' not found or mismatched in table",
                s
            );
        }
    }
}
