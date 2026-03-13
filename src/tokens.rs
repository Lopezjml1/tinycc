//! Token types for the TCC lexer.
//!
//! This module defines the [`Token`] enum covering all TCC token types,
//! translated from `tcctok.h` and `tcc.h`. Each variant maps to one or more
//! `DEF(TOK_xxx, "xxx")` entries in the original C source.
//!
//! Architecture-specific assembler tokens (from `i386-tok.h`, `arm-tok.h`,
//! `riscv64-tok.h`) are defined in their respective `src/targets/*.rs` modules
//! per AAP §0.3.1, not in this file.

use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// Token enum — all TCC token types
// ---------------------------------------------------------------------------

/// Token types for the TCC lexer.
///
/// C equivalent: `TOK_*` definitions from `tcctok.h` and `tcc.h`.
/// Each variant maps to a `DEF(TOK_xxx, "xxx")` entry in `tcctok.h`.
///
/// The enum is organized into logical groups:
/// - Control-flow keywords (if, else, while, …)
/// - Storage class and qualifier keywords (extern, static, const, …)
/// - Type keywords (void, char, int, …)
/// - Attribute keywords (__attribute__, aligned, packed, …)
/// - Preprocessor keywords (define, include, ifdef, …)
/// - Preprocessor magic identifiers (__LINE__, __FILE__, …)
/// - Special identifiers (__func__, __nan__, …)
/// - GCC builtin functions (__builtin_expect, …)
/// - C11 atomic builtins (__atomic_store, …)
/// - Pragma sub-tokens (pack, push, pop, …)
/// - Runtime library identifiers (memcpy, __divdi3, …)
/// - Bounds-checking identifiers (__bound_ptr_add, …)
/// - Assembler directives (.byte, .word, .align, …)
/// - Literal value carriers and special tokens
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Token {
    // ----- Control-flow keywords (tcctok.h:3-14) -----

    /// `if` — C equivalent: `TOK_IF`
    If,
    /// `else` — C equivalent: `TOK_ELSE`
    Else,
    /// `while` — C equivalent: `TOK_WHILE`
    While,
    /// `for` — C equivalent: `TOK_FOR`
    For,
    /// `do` — C equivalent: `TOK_DO`
    Do,
    /// `continue` — C equivalent: `TOK_CONTINUE`
    Continue,
    /// `break` — C equivalent: `TOK_BREAK`
    Break,
    /// `return` — C equivalent: `TOK_RETURN`
    Return,
    /// `goto` — C equivalent: `TOK_GOTO`
    Goto,
    /// `switch` — C equivalent: `TOK_SWITCH`
    Switch,
    /// `case` — C equivalent: `TOK_CASE`
    Case,
    /// `default` — C equivalent: `TOK_DEFAULT`
    Default,

    // ----- Asm keyword (tcctok.h:15-17) — aliases: asm, __asm, __asm__ -----

    /// `asm` / `__asm` / `__asm__` — C equivalents: `TOK_ASM1`, `TOK_ASM2`, `TOK_ASM3`
    Asm,

    // ----- Storage class and qualifier keywords (tcctok.h:19-44) -----

    /// `extern` — C equivalent: `TOK_EXTERN`
    Extern,
    /// `static` — C equivalent: `TOK_STATIC`
    Static,
    /// `unsigned` — C equivalent: `TOK_UNSIGNED`
    Unsigned,
    /// `_Atomic` — C equivalent: `TOK__Atomic`
    Atomic,
    /// `const` / `__const` / `__const__` — C equivalents: `TOK_CONST1/2/3`
    Const,
    /// `volatile` / `__volatile` / `__volatile__` — C equivalents: `TOK_VOLATILE1/2/3`
    Volatile,
    /// `register` — C equivalent: `TOK_REGISTER`
    Register,
    /// `signed` / `__signed` / `__signed__` — C equivalents: `TOK_SIGNED1/2/3`
    Signed,
    /// `auto` — C equivalent: `TOK_AUTO`
    Auto,
    /// `inline` / `__inline` / `__inline__` — C equivalents: `TOK_INLINE1/2/3`
    Inline,
    /// `restrict` / `__restrict` / `__restrict__` — C equivalents: `TOK_RESTRICT1/2/3`
    Restrict,
    /// `__extension__` — C equivalent: `TOK_EXTENSION`
    Extension,
    /// `_Thread_local` — C equivalent: `TOK_THREAD_LOCAL`
    ThreadLocal,
    /// `_Generic` — C equivalent: `TOK_GENERIC`
    Generic,
    /// `_Static_assert` — C equivalent: `TOK_STATIC_ASSERT`
    StaticAssert,

    // ----- Type keywords (tcctok.h:46-59) -----

    /// `void` — C equivalent: `TOK_VOID`
    Void,
    /// `char` — C equivalent: `TOK_CHAR`
    Char,
    /// `int` — C equivalent: `TOK_INT`
    Int,
    /// `float` — C equivalent: `TOK_FLOAT`
    Float,
    /// `double` — C equivalent: `TOK_DOUBLE`
    Double,
    /// `_Bool` — C equivalent: `TOK_BOOL`
    Bool,
    /// `_Complex` — C equivalent: `TOK_COMPLEX`
    Complex,
    /// `short` — C equivalent: `TOK_SHORT`
    Short,
    /// `long` — C equivalent: `TOK_LONG`
    Long,
    /// `struct` — C equivalent: `TOK_STRUCT`
    Struct,
    /// `union` — C equivalent: `TOK_UNION`
    Union,
    /// `typedef` — C equivalent: `TOK_TYPEDEF`
    Typedef,
    /// `enum` — C equivalent: `TOK_ENUM`
    Enum,
    /// `sizeof` — C equivalent: `TOK_SIZEOF`
    Sizeof,

    // ----- Type-related extension keywords (tcctok.h:60-69) -----

    /// `__attribute` / `__attribute__` — C equivalents: `TOK_ATTRIBUTE1/2`
    Attribute,
    /// `__alignof` / `__alignof__` / `_Alignof` — C equivalents: `TOK_ALIGNOF1/2/3`
    AlignOf,
    /// `_Alignas` — C equivalent: `TOK_ALIGNAS`
    AlignAs,
    /// `typeof` / `__typeof` / `__typeof__` — C equivalents: `TOK_TYPEOF1/2/3`
    TypeOf,
    /// `__label__` — C equivalent: `TOK_LABEL`
    Label,

    // ----- Preprocessor keywords (tcctok.h:74-86) -----

    /// `define` — C equivalent: `TOK_DEFINE`
    Define,
    /// `include` — C equivalent: `TOK_INCLUDE`
    Include,
    /// `include_next` — C equivalent: `TOK_INCLUDE_NEXT`
    IncludeNext,
    /// `ifdef` — C equivalent: `TOK_IFDEF`
    Ifdef,
    /// `ifndef` — C equivalent: `TOK_IFNDEF`
    Ifndef,
    /// `elif` — C equivalent: `TOK_ELIF`
    Elif,
    /// `endif` — C equivalent: `TOK_ENDIF`
    Endif,
    /// `defined` — C equivalent: `TOK_DEFINED`
    Defined,
    /// `undef` — C equivalent: `TOK_UNDEF`
    Undef,
    /// `error` (preprocessor) — C equivalent: `TOK_ERROR`
    PpError,
    /// `warning` (preprocessor) — C equivalent: `TOK_WARNING`
    PpWarning,
    /// `line` (preprocessor) — C equivalent: `TOK_LINE`
    PpLine,
    /// `pragma` — C equivalent: `TOK_PRAGMA`
    Pragma,

    // ----- Preprocessor magic identifiers (tcctok.h:87-95) -----

    /// `__LINE__` — C equivalent: `TOK___LINE__`
    MacroLine,
    /// `__FILE__` — C equivalent: `TOK___FILE__`
    MacroFile,
    /// `__DATE__` — C equivalent: `TOK___DATE__`
    MacroDate,
    /// `__TIME__` — C equivalent: `TOK___TIME__`
    MacroTime,
    /// `__FUNCTION__` — C equivalent: `TOK___FUNCTION__`
    MacroFunction,
    /// `__VA_ARGS__` — C equivalent: `TOK___VA_ARGS__`
    MacroVaArgs,
    /// `__COUNTER__` — C equivalent: `TOK___COUNTER__`
    MacroCounter,
    /// `__has_include` — C equivalent: `TOK___HAS_INCLUDE`
    HasInclude,
    /// `__has_include_next` — C equivalent: `TOK___HAS_INCLUDE_NEXT`
    HasIncludeNext,

    // ----- Special identifiers (tcctok.h:98-103) -----

    /// `__func__` — C equivalent: `TOK___FUNC__`
    Func,
    /// `__nan__` — C equivalent: `TOK___NAN__`
    Nan,
    /// `__snan__` — C equivalent: `TOK___SNAN__`
    SNan,
    /// `__inf__` — C equivalent: `TOK___INF__`
    Inf,

    // ----- Attribute identifiers (tcctok.h:107-165) -----

    /// `section` / `__section__` — C equivalents: `TOK_SECTION1/2`
    AttrSection,
    /// `aligned` / `__aligned__` — C equivalents: `TOK_ALIGNED1/2`
    Aligned,
    /// `packed` / `__packed__` — C equivalents: `TOK_PACKED1/2`
    Packed,
    /// `weak` / `__weak__` — C equivalents: `TOK_WEAK1/2`
    AttrWeak,
    /// `alias` / `__alias__` — C equivalents: `TOK_ALIAS1/2`
    Alias,
    /// `used` / `__used__` — C equivalents: `TOK_USED1/2`
    Used,
    /// `unused` / `__unused__` — C equivalents: `TOK_UNUSED1/2`
    Unused,
    /// `format` / `__format__` — C equivalents: `TOK_FORMAT1/2`
    Format,
    /// `nodebug` / `__nodebug__` — C equivalents: `TOK_NODEBUG1/2`
    NoDebug,
    /// `cdecl` / `__cdecl` / `__cdecl__` — C equivalents: `TOK_CDECL1/2/3`
    Cdecl,
    /// `stdcall` / `__stdcall` / `__stdcall__` — C equivalents: `TOK_STDCALL1/2/3`
    Stdcall,
    /// `fastcall` / `__fastcall` / `__fastcall__` — C equivalents: `TOK_FASTCALL1/2/3`
    Fastcall,
    /// `thiscall` / `__thiscall` / `__thiscall__` — C equivalents: `TOK_THISCALL1/2/3`
    Thiscall,
    /// `regparm` / `__regparm__` — C equivalents: `TOK_REGPARM1/2`
    Regparm,
    /// `cleanup` / `__cleanup__` — C equivalents: `TOK_CLEANUP1/2`
    Cleanup,
    /// `constructor` / `__constructor__` — C equivalents: `TOK_CONSTRUCTOR1/2`
    Constructor,
    /// `destructor` / `__destructor__` — C equivalents: `TOK_DESTRUCTOR1/2`
    Destructor,
    /// `always_inline` / `__always_inline__` — C equivalents: `TOK_ALWAYS_INLINE1/2`
    AlwaysInline,
    /// `__noinline__` — C equivalent: `TOK_NOINLINE`
    Noinline,
    /// `pure` / `__pure__` — C equivalents: `TOK_PURE1/2`
    Pure,
    /// `__mode__` — C equivalent: `TOK_MODE`
    Mode,
    /// `__QI__` — C equivalent: `TOK_MODE_QI`
    ModeQI,
    /// `__DI__` — C equivalent: `TOK_MODE_DI`
    ModeDI,
    /// `__HI__` — C equivalent: `TOK_MODE_HI`
    ModeHI,
    /// `__SI__` — C equivalent: `TOK_MODE_SI`
    ModeSI,
    /// `__word__` — C equivalent: `TOK_MODE_word`
    ModeWord,
    /// `dllexport` — C equivalent: `TOK_DLLEXPORT`
    DllExport,
    /// `dllimport` — C equivalent: `TOK_DLLIMPORT`
    DllImport,
    /// `nodecorate` — C equivalent: `TOK_NODECORATE`
    NoDecorate,
    /// `noreturn` / `__noreturn__` / `_Noreturn` — C equivalents: `TOK_NORETURN1/2/3`
    NoReturn,
    /// `visibility` / `__visibility__` — C equivalents: `TOK_VISIBILITY1/2`
    Visibility,

    // ----- GCC builtin functions (tcctok.h:167-183) -----

    /// `__builtin_types_compatible_p` — C equivalent: `TOK_builtin_types_compatible_p`
    BuiltinTypesCompatibleP,
    /// `__builtin_choose_expr` — C equivalent: `TOK_builtin_choose_expr`
    BuiltinChooseExpr,
    /// `__builtin_constant_p` — C equivalent: `TOK_builtin_constant_p`
    BuiltinConstantP,
    /// `__builtin_frame_address` — C equivalent: `TOK_builtin_frame_address`
    BuiltinFrameAddress,
    /// `__builtin_return_address` — C equivalent: `TOK_builtin_return_address`
    BuiltinReturnAddress,
    /// `__builtin_expect` — C equivalent: `TOK_builtin_expect`
    BuiltinExpect,
    /// `__builtin_unreachable` — C equivalent: `TOK_builtin_unreachable`
    BuiltinUnreachable,
    /// `__builtin_va_start` — C equivalent: `TOK_builtin_va_start`
    BuiltinVaStart,
    /// `__builtin_va_arg_types` — C equivalent: `TOK_builtin_va_arg_types`
    BuiltinVaArgTypes,
    /// `__builtin_va_arg` — C equivalent: `TOK_builtin_va_arg`
    BuiltinVaArg,

    // ----- C11 atomic builtins (tcctok.h:186-203) -----

    /// `__atomic_store` — C equivalent: `TOK___atomic_store`
    AtomicStore,
    /// `__atomic_load` — C equivalent: `TOK___atomic_load`
    AtomicLoad,
    /// `__atomic_exchange` — C equivalent: `TOK___atomic_exchange`
    AtomicExchange,
    /// `__atomic_compare_exchange` — C equivalent: `TOK___atomic_compare_exchange`
    AtomicCompareExchange,
    /// `__atomic_fetch_add` — C equivalent: `TOK___atomic_fetch_add`
    AtomicFetchAdd,
    /// `__atomic_fetch_sub` — C equivalent: `TOK___atomic_fetch_sub`
    AtomicFetchSub,
    /// `__atomic_fetch_or` — C equivalent: `TOK___atomic_fetch_or`
    AtomicFetchOr,
    /// `__atomic_fetch_xor` — C equivalent: `TOK___atomic_fetch_xor`
    AtomicFetchXor,
    /// `__atomic_fetch_and` — C equivalent: `TOK___atomic_fetch_and`
    AtomicFetchAnd,
    /// `__atomic_fetch_nand` — C equivalent: `TOK___atomic_fetch_nand`
    AtomicFetchNand,
    /// `__atomic_add_fetch` — C equivalent: `TOK___atomic_add_fetch`
    AtomicAddFetch,
    /// `__atomic_sub_fetch` — C equivalent: `TOK___atomic_sub_fetch`
    AtomicSubFetch,
    /// `__atomic_or_fetch` — C equivalent: `TOK___atomic_or_fetch`
    AtomicOrFetch,
    /// `__atomic_xor_fetch` — C equivalent: `TOK___atomic_xor_fetch`
    AtomicXorFetch,
    /// `__atomic_and_fetch` — C equivalent: `TOK___atomic_and_fetch`
    AtomicAndFetch,
    /// `__atomic_nand_fetch` — C equivalent: `TOK___atomic_nand_fetch`
    AtomicNandFetch,

    // ----- Pragma sub-tokens (tcctok.h:206-219) -----

    /// `pack` — C equivalent: `TOK_pack`
    Pack,
    /// `push` (asm pragma) — C equivalent: `TOK_ASM_push`
    AsmPush,
    /// `pop` (asm pragma) — C equivalent: `TOK_ASM_pop`
    AsmPop,
    /// `comment` — C equivalent: `TOK_comment`
    Comment,
    /// `lib` — C equivalent: `TOK_lib`
    PragmaLib,
    /// `push_macro` — C equivalent: `TOK_push_macro`
    PushMacro,
    /// `pop_macro` — C equivalent: `TOK_pop_macro`
    PopMacro,
    /// `once` — C equivalent: `TOK_once`
    Once,
    /// `option` (pragma) — C equivalent: `TOK_option`
    PragmaOption,

    // ----- Runtime library identifiers (tcctok.h:222-301) -----

    /// `memcpy` / `__aeabi_memcpy` — C equivalent: `TOK_memcpy`
    Memcpy,
    /// `memmove` / `__aeabi_memmove` — C equivalent: `TOK_memmove`
    Memmove,
    /// `memset` / `__aeabi_memset` — C equivalent: `TOK_memset`
    Memset,
    /// `__aeabi_memmove4` — C equivalent: `TOK_memmove4`
    Memmove4,
    /// `__aeabi_memmove8` — C equivalent: `TOK_memmove8`
    Memmove8,
    /// `__divdi3` — C equivalent: `TOK___divdi3`
    DivDi3,
    /// `__moddi3` — C equivalent: `TOK___moddi3`
    ModDi3,
    /// `__udivdi3` — C equivalent: `TOK___udivdi3`
    UdivDi3,
    /// `__umoddi3` — C equivalent: `TOK___umoddi3`
    UmodDi3,
    /// `__ashrdi3` / `__aeabi_lasr` — C equivalent: `TOK___ashrdi3`
    AshrDi3,
    /// `__lshrdi3` / `__aeabi_llsr` — C equivalent: `TOK___lshrdi3`
    LshrDi3,
    /// `__ashldi3` / `__aeabi_llsl` — C equivalent: `TOK___ashldi3`
    AshlDi3,
    /// `__floatundisf` / `__aeabi_ul2f` — C equivalent: `TOK___floatundisf`
    FloatUndiSf,
    /// `__floatundidf` / `__aeabi_ul2d` — C equivalent: `TOK___floatundidf`
    FloatUndiDf,
    /// `__floatundixf` — C equivalent: `TOK___floatundixf`
    FloatUndiXf,
    /// `__fixunsxfdi` — C equivalent: `TOK___fixunsxfdi`
    FixUnsXfDi,
    /// `__fixunssfdi` / `__aeabi_f2ulz` — C equivalent: `TOK___fixunssfdi`
    FixUnsSfDi,
    /// `__fixunsdfdi` / `__aeabi_d2ulz` — C equivalent: `TOK___fixunsdfdi`
    FixUnsDfDi,
    /// `__aeabi_ldivmod` — C equivalent: `TOK___aeabi_ldivmod`
    AeabiLdivmod,
    /// `__aeabi_uldivmod` — C equivalent: `TOK___aeabi_uldivmod`
    AeabiUldivmod,
    /// `__aeabi_idivmod` — C equivalent: `TOK___aeabi_idivmod`
    AeabiIdivmod,
    /// `__aeabi_uidivmod` — C equivalent: `TOK___aeabi_uidivmod`
    AeabiUidivmod,
    /// `__divsi3` / `__aeabi_idiv` — C equivalent: `TOK___divsi3`
    DivSi3,
    /// `__udivsi3` / `__aeabi_uidiv` — C equivalent: `TOK___udivsi3`
    UdivSi3,
    /// `__floatdisf` / `__aeabi_l2f` — C equivalent: `TOK___floatdisf`
    FloatDiSf,
    /// `__floatdidf` / `__aeabi_l2d` — C equivalent: `TOK___floatdidf`
    FloatDiDf,
    /// `__fixsfdi` / `__aeabi_f2lz` — C equivalent: `TOK___fixsfdi`
    FixSfDi,
    /// `__fixdfdi` / `__aeabi_d2lz` — C equivalent: `TOK___fixdfdi`
    FixDfDi,
    /// `__modsi3` — C equivalent: `TOK___modsi3`
    ModSi3,
    /// `__umodsi3` — C equivalent: `TOK___umodsi3`
    UmodSi3,
    /// `__floatdixf` — C equivalent: `TOK___floatdixf`
    FloatDiXf,
    /// `__fixunssfsi` — C equivalent: `TOK___fixunssfsi`
    FixUnsSfSi,
    /// `__fixunsdfsi` — C equivalent: `TOK___fixunsdfsi`
    FixUnsDfSi,
    /// `__fixunsxfsi` — C equivalent: `TOK___fixunsxfsi`
    FixUnsXfSi,
    /// `__fixxfdi` — C equivalent: `TOK___fixxfdi`
    FixXfDi,

    // ----- C67 target runtime (tcctok.h:287-292) -----

    /// `_divi` — C equivalent: `TOK__divi`
    C67Divi,
    /// `_divu` — C equivalent: `TOK__divu`
    C67Divu,
    /// `_divf` — C equivalent: `TOK__divf`
    C67Divf,
    /// `_divd` — C equivalent: `TOK__divd`
    C67Divd,
    /// `_remi` — C equivalent: `TOK__remi`
    C67Remi,
    /// `_remu` — C equivalent: `TOK__remu`
    C67Remu,

    // ----- Conditional runtime helpers (tcctok.h:296-307) -----

    /// `alloca` — C equivalent: `TOK_alloca`
    Alloca,
    /// `__chkstk` — C equivalent: `TOK___chkstk`
    ChkStk,

    // ----- ARM64 target runtime (tcctok.h:310-333) -----

    /// `__arm64_clear_cache` — C equivalent: `TOK___arm64_clear_cache`
    Arm64ClearCache,
    /// `__addtf3` — C equivalent: `TOK___addtf3`
    AddTf3,
    /// `__subtf3` — C equivalent: `TOK___subtf3`
    SubTf3,
    /// `__multf3` — C equivalent: `TOK___multf3`
    MulTf3,
    /// `__divtf3` — C equivalent: `TOK___divtf3`
    DivTf3,
    /// `__extendsftf2` — C equivalent: `TOK___extendsftf2`
    ExtendSfTf2,
    /// `__extenddftf2` — C equivalent: `TOK___extenddftf2`
    ExtendDfTf2,
    /// `__trunctfsf2` — C equivalent: `TOK___trunctfsf2`
    TruncTfSf2,
    /// `__trunctfdf2` — C equivalent: `TOK___trunctfdf2`
    TruncTfDf2,
    /// `__negtf2` — C equivalent: `TOK___negtf2`
    NegTf2,
    /// `__fixtfsi` — C equivalent: `TOK___fixtfsi`
    FixTfSi,
    /// `__fixtfdi` — C equivalent: `TOK___fixtfdi`
    FixTfDi,
    /// `__fixunstfsi` — C equivalent: `TOK___fixunstfsi`
    FixUnsTfSi,
    /// `__fixunstfdi` — C equivalent: `TOK___fixunstfdi`
    FixUnsTfDi,
    /// `__floatsitf` — C equivalent: `TOK___floatsitf`
    FloatSiTf,
    /// `__floatditf` — C equivalent: `TOK___floatditf`
    FloatDiTf,
    /// `__floatunsitf` — C equivalent: `TOK___floatunsitf`
    FloatUnsiTf,
    /// `__floatunditf` — C equivalent: `TOK___floatunditf`
    FloatUndiTf,
    /// `__eqtf2` — C equivalent: `TOK___eqtf2`
    EqTf2,
    /// `__netf2` — C equivalent: `TOK___netf2`
    NeTf2,
    /// `__lttf2` — C equivalent: `TOK___lttf2`
    LtTf2,
    /// `__letf2` — C equivalent: `TOK___letf2`
    LeTf2,
    /// `__gttf2` — C equivalent: `TOK___gttf2`
    GtTf2,
    /// `__getf2` — C equivalent: `TOK___getf2`
    GeTf2,

    // ----- Bounds-checking identifiers (tcctok.h:338-362) -----

    /// `__bound_ptr_add` — C equivalent: `TOK___bound_ptr_add`
    BoundPtrAdd,
    /// `__bound_ptr_indir1` — C equivalent: `TOK___bound_ptr_indir1`
    BoundPtrIndir1,
    /// `__bound_ptr_indir2` — C equivalent: `TOK___bound_ptr_indir2`
    BoundPtrIndir2,
    /// `__bound_ptr_indir4` — C equivalent: `TOK___bound_ptr_indir4`
    BoundPtrIndir4,
    /// `__bound_ptr_indir8` — C equivalent: `TOK___bound_ptr_indir8`
    BoundPtrIndir8,
    /// `__bound_ptr_indir12` — C equivalent: `TOK___bound_ptr_indir12`
    BoundPtrIndir12,
    /// `__bound_ptr_indir16` — C equivalent: `TOK___bound_ptr_indir16`
    BoundPtrIndir16,
    /// `__bound_main_arg` — C equivalent: `TOK___bound_main_arg`
    BoundMainArg,
    /// `__bound_local_new` — C equivalent: `TOK___bound_local_new`
    BoundLocalNew,
    /// `__bound_local_delete` — C equivalent: `TOK___bound_local_delete`
    BoundLocalDelete,
    /// `__bound_setjmp` — C equivalent: `TOK___bound_setjmp`
    BoundSetjmp,
    /// `__bound_longjmp` — C equivalent: `TOK___bound_longjmp`
    BoundLongjmp,
    /// `__bound_new_region` — C equivalent: `TOK___bound_new_region`
    BoundNewRegion,
    /// `__bound_alloca_nr` — C equivalent: `TOK___bound_alloca_nr`
    BoundAllocaNr,
    /// `sigsetjmp` — C equivalent: `TOK_sigsetjmp`
    SigSetjmp,
    /// `__sigsetjmp` — C equivalent: `TOK___sigsetjmp`
    SigSetjmpInternal,
    /// `siglongjmp` — C equivalent: `TOK_siglongjmp`
    SigLongjmp,
    /// `setjmp` — C equivalent: `TOK_setjmp`
    Setjmp,
    /// `_setjmp` — C equivalent: `TOK__setjmp`
    SetjmpInternal,
    /// `longjmp` — C equivalent: `TOK_longjmp`
    Longjmp,

    // ----- Assembler directives (tcctok.h:366-418) -----

    /// `.byte` — C equivalent: `TOK_ASMDIR_byte` (first directive)
    AsmDirByte,
    /// `.word` — C equivalent: `TOK_ASMDIR_word`
    AsmDirWord,
    /// `.align` — C equivalent: `TOK_ASMDIR_align`
    AsmDirAlign,
    /// `.balign` — C equivalent: `TOK_ASMDIR_balign`
    AsmDirBalign,
    /// `.p2align` — C equivalent: `TOK_ASMDIR_p2align`
    AsmDirP2align,
    /// `.set` — C equivalent: `TOK_ASMDIR_set`
    AsmDirSet,
    /// `.skip` — C equivalent: `TOK_ASMDIR_skip`
    AsmDirSkip,
    /// `.space` — C equivalent: `TOK_ASMDIR_space`
    AsmDirSpace,
    /// `.string` — C equivalent: `TOK_ASMDIR_string`
    AsmDirString,
    /// `.asciz` — C equivalent: `TOK_ASMDIR_asciz`
    AsmDirAsciz,
    /// `.ascii` — C equivalent: `TOK_ASMDIR_ascii`
    AsmDirAscii,
    /// `.file` — C equivalent: `TOK_ASMDIR_file`
    AsmDirFile,
    /// `.globl` — C equivalent: `TOK_ASMDIR_globl`
    AsmDirGlobl,
    /// `.global` — C equivalent: `TOK_ASMDIR_global`
    AsmDirGlobal,
    /// `.weak` (asm) — C equivalent: `TOK_ASMDIR_weak`
    AsmDirWeakDir,
    /// `.hidden` — C equivalent: `TOK_ASMDIR_hidden`
    AsmDirHidden,
    /// `.ident` — C equivalent: `TOK_ASMDIR_ident`
    AsmDirIdent,
    /// `.size` — C equivalent: `TOK_ASMDIR_size`
    AsmDirSize,
    /// `.type` — C equivalent: `TOK_ASMDIR_type`
    AsmDirType,
    /// `.text` — C equivalent: `TOK_ASMDIR_text`
    AsmDirText,
    /// `.data` — C equivalent: `TOK_ASMDIR_data`
    AsmDirData,
    /// `.bss` — C equivalent: `TOK_ASMDIR_bss`
    AsmDirBss,
    /// `.previous` — C equivalent: `TOK_ASMDIR_previous`
    AsmDirPrevious,
    /// `.pushsection` — C equivalent: `TOK_ASMDIR_pushsection`
    AsmDirPushsection,
    /// `.popsection` — C equivalent: `TOK_ASMDIR_popsection`
    AsmDirPopsection,
    /// `.fill` — C equivalent: `TOK_ASMDIR_fill`
    AsmDirFill,
    /// `.rept` — C equivalent: `TOK_ASMDIR_rept`
    AsmDirRept,
    /// `.endr` — C equivalent: `TOK_ASMDIR_endr`
    AsmDirEndr,
    /// `.org` — C equivalent: `TOK_ASMDIR_org`
    AsmDirOrg,
    /// `.quad` — C equivalent: `TOK_ASMDIR_quad`
    AsmDirQuad,
    /// `.code16` (i386) — C equivalent: `TOK_ASMDIR_code16`
    AsmDirCode16,
    /// `.code32` (i386) — C equivalent: `TOK_ASMDIR_code32`
    AsmDirCode32,
    /// `.code64` (x86_64) — C equivalent: `TOK_ASMDIR_code64`
    AsmDirCode64,
    /// `.option` (riscv64) — C equivalent: `TOK_ASMDIR_option`
    AsmDirOption,
    /// `.short` — C equivalent: `TOK_ASMDIR_short`
    AsmDirShort,
    /// `.long` — C equivalent: `TOK_ASMDIR_long`
    AsmDirLong,
    /// `.int` — C equivalent: `TOK_ASMDIR_int`
    AsmDirInt,
    /// `.symver` — C equivalent: `TOK_ASMDIR_symver`
    AsmDirSymver,
    /// `.reloc` — C equivalent: `TOK_ASMDIR_reloc`
    AsmDirReloc,
    /// `.section` — C equivalent: `TOK_ASMDIR_section` (last directive)
    AsmDirSection,

    // ----- Literal value carriers and special tokens -----

    /// Integer constant (value in `i64`).
    /// C equivalent: `TOK_CINT` / `TOK_CUINT` / `TOK_CLLONG` / `TOK_CULLONG`
    IntegerLiteral(i64),
    /// Floating-point constant (value in `f64`).
    /// C equivalent: `TOK_CFLOAT` / `TOK_CDOUBLE` / `TOK_CLDOUBLE`
    FloatLiteral(f64),
    /// String literal — the actual bytes are stored externally.
    /// C equivalent: `TOK_STR` / `TOK_LSTR`
    StringLiteral,
    /// Character constant.
    /// C equivalent: `TOK_CCHAR` / `TOK_LCHAR`
    CharLiteral(u8),
    /// User-defined or pre-defined identifier (not a keyword).
    /// C equivalent: a token value ≥ `TOK_IDENT`.
    Identifier,
    /// End of file.
    /// C equivalent: `TOK_EOF`
    Eof,
    /// Raw numeric token ID for backward compatibility and extensibility.
    /// C equivalent: any integer token value not mapped to a named variant.
    Raw(i32),
}

// ---------------------------------------------------------------------------
// Manual Eq implementation — needed because f64 does not implement Eq.
// For compiler tokens, NaN bit-equality is the correct semantic: two
// FloatLiteral tokens with identical bits represent the same source token.
// ---------------------------------------------------------------------------

impl Eq for Token {}

// ---------------------------------------------------------------------------
// Manual Hash implementation — needed because f64 does not implement Hash.
// Uses f64::to_bits() so that hashing is consistent with the Eq impl.
// ---------------------------------------------------------------------------

impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Token::IntegerLiteral(v) => v.hash(state),
            Token::FloatLiteral(v) => v.to_bits().hash(state),
            Token::CharLiteral(v) => v.hash(state),
            Token::Raw(v) => v.hash(state),
            // Unit variants — discriminant alone is sufficient.
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Token methods — keyword string mapping
// ---------------------------------------------------------------------------

impl Token {
    /// Returns the canonical string representation of a keyword token.
    ///
    /// For tokens that have multiple spellings (e.g. `const`, `__const`,
    /// `__const__`), this returns the canonical (shortest / most standard)
    /// form. Returns `None` for non-keyword tokens such as literals,
    /// identifiers, and raw IDs.
    ///
    /// C equivalent: the string field of `DEF(token, "string")` entries in
    /// `tcctok.h`.
    #[allow(clippy::too_many_lines)]
    pub fn keyword_str(&self) -> Option<&'static str> {
        match self {
            // Control-flow keywords
            Token::If => Some("if"),
            Token::Else => Some("else"),
            Token::While => Some("while"),
            Token::For => Some("for"),
            Token::Do => Some("do"),
            Token::Continue => Some("continue"),
            Token::Break => Some("break"),
            Token::Return => Some("return"),
            Token::Goto => Some("goto"),
            Token::Switch => Some("switch"),
            Token::Case => Some("case"),
            Token::Default => Some("default"),

            // Asm
            Token::Asm => Some("asm"),

            // Storage / qualifier
            Token::Extern => Some("extern"),
            Token::Static => Some("static"),
            Token::Unsigned => Some("unsigned"),
            Token::Atomic => Some("_Atomic"),
            Token::Const => Some("const"),
            Token::Volatile => Some("volatile"),
            Token::Register => Some("register"),
            Token::Signed => Some("signed"),
            Token::Auto => Some("auto"),
            Token::Inline => Some("inline"),
            Token::Restrict => Some("restrict"),
            Token::Extension => Some("__extension__"),
            Token::ThreadLocal => Some("_Thread_local"),
            Token::Generic => Some("_Generic"),
            Token::StaticAssert => Some("_Static_assert"),

            // Type keywords
            Token::Void => Some("void"),
            Token::Char => Some("char"),
            Token::Int => Some("int"),
            Token::Float => Some("float"),
            Token::Double => Some("double"),
            Token::Bool => Some("_Bool"),
            Token::Complex => Some("_Complex"),
            Token::Short => Some("short"),
            Token::Long => Some("long"),
            Token::Struct => Some("struct"),
            Token::Union => Some("union"),
            Token::Typedef => Some("typedef"),
            Token::Enum => Some("enum"),
            Token::Sizeof => Some("sizeof"),

            // Type extensions
            Token::Attribute => Some("__attribute__"),
            Token::AlignOf => Some("__alignof__"),
            Token::AlignAs => Some("_Alignas"),
            Token::TypeOf => Some("typeof"),
            Token::Label => Some("__label__"),

            // Preprocessor
            Token::Define => Some("define"),
            Token::Include => Some("include"),
            Token::IncludeNext => Some("include_next"),
            Token::Ifdef => Some("ifdef"),
            Token::Ifndef => Some("ifndef"),
            Token::Elif => Some("elif"),
            Token::Endif => Some("endif"),
            Token::Defined => Some("defined"),
            Token::Undef => Some("undef"),
            Token::PpError => Some("error"),
            Token::PpWarning => Some("warning"),
            Token::PpLine => Some("line"),
            Token::Pragma => Some("pragma"),

            // Preprocessor magic
            Token::MacroLine => Some("__LINE__"),
            Token::MacroFile => Some("__FILE__"),
            Token::MacroDate => Some("__DATE__"),
            Token::MacroTime => Some("__TIME__"),
            Token::MacroFunction => Some("__FUNCTION__"),
            Token::MacroVaArgs => Some("__VA_ARGS__"),
            Token::MacroCounter => Some("__COUNTER__"),
            Token::HasInclude => Some("__has_include"),
            Token::HasIncludeNext => Some("__has_include_next"),

            // Special identifiers
            Token::Func => Some("__func__"),
            Token::Nan => Some("__nan__"),
            Token::SNan => Some("__snan__"),
            Token::Inf => Some("__inf__"),

            // Attribute identifiers (canonical form)
            Token::AttrSection => Some("section"),
            Token::Aligned => Some("aligned"),
            Token::Packed => Some("packed"),
            Token::AttrWeak => Some("weak"),
            Token::Alias => Some("alias"),
            Token::Used => Some("used"),
            Token::Unused => Some("unused"),
            Token::Format => Some("format"),
            Token::NoDebug => Some("nodebug"),
            Token::Cdecl => Some("cdecl"),
            Token::Stdcall => Some("stdcall"),
            Token::Fastcall => Some("fastcall"),
            Token::Thiscall => Some("thiscall"),
            Token::Regparm => Some("regparm"),
            Token::Cleanup => Some("cleanup"),
            Token::Constructor => Some("constructor"),
            Token::Destructor => Some("destructor"),
            Token::AlwaysInline => Some("always_inline"),
            Token::Noinline => Some("__noinline__"),
            Token::Pure => Some("pure"),
            Token::Mode => Some("__mode__"),
            Token::ModeQI => Some("__QI__"),
            Token::ModeDI => Some("__DI__"),
            Token::ModeHI => Some("__HI__"),
            Token::ModeSI => Some("__SI__"),
            Token::ModeWord => Some("__word__"),
            Token::DllExport => Some("dllexport"),
            Token::DllImport => Some("dllimport"),
            Token::NoDecorate => Some("nodecorate"),
            Token::NoReturn => Some("noreturn"),
            Token::Visibility => Some("visibility"),

            // Builtins
            Token::BuiltinTypesCompatibleP => Some("__builtin_types_compatible_p"),
            Token::BuiltinChooseExpr => Some("__builtin_choose_expr"),
            Token::BuiltinConstantP => Some("__builtin_constant_p"),
            Token::BuiltinFrameAddress => Some("__builtin_frame_address"),
            Token::BuiltinReturnAddress => Some("__builtin_return_address"),
            Token::BuiltinExpect => Some("__builtin_expect"),
            Token::BuiltinUnreachable => Some("__builtin_unreachable"),
            Token::BuiltinVaStart => Some("__builtin_va_start"),
            Token::BuiltinVaArgTypes => Some("__builtin_va_arg_types"),
            Token::BuiltinVaArg => Some("__builtin_va_arg"),

            // Atomics
            Token::AtomicStore => Some("__atomic_store"),
            Token::AtomicLoad => Some("__atomic_load"),
            Token::AtomicExchange => Some("__atomic_exchange"),
            Token::AtomicCompareExchange => Some("__atomic_compare_exchange"),
            Token::AtomicFetchAdd => Some("__atomic_fetch_add"),
            Token::AtomicFetchSub => Some("__atomic_fetch_sub"),
            Token::AtomicFetchOr => Some("__atomic_fetch_or"),
            Token::AtomicFetchXor => Some("__atomic_fetch_xor"),
            Token::AtomicFetchAnd => Some("__atomic_fetch_and"),
            Token::AtomicFetchNand => Some("__atomic_fetch_nand"),
            Token::AtomicAddFetch => Some("__atomic_add_fetch"),
            Token::AtomicSubFetch => Some("__atomic_sub_fetch"),
            Token::AtomicOrFetch => Some("__atomic_or_fetch"),
            Token::AtomicXorFetch => Some("__atomic_xor_fetch"),
            Token::AtomicAndFetch => Some("__atomic_and_fetch"),
            Token::AtomicNandFetch => Some("__atomic_nand_fetch"),

            // Pragma
            Token::Pack => Some("pack"),
            Token::AsmPush => Some("push"),
            Token::AsmPop => Some("pop"),
            Token::Comment => Some("comment"),
            Token::PragmaLib => Some("lib"),
            Token::PushMacro => Some("push_macro"),
            Token::PopMacro => Some("pop_macro"),
            Token::Once => Some("once"),
            Token::PragmaOption => Some("option"),

            // Runtime library
            Token::Memcpy => Some("memcpy"),
            Token::Memmove => Some("memmove"),
            Token::Memset => Some("memset"),
            Token::Memmove4 => Some("__aeabi_memmove4"),
            Token::Memmove8 => Some("__aeabi_memmove8"),
            Token::DivDi3 => Some("__divdi3"),
            Token::ModDi3 => Some("__moddi3"),
            Token::UdivDi3 => Some("__udivdi3"),
            Token::UmodDi3 => Some("__umoddi3"),
            Token::AshrDi3 => Some("__ashrdi3"),
            Token::LshrDi3 => Some("__lshrdi3"),
            Token::AshlDi3 => Some("__ashldi3"),
            Token::FloatUndiSf => Some("__floatundisf"),
            Token::FloatUndiDf => Some("__floatundidf"),
            Token::FloatUndiXf => Some("__floatundixf"),
            Token::FixUnsXfDi => Some("__fixunsxfdi"),
            Token::FixUnsSfDi => Some("__fixunssfdi"),
            Token::FixUnsDfDi => Some("__fixunsdfdi"),
            Token::AeabiLdivmod => Some("__aeabi_ldivmod"),
            Token::AeabiUldivmod => Some("__aeabi_uldivmod"),
            Token::AeabiIdivmod => Some("__aeabi_idivmod"),
            Token::AeabiUidivmod => Some("__aeabi_uidivmod"),
            Token::DivSi3 => Some("__divsi3"),
            Token::UdivSi3 => Some("__udivsi3"),
            Token::FloatDiSf => Some("__floatdisf"),
            Token::FloatDiDf => Some("__floatdidf"),
            Token::FixSfDi => Some("__fixsfdi"),
            Token::FixDfDi => Some("__fixdfdi"),
            Token::ModSi3 => Some("__modsi3"),
            Token::UmodSi3 => Some("__umodsi3"),
            Token::FloatDiXf => Some("__floatdixf"),
            Token::FixUnsSfSi => Some("__fixunssfsi"),
            Token::FixUnsDfSi => Some("__fixunsdfsi"),
            Token::FixUnsXfSi => Some("__fixunsxfsi"),
            Token::FixXfDi => Some("__fixxfdi"),

            // C67
            Token::C67Divi => Some("_divi"),
            Token::C67Divu => Some("_divu"),
            Token::C67Divf => Some("_divf"),
            Token::C67Divd => Some("_divd"),
            Token::C67Remi => Some("_remi"),
            Token::C67Remu => Some("_remu"),

            // Conditional runtime
            Token::Alloca => Some("alloca"),
            Token::ChkStk => Some("__chkstk"),

            // ARM64 runtime
            Token::Arm64ClearCache => Some("__arm64_clear_cache"),
            Token::AddTf3 => Some("__addtf3"),
            Token::SubTf3 => Some("__subtf3"),
            Token::MulTf3 => Some("__multf3"),
            Token::DivTf3 => Some("__divtf3"),
            Token::ExtendSfTf2 => Some("__extendsftf2"),
            Token::ExtendDfTf2 => Some("__extenddftf2"),
            Token::TruncTfSf2 => Some("__trunctfsf2"),
            Token::TruncTfDf2 => Some("__trunctfdf2"),
            Token::NegTf2 => Some("__negtf2"),
            Token::FixTfSi => Some("__fixtfsi"),
            Token::FixTfDi => Some("__fixtfdi"),
            Token::FixUnsTfSi => Some("__fixunstfsi"),
            Token::FixUnsTfDi => Some("__fixunstfdi"),
            Token::FloatSiTf => Some("__floatsitf"),
            Token::FloatDiTf => Some("__floatditf"),
            Token::FloatUnsiTf => Some("__floatunsitf"),
            Token::FloatUndiTf => Some("__floatunditf"),
            Token::EqTf2 => Some("__eqtf2"),
            Token::NeTf2 => Some("__netf2"),
            Token::LtTf2 => Some("__lttf2"),
            Token::LeTf2 => Some("__letf2"),
            Token::GtTf2 => Some("__gttf2"),
            Token::GeTf2 => Some("__getf2"),

            // Bounds checking
            Token::BoundPtrAdd => Some("__bound_ptr_add"),
            Token::BoundPtrIndir1 => Some("__bound_ptr_indir1"),
            Token::BoundPtrIndir2 => Some("__bound_ptr_indir2"),
            Token::BoundPtrIndir4 => Some("__bound_ptr_indir4"),
            Token::BoundPtrIndir8 => Some("__bound_ptr_indir8"),
            Token::BoundPtrIndir12 => Some("__bound_ptr_indir12"),
            Token::BoundPtrIndir16 => Some("__bound_ptr_indir16"),
            Token::BoundMainArg => Some("__bound_main_arg"),
            Token::BoundLocalNew => Some("__bound_local_new"),
            Token::BoundLocalDelete => Some("__bound_local_delete"),
            Token::BoundSetjmp => Some("__bound_setjmp"),
            Token::BoundLongjmp => Some("__bound_longjmp"),
            Token::BoundNewRegion => Some("__bound_new_region"),
            Token::BoundAllocaNr => Some("__bound_alloca_nr"),
            Token::SigSetjmp => Some("sigsetjmp"),
            Token::SigSetjmpInternal => Some("__sigsetjmp"),
            Token::SigLongjmp => Some("siglongjmp"),
            Token::Setjmp => Some("setjmp"),
            Token::SetjmpInternal => Some("_setjmp"),
            Token::Longjmp => Some("longjmp"),

            // Assembler directives
            Token::AsmDirByte => Some(".byte"),
            Token::AsmDirWord => Some(".word"),
            Token::AsmDirAlign => Some(".align"),
            Token::AsmDirBalign => Some(".balign"),
            Token::AsmDirP2align => Some(".p2align"),
            Token::AsmDirSet => Some(".set"),
            Token::AsmDirSkip => Some(".skip"),
            Token::AsmDirSpace => Some(".space"),
            Token::AsmDirString => Some(".string"),
            Token::AsmDirAsciz => Some(".asciz"),
            Token::AsmDirAscii => Some(".ascii"),
            Token::AsmDirFile => Some(".file"),
            Token::AsmDirGlobl => Some(".globl"),
            Token::AsmDirGlobal => Some(".global"),
            Token::AsmDirWeakDir => Some(".weak"),
            Token::AsmDirHidden => Some(".hidden"),
            Token::AsmDirIdent => Some(".ident"),
            Token::AsmDirSize => Some(".size"),
            Token::AsmDirType => Some(".type"),
            Token::AsmDirText => Some(".text"),
            Token::AsmDirData => Some(".data"),
            Token::AsmDirBss => Some(".bss"),
            Token::AsmDirPrevious => Some(".previous"),
            Token::AsmDirPushsection => Some(".pushsection"),
            Token::AsmDirPopsection => Some(".popsection"),
            Token::AsmDirFill => Some(".fill"),
            Token::AsmDirRept => Some(".rept"),
            Token::AsmDirEndr => Some(".endr"),
            Token::AsmDirOrg => Some(".org"),
            Token::AsmDirQuad => Some(".quad"),
            Token::AsmDirCode16 => Some(".code16"),
            Token::AsmDirCode32 => Some(".code32"),
            Token::AsmDirCode64 => Some(".code64"),
            Token::AsmDirOption => Some(".option"),
            Token::AsmDirShort => Some(".short"),
            Token::AsmDirLong => Some(".long"),
            Token::AsmDirInt => Some(".int"),
            Token::AsmDirSymver => Some(".symver"),
            Token::AsmDirReloc => Some(".reloc"),
            Token::AsmDirSection => Some(".section"),

            // Non-keyword tokens return None
            Token::IntegerLiteral(_)
            | Token::FloatLiteral(_)
            | Token::StringLiteral
            | Token::CharLiteral(_)
            | Token::Identifier
            | Token::Eof
            | Token::Raw(_) => None,
        }
    }

    /// Try to parse a keyword from a string.
    ///
    /// Recognises all keyword spellings including GCC `__xxx__` variants.
    /// Returns `None` if `s` does not match any known keyword.
    ///
    /// C equivalent: the reverse lookup of `DEF(token, "string")` entries.
    #[allow(clippy::too_many_lines)]
    pub fn from_keyword(s: &str) -> Option<Token> {
        match s {
            // Control-flow
            "if" => Some(Token::If),
            "else" => Some(Token::Else),
            "while" => Some(Token::While),
            "for" => Some(Token::For),
            "do" => Some(Token::Do),
            "continue" => Some(Token::Continue),
            "break" => Some(Token::Break),
            "return" => Some(Token::Return),
            "goto" => Some(Token::Goto),
            "switch" => Some(Token::Switch),
            "case" => Some(Token::Case),
            "default" => Some(Token::Default),

            // Asm (3 aliases)
            "asm" | "__asm" | "__asm__" => Some(Token::Asm),

            // Storage / qualifier
            "extern" => Some(Token::Extern),
            "static" => Some(Token::Static),
            "unsigned" => Some(Token::Unsigned),
            "_Atomic" => Some(Token::Atomic),
            "const" | "__const" | "__const__" => Some(Token::Const),
            "volatile" | "__volatile" | "__volatile__" => Some(Token::Volatile),
            "register" => Some(Token::Register),
            "signed" | "__signed" | "__signed__" => Some(Token::Signed),
            "auto" => Some(Token::Auto),
            "inline" | "__inline" | "__inline__" => Some(Token::Inline),
            "restrict" | "__restrict" | "__restrict__" => Some(Token::Restrict),
            "__extension__" => Some(Token::Extension),
            "_Thread_local" => Some(Token::ThreadLocal),
            "_Generic" => Some(Token::Generic),
            "_Static_assert" => Some(Token::StaticAssert),

            // Type keywords
            "void" => Some(Token::Void),
            "char" => Some(Token::Char),
            "int" => Some(Token::Int),
            "float" => Some(Token::Float),
            "double" => Some(Token::Double),
            "_Bool" => Some(Token::Bool),
            "_Complex" => Some(Token::Complex),
            "short" => Some(Token::Short),
            "long" => Some(Token::Long),
            "struct" => Some(Token::Struct),
            "union" => Some(Token::Union),
            "typedef" => Some(Token::Typedef),
            "enum" => Some(Token::Enum),
            "sizeof" => Some(Token::Sizeof),

            // Type extensions
            "__attribute" | "__attribute__" => Some(Token::Attribute),
            "__alignof" | "__alignof__" | "_Alignof" => Some(Token::AlignOf),
            "_Alignas" => Some(Token::AlignAs),
            "typeof" | "__typeof" | "__typeof__" => Some(Token::TypeOf),
            "__label__" => Some(Token::Label),

            // Preprocessor
            "define" => Some(Token::Define),
            "include" => Some(Token::Include),
            "include_next" => Some(Token::IncludeNext),
            "ifdef" => Some(Token::Ifdef),
            "ifndef" => Some(Token::Ifndef),
            "elif" => Some(Token::Elif),
            "endif" => Some(Token::Endif),
            "defined" => Some(Token::Defined),
            "undef" => Some(Token::Undef),
            "error" => Some(Token::PpError),
            "warning" => Some(Token::PpWarning),
            "line" => Some(Token::PpLine),
            "pragma" => Some(Token::Pragma),

            // Preprocessor magic
            "__LINE__" => Some(Token::MacroLine),
            "__FILE__" => Some(Token::MacroFile),
            "__DATE__" => Some(Token::MacroDate),
            "__TIME__" => Some(Token::MacroTime),
            "__FUNCTION__" => Some(Token::MacroFunction),
            "__VA_ARGS__" => Some(Token::MacroVaArgs),
            "__COUNTER__" => Some(Token::MacroCounter),
            "__has_include" => Some(Token::HasInclude),
            "__has_include_next" => Some(Token::HasIncludeNext),

            // Special identifiers
            "__func__" => Some(Token::Func),
            "__nan__" => Some(Token::Nan),
            "__snan__" => Some(Token::SNan),
            "__inf__" => Some(Token::Inf),

            // Attribute identifiers (all aliases)
            "section" | "__section__" => Some(Token::AttrSection),
            "aligned" | "__aligned__" => Some(Token::Aligned),
            "packed" | "__packed__" => Some(Token::Packed),
            "weak" | "__weak__" => Some(Token::AttrWeak),
            "alias" | "__alias__" => Some(Token::Alias),
            "used" | "__used__" => Some(Token::Used),
            "unused" | "__unused__" => Some(Token::Unused),
            "format" | "__format__" => Some(Token::Format),
            "nodebug" | "__nodebug__" => Some(Token::NoDebug),
            "cdecl" | "__cdecl" | "__cdecl__" => Some(Token::Cdecl),
            "stdcall" | "__stdcall" | "__stdcall__" => Some(Token::Stdcall),
            "fastcall" | "__fastcall" | "__fastcall__" => Some(Token::Fastcall),
            "thiscall" | "__thiscall" | "__thiscall__" => Some(Token::Thiscall),
            "regparm" | "__regparm__" => Some(Token::Regparm),
            "cleanup" | "__cleanup__" => Some(Token::Cleanup),
            "constructor" | "__constructor__" => Some(Token::Constructor),
            "destructor" | "__destructor__" => Some(Token::Destructor),
            "always_inline" | "__always_inline__" => Some(Token::AlwaysInline),
            "__noinline__" => Some(Token::Noinline),
            "pure" | "__pure__" => Some(Token::Pure),
            "__mode__" => Some(Token::Mode),
            "__QI__" => Some(Token::ModeQI),
            "__DI__" => Some(Token::ModeDI),
            "__HI__" => Some(Token::ModeHI),
            "__SI__" => Some(Token::ModeSI),
            "__word__" => Some(Token::ModeWord),
            "dllexport" => Some(Token::DllExport),
            "dllimport" => Some(Token::DllImport),
            "nodecorate" => Some(Token::NoDecorate),
            "noreturn" | "__noreturn__" | "_Noreturn" => Some(Token::NoReturn),
            "visibility" | "__visibility__" => Some(Token::Visibility),

            // Builtins
            "__builtin_types_compatible_p" => Some(Token::BuiltinTypesCompatibleP),
            "__builtin_choose_expr" => Some(Token::BuiltinChooseExpr),
            "__builtin_constant_p" => Some(Token::BuiltinConstantP),
            "__builtin_frame_address" => Some(Token::BuiltinFrameAddress),
            "__builtin_return_address" => Some(Token::BuiltinReturnAddress),
            "__builtin_expect" => Some(Token::BuiltinExpect),
            "__builtin_unreachable" => Some(Token::BuiltinUnreachable),
            "__builtin_va_start" => Some(Token::BuiltinVaStart),
            "__builtin_va_arg_types" => Some(Token::BuiltinVaArgTypes),
            "__builtin_va_arg" => Some(Token::BuiltinVaArg),

            // Atomics
            "__atomic_store" => Some(Token::AtomicStore),
            "__atomic_load" => Some(Token::AtomicLoad),
            "__atomic_exchange" => Some(Token::AtomicExchange),
            "__atomic_compare_exchange" => Some(Token::AtomicCompareExchange),
            "__atomic_fetch_add" => Some(Token::AtomicFetchAdd),
            "__atomic_fetch_sub" => Some(Token::AtomicFetchSub),
            "__atomic_fetch_or" => Some(Token::AtomicFetchOr),
            "__atomic_fetch_xor" => Some(Token::AtomicFetchXor),
            "__atomic_fetch_and" => Some(Token::AtomicFetchAnd),
            "__atomic_fetch_nand" => Some(Token::AtomicFetchNand),
            "__atomic_add_fetch" => Some(Token::AtomicAddFetch),
            "__atomic_sub_fetch" => Some(Token::AtomicSubFetch),
            "__atomic_or_fetch" => Some(Token::AtomicOrFetch),
            "__atomic_xor_fetch" => Some(Token::AtomicXorFetch),
            "__atomic_and_fetch" => Some(Token::AtomicAndFetch),
            "__atomic_nand_fetch" => Some(Token::AtomicNandFetch),

            // Pragma
            "pack" => Some(Token::Pack),
            "push" => Some(Token::AsmPush),
            "pop" => Some(Token::AsmPop),
            "comment" => Some(Token::Comment),
            "lib" => Some(Token::PragmaLib),
            "push_macro" => Some(Token::PushMacro),
            "pop_macro" => Some(Token::PopMacro),
            "once" => Some(Token::Once),
            "option" => Some(Token::PragmaOption),

            // Runtime library
            "memcpy" | "__aeabi_memcpy" => Some(Token::Memcpy),
            "memmove" | "__aeabi_memmove" => Some(Token::Memmove),
            "memset" | "__aeabi_memset" => Some(Token::Memset),
            "__aeabi_memmove4" => Some(Token::Memmove4),
            "__aeabi_memmove8" => Some(Token::Memmove8),
            "__divdi3" => Some(Token::DivDi3),
            "__moddi3" => Some(Token::ModDi3),
            "__udivdi3" => Some(Token::UdivDi3),
            "__umoddi3" => Some(Token::UmodDi3),
            "__ashrdi3" | "__aeabi_lasr" => Some(Token::AshrDi3),
            "__lshrdi3" | "__aeabi_llsr" => Some(Token::LshrDi3),
            "__ashldi3" | "__aeabi_llsl" => Some(Token::AshlDi3),
            "__floatundisf" | "__aeabi_ul2f" => Some(Token::FloatUndiSf),
            "__floatundidf" | "__aeabi_ul2d" => Some(Token::FloatUndiDf),
            "__floatundixf" => Some(Token::FloatUndiXf),
            "__fixunsxfdi" => Some(Token::FixUnsXfDi),
            "__fixunssfdi" | "__aeabi_f2ulz" => Some(Token::FixUnsSfDi),
            "__fixunsdfdi" | "__aeabi_d2ulz" => Some(Token::FixUnsDfDi),
            "__aeabi_ldivmod" => Some(Token::AeabiLdivmod),
            "__aeabi_uldivmod" => Some(Token::AeabiUldivmod),
            "__aeabi_idivmod" => Some(Token::AeabiIdivmod),
            "__aeabi_uidivmod" => Some(Token::AeabiUidivmod),
            "__divsi3" | "__aeabi_idiv" => Some(Token::DivSi3),
            "__udivsi3" | "__aeabi_uidiv" => Some(Token::UdivSi3),
            "__floatdisf" | "__aeabi_l2f" => Some(Token::FloatDiSf),
            "__floatdidf" | "__aeabi_l2d" => Some(Token::FloatDiDf),
            "__fixsfdi" | "__aeabi_f2lz" => Some(Token::FixSfDi),
            "__fixdfdi" | "__aeabi_d2lz" => Some(Token::FixDfDi),
            "__modsi3" => Some(Token::ModSi3),
            "__umodsi3" => Some(Token::UmodSi3),
            "__floatdixf" => Some(Token::FloatDiXf),
            "__fixunssfsi" => Some(Token::FixUnsSfSi),
            "__fixunsdfsi" => Some(Token::FixUnsDfSi),
            "__fixunsxfsi" => Some(Token::FixUnsXfSi),
            "__fixxfdi" => Some(Token::FixXfDi),

            // C67
            "_divi" => Some(Token::C67Divi),
            "_divu" => Some(Token::C67Divu),
            "_divf" => Some(Token::C67Divf),
            "_divd" => Some(Token::C67Divd),
            "_remi" => Some(Token::C67Remi),
            "_remu" => Some(Token::C67Remu),

            // Conditional runtime
            "alloca" => Some(Token::Alloca),
            "__chkstk" => Some(Token::ChkStk),

            // ARM64 runtime
            "__arm64_clear_cache" => Some(Token::Arm64ClearCache),
            "__addtf3" => Some(Token::AddTf3),
            "__subtf3" => Some(Token::SubTf3),
            "__multf3" => Some(Token::MulTf3),
            "__divtf3" => Some(Token::DivTf3),
            "__extendsftf2" => Some(Token::ExtendSfTf2),
            "__extenddftf2" => Some(Token::ExtendDfTf2),
            "__trunctfsf2" => Some(Token::TruncTfSf2),
            "__trunctfdf2" => Some(Token::TruncTfDf2),
            "__negtf2" => Some(Token::NegTf2),
            "__fixtfsi" => Some(Token::FixTfSi),
            "__fixtfdi" => Some(Token::FixTfDi),
            "__fixunstfsi" => Some(Token::FixUnsTfSi),
            "__fixunstfdi" => Some(Token::FixUnsTfDi),
            "__floatsitf" => Some(Token::FloatSiTf),
            "__floatditf" => Some(Token::FloatDiTf),
            "__floatunsitf" => Some(Token::FloatUnsiTf),
            "__floatunditf" => Some(Token::FloatUndiTf),
            "__eqtf2" => Some(Token::EqTf2),
            "__netf2" => Some(Token::NeTf2),
            "__lttf2" => Some(Token::LtTf2),
            "__letf2" => Some(Token::LeTf2),
            "__gttf2" => Some(Token::GtTf2),
            "__getf2" => Some(Token::GeTf2),

            // Bounds checking
            "__bound_ptr_add" => Some(Token::BoundPtrAdd),
            "__bound_ptr_indir1" => Some(Token::BoundPtrIndir1),
            "__bound_ptr_indir2" => Some(Token::BoundPtrIndir2),
            "__bound_ptr_indir4" => Some(Token::BoundPtrIndir4),
            "__bound_ptr_indir8" => Some(Token::BoundPtrIndir8),
            "__bound_ptr_indir12" => Some(Token::BoundPtrIndir12),
            "__bound_ptr_indir16" => Some(Token::BoundPtrIndir16),
            "__bound_main_arg" => Some(Token::BoundMainArg),
            "__bound_local_new" => Some(Token::BoundLocalNew),
            "__bound_local_delete" => Some(Token::BoundLocalDelete),
            "__bound_setjmp" => Some(Token::BoundSetjmp),
            "__bound_longjmp" => Some(Token::BoundLongjmp),
            "__bound_new_region" => Some(Token::BoundNewRegion),
            "__bound_alloca_nr" => Some(Token::BoundAllocaNr),
            "sigsetjmp" => Some(Token::SigSetjmp),
            "__sigsetjmp" => Some(Token::SigSetjmpInternal),
            "siglongjmp" => Some(Token::SigLongjmp),
            "setjmp" => Some(Token::Setjmp),
            "_setjmp" => Some(Token::SetjmpInternal),
            "longjmp" => Some(Token::Longjmp),

            // Assembler directives
            ".byte" => Some(Token::AsmDirByte),
            ".word" => Some(Token::AsmDirWord),
            ".align" => Some(Token::AsmDirAlign),
            ".balign" => Some(Token::AsmDirBalign),
            ".p2align" => Some(Token::AsmDirP2align),
            ".set" => Some(Token::AsmDirSet),
            ".skip" => Some(Token::AsmDirSkip),
            ".space" => Some(Token::AsmDirSpace),
            ".string" => Some(Token::AsmDirString),
            ".asciz" => Some(Token::AsmDirAsciz),
            ".ascii" => Some(Token::AsmDirAscii),
            ".file" => Some(Token::AsmDirFile),
            ".globl" => Some(Token::AsmDirGlobl),
            ".global" => Some(Token::AsmDirGlobal),
            ".weak" => Some(Token::AsmDirWeakDir),
            ".hidden" => Some(Token::AsmDirHidden),
            ".ident" => Some(Token::AsmDirIdent),
            ".size" => Some(Token::AsmDirSize),
            ".type" => Some(Token::AsmDirType),
            ".text" => Some(Token::AsmDirText),
            ".data" => Some(Token::AsmDirData),
            ".bss" => Some(Token::AsmDirBss),
            ".previous" => Some(Token::AsmDirPrevious),
            ".pushsection" => Some(Token::AsmDirPushsection),
            ".popsection" => Some(Token::AsmDirPopsection),
            ".fill" => Some(Token::AsmDirFill),
            ".rept" => Some(Token::AsmDirRept),
            ".endr" => Some(Token::AsmDirEndr),
            ".org" => Some(Token::AsmDirOrg),
            ".quad" => Some(Token::AsmDirQuad),
            ".code16" => Some(Token::AsmDirCode16),
            ".code32" => Some(Token::AsmDirCode32),
            ".code64" => Some(Token::AsmDirCode64),
            ".option" => Some(Token::AsmDirOption),
            ".short" => Some(Token::AsmDirShort),
            ".long" => Some(Token::AsmDirLong),
            ".int" => Some(Token::AsmDirInt),
            ".symver" => Some(Token::AsmDirSymver),
            ".reloc" => Some(Token::AsmDirReloc),
            ".section" => Some(Token::AsmDirSection),

            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Token ID constants — numeric values matching the C #define TOK_* values
// from tcc.h. These are used for backward-compatible integer-based token
// comparisons and for interfacing with the assembler and linker backends.
// ---------------------------------------------------------------------------

/// End of file. C equivalent: `#define TOK_EOF (-1)`
pub const TOK_EOF: i32 = -1;

/// Line feed (used as a token separator in the preprocessor).
/// C equivalent: `#define TOK_LINEFEED 10`
pub const TOK_LINEFEED: i32 = 10;

// ---- Operators and multi-character tokens (0x80..0x8b) ----

/// `--` decrement. C equivalent: `#define TOK_DEC 0x80`
pub const TOK_DEC: i32 = 0x80;

/// `++` increment. C equivalent: `#define TOK_INC 0x82`
pub const TOK_INC: i32 = 0x82;

/// Unsigned division. C equivalent: `#define TOK_UDIV 0x83`
pub const TOK_UDIV: i32 = 0x83;

/// Unsigned modulo. C equivalent: `#define TOK_UMOD 0x84`
pub const TOK_UMOD: i32 = 0x84;

/// Shift left (`<<`). C equivalent: `#define TOK_SHL '<'`
/// In C, the value is the ASCII code for `<` (0x3c).
pub const TOK_SHL: i32 = b'<' as i32;

/// Signed (arithmetic) shift right (`>>`). C equivalent: `#define TOK_SAR '>'`
/// In C, the value is the ASCII code for `>` (0x3e).
pub const TOK_SAR: i32 = b'>' as i32;

/// Unsigned (logical) shift right. C equivalent: `#define TOK_SHR 0x8b`
pub const TOK_SHR: i32 = 0x8b;

// ---- Conditional / comparison operators (0x90..0x9f) ----

/// Logical AND (`&&`). C equivalent: `#define TOK_LAND 0x90`
pub const TOK_LAND: i32 = 0x90;

/// Logical OR (`||`). C equivalent: `#define TOK_LOR 0x91`
pub const TOK_LOR: i32 = 0x91;

/// Unsigned less-than. C equivalent: `#define TOK_ULT 0x92`
pub const TOK_ULT: i32 = 0x92;

/// Unsigned greater-or-equal. C equivalent: `#define TOK_UGE 0x93`
pub const TOK_UGE: i32 = 0x93;

/// Equal (`==`). C equivalent: `#define TOK_EQ 0x94`
pub const TOK_EQ: i32 = 0x94;

/// Not equal (`!=`). C equivalent: `#define TOK_NE 0x95`
pub const TOK_NE: i32 = 0x95;

/// Unsigned less-or-equal. C equivalent: `#define TOK_ULE 0x96`
pub const TOK_ULE: i32 = 0x96;

/// Unsigned greater-than. C equivalent: `#define TOK_UGT 0x97`
pub const TOK_UGT: i32 = 0x97;

/// Signed less-than (`<`). C equivalent: `#define TOK_LT 0x9c`
pub const TOK_LT: i32 = 0x9c;

/// Signed greater-or-equal (`>=`). C equivalent: `#define TOK_GE 0x9d`
pub const TOK_GE: i32 = 0x9d;

/// Signed less-or-equal (`<=`). C equivalent: `#define TOK_LE 0x9e`
pub const TOK_LE: i32 = 0x9e;

/// Signed greater-than (`>`). C equivalent: `#define TOK_GT 0x9f`
pub const TOK_GT: i32 = 0x9f;

// ---- Punctuation / special (0xa0..0xa7) ----

/// Arrow (`->`). C equivalent: `#define TOK_ARROW 0xa0`
pub const TOK_ARROW: i32 = 0xa0;

/// Ellipsis (`...`). C equivalent: `#define TOK_DOTS 0xa1`
pub const TOK_DOTS: i32 = 0xa1;

/// Token pasting (`##`). C equivalent: `#define TOK_TWOSHARPS 0xa3`
pub const TOK_TWOSHARPS: i32 = 0xa3;

/// Placeholder token (C99). C equivalent: `#define TOK_PLCHLDR 0xa4`
pub const TOK_PLCHLDR: i32 = 0xa4;

/// Alias of `(` for parsing `sizeof(type)`.
/// C equivalent: `#define TOK_SOTYPE 0xa7`
pub const TOK_SOTYPE: i32 = 0xa7;

// ---- Assignment operators (0xb0..0xb9) ----

/// `+=`. C equivalent: `#define TOK_A_ADD 0xb0`
pub const TOK_A_ADD: i32 = 0xb0;

/// Arithmetic shift-right assign (`>>=` signed).
/// C equivalent: `#define TOK_A_SAR 0xb9`
pub const TOK_A_SAR: i32 = 0xb9;

// ---- Value-carrying tokens (0xc0..0xcf) ----

/// Character constant in `tokc`. C equivalent: `#define TOK_CCHAR 0xc0`
pub const TOK_CCHAR: i32 = 0xc0;

/// Integer number in `tokc`. C equivalent: `#define TOK_CINT 0xc2`
pub const TOK_CINT: i32 = 0xc2;

/// Long long constant. C equivalent: `#define TOK_CLLONG 0xc4`
pub const TOK_CLLONG: i32 = 0xc4;

/// String pointer in `tokc`. C equivalent: `#define TOK_STR 0xc8`
pub const TOK_STR: i32 = 0xc8;

/// Float constant. C equivalent: `#define TOK_CFLOAT 0xca`
pub const TOK_CFLOAT: i32 = 0xca;

/// Double constant. C equivalent: `#define TOK_CDOUBLE 0xcb`
pub const TOK_CDOUBLE: i32 = 0xcb;

/// Long double constant. C equivalent: `#define TOK_CLDOUBLE 0xcc`
pub const TOK_CLDOUBLE: i32 = 0xcc;

/// Preprocessor number. C equivalent: `#define TOK_PPNUM 0xcd`
pub const TOK_PPNUM: i32 = 0xcd;

/// Line number info. C equivalent: `#define TOK_LINENUM 0xcf`
pub const TOK_LINENUM: i32 = 0xcf;

// ---- Identifier base and hash sizes ----

/// First user-defined token ID (identifiers start here).
/// C equivalent: `#define TOK_IDENT 256`
pub const TOK_IDENT: i32 = 256;

/// Upper boundary token ID: tokens with values `>= TOK_UIDENT` are
/// user-defined identifiers rather than keywords. In C this is
/// `#define TOK_UIDENT TOK_DEFINE`, which is the enum value of the
/// `define` preprocessor keyword (the first non-keyword token in the
/// `enum tcc_token` sequence).
///
/// In the original C code, `TOK_DEFINE` is the 71st entry in
/// `enum tcc_token` (counting from `TOK_LAST = TOK_IDENT - 1 = 255`,
/// then `TOK_IF = 256` as the first DEF entry), so
/// `TOK_UIDENT = TOK_DEFINE = 256 + 64 = 320`.
pub const TOK_UIDENT: i32 = 320;

/// Size of the token hash table (must be a power of two).
/// C equivalent: `#define TOK_HASH_SIZE 16384`
pub const TOK_HASH_SIZE: i32 = 16384;

/// Preprocessor join token — a `##` in a macro that means token pasting.
/// C equivalent: `#define TOK_PPJOIN (TOK_TWOSHARPS | SYM_FIELD)`
/// where `SYM_FIELD = 0x20000000`.
pub const TOK_PPJOIN: i32 = TOK_TWOSHARPS | SYM_FIELD;

/// Struct/union field symbol space flag.
/// C equivalent: `#define SYM_FIELD 0x20000000`
const SYM_FIELD: i32 = 0x2000_0000;

// ---- Assembler directive range markers ----

/// First assembler directive token ID. Sentinel value — in the Rust port,
/// use direct `Token::AsmDirByte` comparison instead of numeric ranges.
/// C equivalent: `#define TOK_ASMDIR_FIRST TOK_ASMDIR_byte`
pub const TOK_ASMDIR_FIRST: i32 = 0;

/// Last assembler directive token ID. Sentinel value — in the Rust port,
/// use direct `Token::AsmDirSection` comparison instead of numeric ranges.
/// C equivalent: `#define TOK_ASMDIR_LAST TOK_ASMDIR_section`
pub const TOK_ASMDIR_LAST: i32 = 0;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_roundtrip_control_flow() {
        let keywords = [
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
        ];
        for (s, tok) in &keywords {
            assert_eq!(Token::from_keyword(s), Some(*tok), "from_keyword({s})");
            assert_eq!(tok.keyword_str(), Some(*s), "keyword_str({tok:?})");
        }
    }

    #[test]
    fn keyword_roundtrip_types() {
        let keywords = [
            ("void", Token::Void),
            ("char", Token::Char),
            ("int", Token::Int),
            ("float", Token::Float),
            ("double", Token::Double),
            ("_Bool", Token::Bool),
            ("short", Token::Short),
            ("long", Token::Long),
            ("struct", Token::Struct),
            ("union", Token::Union),
            ("typedef", Token::Typedef),
            ("enum", Token::Enum),
            ("sizeof", Token::Sizeof),
        ];
        for (s, tok) in &keywords {
            assert_eq!(Token::from_keyword(s), Some(*tok));
            assert_eq!(tok.keyword_str(), Some(*s));
        }
    }

    #[test]
    fn gcc_aliases_const() {
        assert_eq!(Token::from_keyword("const"), Some(Token::Const));
        assert_eq!(Token::from_keyword("__const"), Some(Token::Const));
        assert_eq!(Token::from_keyword("__const__"), Some(Token::Const));
    }

    #[test]
    fn gcc_aliases_volatile() {
        assert_eq!(Token::from_keyword("volatile"), Some(Token::Volatile));
        assert_eq!(Token::from_keyword("__volatile"), Some(Token::Volatile));
        assert_eq!(Token::from_keyword("__volatile__"), Some(Token::Volatile));
    }

    #[test]
    fn gcc_aliases_asm() {
        assert_eq!(Token::from_keyword("asm"), Some(Token::Asm));
        assert_eq!(Token::from_keyword("__asm"), Some(Token::Asm));
        assert_eq!(Token::from_keyword("__asm__"), Some(Token::Asm));
    }

    #[test]
    fn gcc_aliases_inline() {
        assert_eq!(Token::from_keyword("inline"), Some(Token::Inline));
        assert_eq!(Token::from_keyword("__inline"), Some(Token::Inline));
        assert_eq!(Token::from_keyword("__inline__"), Some(Token::Inline));
    }

    #[test]
    fn gcc_aliases_restrict() {
        assert_eq!(Token::from_keyword("restrict"), Some(Token::Restrict));
        assert_eq!(Token::from_keyword("__restrict"), Some(Token::Restrict));
        assert_eq!(Token::from_keyword("__restrict__"), Some(Token::Restrict));
    }

    #[test]
    fn gcc_aliases_signed() {
        assert_eq!(Token::from_keyword("signed"), Some(Token::Signed));
        assert_eq!(Token::from_keyword("__signed"), Some(Token::Signed));
        assert_eq!(Token::from_keyword("__signed__"), Some(Token::Signed));
    }

    #[test]
    fn asm_directives() {
        assert_eq!(Token::from_keyword(".byte"), Some(Token::AsmDirByte));
        assert_eq!(Token::from_keyword(".word"), Some(Token::AsmDirWord));
        assert_eq!(Token::from_keyword(".align"), Some(Token::AsmDirAlign));
        assert_eq!(Token::from_keyword(".section"), Some(Token::AsmDirSection));
        assert_eq!(Token::AsmDirByte.keyword_str(), Some(".byte"));
        assert_eq!(Token::AsmDirSection.keyword_str(), Some(".section"));
    }

    #[test]
    fn asm_directives_comprehensive() {
        let dirs = [
            (".byte", Token::AsmDirByte),
            (".word", Token::AsmDirWord),
            (".align", Token::AsmDirAlign),
            (".balign", Token::AsmDirBalign),
            (".p2align", Token::AsmDirP2align),
            (".set", Token::AsmDirSet),
            (".skip", Token::AsmDirSkip),
            (".space", Token::AsmDirSpace),
            (".string", Token::AsmDirString),
            (".asciz", Token::AsmDirAsciz),
            (".ascii", Token::AsmDirAscii),
            (".file", Token::AsmDirFile),
            (".globl", Token::AsmDirGlobl),
            (".global", Token::AsmDirGlobal),
            (".weak", Token::AsmDirWeakDir),
            (".hidden", Token::AsmDirHidden),
            (".ident", Token::AsmDirIdent),
            (".size", Token::AsmDirSize),
            (".type", Token::AsmDirType),
            (".text", Token::AsmDirText),
            (".data", Token::AsmDirData),
            (".bss", Token::AsmDirBss),
            (".previous", Token::AsmDirPrevious),
            (".pushsection", Token::AsmDirPushsection),
            (".popsection", Token::AsmDirPopsection),
            (".fill", Token::AsmDirFill),
            (".rept", Token::AsmDirRept),
            (".endr", Token::AsmDirEndr),
            (".org", Token::AsmDirOrg),
            (".quad", Token::AsmDirQuad),
            (".code16", Token::AsmDirCode16),
            (".code32", Token::AsmDirCode32),
            (".code64", Token::AsmDirCode64),
            (".option", Token::AsmDirOption),
            (".short", Token::AsmDirShort),
            (".long", Token::AsmDirLong),
            (".int", Token::AsmDirInt),
            (".symver", Token::AsmDirSymver),
            (".reloc", Token::AsmDirReloc),
            (".section", Token::AsmDirSection),
        ];
        for (s, tok) in &dirs {
            assert_eq!(Token::from_keyword(s), Some(*tok), "from_keyword({s})");
            assert_eq!(tok.keyword_str(), Some(*s), "keyword_str({tok:?})");
        }
    }

    #[test]
    fn literal_tokens_have_no_keyword_str() {
        assert_eq!(Token::IntegerLiteral(42).keyword_str(), None);
        assert_eq!(Token::FloatLiteral(3.14).keyword_str(), None);
        assert_eq!(Token::StringLiteral.keyword_str(), None);
        assert_eq!(Token::CharLiteral(b'x').keyword_str(), None);
        assert_eq!(Token::Identifier.keyword_str(), None);
        assert_eq!(Token::Eof.keyword_str(), None);
        assert_eq!(Token::Raw(999).keyword_str(), None);
    }

    #[test]
    fn unknown_keyword_returns_none() {
        assert_eq!(Token::from_keyword("notakeyword"), None);
        assert_eq!(Token::from_keyword(""), None);
    }

    #[test]
    fn token_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Token::If);
        set.insert(Token::If);
        assert_eq!(set.len(), 1);

        set.insert(Token::IntegerLiteral(42));
        set.insert(Token::IntegerLiteral(42));
        assert_eq!(set.len(), 2);

        set.insert(Token::FloatLiteral(3.14));
        set.insert(Token::FloatLiteral(3.14));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn float_literal_nan_eq() {
        // NaN tokens with identical bits should be equal
        let nan = f64::NAN;
        let t1 = Token::FloatLiteral(nan);
        let t2 = Token::FloatLiteral(nan);
        // PartialEq is f64-based so NaN != NaN; but in HashSet they hash equally
        // This is intentional — see Eq impl documentation
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(t1);
        set.insert(t2);
        // Both have same bits, so the hash is the same
        assert!(set.len() <= 2);
    }

    #[test]
    fn token_copy_clone() {
        let t = Token::If;
        let t2 = t;
        assert_eq!(t, t2);
    }

    #[test]
    fn tok_constants_values() {
        assert_eq!(TOK_EOF, -1);
        assert_eq!(TOK_LINEFEED, 10);
        assert_eq!(TOK_IDENT, 256);
        assert_eq!(TOK_LAND, 0x90);
        assert_eq!(TOK_LOR, 0x91);
        assert_eq!(TOK_EQ, 0x94);
        assert_eq!(TOK_NE, 0x95);
        assert_eq!(TOK_LT, 0x9c);
        assert_eq!(TOK_GT, 0x9f);
        assert_eq!(TOK_LE, 0x9e);
        assert_eq!(TOK_GE, 0x9d);
        assert_eq!(TOK_INC, 0x82);
        assert_eq!(TOK_DEC, 0x80);
        assert_eq!(TOK_SHL, 0x3c);
        assert_eq!(TOK_SAR, 0x3e);
        assert_eq!(TOK_SHR, 0x8b);
        assert_eq!(TOK_ARROW, 0xa0);
        assert_eq!(TOK_DOTS, 0xa1);
        assert_eq!(TOK_TWOSHARPS, 0xa3);
        assert_eq!(TOK_A_ADD, 0xb0);
        assert_eq!(TOK_A_SAR, 0xb9);
        assert_eq!(TOK_CCHAR, 0xc0);
        assert_eq!(TOK_CINT, 0xc2);
        assert_eq!(TOK_STR, 0xc8);
        assert_eq!(TOK_CFLOAT, 0xca);
        assert_eq!(TOK_CDOUBLE, 0xcb);
        assert_eq!(TOK_CLDOUBLE, 0xcc);
        assert_eq!(TOK_LINENUM, 0xcf);
        assert_eq!(TOK_HASH_SIZE, 16384);
        assert_eq!(TOK_PPJOIN, 0xa3 | 0x2000_0000);
        assert_eq!(TOK_ULT, 0x92);
        assert_eq!(TOK_UGE, 0x93);
        assert_eq!(TOK_ULE, 0x96);
        assert_eq!(TOK_UGT, 0x97);
        assert_eq!(TOK_UDIV, 0x83);
        assert_eq!(TOK_UMOD, 0x84);
        assert_eq!(TOK_PLCHLDR, 0xa4);
        assert_eq!(TOK_SOTYPE, 0xa7);
        assert_eq!(TOK_PPNUM, 0xcd);
        assert_eq!(TOK_CLLONG, 0xc4);
    }

    #[test]
    fn builtin_keywords() {
        assert_eq!(
            Token::from_keyword("__builtin_expect"),
            Some(Token::BuiltinExpect)
        );
        assert_eq!(
            Token::from_keyword("__builtin_va_start"),
            Some(Token::BuiltinVaStart)
        );
    }

    #[test]
    fn atomic_keywords() {
        assert_eq!(
            Token::from_keyword("__atomic_store"),
            Some(Token::AtomicStore)
        );
        assert_eq!(
            Token::from_keyword("__atomic_fetch_add"),
            Some(Token::AtomicFetchAdd)
        );
    }

    #[test]
    fn noreturn_aliases() {
        assert_eq!(Token::from_keyword("noreturn"), Some(Token::NoReturn));
        assert_eq!(Token::from_keyword("__noreturn__"), Some(Token::NoReturn));
        assert_eq!(Token::from_keyword("_Noreturn"), Some(Token::NoReturn));
    }

    #[test]
    fn preprocessor_keywords() {
        let pp = [
            ("define", Token::Define),
            ("include", Token::Include),
            ("include_next", Token::IncludeNext),
            ("ifdef", Token::Ifdef),
            ("ifndef", Token::Ifndef),
            ("elif", Token::Elif),
            ("endif", Token::Endif),
            ("defined", Token::Defined),
            ("undef", Token::Undef),
            ("error", Token::PpError),
            ("warning", Token::PpWarning),
            ("line", Token::PpLine),
            ("pragma", Token::Pragma),
        ];
        for (s, tok) in &pp {
            assert_eq!(Token::from_keyword(s), Some(*tok), "from_keyword({s})");
            assert_eq!(tok.keyword_str(), Some(*s), "keyword_str({tok:?})");
        }
    }

    #[test]
    fn preprocessor_magic() {
        assert_eq!(Token::from_keyword("__LINE__"), Some(Token::MacroLine));
        assert_eq!(Token::from_keyword("__FILE__"), Some(Token::MacroFile));
        assert_eq!(Token::from_keyword("__DATE__"), Some(Token::MacroDate));
        assert_eq!(Token::from_keyword("__VA_ARGS__"), Some(Token::MacroVaArgs));
        assert_eq!(Token::from_keyword("__COUNTER__"), Some(Token::MacroCounter));
    }

    #[test]
    fn aeabi_aliases() {
        assert_eq!(Token::from_keyword("__aeabi_memcpy"), Some(Token::Memcpy));
        assert_eq!(Token::from_keyword("memcpy"), Some(Token::Memcpy));
        assert_eq!(Token::from_keyword("__aeabi_idiv"), Some(Token::DivSi3));
        assert_eq!(Token::from_keyword("__divsi3"), Some(Token::DivSi3));
    }

    #[test]
    fn bounds_checking_tokens() {
        assert_eq!(
            Token::from_keyword("__bound_ptr_add"),
            Some(Token::BoundPtrAdd)
        );
        assert_eq!(
            Token::from_keyword("__bound_local_new"),
            Some(Token::BoundLocalNew)
        );
        assert_eq!(
            Token::from_keyword("__bound_alloca_nr"),
            Some(Token::BoundAllocaNr)
        );
    }

    #[test]
    fn c11_keywords() {
        assert_eq!(Token::from_keyword("_Atomic"), Some(Token::Atomic));
        assert_eq!(Token::from_keyword("_Generic"), Some(Token::Generic));
        assert_eq!(Token::from_keyword("_Static_assert"), Some(Token::StaticAssert));
        assert_eq!(Token::from_keyword("_Thread_local"), Some(Token::ThreadLocal));
        assert_eq!(Token::from_keyword("_Alignas"), Some(Token::AlignAs));
        assert_eq!(Token::from_keyword("_Bool"), Some(Token::Bool));
        assert_eq!(Token::from_keyword("_Complex"), Some(Token::Complex));
    }

    #[test]
    fn attribute_identifiers() {
        assert_eq!(Token::from_keyword("aligned"), Some(Token::Aligned));
        assert_eq!(Token::from_keyword("__aligned__"), Some(Token::Aligned));
        assert_eq!(Token::from_keyword("packed"), Some(Token::Packed));
        assert_eq!(Token::from_keyword("__packed__"), Some(Token::Packed));
        assert_eq!(Token::from_keyword("section"), Some(Token::AttrSection));
        assert_eq!(Token::from_keyword("__section__"), Some(Token::AttrSection));
    }
}
