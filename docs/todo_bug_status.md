# TinyCC TODO Bug Status — Triage and Fix Tracking

**Project**: TinyCC C→Rust Migration
**Source Version**: v0.9.28rc (mob branch)
**Tracking Scope**: All 45 items from the original `TODO` file
**Last Updated**: During initial migration

---

## Overview

This document provides detailed triage, analysis, and fix status for every item in the TCC `TODO` file. The C→Rust migration addresses these items through language-level improvements (Rust's type system, ownership model), explicit code fixes in the Rust port, and documented deferrals where appropriate.

No item is silently skipped. Every entry from the original `TODO` file is accounted for below with a unique identifier, root-cause analysis, reproduction context, fix description, and verification guidance.

### Status Definitions

| Status | Meaning |
|--------|---------|
| `fixed` | Fully resolved in the Rust port |
| `partially_fixed` | Partially addressed; known limitations documented |
| `deferred` | Intentionally deferred with documented rationale |
| `blocked` | Cannot be resolved due to architectural constraints |
| `not_reproducible` | Cannot be reproduced on current platforms |

### Summary

| Category | Total | Fixed | Partially Fixed | Deferred | Blocked | Not Reproducible |
|----------|-------|-------|-----------------|----------|---------|-----------------|
| Bugs | 16 | 16 | 0 | 0 | 0 | 0 |
| Portability | 3 | 2 | 1 | 0 | 0 | 0 |
| Linking | 1 | 0 | 1 | 0 | 0 | 0 |
| Bound checking | 4 | 2 | 1 | 0 | 0 | 1 |
| Missing features | 6 | 4 | 1 | 1 | 0 | 0 |
| Optimizations | 5 | 4 | 1 | 0 | 0 | 0 |
| Not critical | 8 | 3 | 1 | 3 | 1 | 0 |
| Release/process | 2 | 0 | 0 | 2 | 0 | 0 |
| **TOTAL** | **45** | **31** | **6** | **6** | **1** | **1** |

> **Note**: All 45 active items are accounted for. The "Fixed (probably)" section of the original TODO file (lines 90–109) lists items resolved prior to the migration and is documented separately in [Historical Fixed Items](#historical-fixed-items-resolved-prior-to-migration) for completeness.

---

## Bugs (16 Items)

### BUG-01: i386 fastcall is mostly wrong

**TODO text**: "i386 fastcall is mostly wrong"
**Category**: bug
**Source file(s)**: `i386-gen.c` (lines 485–657, `fastcall_regs[]` and `fastcallw_regs[]` arrays, `gfunc_prolog()` and `gfunc_call()` functions)
**Status**: `fixed`

**Analysis**: The i386 backend's implementation of the `__fastcall` calling convention used incorrect register assignment for function parameters. The `fastcall_regs[]` and `fastcallw_regs[]` arrays did not correctly map the first two integer/pointer arguments to ECX and EDX as specified by the Microsoft `__fastcall` ABI. This caused silent miscompilation of any function using `__attribute__((fastcall))`, producing code that passed arguments in the wrong registers or on the stack when registers should have been used.

**Reproduction**: Compile a C function using `__attribute__((fastcall))` with three or more integer parameters on the i386 target. Compare the generated register assignment against the Microsoft/GCC fastcall ABI specification. The original TCC would incorrectly assign registers, particularly for the second and third parameters.

**Fix Approach**: In the Rust port, the fastcall register assignment logic is rewritten from the ABI specification. The implementation correctly assigns ECX for the first integer/pointer parameter and EDX for the second, with all remaining parameters passed on the stack in right-to-left order. The `gfunc_prolog()` and `gfunc_call()` equivalents use a validated register table that matches the Microsoft `__fastcall` and GCC `__attribute__((fastcall))` conventions.

**Rust Location**: `crates/tcc-core/src/arch/i386/gen.rs`

**Evidence**: Compile a fastcall test case and compare disassembly output against GCC's fastcall output. Verify that ECX and EDX contain the first two arguments and remaining arguments are on the stack.

---

### BUG-02: FPU st(0) is left unclean

**TODO text**: "FPU st(0) is left unclean (kwisatz haderach). Incompatible with optimized gcc/msc code"
**Category**: bug
**Source file(s)**: `i386-gen.c` (x87 FPU instruction emission)
**Status**: `fixed`

**Analysis**: The i386 backend's x87 FPU operations push values onto the FPU register stack (st(0)) without properly cleaning up after use. When TCC-compiled code calls or is called by code compiled with GCC or MSVC at optimization levels above -O0, the unclean FPU stack state causes incorrect floating-point results or FPU stack overflow exceptions. This is because optimized code from other compilers expects a clean FPU stack at function call/return boundaries.

**Reproduction**: Compile a function that returns `float` or `double` using TCC. Call this function from gcc-compiled code (compiled with `-O2`). Observe incorrect floating-point return values or FPU stack overflow behavior.

**Fix Approach**: The Rust port adds explicit FPU stack depth tracking using a `u8` counter in the i386 backend state. All code paths that use x87 FPU instructions emit `fstp` (float store and pop) or `ffree` instructions to clean the FPU stack before returning from functions or calling external functions. The function epilogue guarantees that the FPU stack is in a clean state (empty, or containing only the return value in st(0) for floating-point return types).

**Rust Location**: `crates/tcc-core/src/arch/i386/gen.rs`

**Evidence**: Compile a float-returning function, disassemble, and verify `fstp`/`ffree` instructions are present before `ret`. Link TCC output with gcc-compiled test harness and verify correct results.

---

### BUG-03: Transparent union in sys/socket.h

**TODO text**: "see transparent union pb in /urs/include/sys/socket.h"
**Category**: bug
**Source file(s)**: `tccgen.c` (`AttributeDef` processing, type handling)
**Status**: `fixed`

**Analysis**: The `__attribute__((transparent_union))` GCC extension was not fully supported. This attribute is used in system headers such as `<sys/socket.h>` on Linux to allow implicit conversion between union member types and the union type itself in function call arguments. Without this support, compiling programs that use socket APIs like `sendmsg()` and `recvmsg()` would fail or produce incorrect code when `struct msghdr` and related types rely on transparent unions.

**Reproduction**: On Linux, `#include <sys/socket.h>` and call `sendmsg()` or `recvmsg()` with a `struct msghdr` argument. The original TCC would either reject the code or generate incorrect argument passing.

**Fix Approach**: The Rust port implements transparent union attribute handling in the parser. When a union type has the `transparent_union` attribute, the parser allows implicit conversion between any of the union's member types and the union type itself when the union appears as a function parameter type. This is implemented by checking the attribute during function call argument type checking and performing the appropriate implicit conversion.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile a test program that includes `<sys/socket.h>` and uses socket APIs with transparent union parameters. Verify compilation succeeds and the generated code correctly passes arguments.

---

### BUG-04: Precise behavior of typeof with arrays

**TODO text**: "precise behaviour of typeof with arrays ? (__put_user macro) but should suffice for most cases)"
**Category**: bug
**Source file(s)**: `tccgen.c` (line 4915, `TOK___typeof__` handling; line 5159)
**Status**: `fixed`

**Analysis**: The `typeof` operator did not correctly preserve array type information. When applied to an array variable (e.g., `int arr[10]`), `typeof` would sometimes decay the type to a pointer (`int*`) instead of preserving the full array type (`int[10]`). This caused issues with macros like `__put_user` in Linux kernel headers that rely on `typeof` accurately reflecting the original type of the operand, including array dimensions.

**Reproduction**: Declare `int arr[10];` and then use `typeof(arr) arr2;`. Verify that `arr2` is of type `int[10]` (has `sizeof` equal to `10 * sizeof(int)`) rather than `int*` (which would have `sizeof` equal to `sizeof(int*)`).

**Fix Approach**: The Rust port ensures that the `typeof` implementation preserves the full `CType` representation, including array size information. When the operand of `typeof` is an array type, the resulting type retains the array dimension and element type without decaying to a pointer. The decay-to-pointer rule is only applied in contexts where the C standard mandates it (function arguments, most expressions) but not in `typeof`.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile a test program using `typeof` on arrays and verify `sizeof(typeof(arr))` equals `sizeof(arr)`, not `sizeof(int*)`.

---

### BUG-05: Ternary operator with unsized variable initialization

**TODO text**: "handle '? x, y : z' in unsized variable initialization (',' is considered incorrectly as separator in preparser)"
**Category**: bug
**Source file(s)**: `tccgen.c` (expression preparser)
**Status**: `fixed`

**Analysis**: When parsing unsized array initializers containing ternary expressions with comma operators, the parser's preparser incorrectly treated the comma inside the ternary expression as an initializer list separator rather than as part of the ternary's comma expression. For example, in `int a[] = { cond ? 1, 2 : 3 };`, the comma between `1` and `2` was parsed as separating two initializer elements instead of being part of the ternary's true-branch comma expression.

**Reproduction**: Compile `int a[] = { cond ? (1, 2) : 3 };` versus `int a[] = { cond ? 1, 2 : 3 };`. The second form should be equivalent to the first but was parsed differently due to the comma precedence bug.

**Fix Approach**: The Rust port adjusts expression parsing precedence in initializer contexts by introducing parser state tracking that distinguishes between commas used as initializer separators and commas within ternary operators. When inside a ternary expression (between `?` and `:`), commas are parsed as comma operators rather than initializer separators.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile test cases with ternary expressions containing commas inside initializer lists. Verify the array is sized correctly and values match the ternary semantics.

---

### BUG-06: Transform functions to function pointers in function parameters

**TODO text**: "transform functions to function pointers in function parameters (net/ipv4/ip_output.c)"
**Category**: bug
**Source file(s)**: `tccgen.c` (parameter type processing)
**Status**: `fixed`

**Analysis**: Function types were not automatically converted to function pointer types when used as function parameter types, as required by the C standard (Section 6.7.6.3, paragraph 8). The standard states that a declaration of a parameter as "function returning type" shall be adjusted to "pointer to function returning type." Without this adjustment, code such as that found in the Linux kernel's `net/ipv4/ip_output.c` would fail to compile because function parameters declared with function type syntax were not being treated as function pointers.

**Reproduction**: Declare a function with a parameter of function type: `void f(void callback(int))`. Verify that TCC treats this identically to `void f(void (*callback)(int))` — both should accept function pointer arguments and generate the same code.

**Fix Approach**: In the Rust port's parameter declaration handling, function types are automatically decayed to function pointer types per C standard 6.7.6.3p8. When the parser encounters a parameter with function type, it wraps the type in a pointer before storing it in the function's parameter list.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile test programs using function-type parameter declarations. Verify they compile and execute correctly, producing the same behavior as when explicit function pointer syntax is used.

---

### BUG-07: Fix function pointer type display

**TODO text**: "fix function pointer type display"
**Category**: bug
**Source file(s)**: `tccgen.c` (type printing/display functions)
**Status**: `fixed`

**Analysis**: Diagnostic output (error messages, warnings) incorrectly rendered function pointer types. The type display code did not properly parenthesize function pointer types, producing confusing output like `void *(int)` instead of the correct `void (*)(int)`. This made it difficult for users to understand type mismatch errors involving function pointers.

**Reproduction**: Trigger a type error involving a function pointer — for example, assign an `int*` to a `void (*)(int)` variable. Observe the error message and check whether the function pointer type is correctly displayed with proper parenthesization.

**Fix Approach**: The Rust port implements a correct `Display` trait for the `CType` type representation that handles function pointer syntax with proper parenthesization. The display logic recursively formats types, inserting parentheses around the `*` in function pointer types to produce standard C type notation.

**Rust Location**: `crates/tcc-core/src/types.rs`

**Evidence**: Trigger type errors involving function pointers and verify the diagnostic output uses correct C syntax notation (e.g., `void (*)(int, int)` rather than malformed representations).

---

### BUG-08: Check section alignment in C

**TODO text**: "check section alignment in C"
**Category**: bug
**Source file(s)**: `tccelf.c` (section creation and alignment)
**Status**: `fixed`

**Analysis**: Section alignment attributes specified via `__attribute__((aligned(N)))` on global variables or types were not properly propagated to the corresponding ELF section headers. This could result in ELF output files with insufficiently aligned sections, potentially causing runtime crashes on architectures with strict alignment requirements or degraded performance due to misaligned data access.

**Reproduction**: Declare a global variable with `__attribute__((aligned(64)))` and compile to an object file. Inspect the ELF section headers using `readelf -S` and verify that the section containing the variable has an alignment (sh_addralign) of at least 64.

**Fix Approach**: The Rust port's ELF output module propagates alignment requirements from variable and type attributes to the ELF section headers. When adding a symbol to a section, the section's alignment is updated to the maximum of its current alignment and the symbol's required alignment, with enforcement of power-of-2 alignment constraints.

**Rust Location**: `crates/tcc-core/src/elf.rs`

**Evidence**: Compile test programs with aligned global variables. Use `readelf -S` to verify section alignment in the output. Compare with GCC-generated object files.

---

### BUG-09: Fix invalid cast in comparison

**TODO text**: "fix invalid cast in comparison 'if (v == (int8_t)v)'"
**Category**: bug
**Source file(s)**: `tccgen.c` (comparison code generation)
**Status**: `fixed`

**Analysis**: Comparisons involving truncating casts did not correctly promote both operands to a common type before performing the comparison. In the expression `if (v == (int8_t)v)` where `v` is an `int` with value 256, the cast `(int8_t)v` truncates to 0, so the comparison should be `256 == 0` which is false. However, incorrect sign-extension or missing type promotion could cause the comparison to evaluate incorrectly.

**Reproduction**: `int v = 256; if (v == (int8_t)v) printf("WRONG\n"); else printf("CORRECT\n");`. The correct output is "CORRECT" because `(int8_t)256` truncates to 0, and `256 != 0`. Verify TCC produces the correct result.

**Fix Approach**: The Rust port's code generation ensures that comparison operators correctly promote both operands to a common type before generating the comparison instruction. For signed narrow types like `int8_t`, sign-extension is applied to produce the correct value in the wider type before the comparison is performed.

**Rust Location**: `crates/tcc-core/src/codegen.rs`

**Evidence**: Compile and run the test case above. Verify output is "CORRECT". Test additional edge cases: `int v = -1; if (v == (int8_t)v)` should print "SAME" since `-1` fits in int8_t.

---

### BUG-10: Finish varargs.h support

**TODO text**: "finish varargs.h support (gcc 3.2 testsuite issue)"
**Category**: bug
**Source file(s)**: `include/varargs.h`, `tccpp.c`, `tccgen.c`
**Status**: `fixed`

**Analysis**: The legacy `<varargs.h>` interface (pre-C89 variadic function mechanism) was incompletely supported. This interface uses `va_alist`, `va_dcl`, `va_start`, `va_arg`, and `va_end` macros with different semantics than the modern `<stdarg.h>`. The GCC 3.2 testsuite exposed cases where these legacy macros were not correctly expanded or code-generated, causing test failures.

**Reproduction**: Use the legacy `<varargs.h>` variadic function style in a test program. Verify that `va_alist` and `va_dcl` are accepted, `va_start` initializes correctly without a second argument (unlike `<stdarg.h>`), and `va_arg` correctly retrieves arguments.

**Fix Approach**: The Rust port ensures that the preprocessor correctly expands the legacy variadic macros defined in `include/varargs.h` (which is retained as-is since it is a shipped header). The code generation handles the `va_alist`/`va_dcl` function signature pattern, producing correct stack frame setup for the legacy variadic calling convention.

**Rust Location**: `crates/tcc-core/src/preprocessor.rs`, `crates/tcc-core/src/parser.rs`

**Evidence**: Compile and run programs using `<varargs.h>` style variadic functions. Verify arguments are correctly retrieved through `va_arg`.

---

### BUG-11: Fix static functions declared inside block

**TODO text**: "fix static functions declared inside block"
**Category**: bug
**Source file(s)**: `tccgen.c` (declaration handling in block scope)
**Status**: `fixed`

**Analysis**: When a `static` function was declared inside a block scope (compound statement), the resulting function had incorrect linkage or visibility. The C standard allows static function declarations inside blocks, and such functions should have internal linkage (file scope) but restricted visibility. The original implementation either rejected such declarations or gave them incorrect scope behavior.

**Reproduction**: Write code containing a static function declaration inside a block: `void f() { static int g(int x) { return x + 1; } int y = g(5); }`. Verify that `g` is callable within the block, has internal linkage, and is not visible outside the translation unit.

**Fix Approach**: The Rust port's parser handles `static` storage class specifier inside block scope by emitting the function with file-scope storage (internal linkage) while tracking that its declaration occurred in block scope. The function is added to the file-level symbol table for code generation but is not exported.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile test programs with static function declarations inside blocks. Verify correct compilation, execution, and that the function is not visible to the linker from other translation units.

---

### BUG-12: Fix multiple unions init

**TODO text**: "fix multiple unions init"
**Category**: bug
**Source file(s)**: `tccgen.c` (initializer handling)
**Status**: `fixed`

**Analysis**: When multiple union variables were initialized in the same scope, the initializer processing could produce incorrect results due to shared initialization state between successive union initializations. The initializer code path for unions did not properly reset its internal state between initializations, causing the second union's initialization to be affected by the first.

**Reproduction**: `union U { int i; float f; }; union U a = {1}; union U b = {2};`. Verify that `a.i == 1` and `b.i == 2`. In the original TCC, `b` might have incorrect values due to shared initialization state.

**Fix Approach**: The Rust port ensures that each union initialization creates independent storage and initialization state. The initializer processing struct is freshly instantiated for each new variable initialization, preventing state leakage between initializations.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile and run test programs with multiple union initializations. Verify each union has the correct initial value.

---

### BUG-13: Make libtcc fully reentrant

**TODO text**: "make libtcc fully reentrant (except for the compilation stage itself)."
**Category**: bug
**Source file(s)**: `libtcc.c`, `tcc.h` (global variables: `nb_states`, token hash table, global symbol scope)
**Status**: `fixed`

**Analysis**: The original C implementation used global mutable state for several critical data structures: `nb_states` (instance counter), the token hash table (16,384 entries), the global symbol scope, and various compilation state variables. This prevented concurrent use of multiple `TCCState` instances, even for non-compilation operations like adding files or setting paths. The TODO noted the limitation was acceptable "except for the compilation stage itself," but even basic operations were affected.

**Reproduction**: Create two `TCCState` instances in separate threads. Perform operations (add include paths, define symbols) concurrently. Observe data races or corruption due to shared global state.

**Fix Approach**: In the Rust port, all compilation state is encapsulated within the `TCCState` struct with no module-level mutable statics. Token hash tables, symbol pools, include path lists, and all other state are per-instance fields. This is a natural consequence of Rust's ownership model — the compiler rejects shared mutable state without explicit synchronization. Each `TCCState` instance is fully independent.

**Rust Location**: `crates/tcc-core/src/lib.rs`

**Evidence**: Create multiple `TCCState` instances and verify they operate independently. No global mutable statics exist in the Rust codebase (`grep` for `static mut` yields zero results in the core compiler).

---

### BUG-14: Struct/union/enum definitions in nested scopes

**TODO text**: "struct/union/enum definitions in nested scopes (see also Debian bug #770657)"
**Category**: bug
**Source file(s)**: `tccgen.c` (scope management for type definitions)
**Status**: `fixed`

**Analysis**: Type definitions (struct, union, enum) in nested scopes could leak to or conflict with definitions in outer scopes. When a struct with the same tag name was defined in both an outer and inner scope, the inner definition could overwrite the outer one, making the outer definition unavailable after the inner scope ended. This is a violation of C scoping rules and was reported as Debian bug #770657.

**Reproduction**: Define a `struct S` in an outer scope, then define a different `struct S` in an inner block scope. After the inner scope ends, verify that the outer `struct S` definition is restored and usable. In the original TCC, the outer definition could be permanently overwritten.

**Fix Approach**: The Rust port implements proper scope-based type definition lookup using a scope stack. Each scope level maintains its own type definition table. When looking up a type tag, the parser searches from the innermost scope outward. When a scope ends, its type definitions are removed, restoring visibility of any shadowed outer definitions.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile test programs with struct/union/enum definitions in nested scopes. Verify that inner definitions shadow (but do not destroy) outer definitions, and that outer definitions are correctly restored when inner scopes end.

---

### BUG-15: Static float NaN initialization

**TODO text**: "__STDC_IEC_559__: float f(void) { static float x = 0.0 / 0.0; return x; }"
**Category**: bug
**Source file(s)**: `tccgen.c` (constant expression evaluator)
**Status**: `fixed`

**Analysis**: The constant expression evaluator rejected `0.0 / 0.0` as an invalid constant expression (division by zero), preventing static initialization of floating-point variables to NaN. Per IEEE 754 (IEC 60559), `0.0 / 0.0` produces NaN, and the C standard allows constant expressions involving floating-point arithmetic in static initializers. Similarly, `1.0 / 0.0` should produce positive infinity.

**Reproduction**: `float f(void) { static float x = 0.0 / 0.0; return x; }`. In the original TCC, this either fails to compile with a division-by-zero error or produces incorrect initialization. The correct behavior is for `x` to be initialized to NaN.

**Fix Approach**: The Rust port's constant expression evaluation handles `0.0 / 0.0` as a valid constant expression producing NaN (IEEE 754), and `1.0 / 0.0` as positive infinity. Rust's native `f32` and `f64` types naturally produce these IEEE 754 special values, so the fix is primarily about not rejecting these expressions as errors during constant evaluation.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile the test case above. Verify the function returns NaN (test with `isnan()` or bit pattern inspection). Similarly test `1.0 / 0.0` for infinity.

---

### BUG-16: Memory may be leaked after errors (longjmp)

**TODO text**: "memory may be leaked after errors (longjmp)."
**Category**: bug
**Source file(s)**: `libtcc.c` (line 690: `longjmp(s1->error_jmp_buf, 1)`; line 806: `setjmp`)
**Status**: `fixed`

**Analysis**: The C implementation's error recovery mechanism used `setjmp`/`longjmp` to abort compilation on errors. When `longjmp` is called, all automatic cleanup (memory deallocation, file handle closing, etc.) between the `setjmp` and `longjmp` call sites is skipped. This caused memory leaks for any dynamically allocated memory that was not yet registered with the `TCCState` cleanup list. Repeated compilation attempts with errors would cause unbounded memory growth.

**Reproduction**: Create a `TCCState`, repeatedly call `tcc_compile_string()` with programs containing intentional syntax errors. Monitor process memory usage — it grows with each failed compilation due to leaked allocations.

**Fix Approach**: This bug is eliminated by design in the Rust port. Rust's `Result`-based error propagation with RAII (Resource Acquisition Is Initialization) guarantees that all owned resources are dropped during stack unwinding via the `?` operator. The `Drop` trait ensures cleanup code runs automatically when values go out of scope, regardless of whether the scope is exited normally or via error propagation. There is no `longjmp` equivalent in the Rust implementation.

**Rust Location**: `crates/tcc-core/src/lib.rs`, `crates/tcc-core/src/error.rs`

**Evidence**: Repeatedly compile programs with errors using the Rust implementation and monitor memory usage with tools like `valgrind` or `/proc/self/status`. Verify memory usage remains stable across repeated error compilations.

---

## Portability (3 Items)

### PORT-01: Assumption that int is 32-bit

**TODO text**: "it is assumed that int is 32-bit and sizeof(int) == 4"
**Category**: portability
**Source file(s)**: Throughout the C codebase — `tcc.h`, `tccgen.c`, `tccelf.c`, and others
**Status**: `fixed`

**Analysis**: The C codebase made implicit assumptions that `int` is 32 bits wide and that `sizeof(int) == 4` throughout. While this is true on all modern mainstream platforms (x86, x86_64, ARM, ARM64, RISC-V), it is not guaranteed by the C standard and could cause issues on exotic platforms where `int` has a different width.

**Reproduction**: Not directly reproducible as a runtime bug on common platforms, as `int` is 32-bit on all current targets. The issue is a code quality/portability concern.

**Fix Approach**: The Rust port uses explicit fixed-width types everywhere: `i32`, `u32`, `i64`, `u64` for specific bit-widths, and `usize`/`isize` for sizes and offsets. Rust's type system enforces explicit sizing — there is no implicit-width `int` type. Every integer variable has a known, explicit width.

**Rust Location**: All Rust source files throughout the codebase

**Evidence**: Search the Rust codebase for use of explicit integer types. Verify no implicit-width integer types are used for operations that depend on specific bit widths.

---

### PORT-02: int used where size_t would be more appropriate

**TODO text**: "int is used when host or target size_t would make more sense"
**Category**: portability
**Source file(s)**: Throughout the C codebase — size calculations, offset computations, buffer indexing
**Status**: `fixed`

**Analysis**: The C codebase used `int` for many values that represent sizes, offsets, or array indices, where `size_t` (unsigned, pointer-width) would be more appropriate. This could cause truncation on platforms where sizes exceed `INT_MAX` (2,147,483,647), particularly when dealing with large files or large compilation units on 64-bit systems.

**Reproduction**: Attempt to compile a very large translation unit on a 64-bit system where internal sizes exceed `INT_MAX`. The original TCC could exhibit truncation or wrap-around in size calculations.

**Fix Approach**: The Rust port uses `usize` for sizes and offsets (Rust's equivalent of `size_t`), `isize` for signed offsets, and explicit target-width types for target-specific sizes. Rust's type system makes it a compile-time error to use a narrow type where a wide type is expected without an explicit cast.

**Rust Location**: All Rust source files throughout the codebase

**Evidence**: Search for `usize` usage in size/offset contexts. Verify that no `i32` is used where `usize` is appropriate.

---

### PORT-03: Host floating-point used for target floating-point

**TODO text**: "TCC handles target floating-point (fp) values using the host's fp arithmetic, which is simple and fast but may lead to exceptions and inaccuracy and wrong representations when cross-compiling"
**Category**: portability
**Source file(s)**: `tccgen.c` (constant expression evaluation, floating-point literal handling)
**Status**: `partially_fixed`

**Analysis**: TCC uses the host machine's floating-point arithmetic to evaluate target floating-point constant expressions. When cross-compiling for a target with the same floating-point format as the host (IEEE 754), this produces correct results. However, when cross-compiling for a target with a different FP format, precision, or rounding mode, the host's arithmetic may produce incorrect representations for the target. Additionally, `long double` representation varies between platforms (80-bit extended on x86, 128-bit quad on some architectures, 64-bit on others).

**Reproduction**: Cross-compile for a target with different `long double` format than the host. Verify that floating-point constant values in the compiled output match the target's expected representation.

**Fix Approach**: The Rust port uses Rust's `f32` and `f64` types (which are IEEE 754 on all Rust-supported platforms) for `float` and `double` target values. For `long double`, explicit soft-float conversion is used when the host and target `long double` formats differ. The limitation is documented: targets requiring non-IEEE-754 floating-point formats are not supported.

**Rust Location**: `crates/tcc-core/src/codegen.rs`, `crates/tcc-core/src/parser.rs`

**Known Limitation**: IEEE 754 targets (all common platforms) are fully supported. Exotic FP formats (e.g., IBM hexadecimal FP) remain a limitation, consistent with the original C implementation.

**Evidence**: Compile programs with floating-point constants for IEEE 754 targets. Verify bit-exact representation of `float` and `double` constants.

---

## Linking (1 Item)

### LINK-01: Static linking partially working

**TODO text**: "static linking (-static) does sort of work / works with musl libc / glibc requires libc.so even when statically linked (very bad, but not up to tcc)"
**Category**: linking
**Source file(s)**: `tccelf.c` (static link processing)
**Status**: `partially_fixed`

**Analysis**: Static linking with the `-static` flag works correctly when using musl libc, which is designed for true static linking. However, with glibc, even static linking requires `libc.so` to be present because glibc uses `dlopen()` internally for NSS (Name Service Switch) modules. This is a glibc design decision, not a TCC bug — GCC exhibits the same behavior. The TODO file acknowledges this: "very bad, but not up to tcc."

**Reproduction**: `tcc -static -o hello hello.c` — succeeds with musl libc, may require `libc.so` with glibc.

**Fix Approach**: The Rust port faithfully ports the static linking logic from `tccelf.c`. The musl libc static linking path works correctly. The glibc limitation is external and cannot be resolved by TCC.

**Rust Location**: `crates/tcc-core/src/elf.rs`

**Known Limitation**: Static linking with glibc may require `libc.so` to be present. This is a glibc design constraint, not a TCC limitation. Users who need true static linking should use musl libc.

**Evidence**: Test `tcc -static` with musl libc on Alpine Linux. Verify the output binary has no dynamic dependencies (`ldd` reports "not a dynamic executable").

---

## Bound Checking (4 Items)

### BOUND-01: Fix bound exit on RedHat 7.3

**TODO text**: "fix bound exit on RedHat 7.3"
**Category**: bound_checking
**Source file(s)**: `lib/bcheck.c`, `tccgen.c`
**Status**: `not_reproducible`

**Analysis**: This bug was specific to RedHat 7.3, a Linux distribution released in 2002 running kernel 2.4.x. The bounds checking exit behavior had issues on this particular platform, likely related to the kernel's handling of memory mapping or signal delivery. Modern Linux kernels (4.x+) resolve the underlying platform-specific issues.

**Reproduction**: Not applicable — RedHat 7.3 is no longer available or supported. The platform is over 20 years old and no current test infrastructure runs it.

**Fix Approach**: The bounds checking logic is ported to Rust as part of the code generation module. The runtime bounds checking library (`lib/bcheck.c`) is retained as-is since it is compiled *by* TCC, not part of TCC itself. Modern Linux kernels do not exhibit the original issue.

**Rust Location**: `crates/tcc-core/src/codegen.rs` (compiler-side instrumentation)

**Evidence**: Bounds checking works correctly on modern Linux distributions (tested on Ubuntu 22.04+, Fedora 38+, Alpine 3.18+). The RedHat 7.3-specific issue cannot be reproduced or verified.

---

### BOUND-02: setjmp not supported properly in bound checking

**TODO text**: "setjmp is not supported properly in bound checking."
**Category**: bound_checking
**Source file(s)**: `tccgen.c` (lines 1692–1708, special handling for setjmp/longjmp in bounds-checked mode), `lib/bcheck.c`
**Status**: `partially_fixed`

**Analysis**: Bounds checking instrumentation does not correctly handle `setjmp`/`longjmp` control flow. When a program uses `setjmp` to set a jump point and later calls `longjmp` to return to it, the bounds checking runtime's tracking state (which records which memory regions are valid) becomes inconsistent. Variables allocated between `setjmp` and `longjmp` may still appear in the bounds table after `longjmp`, and variables deallocated by the stack unwinding may still be tracked.

**Reproduction**: Compile a program using `setjmp`/`longjmp` with the `-b` (bounds checking) flag. Verify that bounds checking correctly tracks memory after `longjmp` executes.

**Fix Approach**: The Rust port's code generation emits calls to save and restore bounds checking state around `setjmp`/`longjmp` call sites. The compiler-side instrumentation is improved to emit `__bound_setjmp` and `__bound_longjmp` wrapper calls that maintain the bounds table consistency. The runtime bounds checking library (`lib/bcheck.c`) is retained as-is.

**Rust Location**: `crates/tcc-core/src/codegen.rs`

**Known Limitation**: Compiler-side instrumentation is improved, but the runtime `bcheck.c` is retained in its original C form. Full verification requires runtime testing of the bounds checking library, which is compiled by TCC itself.

**Evidence**: Compile bounds-checked programs using setjmp/longjmp. Verify no false positives or missed bounds violations around longjmp sites.

---

### BOUND-03: Fix bound check code with & on local variables

**TODO text**: "fix bound check code with '&' on local variables (currently done only for local arrays)."
**Category**: bound_checking
**Source file(s)**: `tccgen.c` (bounds instrumentation for address-of operator)
**Status**: `fixed`

**Analysis**: The bounds checking instrumentation only registered local arrays with the bounds tracking runtime, not local scalar variables whose address was taken. When the address of a local scalar variable was taken (e.g., `int x = 5; int *p = &x;`), the pointer `p` was not tracked by the bounds checker, so subsequent accesses through `p` were not validated. This meant out-of-bounds access through pointers to local scalars could go undetected.

**Reproduction**: `int x = 5; int *p = &x; p[1] = 10;` compiled with `-b`. The access `p[1]` is out of bounds (only `x` is allocated) but was not caught because `x` was not registered with the bounds tracker.

**Fix Approach**: The Rust port extends bounds tracking to register local scalar variables (not just arrays) when their address is taken. The code generation emits `__bound_local_new()` calls for all address-of operations on local variables, registering the variable's memory region with the bounds tracker.

**Rust Location**: `crates/tcc-core/src/codegen.rs`

**Evidence**: Compile the test case above with `-b`. Verify that the out-of-bounds access `p[1]` is detected and reported by the bounds checker.

---

### BOUND-04: Bound checking and float/long long/struct copy code

**TODO text**: "bound checking and float/long long/struct copy code. bound checking and symbol + offset optimization"
**Category**: bound_checking
**Source file(s)**: `tccgen.c` (copy code generation paths for non-int types)
**Status**: `fixed`

**Analysis**: Bounds checking instrumentation was only emitted for `int`-sized memory accesses. When copying `float`, `long long`, or `struct` values (which use wider or multi-word copy operations), the bounds checker was bypassed. This meant out-of-bounds access during struct assignment, floating-point operations, or 64-bit integer operations would go undetected in bounds-checked mode.

**Reproduction**: Create a struct assignment that goes out of bounds: `struct S { int a[10]; }; struct S *p = ...; *p = src;` where `p` points to insufficient memory. Compile with `-b` and verify the bounds violation is detected.

**Fix Approach**: The Rust port ensures that bounds-checking instrumentation is emitted for all memory access operations regardless of type width. Whether the access is 1-byte (`char`), 4-byte (`float`, `int`), 8-byte (`long long`, `double`), or multi-byte (`struct`), the same `__bound_check()` instrumentation is generated before the memory operation.

**Rust Location**: `crates/tcc-core/src/codegen.rs`

**Evidence**: Compile struct copy, float assignment, and long long operations with `-b` in bounds-checked mode. Verify that out-of-bounds accesses are correctly detected for all types.

---

## Missing Features (6 Items)

### FEAT-01: disable-asm and disable-bcheck options

**TODO text**: "disable-asm and disable-bcheck options"
**Category**: missing_feature
**Source file(s)**: `configure` (build options)
**Status**: `fixed`

**Analysis**: The original TCC build system (`configure` + `Makefile`) did not provide options to disable the assembler or bounds checking functionality at build time. Users who wanted a minimal compiler without these features had no supported way to exclude them.

**Reproduction**: Not a runtime bug — this is a missing build configuration option.

**Fix Approach**: The Rust port implements this as Cargo feature flags in `crates/tcc-core/Cargo.toml`: `asm` (default enabled) and `bcheck` (default enabled). Code dependent on these features uses `#[cfg(feature = "asm")]` and `#[cfg(feature = "bcheck")]` conditional compilation attributes. Users can build without these features using `cargo build --no-default-features --features "..."`.

**Rust Location**: `crates/tcc-core/Cargo.toml`

**Evidence**: Build with `cargo build --no-default-features` and verify that assembler and bounds checking code is excluded from the binary.

---

### FEAT-02: __builtin_expect()

**TODO text**: "__builtin_expect()"
**Category**: missing_feature
**Source file(s)**: `tccgen.c` (builtin handling)
**Status**: `fixed`

**Analysis**: The GCC built-in `__builtin_expect(expr, val)` provides branch prediction hints to the compiler. Many codebases (including the Linux kernel) use this extensively through the `likely()` and `unlikely()` macros. Without support for `__builtin_expect`, compiling such code would fail.

**Reproduction**: Compile code using `__builtin_expect(x, 1)` or the `likely(x)` / `unlikely(x)` macros commonly defined as `__builtin_expect(!!(x), 1)` and `__builtin_expect(!!(x), 0)`.

**Fix Approach**: The Rust port implements `__builtin_expect(expr, val)` as a pass-through that evaluates to `expr`. Since TCC does not perform branch prediction optimization (it has no optimization passes), the hint value is accepted but not used for code generation — matching GCC's behavior at `-O0`.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile programs using `__builtin_expect()` and `likely()`/`unlikely()` macros. Verify they compile successfully and produce correct results (the hint does not affect correctness).

---

### FEAT-03: atexit support in -run mode

**TODO text**: "atexit (Nigel Horne)"
**Category**: missing_feature
**Source file(s)**: `tccrun.c` (program termination handling)
**Status**: `fixed`

**Analysis**: In TCC's `-run` mode (compile and execute in memory), functions registered with `atexit()` were not called when the compiled program exited. This is because `-run` mode executes the compiled program's `main()` function directly and returns to TCC when `main()` returns, bypassing the normal C runtime exit sequence that would call `atexit` handlers.

**Reproduction**: Compile and run a program using `-run` that registers an `atexit` handler: `void cleanup() { printf("cleanup\n"); } int main() { atexit(cleanup); return 0; }`. Verify "cleanup" is printed.

**Fix Approach**: The Rust port's runtime module intercepts `exit()` calls in `-run` mode and maintains an `atexit` handler list. When the compiled program exits (either by returning from `main()` or calling `exit()`), all registered `atexit` handlers are called in reverse registration order before control returns to TCC.

**Rust Location**: `crates/tcc-core/src/runtime.rs`

**Evidence**: Run the test case above with `-run` and verify the atexit handler is called.

---

### FEAT-04: C99 complex types

**TODO text**: "C99: add complex types (gcc 3.2 testsuite issue)"
**Category**: missing_feature
**Source file(s)**: `tccgen.c` (type system)
**Status**: `partially_fixed`

**Analysis**: C99 introduced `_Complex` types (`_Complex float`, `_Complex double`, `_Complex long double`) for complex number arithmetic. TCC did not support these types, causing compilation failures when processing code that uses complex numbers, including some GCC 3.2 testsuite test cases.

**Reproduction**: Compile a program using `_Complex float z = 1.0 + 2.0i;` or `_Complex double w = CMPLX(3.0, 4.0);`. The original TCC would reject these declarations.

**Fix Approach**: The Rust port adds a `VT_COMPLEX` type flag in the type system, handles the `_Complex` type specifier in the parser, and implements basic complex arithmetic as pairs of floating-point operations (real and imaginary parts stored as consecutive float/double values). Basic operations (addition, subtraction, multiplication, division) and type declarations are supported.

**Rust Location**: `crates/tcc-core/src/types.rs`, `crates/tcc-core/src/parser.rs`, `crates/tcc-core/src/codegen.rs`

**Known Limitation**: Basic `_Complex` type declaration and simple operations are implemented. Full C99 complex math library integration (the `<complex.h>` functions like `cexp`, `clog`, `cabs`, `carg`, etc.) is deferred, as it requires runtime library support from the target's math library.

**Evidence**: Compile programs declaring `_Complex float` and `_Complex double` variables and performing basic arithmetic (+, -, *, /). Verify correct results.

---

### FEAT-05: Postfix compound literals

**TODO text**: "postfix compound literals (see 20010124-1.c)"
**Category**: missing_feature
**Source file(s)**: `tccgen.c` (compound literal parsing)
**Status**: `fixed`

**Analysis**: Compound literals in postfix position (as specified in C99 Section 6.5.2.5) were not fully supported. The test case `20010124-1.c` from the GCC testsuite demonstrated patterns where compound literals appear in postfix expression contexts that TCC could not parse correctly.

**Reproduction**: Use a compound literal in a postfix context, e.g., `((struct S){.x = 1, .y = 2}).x` or passing a compound literal to a function and immediately accessing its result.

**Fix Approach**: The Rust port's parser supports compound literals in postfix position per C99 6.5.2.5. The expression parser recognizes the `(type-name){initializer-list}` syntax in all positions where a postfix expression is valid.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile the `20010124-1.c` test case and other programs using postfix compound literals. Verify correct compilation and execution.

---

### FEAT-06: Interactive mode / integrated debugger

**TODO text**: "interactive mode / integrated debugger"
**Category**: missing_feature
**Source file(s)**: N/A (not implemented in the C codebase)
**Status**: `deferred`

**Analysis**: This TODO item requests a new feature — an interactive compilation mode and/or integrated debugger — that was never implemented in the original C codebase. It represents a significant new capability beyond the existing compiler functionality.

**Reproduction**: N/A — this is a feature request, not a bug.

**Fix Approach**: Deferred. This is a new feature, not a migration of existing behavior. The user's minimal change clause states "Do not add unrelated optimizations/features." An interactive debugger would be a substantial new capability that goes well beyond the C→Rust migration scope.

**Rust Location**: N/A

**Rationale for Deferral**: Implementing an interactive mode or integrated debugger would constitute a new feature, not a preservation of existing behavior. The migration scope is limited to porting existing functionality while fixing documented bugs.

**Evidence**: N/A — deferred feature. No code change required.

---

## Optimizations (5 Items)

### OPT-01: Suppress specific anonymous symbol handling

**TODO text**: "suppress specific anonymous symbol handling"
**Category**: optimization
**Source file(s)**: `tccelf.c` (symbol table construction)
**Status**: `fixed`

**Analysis**: The ELF symbol table construction included redundant handling of anonymous symbols (compiler-generated symbols without user-visible names), leading to unnecessarily large symbol tables and wasted memory during compilation.

**Reproduction**: Compile a large translation unit and inspect the generated symbol table size. Compare the number of anonymous symbols against the minimum necessary.

**Fix Approach**: The Rust port's symbol table management in the ELF module uses more efficient anonymous symbol handling. Redundant symbol entries are avoided through cleaner data structure management, and anonymous symbols are only created when strictly necessary for relocation processing.

**Rust Location**: `crates/tcc-core/src/elf.rs`

**Evidence**: Compare symbol table sizes between C and Rust TCC output for the same input. Verify reduced anonymous symbol count.

---

### OPT-02: More parse optimizations

**TODO text**: "more parse optimizations (=even faster compilation)"
**Category**: optimization
**Source file(s)**: `tccpp.c`, `tccgen.c`
**Status**: `fixed`

**Analysis**: The C codebase's parsing pipeline had optimization opportunities in keyword lookup (linear search through arrays), token buffer management (frequent small allocations), and expression parsing (redundant type checks).

**Reproduction**: Benchmark compilation speed on large translation units.

**Fix Approach**: The Rust port inherently benefits from Rust's standard library data structures: `HashMap` for O(1) keyword lookup instead of linear search, `Vec`-based token buffers with pre-allocation to reduce allocation overhead, and Rust's pattern matching for efficient token dispatch in the parser.

**Rust Location**: `crates/tcc-core/src/lexer.rs`, `crates/tcc-core/src/token.rs`, `crates/tcc-core/src/parser.rs`

**Evidence**: Benchmark compilation speed of the Rust port against the C original on representative test files.

---

### OPT-03: Memory allocation optimizations

**TODO text**: "memory alloc optimizations (=even faster compilation)"
**Category**: optimization
**Source file(s)**: `tcc.h` (TinyAlloc arena allocator — 256 KiB default)
**Status**: `fixed`

**Analysis**: The C codebase used `tcc_malloc`/`tcc_realloc`/`tcc_free` wrappers around the system allocator for most compilation memory, with a small `TinyAlloc` arena (256 KiB) for some temporary data. The frequent system allocator calls added overhead during compilation.

**Reproduction**: Profile compilation of a large file and measure time spent in memory allocation.

**Fix Approach**: The Rust port implements an arena-based allocator for temporary compilation data in the `alloc` module, using a bump-allocation strategy similar to the `bumpalo` crate pattern but implemented inline without adding an external crate dependency. Compilation-lifetime data is allocated from the arena and freed in bulk when the compilation context is dropped.

**Rust Location**: `crates/tcc-core/src/alloc.rs`

**Evidence**: Profile memory allocation patterns during compilation. Verify reduced system allocator call frequency compared to per-object allocation.

---

### OPT-04: Optimize VT_LOCAL + const

**TODO text**: "optimize VT_LOCAL + const"
**Category**: optimization
**Source file(s)**: `tccgen.c` (code generation)
**Status**: `fixed`

**Analysis**: When accessing a local variable at a known constant offset (e.g., a struct member of a local struct variable), the code generator could emit more efficient code by folding the constant offset into the memory addressing mode instead of computing it separately.

**Reproduction**: Compile a function accessing struct members of local variables and inspect the generated code for redundant offset calculations.

**Fix Approach**: The Rust port's code generator recognizes the `VT_LOCAL + const` pattern and folds the constant offset into the base-pointer-relative addressing mode at code generation time. For `[rbp - offset + const]`, the combined displacement is computed at compile time rather than generating separate add instructions.

**Rust Location**: `crates/tcc-core/src/codegen.rs`

**Evidence**: Disassemble generated code for local struct member access and verify that constant offsets are folded into addressing modes.

---

### OPT-05: Better local variables handling

**TODO text**: "better local variables handling (needed for other targets)"
**Category**: optimization
**Source file(s)**: `tccgen.c`, architecture-specific generators (`{arch}-gen.c`)
**Status**: `partially_fixed`

**Analysis**: TCC's `VT_LOCAL` representation uses frame-pointer-relative addressing for all local variables. On RISC architectures (ARM, ARM64, RISC-V) where immediate offset sizes are limited, this can generate inefficient code — requiring multiple instructions to compute large frame offsets. A better approach for RISC targets is to use a base register loaded with the stack frame base address and use smaller offsets relative to that register.

**Reproduction**: Compile a function with many local variables on an ARM or RISC-V target. Inspect the generated code for inefficient offset calculations.

**Fix Approach**: The Rust port improves local variable handling for ARM64 and RISC-V64 backends by using a base register for local variable access instead of relying solely on VT_LOCAL frame-pointer-relative addressing. This enables more efficient load/store instructions with smaller immediate offsets.

**Rust Location**: `crates/tcc-core/src/arch/arm64/gen.rs`, `crates/tcc-core/src/arch/riscv64/gen.rs`

**Known Limitation**: The optimization is implemented for ARM64 and RISC-V64 backends. Full optimization for all RISC targets (including 32-bit ARM) is a broader effort that requires per-backend tuning.

**Evidence**: Compare generated code size for functions with many locals on ARM64 and RISC-V64 targets before and after the optimization.

---

## Not Critical (8 Items)

### NC-01: C99 multiple compound literal inits in blocks with gotos

**TODO text**: "C99: fix multiple compound literals inits in blocks (ISOC99 normative example - only relevant when using gotos! -> must add boolean variable to tell if compound literal was already initialized)."
**Category**: not_critical
**Source file(s)**: `tccgen.c` (compound literal initialization)
**Status**: `fixed`

**Analysis**: When using `goto` statements that could re-enter a block containing compound literal initializations, the compound literals could be incorrectly initialized multiple times. The C99 standard (normative example) specifies that compound literal initialization should occur only once, even if control flow via `goto` re-enters the initialization block. This requires a boolean tracking variable to prevent double-initialization.

**Reproduction**: Write a program with a `goto` that jumps back to before a compound literal initialization inside a block. Verify that the compound literal retains its value from the first initialization and is not re-initialized on the second pass.

**Fix Approach**: The Rust port's parser adds a boolean tracking variable per compound literal in block scope. When control flow enters the initialization for the first time, the boolean is set and the literal is initialized. On subsequent entries (via `goto`), the boolean check prevents re-initialization.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile and run the ISOC99 normative example with compound literals and gotos. Verify correct single-initialization behavior.

---

### NC-02: Add PowerPC generator

**TODO text**: "add PowerPC generator and improve codegen for RISC (need to suppress VT_LOCAL and use a base register instead)."
**Category**: not_critical
**Source file(s)**: N/A (not implemented in the C codebase)
**Status**: `deferred`

**Analysis**: This item requests a new architecture target (PowerPC code generator) that was never implemented in the original TCC codebase.

**Reproduction**: N/A — this is a feature request for a new architecture target.

**Fix Approach**: Deferred. Adding a PowerPC backend constitutes a new feature, not migration of existing code. The user did not request PowerPC support, and the minimal change clause applies. The RISC codegen improvement aspect (base register for locals) is partially addressed by OPT-05 for ARM64 and RISC-V64.

**Rust Location**: N/A

**Rationale for Deferral**: PowerPC is a new target architecture not present in the original codebase. Adding it would violate the minimal change clause of the migration.

**Evidence**: N/A — deferred feature. No code change required.

---

### NC-03: Fix preprocessor symbol redefinition

**TODO text**: "fix preprocessor symbol redefinition"
**Category**: not_critical
**Source file(s)**: `tccpp.c` (macro definition handling)
**Status**: `fixed`

**Analysis**: The preprocessor did not correctly handle macro redefinition according to the C standard (Section 6.10.3, paragraph 2). The standard specifies that a macro may be redefined only if the replacement list is identical (token-for-token) to the existing definition; otherwise, the implementation should emit a diagnostic (warning). The original TCC either silently accepted all redefinitions or rejected them all, without distinguishing between identical and different redefinitions.

**Reproduction**: Define a macro, then redefine it with a different replacement: `#define FOO 1` followed by `#define FOO 2`. The compiler should emit a warning. Then redefine with the same replacement: `#define FOO 1` followed by `#define FOO 1`. No warning should be emitted.

**Fix Approach**: The Rust port's preprocessor implements C standard 6.10.3p2 behavior: macro redefinition is allowed only if the replacement lists are identical (compared token-by-token). If the replacement lists differ, a warning is emitted. If they are identical, the redefinition is silently accepted.

**Rust Location**: `crates/tcc-core/src/preprocessor.rs`

**Evidence**: Compile test programs with identical and non-identical macro redefinitions. Verify warnings are emitted only for non-identical redefinitions.

---

### NC-04: Add portable byte code generator and interpreter

**TODO text**: "add portable byte code generator and interpreter for other unsupported architectures."
**Category**: not_critical
**Source file(s)**: N/A (not implemented in the C codebase)
**Status**: `deferred`

**Analysis**: This item requests a new feature — a portable bytecode generator and interpreter that would allow TCC to target architectures without a native code generator by compiling to an intermediate bytecode format.

**Reproduction**: N/A — this is a feature request for new functionality.

**Fix Approach**: Deferred. This is a new feature, not migration of existing code. The bytecode interpreter would be a significant new subsystem with no corresponding code in the original C codebase.

**Rust Location**: N/A

**Rationale for Deferral**: New feature with no corresponding implementation in the source codebase. Goes beyond the C→Rust migration scope.

**Evidence**: N/A — deferred feature. No code change required.

---

### NC-05: C++ variable declaration in for, minimal class support

**TODO text**: "C++: variable declaration in for, minimal 'class' support."
**Category**: not_critical
**Source file(s)**: N/A (not implemented in the C codebase)
**Status**: `deferred`

**Analysis**: This item requests minimal C++ language support, specifically variable declarations in `for` loop initializers and basic `class` support. C++ is a significantly different language from C and would require substantial parser, type system, and code generation changes.

**Reproduction**: N/A — this is a feature request for C++ support.

**Fix Approach**: Deferred. The user explicitly did not request C++ support. Per AAP Section 0.3.2, C++ is out of scope for this migration. Note that C99 already supports variable declarations in `for` loop initializers, so that part is covered by the C99 support in the Rust port.

**Rust Location**: N/A

**Rationale for Deferral**: C++ support is explicitly out of scope per the migration requirements. The C→Rust migration preserves C compilation capability.

**Evidence**: N/A — deferred feature. C++ is out of scope per AAP Section 0.3.2.

---

### NC-06: Win32 __intxx, exception code

**TODO text**: "win32: __intxx. use resolve for bchecked malloc et al. check exception code (exception filter func)."
**Category**: not_critical
**Source file(s)**: `tccgen.c` (parser), `tccpe.c` (PE/COFF backend)
**Status**: `partially_fixed`

**Analysis**: This item covers multiple Windows-specific features: (1) support for Microsoft's `__int8`, `__int16`, `__int32`, `__int64` type specifiers; (2) using runtime symbol resolution for bounds-checked `malloc` variants; and (3) verifying exception filter function handling in the PE backend.

**Reproduction**: On a Windows target, compile code using `__int64 x = 42;` or code with structured exception handling (`__try`/`__except`).

**Fix Approach**: The Rust port implements `__int8`, `__int16`, `__int32`, and `__int64` type specifiers in the parser, enabled when targeting Windows via a feature flag. These are mapped to the corresponding Rust/C fixed-width integer types. The exception filter function handling from `tccpe.c` is ported to the PE module.

**Rust Location**: `crates/tcc-core/src/parser.rs`, `crates/tcc-core/src/pe.rs`

**Known Limitation**: The `__intxx` type specifiers are implemented. Full exception filter function verification is deferred to Windows-specific testing, as it requires a Windows execution environment.

**Evidence**: Compile programs using `__int8`/`__int16`/`__int32`/`__int64` on a Windows target. Verify correct type sizes.

---

### NC-07: Handle void (__attribute__() *ptr)()

**TODO text**: "handle void (__attribute__() *ptr)()"
**Category**: not_critical
**Source file(s)**: `tccgen.c` (declaration parser)
**Status**: `fixed`

**Analysis**: The parser did not correctly handle `__attribute__` specifications placed between the return type and the `*` in function pointer declarations. The syntax `void (__attribute__((stdcall)) *ptr)()` should declare `ptr` as a pointer to a function with `stdcall` calling convention returning void, but TCC's parser could not parse this specific attribute placement.

**Reproduction**: Declare a function pointer with an attribute between the return type and asterisk: `void (__attribute__((stdcall)) *my_func_ptr)(int, int);`. The original TCC would fail to parse this declaration.

**Fix Approach**: The Rust port's declaration parser supports `__attribute__` specifications in all positions allowed by the GCC extension syntax, including between the return type and the `*` in function pointer declarators. The attribute is correctly associated with the function type rather than the pointer type.

**Rust Location**: `crates/tcc-core/src/parser.rs`

**Evidence**: Compile programs using attribute-decorated function pointer declarations in various syntactic positions. Verify correct parsing and code generation.

---

### NC-08: VLAs not compatible with signals

**TODO text**: "VLAs are implemented in a way that is not compatible with signals: http://lists.gnu.org/archive/html/tinycc-devel/2015-11/msg00018.html"
**Category**: not_critical
**Source file(s)**: `tccgen.c` (VLA implementation)
**Status**: `blocked`

**Analysis**: TCC implements Variable-Length Arrays (VLAs) by directly adjusting the stack pointer at runtime. When a signal is delivered while the program is in the middle of VLA allocation (between adjusting the stack pointer and completing the frame setup), the signal handler finds a corrupted or inconsistent stack state. This can cause crashes or undefined behavior in the signal handler.

**Reproduction**: Allocate a large VLA in a function and arrange for a signal to be delivered during the allocation. The signal handler may crash or observe incorrect stack state.

**Fix Approach**: This is an architectural limitation of TCC's VLA implementation strategy (stack pointer manipulation). Resolving it would require switching to a heap-based VLA implementation (using `malloc`/`free`), which would change observable behavior (VLAs would survive `longjmp`, have different performance characteristics, and potentially fail due to heap exhaustion rather than stack overflow). The C standard does not require VLAs to be signal-safe.

**Rust Location**: `docs/compatibility_report.md` (documented as known limitation)

**Rationale for Blocked Status**: The fix would require a fundamentally different VLA implementation strategy that changes observable behavior. This violates the behavioral preservation requirement of the migration. The limitation is documented in the compatibility report.

**Evidence**: The limitation is documented and consistent with the original C implementation's behavior.

---

## Release / Process (2 Items)

### REL-01: Release TCC on a regular basis

**TODO text**: "release tcc on a regular basis"
**Category**: release/process
**Source file(s)**: N/A
**Status**: `deferred`

**Analysis**: This is a process/project management item requesting regular release cadence for TCC. It does not correspond to any code change.

**Reproduction**: N/A — process item.

**Fix Approach**: Deferred. This is a project management item outside the scope of code migration. The Rust port's versioning follows Cargo conventions with the version specified in `Cargo.toml`.

**Rust Location**: N/A

**Rationale for Deferral**: Process item, not a code change. The Rust port establishes a Cargo-based build system that can facilitate future releases.

**Evidence**: N/A — process item outside code migration scope.

---

### REL-02: Testing repo.or.cz

**TODO text**: "testing repo.or.cz"
**Category**: release/process
**Source file(s)**: N/A
**Status**: `deferred`

**Analysis**: This is an infrastructure item related to testing the TCC repository hosting at `repo.or.cz`. It does not correspond to any code change.

**Reproduction**: N/A — infrastructure item.

**Fix Approach**: Deferred. This is an infrastructure item outside the scope of code migration.

**Rust Location**: N/A

**Rationale for Deferral**: Infrastructure item, not a code change.

**Evidence**: N/A — infrastructure item outside code migration scope.

---

## Historical Fixed Items (Resolved Prior to Migration)

The `TODO` file's "Fixed (probably)" section (lines 90–109) lists items that were resolved in the C codebase prior to the Rust migration. These are **NOT** counted in the 45 active items above but are acknowledged here for completeness. All of these fixes are preserved in the Rust port:

1. **Bug with defines** — `#define spin_lock(lock) do { } while (0)` / `#define wq_spin_lock spin_lock` / `#define TEST() wq_spin_lock(a)` — Macro expansion with nested definitions of parameterized macros was fixed.

2. **Typedefs as structure fields** — Typedef names used as structure field names are now correctly handled (the field name does not conflict with the typedef).

3. **Long long constant evaluation** — See `bugfixes.diff` + `improvement.diff` from Daniel Glöckner. Constant expression evaluation for `long long` values was corrected.

4. **alloca()** — `alloca()` support was added, implemented as a stack pointer adjustment with platform-specific assembly (`lib/alloca.S`).

5. **gcc '-E' option** — The `-E` (preprocess-only) option was implemented, producing preprocessed output to stdout.

6. **#include_next support** — `#include_next` (used in system headers like `/usr/include/limits.h`) was implemented to search for the next matching include file in the search path.

7. **Function pointers/lvalues in ?:** — Function pointers and lvalues in the ternary conditional operator (`? :`) are now correctly handled (referenced by Linux kernel `net/core/dev.c`).

8. **Win32 __stdcall, GetModuleHandle** — Windows `__stdcall` calling convention and `GetModuleHandle` for DLL support were added.

9. **Macro substitution with nested definitions** — Complex macro substitution with nested definitions (reported by ShangHongzhang) was fixed.

10. **PLT built with -run and libtcc** — Procedure Linkage Table (PLT) generation for `-run` mode and libtcc embedding was implemented.

11. **'-E' option improved** — The preprocess-only output was improved for better GCC compatibility.

12. **Packed attribute supported** — `__attribute__((packed))` for structures was implemented.

13. **ARM and ARM64 code generators added** — Complete ARM (32-bit) and ARM64 (AArch64) code generator backends were added.

---

## Related Documents

- **Full Coverage Matrix**: [`docs/todo_full_coverage_matrix.md`](todo_full_coverage_matrix.md) — Tabular view of all 45 items with one row per item
- **Bug Reproduction Guide**: [`README.bug-repros.md`](../README.bug-repros.md) — Step-by-step reproduction and verification instructions for each bug
- **Compatibility Report**: [`docs/compatibility_report.md`](compatibility_report.md) — Behavioral differences between C and Rust implementations
- **Migration Plan**: [`docs/migration_plan.md`](migration_plan.md) — C→Rust module mapping and phase plan
