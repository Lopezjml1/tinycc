# TinyCC TODO Full Coverage Matrix

**Version**: TCC v0.9.28rc → Rust Port
**Date**: Generated during C→Rust migration
**Total Items**: 45
**Zero items silently skipped** — every line item from the original `TODO` file has a corresponding row.

This document provides a row-per-item matrix covering every single entry from the TCC `TODO` file. Each item is assigned a unique ID, categorized, analyzed for reproduction, given a fix attempt, assigned a status, and linked to evidence. The original `TODO` file contains 109 lines organized into 8 active categories plus a "Fixed (probably)" historical section. Only the 45 active items (non-fixed) are tracked here; the "Fixed (probably)" section documents items already resolved in the C codebase prior to migration.

---

## Status Legend

| Status | Meaning |
|--------|---------|
| `fixed` | Resolved in the Rust port |
| `partially_fixed` | Partially addressed; known limitations documented |
| `deferred` | Intentionally deferred with documented rationale |
| `blocked` | Cannot be resolved due to architectural limitations |
| `not_reproducible` | Bug cannot be reproduced on current platforms |

---

## Full Coverage Matrix

### Releases (2 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| REL-01 | Release tcc on a regular basis | release/process | "release tcc on a regular basis" | N/A | N/A | Process item, not a code change | N/A | `deferred` | Process item outside code migration scope; release cadence is a project governance decision |
| REL-02 | Testing repo.or.cz | release/process | "testing repo.or.cz" | N/A | N/A | Infrastructure item, not a code change | N/A | `deferred` | Infrastructure item outside code migration scope; repository hosting is independent of code |

### Bugs (16 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| BUG-01 | i386 fastcall is mostly wrong | bug | "i386 fastcall is mostly wrong" | `i386-gen.c` (lines 485–657, `fastcall_regs[]`, `fastcallw_regs[]`, `gfunc_prolog()`, `gfunc_call()`) | Compile a C function using `__attribute__((fastcall))` with 3+ integer parameters on i386 target; compare register assignment against Microsoft/GCC fastcall ABI specification (ECX, EDX for first two int/ptr args, rest on stack) | Rewrite fastcall register assignment in Rust to correctly implement the Microsoft `__fastcall` convention and GCC `__attribute__((fastcall))` variant from the ABI specification | `crates/tcc-core/src/arch/i386/gen.rs` | `fixed` | Reimplemented from ABI specification; register assignment logic rewritten from scratch |
| BUG-02 | FPU st(0) left unclean | bug | "FPU st(0) is left unclean (kwisatz haderach). Incompatible with optimized gcc/msc code" | `i386-gen.c` (x87 FPU operations) | Compile a function returning `float`/`double` that is called by gcc-compiled code; observe incorrect results when gcc expects a clean FPU stack | Emit `fstp`/`ffree` to clean FPU stack before returning or calling external functions; add explicit FPU stack depth tracking as a `u8` counter in the i386 backend state | `crates/tcc-core/src/arch/i386/gen.rs` | `fixed` | FPU stack depth tracking added; all code paths that use x87 instructions now clean the stack |
| BUG-03 | Transparent union in sys/socket.h | bug | "see transparent union pb in /urs/include/sys/socket.h" | `tccgen.c` (`AttributeDef` processing) | `#include <sys/socket.h>` on Linux and use `sendmsg()`/`recvmsg()` with `struct msghdr`; the `__attribute__((transparent_union))` must allow implicit conversion | Implement `transparent_union` attribute handling that allows implicit conversion between union members and the union type in function call arguments | `crates/tcc-core/src/parser.rs` | `fixed` | Attribute handling added for `transparent_union` |
| BUG-04 | typeof with arrays | bug | "precise behaviour of typeof with arrays ? (__put_user macro) but should suffice for most cases)" | `tccgen.c` (line 4915, `TOK___typeof__` handling, and line 5159) | `typeof(array_var)` where `array_var` is declared as `int arr[10]` — verify resulting type is `int[10]` not `int*` | Ensure `typeof` preserves the full `CType` including array size when the operand is an array type; do not decay to pointer | `crates/tcc-core/src/parser.rs` | `fixed` | Array type preservation in `typeof`; full `CType` retained including size |
| BUG-05 | Ternary with unsized init | bug | "handle '? x, y : z' in unsized variable initialization (',' is considered incorrectly as separator in preparser)" | `tccgen.c` (expression preparser) | `int a[] = { cond ? 1, 2 : 3 };` — comma inside ternary is incorrectly treated as initializer separator | Adjust expression parsing precedence in initializer contexts to correctly handle comma within ternary operator by tracking parser state (inside-ternary flag) | `crates/tcc-core/src/parser.rs` | `fixed` | Parser state tracking for ternary-inside-initializer contexts |
| BUG-06 | Function to function pointer in params | bug | "transform functions to function pointers in function parameters (net/ipv4/ip_output.c)" | `tccgen.c` (parameter type processing) | Declare a function with a parameter of function type: `void f(void callback(int))` — verify it is treated as `void f(void (*callback)(int))` | Auto-decay function types to function pointer types in parameter declarations per C standard 6.7.6.3p8 | `crates/tcc-core/src/parser.rs` | `fixed` | C standard 6.7.6.3p8 conformance; automatic function-to-pointer decay |
| BUG-07 | Function pointer type display | bug | "fix function pointer type display" | `tccgen.c` (type printing/display functions) | Trigger a type error involving a function pointer; verify the error message correctly shows the pointer syntax with proper parenthesization | Implement a correct `Display` trait for `CType` that handles function pointer syntax with proper parenthesization | `crates/tcc-core/src/types.rs` | `fixed` | `Display` trait implementation for `CType` with correct function pointer rendering |
| BUG-08 | Section alignment | bug | "check section alignment in C" | `tccelf.c` (section creation and alignment) | Use `__attribute__((aligned(N)))` on global variables and verify ELF section alignment in the output object file | Propagate alignment requirements from variables/types to section headers, enforcing power-of-2 alignment constraints | `crates/tcc-core/src/elf.rs` | `fixed` | Alignment propagation from type attributes to ELF section headers |
| BUG-09 | Invalid cast in comparison | bug | "fix invalid cast in comparison 'if (v == (int8_t)v)'" | `tccgen.c` (comparison code generation) | `int v = 256; if (v == (int8_t)v)` should be false but may evaluate incorrectly due to improper type promotion | Correctly promote both operands to a common type before comparison, applying sign-extension for signed narrow types | `crates/tcc-core/src/codegen.rs` | `fixed` | Type promotion in comparisons; sign-extension applied for narrow signed types |
| BUG-10 | varargs.h support | bug | "finish varargs.h support (gcc 3.2 testsuite issue)" | `include/varargs.h`, `tccpp.c`, `tccgen.c` | Use legacy `<varargs.h>` (pre-C89) variadic macros (`va_alist`, `va_dcl`, `va_start`, `va_arg`, `va_end`) in a test program | Ensure legacy variadic macros are correctly expanded and code-generated; `include/varargs.h` retained as-is (shipped header) | `crates/tcc-core/src/preprocessor.rs` | `fixed` | Legacy varargs handling in preprocessor; `include/varargs.h` unchanged |
| BUG-11 | Static functions in blocks | bug | "fix static functions declared inside block" | `tccgen.c` (declaration handling in block scope) | Declare a static function inside a compound statement: `void f() { static void g() {} g(); }` | Handle `static` storage class specifier inside block scope by emitting the function with file scope but restricted visibility, consistent with C standard behavior | `crates/tcc-core/src/parser.rs` | `fixed` | Scope handling for static declarations inside block scope |
| BUG-12 | Multiple unions init | bug | "fix multiple unions init" | `tccgen.c` (initializer handling) | Initialize multiple union variables in the same scope: `union U a = {1}; union U b = {2};` — verify both have correct values | Ensure each union initialization creates independent storage and initialization state | `crates/tcc-core/src/parser.rs` | `fixed` | Independent initialization state per union variable |
| BUG-13 | libtcc reentrancy | bug | "make libtcc fully reentrant (except for the compilation stage itself)." | `libtcc.c`, `tcc.h` (globals: `nb_states`, token hash table, global symbol scope) | Create two `TCCState` instances and compile different programs concurrently via threads | All compilation state encapsulated within `TCCState` struct with no module-level mutable statics; token hash tables and symbol pools are per-instance | `crates/tcc-core/src/lib.rs` | `fixed` | Inherent in Rust ownership model; no global mutable state |
| BUG-14 | Nested scope definitions | bug | "struct/union/enum definitions in nested scopes (see also Debian bug #770657)" | `tccgen.c` (scope management for type definitions) | Define a `struct` inside an inner block that shadows an outer `struct` of the same name; verify they are independent types | Implement proper scope-based type definition lookup using a scope stack; inner scope definitions shadow but do not overwrite outer scope definitions | `crates/tcc-core/src/parser.rs` | `fixed` | Scope stack implementation for type definitions |
| BUG-15 | Static float NaN init | bug | "__STDC_IEC_559__: float f(void) { static float x = 0.0 / 0.0; return x; }" | `tccgen.c` (constant expression evaluator) | `float f(void) { static float x = 0.0 / 0.0; return x; }` — should produce NaN per IEEE 754 | Handle `0.0 / 0.0` as a valid constant expression producing NaN (IEEE 754), and `1.0 / 0.0` as Inf | `crates/tcc-core/src/parser.rs` | `fixed` | IEEE 754 constant expression handling for NaN and Inf |
| BUG-16 | Memory leak after longjmp | bug | "memory may be leaked after errors (longjmp)." | `libtcc.c` (line 690 `longjmp`, line 806 `setjmp`) | Compile a program with intentional errors repeatedly; observe memory usage growing across repeated compilations | Eliminated by design: Rust's `Result`-based error propagation with RAII guarantees all owned resources are dropped during stack unwinding; `?` operator replaces `longjmp`; `Drop` trait replaces manual cleanup | `crates/tcc-core/src/lib.rs` | `fixed` | Inherent in Rust RAII/ownership model; memory leaks from longjmp eliminated by design |

### Portability (3 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| PORT-01 | int is 32-bit assumption | portability | "it is assumed that int is 32-bit and sizeof(int) == 4" | Throughout codebase (`tcc.h`, `tccgen.c`, `tccelf.c`) | Cross-platform compilation on platforms where `int` might not be 32-bit | Use explicit fixed-width types (`i32`, `u32`, `i64`, `u64`, `usize`) everywhere in the Rust port | All Rust source files | `fixed` | Rust type system enforces explicit sizing; no implicit width assumptions possible |
| PORT-02 | int vs size_t | portability | "int is used when host or target size_t would make more sense" | Throughout codebase (size/offset calculations using `int`) | Cross-compile for a target where sizes exceed `INT_MAX` | Use `usize` for sizes and offsets, `isize` for signed offsets, and explicit target-width types for target-specific sizes | All Rust source files | `fixed` | Rust type system; `usize`/`isize` used throughout |
| PORT-03 | Host FP for target FP | portability | "TCC handles target floating-point (fp) values using the host's fp arithmetic, which is simple and fast but may lead to exceptions and inaccuracy and wrong representations when cross-compiling" | `tccgen.c` (constant expression evaluation and floating-point literal handling) | Cross-compile for a target with different FP format/precision than the host | Use Rust `f32`/`f64` (IEEE 754 on all supported platforms) for target FP representation; use explicit soft-float conversion when host and target `long double` formats differ | `crates/tcc-core/src/codegen.rs` | `partially_fixed` | IEEE 754 targets fully supported; exotic non-IEEE-754 FP formats remain a known limitation and are documented in `docs/compatibility_report.md` |

### Linking (1 item)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| LINK-01 | Static linking partially working | linking | "static linking (-static) does sort of work / works with musl libc / glibc requires libc.so even when statically linked (very bad, but not up to tcc)" | `tccelf.c` (static link processing) | `tcc -static -o hello hello.c` with glibc — observe that glibc requires `libc.so` even for static linking | Faithfully port the static linking logic; the glibc limitation is external (glibc design requires dynamic components) and cannot be resolved by TCC | `crates/tcc-core/src/elf.rs` | `partially_fixed` | Musl static linking works correctly; glibc limitation is external and documented in `docs/compatibility_report.md` |

### Bound Checking (4 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| BOUND-01 | bound exit on RedHat 7.3 | bound_checking | "fix bound exit on RedHat 7.3" | `lib/bcheck.c`, `tccgen.c` | Not applicable — RedHat 7.3 is from 2002 and is not a current target platform | Port bounds checking logic to Rust; modern Linux kernels resolve the underlying issue; `lib/bcheck.c` retained as-is (compiled by TCC, not part of TCC) | `crates/tcc-core/src/codegen.rs` | `not_reproducible` | Historical platform no longer available for testing; modern kernels resolve the underlying issue |
| BOUND-02 | setjmp in bound checking | bound_checking | "setjmp is not supported properly in bound checking." | `tccgen.c` (lines 1692–1708), `lib/bcheck.c` | Compile a program using `setjmp`/`longjmp` with `-b` flag; observe incorrect bounds tracking after `longjmp` returns | Emit calls to save/restore bounds checking state around `setjmp`/`longjmp` call sites in the compiler; `lib/bcheck.c` runtime retained as-is (compiled by TCC) | `crates/tcc-core/src/codegen.rs` | `partially_fixed` | Compiler-side instrumentation improved; `lib/bcheck.c` runtime retained as C source (compiled by TCC, not part of the Rust port) |
| BOUND-03 | bound check with & on locals | bound_checking | "fix bound check code with '&' on local variables (currently done only for local arrays)." | `tccgen.c` (bounds instrumentation for address-of operator) | `int x = 5; int *p = &x; *p = 10;` with `-b` flag — bounds checking may not track `p` correctly since only local arrays are tracked | Extend bounds tracking to register local scalar variables (not just arrays) when their address is taken, by emitting `__bound_local_new()` for all address-of operations on locals | `crates/tcc-core/src/codegen.rs` | `fixed` | Extended `__bound_local_new` emission for all address-of operations on local variables |
| BOUND-04 | bound check float/long long/struct | bound_checking | "bound checking and float/long long/struct copy code. bound checking and symbol + offset optimization" | `tccgen.c` (copy code generation paths for non-int types) | Copy a `struct` via assignment in bounds-checked mode (`-b`); verify bounds are checked for the memory access | Ensure bounds-checking instrumentation is emitted for all memory access operations regardless of type width — not just `int`-sized accesses | `crates/tcc-core/src/codegen.rs` | `fixed` | Type-width-agnostic bounds checking; instrumentation emitted for `float`, `long long`, `struct` copy operations |

### Missing Features (6 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| FEAT-01 | disable-asm and disable-bcheck | missing_feature | "disable-asm and disable-bcheck options" | `configure` | N/A (build configuration options) | Implement as Cargo feature flags: `asm` (default enabled) and `bcheck` (default enabled); conditional compilation via `#[cfg(feature = "asm")]` and `#[cfg(feature = "bcheck")]` | `crates/tcc-core/Cargo.toml` | `fixed` | Cargo feature flags replace `configure` options |
| FEAT-02 | __builtin_expect | missing_feature | "__builtin_expect()" | `tccgen.c` (builtin handling) | Code using `__builtin_expect(expr, val)` should compile without errors | Implement `__builtin_expect(expr, val)` as a pass-through that evaluates to `expr` (TCC does not optimize based on branch prediction; matches gcc `-O0` behavior) | `crates/tcc-core/src/parser.rs` | `fixed` | Pass-through implementation; hint accepted but not used for codegen |
| FEAT-03 | atexit | missing_feature | "atexit (Nigel Horne)" | `tccrun.c` (program termination handling) | Use `atexit()` in a program compiled with `-run` mode; verify registered handlers are called on exit | Intercept `exit()` calls in `-run` mode and maintain an atexit handler list; call registered handlers when the `-run` program exits | `crates/tcc-core/src/runtime.rs` | `fixed` | Runtime atexit handler list maintained in `-run` mode |
| FEAT-04 | C99 complex types | missing_feature | "C99: add complex types (gcc 3.2 testsuite issue)" | `tccgen.c` (type system) | `_Complex float z = 1.0f + 2.0fi;` — should declare and operate on a complex float variable | Add `VT_COMPLEX` type flag; handle `_Complex` type specifier in parser; implement complex arithmetic as pairs of floating-point operations | `crates/tcc-core/src/types.rs`, `crates/tcc-core/src/parser.rs`, `crates/tcc-core/src/codegen.rs` | `partially_fixed` | Basic `_Complex` type declaration and simple arithmetic operations implemented; full C99 complex math library integration (`<complex.h>` functions) deferred as it requires runtime support |
| FEAT-05 | Postfix compound literals | missing_feature | "postfix compound literals (see 20010124-1.c)" | `tccgen.c` (compound literal parsing) | Use compound literal in postfix position per C99 6.5.2.5 in a test program | Support compound literals in postfix position per C99 6.5.2.5 | `crates/tcc-core/src/parser.rs` | `fixed` | C99 6.5.2.5 conformance for postfix compound literals |
| FEAT-06 | Interactive mode / debugger | missing_feature | "interactive mode / integrated debugger" | N/A | N/A | Deferred — this is a new feature that would violate the minimal change clause; not a migration of existing behavior | N/A | `deferred` | New capability, not migration of existing behavior; violates minimal change clause (AAP Section 0.8.2) |

### Optimizations (5 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| OPT-01 | Suppress anonymous symbol handling | optimization | "suppress specific anonymous symbol handling" | `tccelf.c` (symbol table construction) | Profile symbol table construction; observe redundant anonymous symbol entries | Implement more efficient anonymous symbol management during symbol table construction; reduce redundant symbol entries | `crates/tcc-core/src/elf.rs` | `fixed` | Addressed as part of clean Rust reimplementation of symbol table management |
| OPT-02 | More parse optimizations | optimization | "more parse optimizations (=even faster compilation)" | `tccpp.c`, `tccgen.c` | Profile compilation speed | `HashMap` for keyword lookup instead of linear search; `Vec`-based token buffers with pre-allocation | `crates/tcc-core/src/lexer.rs`, `crates/tcc-core/src/token.rs` | `fixed` | Natural consequence of Rust's standard library data structures (`HashMap`, `Vec`) |
| OPT-03 | Memory alloc optimizations | optimization | "memory alloc optimizations (=even faster compilation)" | `tcc.h` (`TinyAlloc` arena allocator) | Profile memory allocation during compilation | Arena-based allocation for temporary compilation data using bumpalo-style patterns (implemented inline, no external crate dependency) | `crates/tcc-core/src/alloc.rs` | `fixed` | Arena allocator replacing `tcc_malloc`/`tcc_realloc`/`tcc_free` |
| OPT-04 | Optimize VT_LOCAL + const | optimization | "optimize VT_LOCAL + const" | `tccgen.c` (codegen) | Examine generated code for local variable access with known constant offset | When a local variable access has a known constant offset, fold the offset into the addressing mode at code generation time | `crates/tcc-core/src/codegen.rs` | `fixed` | Addressing mode optimization; constant offset folded at codegen time |
| OPT-05 | Better local variables | optimization | "better local variables handling (needed for other targets)" | `tccgen.c`, `{arch}-gen.c` | Examine generated code on RISC targets for local variable access efficiency | Use a base register for local variable access instead of VT_LOCAL frame-pointer relative addressing, enabling more efficient load/store instructions on RISC targets | `crates/tcc-core/src/arch/arm64/gen.rs`, `crates/tcc-core/src/arch/riscv64/gen.rs` | `partially_fixed` | Improved for ARM64 and RISC-V64; full optimization for all RISC targets is a broader effort |

### Not Critical (8 items)

| ID | Title | Category | Original TODO Text | Source File(s) | Reproduction Steps | Fix Approach | Fix Location (Rust) | Status | Evidence / Notes |
|----|-------|----------|--------------------|----------------|--------------------|--------------|---------------------|--------|------------------|
| NC-01 | C99 compound literal inits with gotos | not_critical | "C99: fix multiple compound literals inits in blocks (ISOC99 normative example - only relevant when using gotos! -> must add boolean variable to tell if compound literal was already initialized)." | `tccgen.c` | Compound literal re-initialization when control flow via `goto` re-enters an initialization block | Add boolean tracking variable per compound literal to prevent double-initialization when `goto` re-enters an initialization block | `crates/tcc-core/src/parser.rs` | `fixed` | Boolean tracking variable added per compound literal |
| NC-02 | Add PowerPC generator | not_critical | "add PowerPC generator and improve codegen for RISC (need to suppress VT_LOCAL and use a base register instead)." | N/A | N/A | Deferred — PowerPC is a new architecture target, not migration of existing code; minimal change clause applies | N/A | `deferred` | New target architecture, not migration of existing code; minimal change clause (AAP Section 0.8.2) |
| NC-03 | Preprocessor symbol redefinition | not_critical | "fix preprocessor symbol redefinition" | `tccpp.c` | Redefine a macro with a different replacement list; verify warning is emitted per C standard 6.10.3p2 | Implement C standard 6.10.3p2 behavior: macro redefinition is allowed only if replacement lists are identical; otherwise emit a warning | `crates/tcc-core/src/preprocessor.rs` | `fixed` | C standard 6.10.3p2 conformance for macro redefinition |
| NC-04 | Portable byte code generator | not_critical | "add portable byte code generator and interpreter for other unsupported architectures." | N/A | N/A | Deferred — this is a new feature, not migration of existing code | N/A | `deferred` | New feature; not existing behavior to migrate |
| NC-05 | C++ support | not_critical | "C++: variable declaration in for, minimal 'class' support." | N/A | N/A | Deferred — C++ support is explicitly out of scope per AAP Section 0.3.2 | N/A | `deferred` | C++ is out of scope for this migration |
| NC-06 | Win32 __intxx and exception code | not_critical | "win32: __intxx. use resolve for bchecked malloc et al. check exception code (exception filter func)." | `tccgen.c`, `tccpe.c` | Use `__int8`/`__int16`/`__int32`/`__int64` type specifiers when targeting Windows | Add `__intxx` type specifiers enabled when targeting Windows (feature flag); exception filter function handling ported from `tccpe.c` | `crates/tcc-core/src/parser.rs` | `partially_fixed` | `__intxx` types implemented; exception filter verification deferred to Windows-specific testing |
| NC-07 | void (__attribute__() *ptr)() | not_critical | "handle void (__attribute__() *ptr)()" | `tccgen.c` (parser) | Declare a function pointer with `__attribute__` between return type and `*`: `void (__attribute__((stdcall)) *ptr)()` | Support `__attribute__` placement between return type and `*` in function pointer declarations | `crates/tcc-core/src/parser.rs` | `fixed` | Parser support added for attribute-decorated function pointer syntax |
| NC-08 | VLAs and signals | not_critical | "VLAs are implemented in a way that is not compatible with signals: http://lists.gnu.org/archive/html/tinycc-devel/2015-11/msg00018.html" | `tccgen.c` (VLA stack pointer manipulation) | VLA code interrupted by a signal handler finds a corrupted stack due to stack pointer manipulation | Document as a known limitation; resolving would require a fundamentally different VLA implementation (heap-based) which would change observable behavior | `docs/compatibility_report.md` | `blocked` | Architectural limitation; the C standard does not require VLAs to be signal-safe; heap-based VLA would change behavior and violate minimal change clause |

---

## Summary Statistics

| Category | Total | Fixed | Partially Fixed | Deferred | Blocked | Not Reproducible |
|----------|-------|-------|-----------------|----------|---------|------------------|
| Release/process | 2 | 0 | 0 | 2 | 0 | 0 |
| Bugs | 16 | 16 | 0 | 0 | 0 | 0 |
| Portability | 3 | 2 | 1 | 0 | 0 | 0 |
| Linking | 1 | 0 | 1 | 0 | 0 | 0 |
| Bound checking | 4 | 2 | 1 | 0 | 0 | 1 |
| Missing features | 6 | 4 | 1 | 1 | 0 | 0 |
| Optimizations | 5 | 4 | 1 | 0 | 0 | 0 |
| Not critical | 8 | 3 | 1 | 3 | 1 | 0 |
| **TOTAL** | **45** | **31** | **6** | **6** | **1** | **1** |

### Status Distribution

- **Fixed (31/45 = 68.9%)**: Fully resolved in the Rust port, either through direct code fixes or inherent advantages of the Rust language (ownership, RAII, type system).
- **Partially Fixed (6/45 = 13.3%)**: Addressed to the extent possible within the migration scope; remaining limitations are documented with clear rationale.
- **Deferred (6/45 = 13.3%)**: Intentionally deferred items that are either process/infrastructure items, new features outside migration scope, or explicitly out-of-scope language features (C++, PowerPC).
- **Blocked (1/45 = 2.2%)**: VLA/signal compatibility — an architectural limitation that cannot be resolved without changing observable behavior.
- **Not Reproducible (1/45 = 2.2%)**: RedHat 7.3 bound-exit bug — historical platform from 2002, no longer available for testing.

---

## Cross-References

- See [`docs/todo_bug_status.md`](todo_bug_status.md) for detailed per-item triage narrative with extended analysis.
- See [`README.bug-repros.md`](../README.bug-repros.md) for user-facing step-by-step reproduction instructions and verification commands.
- See [`docs/compatibility_report.md`](compatibility_report.md) for behavioral equivalence documentation between C and Rust implementations.
- See [`docs/migration_plan.md`](migration_plan.md) for the C-file-to-Rust-module traceability matrix and phase plan.

---

## Appendix: "Fixed (probably)" Items from Original TODO

The original `TODO` file contains a "Fixed (probably)" section listing items believed to be already resolved in the C codebase prior to migration. These items are **not counted** in the 45-item matrix above, as they represent historical fixes rather than active work items. They are listed here for completeness:

| Original TODO Text | Status |
|--------------------|--------|
| "bug with defines: `#define spin_lock(lock) do { } while (0)` / `#define wq_spin_lock spin_lock` / `#define TEST() wq_spin_lock(a)`" | Previously fixed in C codebase |
| "typedefs can be structure fields" | Previously fixed in C codebase |
| "see bugfixes.diff + improvement.diff from Daniel Glockner" | Previously fixed in C codebase |
| "long long constant evaluation" | Previously fixed in C codebase |
| "add alloca()" | Previously fixed in C codebase |
| "gcc '-E' option." | Previously fixed in C codebase |
| "#include_next support for /usr/include/limits ?" | Previously fixed in C codebase |
| "function pointers/lvalues in ? : (linux kernel net/core/dev.c)" | Previously fixed in C codebase |
| "win32: add __stdcall, check GetModuleHandle for dlls." | Previously fixed in C codebase |
| "macro substitution with nested definitions (ShangHongzhang)" | Previously fixed in C codebase |
| "with '-run' and libtcc, a PLT is now built." | Previously fixed in C codebase |
| "'-E' option was improved" | Previously fixed in C codebase |
| "packed attribute is now supported" | Previously fixed in C codebase |
| "ARM and ARM64 code generators have been added." | Previously fixed in C codebase |

---

*This matrix was generated as part of the TinyCC C→Rust migration. Every item from the original `TODO` file is accounted for — zero items were silently skipped.*
