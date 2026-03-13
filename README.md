# tinycc-rs

> A memory-safe Rust port of the Tiny C Compiler (TCC) v0.9.28rc

[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1.html)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org/)

---

## Overview

**tinycc-rs** is a complete, ground-up translation of
[TinyCC](https://bellard.org/tcc/) (Tiny C Compiler) from its original C
implementation into idiomatic, memory-safe Rust (2021 edition). This is not a
wrapper or a partial port — every function across all 17 core modules, 6
architecture backends, and 18 runtime library files has been translated into a
unified Rust crate named `tinycc-rs` (library name: `tcc`).

The original TinyCC was created by **Fabrice Bellard** and is one of the
smallest ANSI C compilers capable of compiling itself. This Rust port preserves
TCC's hallmark properties while gaining Rust's compile-time safety guarantees:

- **SMALL!** Compile and execute C code everywhere — on rescue disks, embedded
  systems, or anywhere a lightweight C compiler is needed.

- **FAST!** TCC generates native machine code and compiles roughly 10× faster
  than `gcc -O0`. The Rust port preserves the single-pass compilation
  architecture (parser emits code directly, no AST) for equivalent throughput.

- **UNLIMITED!** Any C dynamic library can be used directly. TCC targets full
  ISO C99 compliance and can compile itself (self-hosting).

- **SAFE!** The Rust port eliminates entire classes of memory-safety bugs by
  construction. Four known CVEs in the original C code are remediated as a
  natural consequence of Rust's ownership model — no special-case patches
  required. An optional bounds checker is included for compiled C programs.

- **EMBEDDABLE!** The 22-function `libtcc` API is preserved as methods on a
  `TccContext` Rust struct, allowing any Rust or C program to embed a complete
  C compiler as a library.

### Supported Architectures

| Architecture | Code Generation | Assembler | Linker |
|---|---|---|---|
| x86-64 (default) | ✓ | ✓ | ✓ |
| x86 (i386) | ✓ | ✓ | ✓ |
| ARM (32-bit) | ✓ | ✓ | ✓ |
| AArch64 (ARM64) | ✓ | ✓ | ✓ |
| RISC-V 64 | ✓ | ✓ | ✓ |
| TMS320C67 (DSP) | ✓ | — | ✓ |

### Output Formats

- **ELF** — Linux, BSD, and other Unix-like systems
- **PE/COFF** — Windows DLL and EXE generation
- **Mach-O** — macOS executable and dylib output

---

## Building

### Prerequisites

- **Rust toolchain**: Rust 2021 edition (MSRV 1.70). Install via
  [rustup](https://rustup.rs/).

### Quick Start

```bash
# Clone the repository
git clone https://github.com/TinyCC/tinycc.git
cd tinycc

# Build in release mode (optimized with LTO)
cargo build --release

# The compiler binary is produced at:
#   ./target/release/tcc
```

### Debug Build

```bash
cargo build
```

### Build with Specific Architecture Features

```bash
# Build with ARM backend enabled
cargo build --release --features arm

# Build with multiple backends
cargo build --release --features "x86_64,arm,arm64,riscv64"

# Build with bounds-checking support
cargo build --release --features "bounds-checking"
```

---

## Feature Flags

tinycc-rs uses Cargo feature flags to control which architecture backends and
optional subsystems are compiled into the binary.

| Feature | Default | Description |
|---|---|---|
| `x86_64` | ✓ | x86-64 code generation, assembler, and linker backend |
| `i386` | | x86 32-bit code generation, assembler, and linker backend |
| `arm` | | ARM 32-bit code generation, assembler, and linker backend |
| `arm64` | | AArch64 code generation, assembler, and linker backend |
| `riscv64` | | RISC-V 64-bit code generation, assembler, and linker backend |
| `selinux` | | SELinux-compatible W^X enforcement via paired `mmap` (depends on `libc`) |
| `bounds-checking` | | Optional memory and bounds checker for compiled C programs |

To enable a feature:

```bash
cargo build --release --features "arm64"
```

To disable the default `x86_64` feature and use only specific backends:

```bash
cargo build --release --no-default-features --features "arm"
```

---

## Testing

### Run the Full Test Suite

```bash
cargo test
```

### Run Tests Without Stopping on First Failure

```bash
cargo test -- --no-fail-fast
```

### Run Clippy Lints

The project enforces strict Clippy lints including `deny(clippy::cast_sign_loss)`,
`deny(clippy::cast_possible_truncation)`, and `deny(clippy::cast_possible_wrap)`
to guarantee integer safety throughout the codebase.

```bash
cargo clippy -- -D warnings
```

### Test Coverage

The Rust port is validated against the complete TinyCC test suite:

- **`tests/tcctest.c`** — Flagship regression driver with hundreds of test cases
- **`tests/abitest.c`** — ABI harness for struct layout, calling conventions, and varargs
- **`tests/boundtest.c`** — 18 out-of-bounds, use-after-free, and double-free scenarios
- **`tests/libtcc_test.c`** — Single-threaded libtcc API lifecycle
- **`tests/libtcc_test_mt.c`** — Multi-threaded concurrent `TccContext` safety
- **`tests/pp/`** — 49 preprocessor regression fixtures
- **`tests/tests2/`** — 260+ numbered regression programs
- **`tests/cve_regressions.rs`** — 4 CVE-specific regression tests (Rust integration tests)

---

## Usage as a Library

tinycc-rs is published as a Rust crate that can be embedded in any Rust
application, providing a complete C compiler as a library.

### Add to Your Project

```toml
[dependencies]
tinycc-rs = "0.9.28-rc.0"
```

### Basic Example

```rust
use tcc::{TccContext, OutputType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new compiler context
    let mut ctx = TccContext::new()?;

    // Set the output type to in-memory execution
    ctx.set_output_type(OutputType::Memory)?;

    // Compile a C program from a string
    ctx.compile_string(r#"
        #include <stdio.h>
        int main() {
            printf("Hello from TCC!\n");
            return 0;
        }
    "#)?;

    // Relocate and execute
    ctx.relocate()?;
    let exit_code = ctx.run(&[])?;
    println!("Program exited with code: {}", exit_code);

    Ok(())
}
```

### API Overview

The `TccContext` struct exposes the full 22-function libtcc API:

| Method | Description |
|---|---|
| `TccContext::new()` | Create a new compiler context |
| `ctx.set_lib_path(path)` | Set the TCC library path |
| `ctx.set_error_func(f)` | Register a custom error handler callback |
| `ctx.set_options(str)` | Set compiler options from a string |
| `ctx.add_include_path(path)` | Add an include search path (`-I`) |
| `ctx.add_sysinclude_path(path)` | Add a system include search path |
| `ctx.define_symbol(sym, val)` | Define a preprocessor symbol (`-D`) |
| `ctx.undefine_symbol(sym)` | Undefine a preprocessor symbol (`-U`) |
| `ctx.add_file(filename)` | Add a source or object file |
| `ctx.compile_string(buf)` | Compile C source from a string |
| `ctx.set_output_type(type)` | Set output type (executable, DLL, object, memory) |
| `ctx.add_library_path(path)` | Add a library search path (`-L`) |
| `ctx.add_library(name)` | Add a library to link (`-l`) |
| `ctx.add_symbol(name, val)` | Add a symbol with a raw pointer value |
| `ctx.output_file(filename)` | Write output to a file |
| `ctx.run(args)` | Compile, relocate, and execute in memory (`-run`) |
| `ctx.relocate()` | Relocate compiled code for symbol resolution |
| `ctx.get_symbol(name)` | Retrieve a pointer to a compiled symbol |
| `ctx.list_symbols(cb)` | Iterate over all compiled symbols |

The context is automatically cleaned up when it goes out of scope (Rust `Drop`
trait replaces `tcc_delete()`). `TccContext` implements `Send`, so it can be
safely transferred between threads.

---

## CLI Usage

The `tcc` binary supports all standard GCC-compatible flags:

```bash
# Compile a C file to an executable
./target/release/tcc -o hello hello.c

# Compile and run directly (C scripting)
./target/release/tcc -run hello.c

# Compile to object file
./target/release/tcc -c hello.c

# Compile with include and library paths
./target/release/tcc -I./include -L./lib -lm -o program program.c

# Define preprocessor symbols
./target/release/tcc -DNDEBUG -DVERSION=2 -o program program.c

# Enable bounds checking
./target/release/tcc -b -o program program.c

# Generate debug information (DWARF)
./target/release/tcc -gdwarf -o program program.c
```

### C Scripting

Add a shebang line to your C source file and make it executable:

```c
#!/usr/local/bin/tcc -run
#include <stdio.h>

int main() {
    printf("Hello from a C script!\n");
    return 0;
}
```

```bash
chmod +x script.c
./script.c
```

---

## Self-Hosting Validation

tinycc-rs preserves TCC's self-hosting capability. The Rust port can compile
the original TinyCC C source code, and the resulting binary can in turn compile
TCC again, producing bit-identical output. This three-stage bootstrap check is
the ultimate integration test:

### Stage 1 — Build the Rust Port

```bash
cargo build --release
# Produces: ./target/release/tcc
```

### Stage 2 — Compile Original C TCC with the Rust Port

```bash
./target/release/tcc -I./include tcc.c -o tcc_stage1
```

### Stage 3 — Bootstrap Verification

```bash
# The C-compiled TCC compiles itself again
./tcc_stage1 -I./include tcc.c -o tcc_stage2

# Verify bit-identical output
md5sum tcc_stage1 tcc_stage2
# Both checksums must match
```

A successful bootstrap proves that the Rust port correctly implements:

- Complete C99 language parsing (recursive descent)
- Correct native code emission for the host architecture
- Working ELF/PE/Mach-O output generation
- Accurate symbol resolution and linking

---

## CVE Remediation

The Rust port eliminates four known CVEs in the original TinyCC C codebase as
a natural consequence of Rust's memory safety guarantees. No special-case
patches are applied — the vulnerabilities simply cannot exist in safe Rust code.

| CVE | Severity | Original Vulnerability | Rust Remediation |
|---|---|---|---|
| **CVE-2018-20376** | Medium (5.5) | Out-of-bounds write in `asm_parse_directive()` — raw pointer arithmetic on directive buffer | Directive buffer uses `Vec<u8>` with `.push()` / `.extend_from_slice()` — automatic bounds growth |
| **CVE-2018-20374** | Medium (5.5) | Out-of-bounds write in `use_section1()` — unchecked section array index | Section array uses `Vec<Section>` with `.get_mut(idx).ok_or(...)` — checked indexing |
| **CVE-2019-9754** | High (7.8) | Out-of-bounds write in `end_macro()` — macro stack underflow on empty stack | Macro stack uses `Vec<MacroEntry>` with `.pop()` — returns `None` on empty, no underflow |
| **CVE-2006-0635** | Medium | Signed/unsigned comparison — implicit integer promotion causes incorrect evaluation | All comparisons use explicit `TryInto` conversions; `#![deny(clippy::cast_sign_loss)]` enforced |

CVE-specific regression tests are included in `tests/cve_regressions.rs`.

---

## Project Structure

```
tinycc-rs/
├── Cargo.toml                  Package manifest
├── .cargo/config.toml          Clippy lint configuration
├── src/
│   ├── main.rs                 CLI driver (clap)
│   ├── lib.rs                  Public API re-exports
│   ├── error.rs                TccError + TccResult
│   ├── context.rs              TccState + TccContext
│   ├── tokens.rs               Token enum definitions
│   ├── types.rs                Shared type definitions
│   ├── preprocessor.rs         Tokenizer, macros, includes
│   ├── parser.rs               Recursive-descent parser
│   ├── codegen.rs              Value stack, code emission
│   ├── assembler.rs            GAS-style assembler
│   ├── debug.rs                STABS + DWARF generation
│   ├── runtime.rs              W^X enforcement, execution
│   ├── tools.rs                Archiver, dep generator
│   ├── linker/                 Output format backends
│   │   ├── elf.rs              ELF object/executable
│   │   ├── pe.rs               PE/COFF (Windows)
│   │   ├── macho.rs            Mach-O (macOS)
│   │   └── coff.rs             COFF (C67 target)
│   ├── targets/                Architecture backends
│   │   ├── i386.rs             x86 32-bit
│   │   ├── x86_64.rs           x86-64
│   │   ├── arm.rs              ARM 32-bit
│   │   ├── arm64.rs            AArch64
│   │   ├── riscv64.rs          RISC-V 64
│   │   └── c67.rs              TMS320C67 DSP
│   ├── runtime_lib/            Runtime library
│   │   ├── bcheck.rs           Bounds-checking runtime
│   │   ├── libtcc1.rs          64-bit arithmetic helpers
│   │   ├── tcov.rs             Code coverage
│   │   ├── backtrace.rs        Backtrace infrastructure
│   │   ├── builtin.rs          Compiler builtins
│   │   └── ...                 Additional runtime modules
│   └── formats/                Binary format definitions
│       ├── elf.rs              ELF structures
│       ├── dwarf.rs            DWARF constants
│       ├── coff.rs             COFF structures
│       └── stab.rs             STABS definitions
├── tests/
│   └── cve_regressions.rs     CVE regression tests
├── include/                    C standard headers (shipped)
└── tests/                      C test suite inputs
```

---

## Differences from Original TCC

| Aspect | Original TCC (C) | tinycc-rs (Rust) |
|---|---|---|
| Language | C99 with GNU extensions | Rust 2021 edition |
| Memory management | `malloc`/`free` (manual) | `Vec`, `Box`, `String` (RAII) |
| Error handling | `setjmp`/`longjmp` | `Result<T, TccError>` + `?` operator |
| Global state | `TCCState*` passed everywhere | Owned `TccContext` handle |
| Thread safety | Semaphore-based serialization | `Mutex<()>` guard, `Send` trait |
| Integer safety | Implicit C coercion | Explicit `TryInto` conversions |
| Build system | `./configure && make` | `cargo build` |
| CVE exposure | 4 known CVEs | All 4 eliminated by construction |

---

## License

TCC is distributed under the **GNU Lesser General Public License v2.1**
(LGPL-2.1-or-later). See the [COPYING](COPYING) file for details.

The Rust port (tinycc-rs) is distributed under the same license.

---

## Credits

- **Fabrice Bellard** — Original author of TCC
- The [TinyCC community](https://bellard.org/tcc/) for continued development
  and maintenance of the C implementation
- This Rust port was generated with assistance from [Blitzy](https://blitzy.com/)
