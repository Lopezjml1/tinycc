# Tiny C Compiler (Rust Port)

**C Scripting Everywhere — The Smallest ANSI C Compiler**

![License: LGPL](https://img.shields.io/badge/License-LGPL-blue.svg)
![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Version: 0.9.28rc](https://img.shields.io/badge/Version-0.9.28rc-green.svg)

> This is the Rust reimplementation of TCC v0.9.28rc, migrated from the
> original C codebase while preserving identical behavior. The original C
> sources are retained in the repository for historical reference.

## Features

- **SMALL!** You can compile and execute C code everywhere, for example on
  rescue disks.

- **FAST!** tcc generates machine code for i386, x86_64, ARM, AArch64, and
  RISC-V64. Compiles and links about 10 times faster than `gcc -O0`.

- **UNLIMITED!** Any C dynamic library can be used directly. TCC is heading
  toward full ISO C99 compliance. TCC can of course compile itself.

- **SAFE!** tcc includes an optional memory and bound checker. Bound checked
  code can be mixed freely with standard code.

- Compile and execute C source directly. No linking or assembly necessary.
  Full C preprocessor included.

- C script supported: just add `#!/usr/local/bin/tcc -run` at the first line
  of your C source, and execute it directly from the command line.

## Building from Source (Rust)

### Prerequisites

- **Rust stable toolchain** (1.94.x or later) — install via [rustup](https://rustup.rs/):
  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **A C linker** (gcc or clang) for FFI compilation

### Build

```
cargo build --release
```

The compiled binary is at `target/release/tcc`.

### Test

```
cargo test --all
```

### Install

Copy the binary to your PATH:

```
sudo cp target/release/tcc /usr/local/bin/
```

## Legacy C Build (Reference)

The original C-based build system is retained for reference. It requires a
host C compiler and GNU Make:

```
./configure
make
make test
make install
```

**Notes:**

- On BSD hosts, `gmake` should be used instead of `make`.
- For Windows, read `tcc-win32.txt`.
- `makeinfo` must be installed to compile the documentation.
- By default, tcc is installed in `/usr/local/bin`.
- Run `./configure --help` to see configuration options.

> **Note:** The legacy C build compiles the original C sources. The Rust port
> is built exclusively via Cargo (see above).

## Usage

### Introduction

We assume here that you know ANSI C. Look at the example `ex1.c` to know
what the programs look like.

The include file `<tcclib.h>` can be used if you want a small basic libc
include support (especially useful for floppy disks). Of course, you can
also use standard headers, although they are slower to compile.

You can begin your C script with `#!/usr/local/bin/tcc -run` on the first
line and set its execute bits (`chmod a+x your_script`). Then, you can
launch the C code as a shell or Perl script. The command line arguments are
put in `argc` and `argv` of the main function, as in ANSI C.

### Examples

- **ex1.c** — Simplest example (hello world). Can also be launched directly
  as a script: `./ex1.c`.

- **ex2.c** — More complicated example: find a number with the four
  operations given a list of numbers (benchmark).

- **ex3.c** — Compute Fibonacci numbers (benchmark).

- **ex4.c** — X11 program. Very complicated test because standard headers
  are being used. As for `ex1.c`, can also be launched directly as a script:
  `./ex4.c`.

- **ex5.c** — "Hello world" with standard glibc headers.

- **tcctest.c** — Auto test for TCC which tests many subtle possible bugs.
  Used when doing `make test` (legacy) or `cargo test --all` (Rust).

## Project Structure

```
tinycc/
├── Cargo.toml                  Workspace root manifest
├── rust-toolchain.toml         Pins stable Rust toolchain
├── crates/
│   ├── tcc-cli/                Binary crate: CLI driver
│   ├── tcc-core/               Library crate: Compiler pipeline
│   └── tcc-ffi/                Library crate: C-compatible FFI (libtcc API)
├── lib/                        Runtime library (compiled by TCC, retained as C/assembly)
├── include/                    Standard headers provided to programs compiled by TCC
├── tests/                      Test suite (C test inputs + Rust test harness)
├── docs/                       Migration and compatibility documentation
├── examples/                   Example C programs
└── win32/                      Windows support files
```

### Crate Overview

| Crate | Type | Description |
|-------|------|-------------|
| `tcc-cli` | Binary | CLI entry point, option parsing, orchestration |
| `tcc-core` | Library | Lexer, preprocessor, parser, code generator, assembler, linker, ELF/PE/Mach-O output, debug info, runtime execution |
| `tcc-ffi` | Library (cdylib + staticlib) | C-compatible FFI wrappers for all 22 public libtcc API functions |

## Documentation

| Document | Description |
|----------|-------------|
| [Migration Plan](docs/migration_plan.md) | C → Rust module mapping and phase plan |
| [Compatibility Report](docs/compatibility_report.md) | Behavioral equivalence documentation |
| [Bug Reproduction Guide](README.bug-repros.md) | Step-by-step bug reproduction and fix verification |
| [TODO Bug Status](docs/todo_bug_status.md) | Per-item triage and fix tracking for all TODO items |
| [TODO Full Coverage Matrix](docs/todo_full_coverage_matrix.md) | Row-per-item coverage matrix |

For full TCC documentation, see `tcc-doc.texi` (Texinfo source) and
`tcc-doc.html` (rendered HTML). Additional information for the Windows port
is in `tcc-win32.txt`.

## License

TCC is distributed under the **GNU Lesser General Public License** (see
[COPYING](COPYING) file).

Originally by **Fabrice Bellard**.
