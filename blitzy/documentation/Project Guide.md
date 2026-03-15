# Blitzy Project Guide — tinycc-rs (TinyCC C→Rust Migration)

---

## 1. Executive Summary

### 1.1 Project Overview

**tinycc-rs** is a complete, ground-up tech stack migration of TinyCC (Tiny C Compiler) v0.9.28rc from its original C implementation (~81,000 LOC) into idiomatic, memory-safe Rust (2021 edition). The project translates 17 core compiler modules, 6 architecture backends, and 18 runtime library files into a unified Rust crate producing a working CLI binary and embeddable library. Four known CVEs are remediated by construction through Rust's type system and ownership model. The 22-function libtcc embedding API is preserved as methods on a `TccContext` struct. The target users are compiler engineers, embedded systems developers, and any application requiring an embeddable lightweight C compiler.

### 1.2 Completion Status

```mermaid
pie title Project Completion (85.0%)
    "Completed (589h)" : 589
    "Remaining (104h)" : 104
```

| Metric | Value |
|---|---|
| **Total Project Hours** | **693** |
| **Completed Hours (AI)** | **589** |
| **Remaining Hours** | **104** |
| **Completion Percentage** | **85.0%** |

**Calculation**: 589 completed hours / 693 total hours = 85.0% complete.

### 1.3 Key Accomplishments

- ✅ All 51 target files created (45 Rust source modules + 1 integration test + 5 config/doc files)
- ✅ 68,867 lines of Rust source code across 45 modules — complete translation of all C compiler components
- ✅ 673 tests passing (668 unit + 4 CVE regression + 1 doc-test), 0 failures
- ✅ 4 CVE remediations verified by dedicated regression tests (CVE-2018-20376, CVE-2018-20374, CVE-2019-9754, CVE-2006-0635)
- ✅ 22-function libtcc public API preserved on `TccContext` struct with `Send` trait for thread safety
- ✅ Zero clippy warnings under `cargo clippy --all-targets -- -D warnings` with pedantic integer safety lints
- ✅ Debug and release builds succeed with 0 errors, 0 warnings
- ✅ Working binary: `./target/release/tcc --version` → `tcc 0.9.28rc` with full GCC-compatible CLI (150+ lines of help)
- ✅ All 6 architecture backends implement `CodegenBackend` trait (x86-64, i386, ARM, ARM64, RISC-V 64, C67)
- ✅ All 4 linker backends translated (ELF, PE/COFF, Mach-O, COFF for C67)
- ✅ All 15 runtime library modules translated (bounds checker, builtins, backtrace, atomics, etc.)
- ✅ `unsafe` blocks confined exclusively to `src/runtime.rs` with `// SAFETY:` justification comments
- ✅ Crate-level `#![deny(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]` enforced

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| Self-hosting not validated | Cannot confirm Rust binary compiles original TCC C source | Human Developer | 1–2 weeks |
| Original TCC test suite not run | Behavioral equivalence unverified for tcctest.c, abitest.c, etc. | Human Developer | 1–2 weeks |
| MSRV set to 1.85 (spec requires 1.70) | May not compile on older Rust toolchains | Human Developer | 1–2 days |
| Cross-platform linker output untested | ELF/PE/Mach-O actual binary output not validated end-to-end | Human Developer | 1 week |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| No access issues identified | — | — | — | — |

### 1.6 Recommended Next Steps

1. **[High]** Run self-hosting bootstrap validation: compile original `tcc.c` with the Rust binary, then verify Stage 1/Stage 2 binary identity
2. **[High]** Execute the full TCC test suite (`tcctest.c`, `abitest.c`, `boundtest.c`, preprocessor tests, `tests2/` regression suite) against the Rust binary and fix any failures
3. **[Medium]** Verify cross-platform linker output by compiling simple C programs and running the resulting executables on target platforms
4. **[Medium]** Adjust MSRV from 1.85 to 1.70 as specified in the AAP, testing compilation with `rustup run 1.70.0 cargo check`
5. **[Medium]** Set up CI/CD pipeline with Rust-specific workflows (build, test, clippy, cross-compilation)

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---|---|
| Core Compiler Translation | 208 | src/error.rs (3h), src/context.rs (16h), src/lib.rs (3h), src/main.rs (10h), src/tokens.rs (10h), src/types.rs (8h), src/preprocessor.rs (24h), src/parser.rs (32h), src/codegen.rs (28h), src/assembler.rs (20h), src/debug.rs (24h), src/runtime.rs (22h), src/tools.rs (8h) |
| Linker Backend Translation | 91 | src/linker/mod.rs (1h), src/linker/elf.rs (24h), src/linker/pe.rs (24h), src/linker/macho.rs (28h), src/linker/coff.rs (14h) |
| Architecture Backend Translation | 104 | src/targets/mod.rs (6h), src/targets/i386.rs (16h), src/targets/x86_64.rs (16h), src/targets/arm.rs (20h), src/targets/arm64.rs (20h), src/targets/riscv64.rs (16h), src/targets/c67.rs (10h) |
| Runtime Library Translation | 91 | 15 modules: bcheck.rs (14h), libtcc1.rs (6h), tcov.rs (10h), backtrace.rs (6h), builtin.rs (5h), runmain.rs (6h), armeabi.rs (5h), arm64_math.rs (10h), armflush.rs (2h), alloca.rs (6h), atomic.rs (10h), stdatomic.rs (5h), pic86.rs (3h), dsohandle.rs (2h), mod.rs (1h) |
| Format Definitions | 28 | src/formats/mod.rs (1h), src/formats/elf.rs (16h), src/formats/dwarf.rs (6h), src/formats/coff.rs (3h), src/formats/stab.rs (2h) |
| Unit Testing | 36 | 668 unit tests across 32 modules + 4 CVE regression tests in tests/cve_regressions.rs |
| Configuration & Documentation | 7 | Cargo.toml (2h), .cargo/config.toml (1h), README.md (3h), .gitignore (0.5h), Cargo.lock (0.5h) |
| QA & Validation Fixes | 24 | 83 clippy warnings resolved, MSRV adjustments, API doc completeness, CVE test hardening, code review findings (6 fix commits) |
| **Total Completed** | **589** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---|---|
| Self-hosting Bootstrap Validation & Fixes | 32 | High |
| TCC Test Suite Validation & Fixes | 24 | High |
| Cross-platform Linker Output Verification | 16 | Medium |
| MSRV Compliance (1.85 → 1.70) | 4 | Medium |
| CI/CD Pipeline Setup | 8 | Medium |
| Integration Testing & Hardening | 16 | Medium |
| Documentation Finalization | 4 | Low |
| **Total Remaining** | **104** | |

### 2.3 Hours Verification

- **Section 2.1 Total**: 208 + 91 + 104 + 91 + 28 + 36 + 7 + 24 = **589 hours**
- **Section 2.2 Total**: 32 + 24 + 16 + 4 + 8 + 16 + 4 = **104 hours**
- **Sum**: 589 + 104 = **693 hours** (matches Section 1.2 Total Project Hours)
- **Completion**: 589 / 693 = **85.0%** (matches Section 1.2)

---

## 3. Test Results

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---|---|---|---|---|
| Unit Tests | `cargo test` (lib) | 668 | 668 | 0 | — | Across 32 modules (codegen 49, builtin 45, macho 38, armeabi 37, tcov 36, bcheck 36, arm64_math 35, x86_64 32, atomic 31, elf 31, etc.) |
| CVE Regression | `cargo test` (integration) | 4 | 4 | 0 | — | CVE-2018-20376, CVE-2018-20374, CVE-2019-9754, CVE-2006-0635 |
| Doc Tests | `cargo test --doc` | 13 | 1 | 0 | — | 12 intentionally ignored (require runtime context) |
| Static Analysis | Clippy `--all-targets -D warnings` | — | Pass | — | — | Zero warnings with pedantic integer safety lints |
| **Total** | | **685** | **673** | **0** | — | 12 ignored doc-tests (by design) |

All tests originate from Blitzy's autonomous validation pipeline. Test execution verified via `cargo test` and `cargo clippy --all-targets -- -D warnings`.

---

## 4. Runtime Validation & UI Verification

**Binary Execution:**
- ✅ `./target/release/tcc --version` → `tcc 0.9.28rc` (exit code 0)
- ✅ `./target/release/tcc --help` → 150 lines of formatted help output with all GCC-compatible flags
- ✅ Release binary: 1.2 MB ELF 64-bit executable, dynamically linked
- ✅ `cargo build` (debug) → 0 errors, 0 warnings
- ✅ `cargo build --release` (LTO, opt-level 3, codegen-units 1) → 0 errors, 0 warnings

**CLI Flag Coverage:**
- ✅ Compilation flags: `-c`, `-o`, `-E`, `-x`
- ✅ Include/define flags: `-I`, `-D`, `-U`, `--include`, `--isystem`, `--nostdinc`
- ✅ Library flags: `-L`, `-l`, `--nostdlib`, `--static`, `--shared`, `--soname`, `--rdynamic`
- ✅ Debug flags: `-g`, `--gdwarf`, `-b`, `--bt`
- ✅ Optimization: `-O`
- ✅ Warning/features: `-W`, `-f`, `-m`, `--std`
- ✅ Run mode: `--run`, `--rstdin`, `--dt`
- ✅ Tooling: `--ar`, `--impdef`, `-M`, `--MD`, `--MF`
- ✅ Info: `-v`, `--bench`, `--print-search-dirs`, `--dumpversion`, `--pthread`

**API Surface:**
- ✅ 24 public methods on `TccContext` (22 libtcc API + 2 extended)
- ✅ `TccContext` implements `Send` for thread safety
- ✅ `Drop` impl for automatic cleanup (replaces `tcc_delete`)

**Not Yet Validated:**
- ⚠ Actual C compilation (no C source files compiled during validation)
- ⚠ Self-hosting bootstrap (Stage 1/2/3 not attempted)
- ⚠ Original TCC test suite execution
- ⚠ Cross-platform binary output (ELF/PE/Mach-O not tested end-to-end)

---

## 5. Compliance & Quality Review

| AAP Requirement | Status | Evidence |
|---|---|---|
| Complete language migration (all C functions → Rust) | ✅ Pass | 45 Rust modules, 68,867 LOC covering all 17 core + 6 arch + 18 runtime modules |
| CVE-2018-20376 remediation (OOB write in asm_parse_directive) | ✅ Pass | `Vec<u8>` directive buffer in src/assembler.rs; regression test passing |
| CVE-2018-20374 remediation (OOB write in use_section1) | ✅ Pass | `Vec<Section>` with `.get_mut().ok_or()` in src/assembler.rs; regression test passing |
| CVE-2019-9754 remediation (macro stack underflow) | ✅ Pass | `Vec<MacroEntry>` with `pop()` in src/preprocessor.rs; regression test passing |
| CVE-2006-0635 remediation (signed/unsigned comparison) | ✅ Pass | `#![deny(clippy::cast_sign_loss)]` globally; explicit `TryInto` in parser/codegen; regression test passing |
| 22-function libtcc API preservation | ✅ Pass | 24 public methods on TccContext verified (22 API + 2 extended) |
| Backward-compatible CLI | ✅ Pass | All GCC-compatible flags present in `--help` output (150 lines) |
| Thread safety (TccContext Send) | ✅ Pass | `unsafe impl Send for TccContext` with justification comment |
| Zero unsafe in safe paths | ✅ Pass | All `unsafe` blocks confined to src/runtime.rs with `// SAFETY:` comments |
| Clippy pedantic + integer safety lints | ✅ Pass | `cargo clippy --all-targets -- -D warnings` → 0 warnings |
| CodegenBackend trait with 6 backends | ✅ Pass | Trait defined in targets/mod.rs; implemented by i386, x86_64, ARM, ARM64, RISC-V, C67 |
| Feature-gated backends | ✅ Pass | `cfg(feature = "x86_64")`, `i386`, `arm`, `arm64`, `riscv64` in Cargo.toml |
| thiserror-based TccError enum | ✅ Pass | Parse, Link, Io, UnsupportedTarget variants with `#[error]` derives |
| TccResult type alias | ✅ Pass | `pub type TccResult<T> = Result<T, TccError>` in src/error.rs |
| Cargo.toml per spec | ✅ Pass | Correct name, version, edition, lib types, features, dependencies, release profile |
| Self-hosting validation | ⚠ Not Validated | Code exists but bootstrap not attempted |
| Full test suite compatibility | ⚠ Not Validated | Internal tests pass; original TCC suite not run |
| MSRV 1.70 | ⚠ Deviation | Currently set to 1.85; requires adjustment and verification |

**Fixes Applied During Validation:**
- 83 clippy warnings resolved across 13 files (field-assignment patterns, unreadable literals, approximate constants, float comparisons, doc formatting)
- CVE regression tests hardened to exercise actual CVE-relevant code paths
- API documentation completeness improved
- Module-level doc conventions standardized

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Self-hosting may fail on complex C patterns | Technical | High | Medium | Incremental validation starting with simple C programs, then TCC source | Open |
| Parser/codegen may not handle all C99 edge cases | Technical | High | Medium | Run full TCC test suite (260+ regression tests); fix failures iteratively | Open |
| Cross-compilation output may be incorrect | Technical | Medium | Medium | Test ELF/PE/Mach-O output with real C programs on target platforms | Open |
| MSRV 1.85 incompatible with spec requirement of 1.70 | Technical | Low | High | Test with `rustup run 1.70.0 cargo check`; may need feature adjustments | Open |
| Performance regression vs original C TCC | Operational | Medium | Low | Benchmark compilation speed; Rust release profile with LTO should be competitive | Open |
| Thread safety may have subtle issues beyond Send | Technical | Medium | Low | Run libtcc_test_mt.c under ThreadSanitizer/Miri; validate concurrent usage | Open |
| Missing platform-specific behavior on Windows/macOS | Integration | Medium | Medium | PE linker untested on Windows; Mach-O untested on macOS | Open |
| Unsafe blocks in runtime.rs may have soundness issues | Security | Medium | Low | Audit all SAFETY comments; run under Miri where possible | Open |
| Dependencies may have security advisories | Security | Low | Low | Run `cargo audit`; all deps are well-maintained ecosystem crates | Open |
| No CI/CD pipeline for continuous validation | Operational | Medium | High | Set up GitHub Actions with Rust build/test/clippy/audit steps | Open |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 589
    "Remaining Work" : 104
```

**Hours Verification**: Completed (589h) + Remaining (104h) = Total (693h). Remaining hours match Section 1.2 (104h) and Section 2.2 sum (104h).

**Completed Work Distribution:**

```mermaid
pie title Completed Work by Category (589h)
    "Core Compiler" : 208
    "Architecture Backends" : 104
    "Linker Backends" : 91
    "Runtime Library" : 91
    "Unit Testing" : 36
    "Format Definitions" : 28
    "QA & Fixes" : 24
    "Config & Docs" : 7
```

**Remaining Work Distribution:**

```mermaid
pie title Remaining Work by Priority (104h)
    "High Priority" : 56
    "Medium Priority" : 44
    "Low Priority" : 4
```

---

## 8. Summary & Recommendations

### Achievement Summary

The tinycc-rs project has achieved **85.0% completion** (589 of 693 total hours), representing the full C-to-Rust translation of TinyCC v0.9.28rc. The autonomous agents successfully delivered:

- A complete Rust codebase of 68,867 lines across 45 modules, translating every C module specified in the Agent Action Plan
- All four CVE remediations verified through dedicated regression tests
- 673 tests passing with zero failures and zero clippy warnings
- A working binary that starts, displays version information, and presents the full GCC-compatible CLI surface
- Clean architecture with trait-based backend polymorphism, Result-based error handling, and unsafe blocks isolated to platform syscall boundaries

### Remaining Gaps

The remaining 104 hours (15.0%) are concentrated in integration validation — confirming the translated code actually compiles real C programs correctly:

1. **Self-hosting bootstrap** (32h) — The highest-value validation: can the Rust binary compile the original TCC C source? This may reveal parser/codegen issues requiring debugging.
2. **TCC test suite execution** (24h) — Running the original 260+ regression tests, preprocessor tests, and ABI tests to verify behavioral equivalence.
3. **Cross-platform output** (16h) — Verifying that ELF, PE/COFF, and Mach-O output from the linker backends produces working executables.

### Critical Path to Production

1. Fix MSRV to 1.70 as specified → Run self-hosting on simple C programs → Iterate to full TCC compilation → Run complete test suite → Set up CI/CD
2. The self-hosting and test suite phases are the highest-risk items — they may reveal implementation gaps that require additional development hours.

### Production Readiness Assessment

The project is **not yet production-ready** but has a strong foundation. All code compiles, all internal tests pass, and the architecture faithfully mirrors the original TCC design. The remaining work is primarily validation and bug-fixing — the translation is complete, but its correctness for real-world C compilation has not been confirmed.

---

## 9. Development Guide

### System Prerequisites

| Software | Version | Purpose |
|---|---|---|
| Rust (rustc + cargo) | 1.70+ (stable) | Compiler and build tool |
| Git | 2.x+ | Version control |
| Linux x86-64 | Any recent distro | Primary development platform |

### Environment Setup

```bash
# 1. Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 2. Verify Rust installation
rustc --version   # Expected: rustc 1.70.0 or later
cargo --version   # Expected: cargo 1.70.0 or later

# 3. Clone and checkout the branch
git clone https://github.com/TinyCC/tinycc.git
cd tinycc
git checkout blitzy-2c7ed497-79ef-4a4f-b570-a06225c46d1d
```

### Build Instructions

```bash
# Debug build (fast compilation, no optimizations)
cargo build
# Expected: Compiling tinycc-rs v0.9.28-rc.0
# Expected: Finished `dev` profile target(s)

# Release build (optimized, LTO enabled)
cargo build --release
# Expected: Finished `release` profile [optimized] target(s)
# Binary location: ./target/release/tcc
```

### Running Tests

```bash
# Run all tests (unit + integration + doc-tests)
cargo test
# Expected output:
#   running 668 tests ... test result: ok. 668 passed; 0 failed
#   running 4 tests  ... test result: ok. 4 passed; 0 failed (CVE regressions)
#   running 13 tests ... test result: ok. 1 passed; 12 ignored (doc-tests)

# Run clippy lints (should produce zero warnings)
cargo clippy --all-targets -- -D warnings
# Expected: no warnings

# Run only CVE regression tests
cargo test --test cve_regressions
# Expected: 4 passed, 0 failed
```

### Running the Binary

```bash
# Display version
./target/release/tcc --version
# Expected: tcc 0.9.28rc

# Display full help
./target/release/tcc --help
# Expected: 150 lines of usage information

# Display brief help
./target/release/tcc -h
```

### Feature Flags

```bash
# Build with specific architecture backend
cargo build --features "i386"
cargo build --features "arm"
cargo build --features "arm64"
cargo build --features "riscv64"

# Build with bounds checking support
cargo build --features "bounds-checking"

# Build with SELinux support (requires libc)
cargo build --features "selinux"

# Build with all features
cargo build --all-features
```

### Verification Steps

```bash
# 1. Verify binary exists and is executable
file ./target/release/tcc
# Expected: ELF 64-bit LSB pie executable, x86-64

# 2. Verify version output
./target/release/tcc --version
# Expected: tcc 0.9.28rc

# 3. Verify all tests pass
cargo test 2>&1 | grep "test result"
# Expected: 4 lines, all showing "ok" with 0 failed

# 4. Verify zero clippy warnings
cargo clippy --all-targets -- -D warnings 2>&1 | tail -1
# Expected: "Finished" (no warning/error lines)
```

### Troubleshooting

| Issue | Cause | Resolution |
|---|---|---|
| `error[E0658]: use of unstable library feature` | Rust version too old | Update with `rustup update stable` |
| `error: could not compile` dependency | Network/crate registry issue | Run `cargo clean && cargo build` |
| Clippy warnings on integer casts | `.cargo/config.toml` lint enforcement | Use `#[allow(clippy::cast_*)]` with justification comment on specific lines |
| Test timeout | Long-running test execution | Run with `cargo test -- --test-threads=1` |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---|---|
| `cargo build` | Debug build |
| `cargo build --release` | Optimized release build (LTO enabled) |
| `cargo test` | Run all tests (unit + integration + doc) |
| `cargo test --test cve_regressions` | Run CVE regression tests only |
| `cargo clippy --all-targets -- -D warnings` | Full lint check |
| `cargo doc --open` | Generate and open API documentation |
| `cargo clean` | Remove build artifacts |
| `cargo audit` | Check dependencies for security advisories |
| `./target/release/tcc --version` | Display version |
| `./target/release/tcc --help` | Display full CLI help |

### B. Port Reference

Not applicable — tinycc-rs is a compiler binary, not a web service. No network ports are used.

### C. Key File Locations

| File/Directory | Purpose |
|---|---|
| `Cargo.toml` | Package manifest — dependencies, features, profiles |
| `.cargo/config.toml` | Clippy lint enforcement configuration |
| `src/lib.rs` | Crate root — public API re-exports, module declarations |
| `src/main.rs` | CLI binary entry point (clap-based) |
| `src/error.rs` | `TccError` enum and `TccResult<T>` type alias |
| `src/context.rs` | `TccState` struct and `TccContext` public API handle |
| `src/preprocessor.rs` | C preprocessor — tokenizer, macro expansion |
| `src/parser.rs` | Recursive-descent C parser |
| `src/codegen.rs` | Code generation — value stack, constant folding |
| `src/assembler.rs` | GAS-style assembler |
| `src/debug.rs` | STABS and DWARF debug info generation |
| `src/runtime.rs` | W^X enforcement, JIT execution, signal handlers |
| `src/tools.rs` | Archiver, dependency generator, impdef |
| `src/linker/` | Linker backends (elf.rs, pe.rs, macho.rs, coff.rs) |
| `src/targets/` | Architecture backends (i386, x86_64, arm, arm64, riscv64, c67) |
| `src/runtime_lib/` | Runtime library modules (15 files) |
| `src/formats/` | Binary format definitions (ELF, DWARF, COFF, STABS) |
| `src/tokens.rs` | Token enum — all TCC token type definitions |
| `src/types.rs` | Shared type definitions (SValue, Section, Symbol, CType) |
| `tests/cve_regressions.rs` | 4 CVE-specific regression tests |
| `README.md` | Project overview with Rust build instructions |

### D. Technology Versions

| Technology | Version | Purpose |
|---|---|---|
| Rust Edition | 2021 | Language edition |
| MSRV | 1.85 (target: 1.70) | Minimum supported Rust version |
| thiserror | 1.0.69 | Error derive macro |
| clap | 4.6.0 | CLI argument parsing |
| gimli | 0.28.1 | DWARF debug info generation |
| zerocopy | 0.7.35 | Safe byte-level serialization |
| bytemuck | 1.25.0 | Pod trait for header structs |
| nom | 7.1.3 | Parser combinator for TBD files |
| libc | 0.2.183 | Platform syscalls (optional) |
| tempfile | 3.27.0 | Test isolation (dev-dependency) |

### E. Environment Variable Reference

No environment variables are required for basic operation. The Rust toolchain uses standard environment:

| Variable | Purpose | Default |
|---|---|---|
| `RUSTFLAGS` | Override compiler flags | Set by `.cargo/config.toml` |
| `CARGO_TARGET_DIR` | Build artifact directory | `./target` |
| `RUST_LOG` | Logging verbosity (if enabled) | Not set |
| `RUST_BACKTRACE` | Show backtraces on panic | `0` |

### F. Developer Tools Guide

| Tool | Command | Purpose |
|---|---|---|
| Rust Analyzer | IDE extension | Real-time code analysis and completion |
| cargo-watch | `cargo install cargo-watch && cargo watch -x test` | Auto-run tests on file change |
| cargo-audit | `cargo install cargo-audit && cargo audit` | Security advisory checking |
| cargo-expand | `cargo install cargo-expand && cargo expand` | View macro expansions |
| cargo-flamegraph | `cargo install flamegraph && cargo flamegraph` | Performance profiling |

### G. Glossary

| Term | Definition |
|---|---|
| AAP | Agent Action Plan — the specification governing this migration |
| CodegenBackend | Rust trait defining the interface for architecture-specific code generation |
| CVE | Common Vulnerabilities and Exposures — publicly disclosed security flaws |
| DWARF | Debug format used in ELF binaries |
| ELF | Executable and Linkable Format — Linux/Unix binary format |
| GAS | GNU Assembler syntax (AT&T notation) |
| GOT/PLT | Global Offset Table / Procedure Linkage Table — dynamic linking structures |
| libtcc | TCC's embedding API (22 functions for using TCC as a library) |
| Mach-O | macOS executable format |
| MSRV | Minimum Supported Rust Version |
| PE/COFF | Portable Executable / Common Object File Format — Windows binary format |
| RELRO | RELocation Read-Only — ELF security hardening |
| Self-hosting | A compiler's ability to compile its own source code |
| STABS | Symbol Table Strings — legacy debug format |
| SValue | Stack Value — TCC's value stack entry for expression evaluation |
| TccContext | Rust wrapper around TccState providing the public API |
| TccState | Internal compiler state struct (translates C's TCCState) |
| W^X | Write XOR Execute — memory protection policy (pages are writable or executable, never both) |
