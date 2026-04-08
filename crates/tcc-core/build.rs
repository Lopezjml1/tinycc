//! Build script for `tcc-core` — Host/Target Detection
//!
//! This Cargo build script replaces `conftest.c` (308 lines) which was a C program
//! used by the `configure` shell script to detect host compiler, architecture, OS,
//! endianness, and compiler version at build time.
//!
//! The Rust `build.rs` performs the same host/target detection using Cargo's built-in
//! `CARGO_CFG_TARGET_*` environment variables, then emits `cargo:rustc-cfg` and
//! `cargo:rustc-env` directives so the rest of the `tcc-core` crate can conditionally
//! compile architecture-specific code.
//!
//! # C-to-Rust Mapping
//!
//! | C Define / Variable              | Rust cfg / env                             |
//! |----------------------------------|--------------------------------------------|
//! | `TCC_TARGET_I386`                | `cfg(tcc_target = "i386")`                 |
//! | `TCC_TARGET_X86_64`              | `cfg(tcc_target = "x86_64")`               |
//! | `TCC_TARGET_ARM`                 | `cfg(tcc_target = "arm")`                  |
//! | `TCC_TARGET_ARM64`               | `cfg(tcc_target = "arm64")`                |
//! | `TCC_TARGET_RISCV64`             | `cfg(tcc_target = "riscv64")`              |
//! | `TCC_TARGET_PE`                  | `cfg(tcc_target_pe)`                       |
//! | `TCC_TARGET_MACHO`               | `cfg(tcc_target_macho)`                    |
//! | `TCC_IS_NATIVE`                  | `cfg(tcc_is_native)`                       |
//! | `TARGETOS_Linux`                 | `cfg(tcc_os = "linux")`                    |
//! | `TARGETOS_BSD`                   | `cfg(tcc_os_bsd)`                          |
//! | `TCC_TARGET_UNIX`                | `cfg(tcc_target_unix)`                     |
//! | `TCC_USING_DOUBLE_FOR_LDOUBLE`   | `cfg(tcc_using_double_for_ldouble)`        |
//! | `ELF_OBJ_ONLY`                   | `cfg(tcc_elf_obj_only)`                    |
//! | `CONFIG_TCC_BACKTRACE`           | `cfg(tcc_config_backtrace)`                |
//! | `CONFIG_NEW_MACHO`               | `cfg(tcc_config_new_macho)`                |
//! | `CONFIG_TCCDIR`                  | `env!("TCC_CONFIG_TCCDIR")`                |
//! | `CONFIG_SYSROOT`                 | `env!("TCC_CONFIG_SYSROOT")`               |
//! | `CONFIG_TCC_SYSINCLUDEPATHS`     | `env!("TCC_CONFIG_SYSINCLUDEPATHS")`       |
//! | `CONFIG_TCC_LIBPATHS`            | `env!("TCC_CONFIG_LIBPATHS")`              |
//! | `CONFIG_TCC_CRTPREFIX`           | `env!("TCC_CONFIG_CRTPREFIX")`             |
//! | `CONFIG_TCC_ELFINTERP`           | `env!("TCC_CONFIG_ELFINTERP")`             |
//! | `PTR_SIZE` / `__SIZEOF_POINTER__`| `env!("TCC_PTR_SIZE")`                     |
//! | `LONG_SIZE` / `__SIZEOF_LONG__`  | `env!("TCC_LONG_SIZE")`                    |
//! | `CONFIG_TRIPLET`                 | `env!("TCC_TRIPLET")`                      |

use std::env;
use std::path::Path;

fn main() {
    // ========================================================================
    // Phase 0: Declare expected custom cfg values (Rust 1.80+ check-cfg)
    // ========================================================================
    // This prevents "unexpected cfg" warnings when compiling the crate.
    declare_expected_cfgs();

    // ========================================================================
    // Phase 1: Read all Cargo-provided target properties
    // ========================================================================
    // These environment variables are set by Cargo for build scripts.
    // See: https://doc.rust-lang.org/cargo/reference/environment-variables.html
    //
    // NOTE: Host C compiler detection (e.g., via the `cc` crate) is intentionally
    // omitted. The C conftest.c needed to detect the host C compiler because TCC
    // was built with `make`/`cc`. The Rust port uses Cargo, which handles toolchain
    // detection natively. If host C compiler detection is needed in the future
    // (e.g., for compiling the `lib/` runtime library), it should be gated behind
    // a Cargo feature flag to avoid unnecessary build-time overhead.
    let target_arch = env_var("CARGO_CFG_TARGET_ARCH");
    let target_os = env_var("CARGO_CFG_TARGET_OS");
    let target_env = env_var("CARGO_CFG_TARGET_ENV");
    let target_endian = env_var("CARGO_CFG_TARGET_ENDIAN");
    let target_pointer_width = env_var("CARGO_CFG_TARGET_POINTER_WIDTH");
    let host = env_var("HOST");
    let target = env_var("TARGET");

    // ========================================================================
    // Phase 2: Architecture Detection
    // ========================================================================
    // Maps Cargo's CARGO_CFG_TARGET_ARCH to TCC's target architecture names.
    //
    // C equivalent: conftest.c lines 182-194 (TRIPLET_ARCH detection)
    //               tcc.h lines 146-177 (TCC_TARGET_* selection)
    //
    // Note: Cargo uses "x86" for 32-bit x86 (not "i386"), and "aarch64" for
    // ARM64 (not "arm64"). We map to TCC's naming conventions.
    let tcc_arch = match target_arch.as_str() {
        "x86" => "i386",       // conftest.c: __i386__ → "i386"
        "x86_64" => "x86_64",  // conftest.c: __x86_64__ → "x86_64"
        "arm" => "arm",        // conftest.c: __arm__ → "arm"
        "aarch64" => "arm64",  // conftest.c: __aarch64__ → "aarch64"; TCC uses "arm64" internally
        "riscv64" => "riscv64", // conftest.c: __riscv && __LP64__ → "riscv64"
        _ => "unknown",        // Graceful fallback for unsupported architectures
    };

    // Emit tcc_target="..." cfg — replaces TCC_TARGET_* defines from tcc.h lines 146-151
    println!("cargo:rustc-cfg=tcc_target=\"{}\"", tcc_arch);

    // ========================================================================
    // Phase 3: OS Detection
    // ========================================================================
    // Maps Cargo's CARGO_CFG_TARGET_OS to TCC's OS identification.
    //
    // C equivalent: conftest.c lines 197-211 (TRIPLET_OS detection)
    //               tcc.h lines 213-226 (TARGETOS_* and TCC_TARGET_UNIX/PE/MACHO)
    let tcc_os = match target_os.as_str() {
        "linux" => "linux",       // conftest.c: __linux__ → "linux"
        "android" => "android",   // conftest.c: __ANDROID__ → "android"
        "windows" => "windows",   // conftest.c: _WIN32 → "win32"
        "macos" => "macos",       // conftest.c: __APPLE__ → "darwin"
        "freebsd" => "freebsd",   // conftest.c: __FreeBSD__ → "kfreebsd"
        "openbsd" => "openbsd",   // conftest.c: __OpenBSD__
        "netbsd" => "netbsd",     // conftest.c: __NetBSD__
        "dragonfly" => "dragonfly",
        _ => "unknown",           // Graceful fallback
    };
    println!("cargo:rustc-cfg=tcc_os=\"{}\"", tcc_os);

    // PE flag for Windows targets — replaces TCC_TARGET_PE from tcc.h lines 171-173
    let is_pe = target_os == "windows";
    if is_pe {
        println!("cargo:rustc-cfg=tcc_target_pe");
    }

    // MACHO flag for macOS targets — replaces TCC_TARGET_MACHO from tcc.h lines 174-176
    let is_macho = target_os == "macos";
    if is_macho {
        println!("cargo:rustc-cfg=tcc_target_macho");
    }

    // BSD family flag — replaces TARGETOS_BSD from tcc.h lines 213-217
    let is_bsd = matches!(
        target_os.as_str(),
        "freebsd" | "openbsd" | "netbsd" | "dragonfly"
    );
    if is_bsd {
        println!("cargo:rustc-cfg=tcc_os_bsd");
    }

    // UNIX target flag — replaces TCC_TARGET_UNIX from tcc.h lines 222-226
    // Set when target is neither PE (Windows) nor MACHO (macOS)
    let is_unix_target = !is_pe && !is_macho;
    if is_unix_target {
        println!("cargo:rustc-cfg=tcc_target_unix");
    }

    // ELF_OBJ_ONLY — replaces tcc.h line 223
    // On PE and MACHO targets, TCC creates ELF .o files but native executables
    if is_pe || is_macho {
        println!("cargo:rustc-cfg=tcc_elf_obj_only");
    }

    // ========================================================================
    // Phase 4: Native Compilation Detection
    // ========================================================================
    // Detects if host and target match, enabling features like -run mode.
    //
    // C equivalent: tcc.h lines 179-193 (TCC_IS_NATIVE)
    // The C code checks that both arch and OS (PE/MACHO) status match between
    // host and target. Comparing full triples achieves the same result.
    let is_native = host == target;
    if is_native {
        println!("cargo:rustc-cfg=tcc_is_native");
    }

    // ========================================================================
    // Phase 5: Long Double Handling
    // ========================================================================
    // Determines if `long double` should use `double` representation (64-bit).
    //
    // C equivalent: tcc.h lines 228-234 (TCC_USING_DOUBLE_FOR_LDOUBLE)
    // On Windows (PE targets), ARM64 macOS, and non-GCC Windows compilers,
    // long double is the same as double (no 80-bit x87 extended precision).
    let using_double_for_ldouble = is_pe
        || (is_macho && tcc_arch == "arm64")
        || (target_os == "windows");
    if using_double_for_ldouble {
        println!("cargo:rustc-cfg=tcc_using_double_for_ldouble");
    }

    // ========================================================================
    // Phase 6: Default Compiler Configuration Flags
    // ========================================================================
    // CONFIG_TCC_BACKTRACE — always enabled by default (tcc.h lines 195-199)
    // Enables built-in stack backtrace support for -run and -bt modes.
    println!("cargo:rustc-cfg=tcc_config_backtrace");

    // CONFIG_NEW_MACHO — enabled for macOS targets (tcc.h lines 207-211)
    // Uses the new Mach-O output format (enabled by default on macOS 11+).
    if is_macho {
        println!("cargo:rustc-cfg=tcc_config_new_macho");
    }

    // CONFIG_TCC_SEMLOCK — thread-safety support, always enabled (tcc.h lines 241-243)
    println!("cargo:rustc-cfg=tcc_config_semlock");

    // ========================================================================
    // Phase 7: ABI Detection and Triplet Construction
    // ========================================================================
    // Constructs the GNU-style target triplet (ARCH-OS-ABI).
    //
    // C equivalent: conftest.c lines 182-236 (TRIPLET_ARCH, TRIPLET_OS, TRIPLET_ABI)
    //
    // The triplet is used for locating system libraries and headers in
    // multiarch directory layouts (e.g., /usr/lib/x86_64-linux-gnu/).

    // Triplet architecture component — matches conftest.c conventions
    let triplet_arch = match target_arch.as_str() {
        "x86" => "i386",
        "x86_64" => "x86_64",
        "arm" => "arm",
        "aarch64" => "aarch64", // Triplet uses "aarch64" (not "arm64")
        "riscv64" => "riscv64",
        _ => "unknown",
    };

    // Triplet OS component — matches conftest.c conventions
    let triplet_os = match target_os.as_str() {
        "linux" => "linux",
        "android" => "linux",     // Android uses "linux" in the triplet
        "freebsd" => "kfreebsd",  // conftest.c: __FreeBSD__ → "kfreebsd"
        "netbsd" => "netbsd",
        "openbsd" => "openbsd",
        "windows" => "win32",     // conftest.c: _WIN32 → "win32"
        "macos" => "darwin",      // conftest.c: __APPLE__ → "darwin"
        _ => "unknown",
    };

    // ABI prefix: "android" on Android, "gnu" otherwise
    // C equivalent: conftest.c lines 213-217
    let abi_prefix = if target_os == "android" {
        "android"
    } else {
        "gnu"
    };

    // ABI suffix: ARM EABI gets "eabihf" or "eabi"; others use just the prefix.
    // C equivalent: conftest.c lines 220-228
    let triplet_abi = if target_arch == "arm" {
        // Check the full Rust target triple for hard-float indication.
        // arm-unknown-linux-gnueabihf → hard-float (VFP)
        // arm-unknown-linux-gnueabi → soft-float
        if target.contains("eabihf") {
            format!("{}eabihf", abi_prefix)
        } else {
            format!("{}eabi", abi_prefix)
        }
    } else {
        abi_prefix.to_string()
    };

    // Triplet assembly — follows conftest.c lines 230-236:
    //   Windows MSVC:  ARCH-pc-windows-msvc   (modern MSVC toolchain)
    //   Windows GNU:   ARCH-w64-mingw32       (MinGW-w64 toolchain)
    //   GNU Hurd:      ARCH-pc-gnu            (GCC/libc convention)
    //   Default:       ARCH-OS-ABI
    //
    // The original C conftest.c used a single "ARCH-win32-" format for all
    // Windows targets because TCC only supported the MinGW environment.
    // The Rust port distinguishes MSVC vs GNU environments on Windows to
    // enable correct sysroot path construction for both toolchains.
    let triplet = if is_pe {
        // Distinguish MSVC vs GNU (MinGW) toolchains on Windows.
        // Cargo sets CARGO_CFG_TARGET_ENV to "msvc" or "gnu" accordingly.
        if target_env == "msvc" {
            format!("{}-pc-windows-msvc", triplet_arch)
        } else {
            // MinGW-w64 convention: x86_64-w64-mingw32 / i686-w64-mingw32
            format!("{}-w64-mingw32", triplet_arch)
        }
    } else if target_os == "hurd" {
        // GNU Hurd convention: {arch}-pc-gnu (matches GCC/libc triplet format).
        // The previous "{arch}-gnu-gnu" format was non-standard.
        format!("{}-pc-gnu", triplet_arch)
    } else {
        format!("{}-{}-{}", triplet_arch, triplet_os, triplet_abi)
    };

    // ========================================================================
    // Phase 8: System Path Configuration
    // ========================================================================
    // Determines library/include/CRT paths, matching the C build system's
    // CONFIG_* path defines from tcc.h lines 247-337 and the configure script.
    //
    // Key concepts:
    //   {B}    = TCC library directory (CONFIG_TCCDIR), resolved at runtime
    //   sysroot = system root prefix (empty by default)
    //   triplet = multiarch directory component (e.g., "x86_64-linux-gnu")
    //   lddir   = library directory name ("lib" or "lib64")

    // CONFIG_SYSROOT — tcc.h line 247-249; default is empty string
    // Can be overridden via TCC_SYSROOT environment variable at build time.
    let sysroot = env::var("TCC_SYSROOT").unwrap_or_default();

    // Determine whether the system uses triplet-based multiarch directories.
    // On native builds, probe the filesystem (mimicking configure script).
    // On cross builds, assume triplet layout is available.
    let use_triplet = if is_native && !is_pe && !is_macho {
        // Probe for the triplet directory on the host filesystem,
        // same as configure: `test -f "/usr/lib/$_triplet/crti.o"`
        let triplet_lib_dir = format!("/usr/lib/{}", triplet);
        Path::new(&triplet_lib_dir).is_dir()
    } else if !is_pe && !is_macho {
        // For cross compilation on Unix, assume triplet layout
        true
    } else {
        false
    };

    // Determine the library directory name.
    // Default is "lib", but some 64-bit systems (RHEL, Fedora) use "lib64"
    // when multiarch triplet directories are not available.
    //
    // C equivalent: configure script lines 475-479
    //   if test -z "$triplet"; then
    //     case $cpu in x86_64|arm64|riscv64)
    //       if test -f "/usr/lib64/crti.o" ; then
    //         tcc_lddir="lib64"
    //       fi
    //     esac
    //   fi
    let lddir = if !use_triplet && !is_pe && !is_macho && is_native {
        let is_64bit_arch = matches!(tcc_arch, "x86_64" | "arm64" | "riscv64");
        if is_64bit_arch && Path::new("/usr/lib64/crti.o").exists() {
            "lib64"
        } else {
            "lib"
        }
    } else {
        "lib"
    };

    // CONFIG_TCCDIR — tcc.h lines 250-252
    // Default: "/usr/local/lib/tcc" on Unix; determined at runtime on Windows.
    // Can be overridden via TCC_TCCDIR environment variable at build time.
    let tccdir = env::var("TCC_TCCDIR").unwrap_or_else(|_| {
        if is_pe {
            // On Windows, tccdir is determined at runtime from executable path
            String::new()
        } else {
            "/usr/local/lib/tcc".to_string()
        }
    });

    // CONFIG_USR_INCLUDE — tcc.h lines 269-271
    let usr_include = "/usr/include";

    // Helper closures for multiarch path construction.
    //
    // USE_TRIPLET(s) = "s/TRIPLET" if triplet is active, else "s"
    //   C equivalent: tcc.h line 257
    //
    // ALSO_TRIPLET(s) = "s/TRIPLET:s" if triplet is active, else "s"
    //   C equivalent: tcc.h line 258
    let use_triplet_path = |base: &str| -> String {
        if use_triplet {
            format!("{}/{}", base, triplet)
        } else {
            base.to_string()
        }
    };

    let also_triplet = |base: &str| -> String {
        if use_triplet {
            format!("{}/{}:{}", base, triplet, base)
        } else {
            base.to_string()
        }
    };

    // CONFIG_TCC_SYSINCLUDEPATHS — tcc.h lines 276-285
    // System include search paths for the C preprocessor.
    //
    // Windows (PE): "{B}/include;{B}/include/winapi"
    // Unix:         "{B}/include" : ALSO_TRIPLET(sysroot/usr/local/include)
    //                             : ALSO_TRIPLET(sysroot/usr/include)
    let sysincludepaths = if is_pe {
        "{B}/include;{B}/include/winapi".to_string()
    } else {
        let sysroot_prefix = if sysroot.is_empty() {
            String::new()
        } else {
            sysroot.clone()
        };
        let usr_local_inc =
            also_triplet(&format!("{}/usr/local/include", sysroot_prefix));
        let usr_inc =
            also_triplet(&format!("{}{}", sysroot_prefix, usr_include));
        format!("{{B}}/include:{}:{}", usr_local_inc, usr_inc)
    };

    // CONFIG_TCC_LIBPATHS — tcc.h lines 288-298
    // Library search paths for the linker.
    //
    // Windows (PE): "{B}/lib"
    // Unix:         "{B}" : ALSO_TRIPLET(sysroot/usr/LDDIR)
    //                     : ALSO_TRIPLET(sysroot/LDDIR)
    //                     : ALSO_TRIPLET(sysroot/usr/local/LDDIR)
    let libpaths = if is_pe {
        "{B}/lib".to_string()
    } else {
        let sysroot_prefix = if sysroot.is_empty() {
            String::new()
        } else {
            sysroot.clone()
        };
        let usr_lib =
            also_triplet(&format!("{}/usr/{}", sysroot_prefix, lddir));
        let root_lib =
            also_triplet(&format!("{}/{}", sysroot_prefix, lddir));
        let usr_local_lib =
            also_triplet(&format!("{}/usr/local/{}", sysroot_prefix, lddir));
        format!("{{B}}:{}:{}:{}", usr_lib, root_lib, usr_local_lib)
    };

    // CONFIG_TCC_CRTPREFIX — tcc.h lines 265-267
    // Path to find crt1.o, crti.o, and crtn.o (C runtime startup files).
    //
    // Default: USE_TRIPLET(sysroot/usr/LDDIR)
    let crtprefix = if is_pe {
        "{B}/lib".to_string()
    } else {
        let sysroot_prefix = if sysroot.is_empty() {
            String::new()
        } else {
            sysroot.clone()
        };
        use_triplet_path(&format!("{}/usr/{}", sysroot_prefix, lddir))
    };

    // CONFIG_TCC_ELFINTERP — tcc.h lines 300-317
    // ELF dynamic linker/interpreter path, architecture-specific.
    let elfinterp = if is_pe {
        // PE targets don't use an ELF interpreter
        "-".to_string()
    } else if is_macho {
        // macOS uses dyld, not an ELF interpreter; emit placeholder
        "/usr/lib/dyld".to_string()
    } else {
        match tcc_arch {
            // tcc.h line 307: /lib/ld-linux-aarch64.so.1
            "arm64" => "/lib/ld-linux-aarch64.so.1".to_string(),
            // tcc.h line 309: /lib64/ld-linux-x86-64.so.2
            "x86_64" => "/lib64/ld-linux-x86-64.so.2".to_string(),
            // tcc.h line 311: /lib/ld-linux-riscv64-lp64d.so.1
            "riscv64" => "/lib/ld-linux-riscv64-lp64d.so.1".to_string(),
            // tcc.h lines 312-313: ARM EABI — depends on hard-float
            "arm" => {
                if target.contains("eabihf") {
                    "/lib/ld-linux-armhf.so.3".to_string()
                } else {
                    "/lib/ld-linux.so.3".to_string()
                }
            }
            // tcc.h line 315: default i386 — /lib/ld-linux.so.2
            "i386" => "/lib/ld-linux.so.2".to_string(),
            // Fallback for unknown architectures
            _ => "/lib/ld-linux.so.2".to_string(),
        }
    };

    // Emit all path configuration as compile-time environment variables.
    // These are accessible in Rust code via `env!("TCC_CONFIG_TCCDIR")` etc.
    println!("cargo:rustc-env=TCC_CONFIG_TCCDIR={}", tccdir);
    println!("cargo:rustc-env=TCC_CONFIG_SYSROOT={}", sysroot);
    println!("cargo:rustc-env=TCC_CONFIG_LDDIR={}", lddir);
    // Always emit the full triplet string — conftest.c outputs it unconditionally.
    // The `use_triplet` flag only controls whether triplet-based paths are added
    // to system include/library search paths.
    println!("cargo:rustc-env=TCC_TRIPLET={}", triplet);
    println!("cargo:rustc-env=TCC_CONFIG_SYSINCLUDEPATHS={}", sysincludepaths);
    println!("cargo:rustc-env=TCC_CONFIG_LIBPATHS={}", libpaths);
    println!("cargo:rustc-env=TCC_CONFIG_CRTPREFIX={}", crtprefix);
    println!("cargo:rustc-env=TCC_CONFIG_ELFINTERP={}", elfinterp);
    println!("cargo:rustc-env=TCC_CONFIG_USR_INCLUDE={}", usr_include);

    // ========================================================================
    // Phase 9: Endianness and Size Configuration
    // ========================================================================
    // C equivalent: conftest.c lines 244-248 (bigendian detection)

    // Endianness — emit cfg flag for big-endian targets
    if target_endian == "big" {
        println!("cargo:rustc-cfg=tcc_bigendian");
    }

    // Pointer size in bytes — replaces __SIZEOF_POINTER__ / PTR_SIZE
    // from conftest.c C2STR mode lines 26-27
    let ptr_size = match target_pointer_width.as_str() {
        "64" => "8",
        "32" => "4",
        "16" => "2",
        _ => "4", // Safe default: assume 32-bit if unknown
    };
    println!("cargo:rustc-env=TCC_PTR_SIZE={}", ptr_size);

    // Long size in bytes — replaces __SIZEOF_LONG__ / LONG_SIZE
    // from conftest.c C2STR mode lines 26-27
    //
    // On most 64-bit Unix/POSIX systems, `long` is 8 bytes (LP64 data model).
    // On Windows (even 64-bit), `long` is 4 bytes (LLP64 data model).
    // On all 32-bit systems, `long` is 4 bytes.
    let long_size = if target_pointer_width == "64" && !is_pe {
        "8"
    } else {
        "4"
    };
    println!("cargo:rustc-env=TCC_LONG_SIZE={}", long_size);

    // ========================================================================
    // Phase 10: Feature Flag Interaction
    // ========================================================================
    // Maps Cargo feature flags (defined in Cargo.toml [features]) to
    // tcc_backend_* cfg directives for conditional compilation of architecture
    // backends.
    //
    // This replaces the TCC_TARGET_* compile-time guards from tcc.h lines 146-151
    // and the --enable/--disable options from the configure script.

    // Architecture backend features
    emit_feature_cfg("i386", "tcc_backend_i386");
    emit_feature_cfg("x86_64", "tcc_backend_x86_64");
    emit_feature_cfg("arm", "tcc_backend_arm");
    emit_feature_cfg("arm64", "tcc_backend_arm64");
    emit_feature_cfg("riscv64", "tcc_backend_riscv64");
    emit_feature_cfg("c67", "tcc_backend_c67");
    emit_feature_cfg("il", "tcc_backend_il");

    // Optional compiler subsystem features — from TODO FEAT-01
    emit_feature_cfg("asm", "tcc_asm_enabled");
    emit_feature_cfg("bcheck", "tcc_bcheck_enabled");

    // ========================================================================
    // Phase 11: Target Environment and ARM-Specific Flags
    // ========================================================================
    // Emit cfg for the target C runtime environment (gnu, musl, msvc).
    match target_env.as_str() {
        "gnu" => println!("cargo:rustc-cfg=tcc_env=\"gnu\""),
        "musl" => println!("cargo:rustc-cfg=tcc_env=\"musl\""),
        "msvc" => println!("cargo:rustc-cfg=tcc_env=\"msvc\""),
        "sgx" => println!("cargo:rustc-cfg=tcc_env=\"sgx\""),
        _ => {} // Graceful fallback for unknown environments
    }

    // ARM-specific flags — replaces TCC_ARM_EABI, TCC_ARM_VFP, TCC_ARM_HARDFLOAT
    // from tcc.h lines 160-163
    if target_arch == "arm" {
        // Modern ARM targets universally use EABI
        println!("cargo:rustc-cfg=tcc_arm_eabi");

        // Check for hard-float ABI (VFP hardware floating-point)
        if target.contains("eabihf") {
            println!("cargo:rustc-cfg=tcc_arm_hardfloat");
            println!("cargo:rustc-cfg=tcc_arm_vfp");
        }
    }

    // ========================================================================
    // Phase 12: Rerun Triggers
    // ========================================================================
    // Cargo should re-run this build script when build.rs itself changes,
    // or when override environment variables change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TCC_SYSROOT");
    println!("cargo:rerun-if-env-changed=TCC_TCCDIR");
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Reads a Cargo environment variable, returning an empty string if not set.
///
/// Build scripts have access to a specific set of environment variables set by
/// Cargo (CARGO_CFG_TARGET_*, HOST, TARGET, etc.). This helper provides a safe
/// default for optional variables.
fn env_var(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

/// Checks if a Cargo feature flag is enabled and emits the corresponding cfg.
///
/// Cargo sets `CARGO_FEATURE_<NAME>` (uppercased, hyphens → underscores)
/// for each enabled feature. This function maps feature names to cfg directives.
fn emit_feature_cfg(feature_name: &str, cfg_name: &str) {
    let env_name = format!(
        "CARGO_FEATURE_{}",
        feature_name.to_uppercase().replace('-', "_")
    );
    if env::var(&env_name).is_ok() {
        println!("cargo:rustc-cfg={}", cfg_name);
    }
}

/// Declares all expected custom cfg values to suppress "unexpected cfg" warnings
/// in Rust 1.80+ (check-cfg lint).
///
/// This ensures that `#[cfg(tcc_target = "x86_64")]` and similar attributes
/// don't produce compiler warnings about unrecognized cfg names.
fn declare_expected_cfgs() {
    // Architecture target — key=value cfg
    println!(
        "cargo:rustc-check-cfg=cfg(tcc_target, values(\
         \"i386\", \"x86_64\", \"arm\", \"arm64\", \"riscv64\", \"unknown\"\
         ))"
    );

    // OS target — key=value cfg
    println!(
        "cargo:rustc-check-cfg=cfg(tcc_os, values(\
         \"linux\", \"android\", \"windows\", \"macos\", \
         \"freebsd\", \"openbsd\", \"netbsd\", \"dragonfly\", \"unknown\"\
         ))"
    );

    // Target environment — key=value cfg
    println!(
        "cargo:rustc-check-cfg=cfg(tcc_env, values(\
         \"gnu\", \"musl\", \"msvc\", \"sgx\"\
         ))"
    );

    // Boolean cfg flags (no value)
    let boolean_cfgs = [
        "tcc_target_pe",
        "tcc_target_macho",
        "tcc_is_native",
        "tcc_os_bsd",
        "tcc_target_unix",
        "tcc_elf_obj_only",
        "tcc_using_double_for_ldouble",
        "tcc_bigendian",
        "tcc_config_backtrace",
        "tcc_config_new_macho",
        "tcc_config_semlock",
        "tcc_arm_eabi",
        "tcc_arm_hardfloat",
        "tcc_arm_vfp",
        "tcc_backend_i386",
        "tcc_backend_x86_64",
        "tcc_backend_arm",
        "tcc_backend_arm64",
        "tcc_backend_riscv64",
        "tcc_backend_c67",
        "tcc_backend_il",
        "tcc_asm_enabled",
        "tcc_bcheck_enabled",
    ];

    for cfg_name in &boolean_cfgs {
        println!("cargo:rustc-check-cfg=cfg({})", cfg_name);
    }
}
