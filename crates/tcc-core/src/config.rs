//! Build-time configuration constants for the TCC compiler.
//!
//! This module provides compile-time constants that replace the `CONFIG_*`
//! preprocessor defines from the original C codebase's `tcc.h` (lines 247-337).
//! Values are populated by the `build.rs` script via `env!()` / `option_env!()`
//! macros, providing zero runtime overhead for path and platform configuration.
//!
//! # Path Configuration
//!
//! Several path constants use a `{B}` placeholder that represents the TCC
//! library base directory. This placeholder is expanded at runtime using
//! [`expand_path`] when the actual base directory is known (which may be
//! overridden via the `-B` command-line option).
//!
//! # Platform Constants
//!
//! Platform-specific constants ([`PTR_SIZE`], [`LONG_SIZE`], [`PATHSEP`],
//! [`DIRSEP`], [`USING_DOUBLE_FOR_LDOUBLE`]) are determined at compile time
//! based on the target architecture and operating system, via `build.rs`
//! environment variables and `cfg` flags.
//!
//! # Relationship to `build.rs`
//!
//! The `build.rs` script in the `tcc-core` crate detects host and target
//! properties (architecture, OS, pointer width, triplet) and emits
//! `cargo:rustc-env=TCC_*=<value>` directives that are consumed here.
//! This replaces the `configure` script and `conftest.c` host-detection
//! mechanism from the original C build system.

// ============================================================================
// Compile-Time Helper Functions
// ============================================================================
// These const fn helpers enable compile-time evaluation of configuration
// values from environment variables, working around limitations of const
// evaluation (e.g., str::parse() is not const).

/// Compile-time helper to extract a value from `Option<&str>` with a default.
///
/// Used for configuration values from `option_env!()` that have sensible
/// defaults when the environment variable is not set. This exists because
/// `Option::unwrap_or` in const context requires `T: ~const Destruct`,
/// and this explicit match avoids any trait-bound ambiguity across
/// Rust editions.
const fn const_unwrap_option_str(opt: Option<&'static str>, default: &'static str) -> &'static str {
    match opt {
        Some(val) => val,
        None => default,
    }
}

/// Compile-time conversion of a numeric size string to `usize`.
///
/// Valid inputs are `"2"`, `"4"`, and `"8"` — the only pointer/long sizes
/// emitted by `build.rs` (derived from `CARGO_CFG_TARGET_POINTER_WIDTH`).
/// Returns `4` as a safe default for any unrecognized input.
///
/// This replaces `str::parse::<usize>()` which is not available in const
/// evaluation context.
const fn parse_size_str(s: &str) -> usize {
    let b = s.as_bytes();
    if b.is_empty() {
        return 4; // safe default for empty input
    }
    // Match the first byte — valid size strings are single-character
    // ASCII digits emitted by build.rs: "2", "4", or "8"
    match b[0] {
        b'8' => 8,
        b'4' => 4,
        b'2' => 2,
        _ => 4, // safe fallback for unexpected values
    }
}

// ============================================================================
// Path Configuration Constants
// ============================================================================

/// Default TCC library directory.
///
/// Corresponds to `CONFIG_TCCDIR` in `tcc.h` (line 251).
/// On Unix systems, defaults to `/usr/local/lib/tcc`.
/// On Windows, defaults to the directory containing the TCC executable.
///
/// This directory contains:
/// - `libtcc1.a` — the TCC runtime support library
/// - `include/` — TCC-specific headers (`stdarg.h`, `stddef.h`, etc.)
/// - Architecture-specific subdirectories for cross-compilation
///
/// Can be overridden at runtime via the `-B <dir>` command-line flag
/// (see [`tcc_lib_path`]).
pub const TCCDIR: &str = env!("TCC_CONFIG_TCCDIR");

/// System root prefix for all include and library paths.
///
/// Corresponds to `CONFIG_SYSROOT` in `tcc.h` (line 248).
/// Defaults to `""` (empty string). When set to a non-empty value,
/// all system include and library search paths are prefixed with
/// this value, enabling cross-compilation with a sysroot directory
/// (similar to GCC's `--sysroot=<dir>` option).
///
/// Uses `option_env!()` for robustness — falls back to `""` if the
/// environment variable is not set by `build.rs`.
pub const SYSROOT: &str = const_unwrap_option_str(option_env!("TCC_CONFIG_SYSROOT"), "");

/// Library directory name within the system hierarchy.
///
/// Corresponds to `CONFIG_LDDIR` in `tcc.h` (line 254).
/// Typically `"lib"` on most systems, or `"lib64"` on 64-bit x86_64
/// multilib systems. Used to construct library search paths such as
/// `/usr/lib` or `/usr/lib64`.
///
/// Determined by `build.rs` based on the target architecture and
/// operating system conventions.
pub const LDDIR: &str = const_unwrap_option_str(option_env!("TCC_CONFIG_LDDIR"), "lib");

/// GNU-style target triplet for multiarch directory layout.
///
/// Corresponds to `CONFIG_TRIPLET` in `tcc.h` (line 255) and is emitted
/// by `build.rs` as `TCC_TRIPLET` via `cargo:rustc-env`.
///
/// The triplet is used by the compiler to locate architecture-specific
/// system libraries and headers in multiarch directory layouts. For example,
/// on Debian/Ubuntu x86_64 systems, system libraries are found under
/// `/usr/lib/x86_64-linux-gnu/` where `x86_64-linux-gnu` is the triplet.
///
/// Values by platform:
/// - Linux x86_64: `"x86_64-linux-gnu"`
/// - Linux ARM64: `"aarch64-linux-gnu"`
/// - Windows MSVC: `"x86_64-pc-windows-msvc"`
/// - Windows MinGW: `"x86_64-w64-mingw32"`
/// - macOS: `"x86_64-darwin-gnu"` or `"aarch64-darwin-gnu"`
/// - GNU Hurd: `"{arch}-pc-gnu"`
///
/// Constructed by `build.rs` Phase 7 (ABI Detection and Triplet Construction).
pub const TCC_TARGET_TRIPLET: &str = env!("TCC_TRIPLET");

/// CRT (C Runtime) object file search paths.
///
/// Corresponds to `CONFIG_TCC_CRTPREFIX` in `tcc.h` (line 266).
/// A separator-delimited list of directories to search for CRT startup
/// files (`crt1.o`, `crti.o`, `crtn.o`) needed for linking executables.
///
/// May contain the `{B}` placeholder which is expanded to the TCC
/// library directory at runtime via [`expand_path`]. Use [`split_paths`]
/// to decompose into individual directory entries.
pub const CRT_PREFIX: &str = env!("TCC_CONFIG_CRTPREFIX");

/// Standard user include path for system C library headers.
///
/// Corresponds to `CONFIG_USR_INCLUDE` in `tcc.h` (line 270).
/// Defaults to `"/usr/include"` on Unix systems. This is the primary
/// system header search path for standard C library headers
/// (`<stdio.h>`, `<stdlib.h>`, etc.).
pub const USR_INCLUDE: &str = const_unwrap_option_str(
    option_env!("TCC_CONFIG_USR_INCLUDE"),
    "/usr/include",
);

/// System include search paths (separator-delimited).
///
/// Corresponds to `CONFIG_TCC_SYSINCLUDEPATHS` in `tcc.h` (lines 276-285).
/// A separator-delimited list of directories to search for system headers.
/// Includes paths for:
/// - TCC-specific headers (`{B}/include`)
/// - Standard library headers (`/usr/include`)
/// - Architecture-specific headers (via triplet subdirectories on Linux)
///
/// May contain `{B}` placeholders expanded at runtime via [`expand_path`].
/// Use [`split_paths`] to decompose into individual directory entries.
pub const SYSINCLUDE_PATHS: &str = env!("TCC_CONFIG_SYSINCLUDEPATHS");

/// Library search paths (separator-delimited).
///
/// Corresponds to `CONFIG_TCC_LIBPATHS` in `tcc.h` (lines 288-298).
/// A separator-delimited list of directories to search for libraries
/// specified via `-l` flags during linking. Includes:
/// - TCC library directory (`{B}`)
/// - System library directories (`/usr/lib`, `/lib`)
/// - Architecture-specific library paths (via triplet subdirectories)
///
/// May contain `{B}` placeholders expanded at runtime via [`expand_path`].
/// Use [`split_paths`] to decompose into individual directory entries.
pub const LIB_PATHS: &str = env!("TCC_CONFIG_LIBPATHS");

/// ELF dynamic linker/interpreter path.
///
/// Corresponds to `CONFIG_TCC_ELFINTERP` in `tcc.h` (lines 301-317).
/// Architecture-specific path to the ELF interpreter (dynamic linker)
/// embedded in the `.interp` section of dynamically-linked executables.
///
/// Common values by architecture:
/// - x86_64: `/lib64/ld-linux-x86-64.so.2`
/// - i386: `/lib/ld-linux.so.2`
/// - ARM: `/lib/ld-linux.so.3`
/// - ARM64: `/lib/ld-linux-aarch64.so.1`
/// - RISC-V64: `/lib/ld-linux-riscv64-lp64d.so.1`
pub const ELF_INTERP: &str = env!("TCC_CONFIG_ELFINTERP");

/// Cross-compilation tool prefix.
///
/// Corresponds to `CONFIG_TCC_CROSSPREFIX` in `tcc.h` (line 336).
/// Defaults to `""` (empty, meaning native compilation). When set,
/// this prefix is prepended to tool names for cross-compilation
/// workflows (e.g., `arm-linux-gnueabihf-`).
///
/// Uses `option_env!()` because `build.rs` does not emit this variable;
/// it is only set externally when configuring for cross-compilation.
pub const CROSS_PREFIX: &str = const_unwrap_option_str(
    option_env!("TCC_CONFIG_CROSSPREFIX"),
    "",
);

/// Name of the TCC runtime support library.
///
/// Corresponds to `TCC_LIBTCC1` in `tcc.h` (line 326).
/// This static archive contains runtime support functions
/// (`__udivdi3`, `__moddi3`, `__fixdfdi`, etc.) that are linked
/// into compiled programs when they use operations not directly
/// supported by the target instruction set (e.g., 64-bit division
/// on 32-bit targets).
pub const LIBTCC1: &str = "libtcc1.a";

// ============================================================================
// Target Platform Constants
// ============================================================================

/// Pointer size in bytes for the compilation target.
///
/// Derived from the `TCC_PTR_SIZE` environment variable emitted by
/// `build.rs`, which reads `CARGO_CFG_TARGET_POINTER_WIDTH`:
/// - 64-bit targets: `8`
/// - 32-bit targets: `4`
/// - 16-bit targets: `2` (rare, embedded only)
///
/// Replaces `PTR_SIZE` / `__SIZEOF_POINTER__` from the C codebase
/// (`conftest.c` C2STR mode, lines 26-27).
pub const PTR_SIZE: usize = parse_size_str(env!("TCC_PTR_SIZE"));

/// Long integer size in bytes for the compilation target.
///
/// Derived from the `TCC_LONG_SIZE` environment variable emitted by
/// `build.rs`, based on target pointer width and operating system:
/// - 64-bit Unix/POSIX (LP64 data model): `8` bytes
/// - 64-bit Windows (LLP64 data model): `4` bytes
/// - All 32-bit systems: `4` bytes
///
/// Replaces `LONG_SIZE` / `__SIZEOF_LONG__` from the C codebase
/// (`conftest.c` C2STR mode, lines 26-27).
pub const LONG_SIZE: usize = parse_size_str(env!("TCC_LONG_SIZE"));

/// Whether `long double` uses `double` representation on this target.
///
/// Corresponds to `TCC_USING_DOUBLE_FOR_LDOUBLE` in `tcc.h` (lines 228-234).
/// Set to `true` on platforms where `long double` has the same 64-bit
/// IEEE 754 representation as `double`:
/// - Windows (MSVC and MinGW): always `true`
/// - macOS on ARM64 (Apple Silicon): `true`
/// - All other platforms: `false` (typically 80-bit x87 extended precision
///   on x86/x86_64, or 128-bit IEEE 754 on some RISC architectures)
///
/// Determined by `build.rs` which emits `cfg(tcc_using_double_for_ldouble)`
/// based on target properties.
pub const USING_DOUBLE_FOR_LDOUBLE: bool = cfg!(tcc_using_double_for_ldouble);

// ============================================================================
// Platform Separator Constants
// ============================================================================

/// Path list separator for search path strings.
///
/// Used to delimit multiple directory entries within configuration
/// strings like [`SYSINCLUDE_PATHS`], [`LIB_PATHS`], and [`CRT_PREFIX`].
///
/// - Unix/POSIX: `":"` (colon)
/// - Windows: `";"` (semicolon)
///
/// See [`split_paths`] for decomposing path lists using this separator.
#[cfg(windows)]
pub const PATHSEP: &str = ";";

/// Path list separator for search path strings.
///
/// Used to delimit multiple directory entries within configuration
/// strings like [`SYSINCLUDE_PATHS`], [`LIB_PATHS`], and [`CRT_PREFIX`].
///
/// - Unix/POSIX: `":"` (colon)
/// - Windows: `";"` (semicolon)
///
/// See [`split_paths`] for decomposing path lists using this separator.
#[cfg(not(windows))]
pub const PATHSEP: &str = ":";

/// Directory separator character for filesystem paths.
///
/// Used when constructing file paths programmatically to ensure
/// platform-appropriate path formatting.
///
/// - Unix/POSIX: `'/'` (forward slash)
/// - Windows: `'\\'` (backslash)
#[cfg(windows)]
pub const DIRSEP: char = '\\';

/// Directory separator character for filesystem paths.
///
/// Used when constructing file paths programmatically to ensure
/// platform-appropriate path formatting.
///
/// - Unix/POSIX: `'/'` (forward slash)
/// - Windows: `'\\'` (backslash)
#[cfg(not(windows))]
pub const DIRSEP: char = '/';

// ============================================================================
// Version Constants
// ============================================================================

/// TCC version string.
///
/// Matches the content of the `VERSION` file in the repository root
/// (`0.9.28rc`). This version identifier is used in:
/// - Compiler diagnostic output and `--version` display
/// - The `__TCC__` predefined macro value
/// - The `tcc-core` Cargo package version metadata
pub const TCC_VERSION: &str = "0.9.28rc";

// ============================================================================
// Compiler Feature Flags
// ============================================================================

/// Whether TCC predefined macros from `tccdefs.h` are auto-included.
///
/// Corresponds to `CONFIG_TCC_PREDEFS` in `tcc.h` (line 337).
/// When `true`, the preprocessor automatically includes the built-in
/// `tccdefs.h` header before processing user source files. This header
/// provides compatibility definitions for GCC/MSVC builtins, type traits,
/// and platform-specific macros.
///
/// Enabled by default in the C codebase and preserved in the Rust port.
/// The preprocessor module should check this flag to determine whether
/// to inject the predefined header.
pub const CONFIG_TCC_PREDEFS: bool = true;

/// Whether multiprocess compilation locking is enabled.
///
/// Corresponds to `CONFIG_TCC_SEMLOCK` in `tcc.h` (lines 241-243).
/// When `true`, TCC uses semaphore-based locking to prevent concurrent
/// writes to output files when multiple TCC instances run in parallel.
///
/// Mapped from the `tcc_config_semlock` cfg flag emitted by `build.rs`.
/// In the Rust port, Rust's ownership model and `std::fs` file locking
/// provide equivalent safety guarantees, but this flag is preserved for
/// behavioral compatibility with the C implementation.
pub const CONFIG_TCC_SEMLOCK: bool = cfg!(tcc_config_semlock);

// ============================================================================
// Helper Functions
// ============================================================================

/// Returns the effective TCC library directory path, with optional override.
///
/// If `override_path` is `Some`, returns the override path as-is.
/// Otherwise, returns the default [`TCCDIR`] configured at build time.
///
/// This function supports the `-B <dir>` command-line option, which
/// allows users to specify an alternative TCC library directory at
/// runtime. All subsequent path resolution (include paths, library
/// paths, CRT object paths) uses this directory as the `{B}` base.
///
/// # Arguments
///
/// * `override_path` - Optional path from the `-B` command-line flag.
///   If `None`, the compile-time default [`TCCDIR`] is used.
///
/// # Returns
///
/// The effective TCC library directory as an owned `String`.
///
/// # Examples
///
/// ```
/// use tcc_core::config::tcc_lib_path;
///
/// // Use build-time default
/// let default_path = tcc_lib_path(None);
///
/// // Override with custom path (e.g., from `-B /opt/tcc/lib`)
/// let custom_path = tcc_lib_path(Some("/opt/tcc/lib"));
/// assert_eq!(custom_path, "/opt/tcc/lib");
/// ```
pub fn tcc_lib_path(override_path: Option<&str>) -> String {
    match override_path {
        Some(path) => path.to_string(),
        None => TCCDIR.to_string(),
    }
}

/// Expands `{B}` placeholders in a path template string.
///
/// The TCC configuration system uses `{B}` as a placeholder for the
/// TCC library base directory in path templates stored in constants
/// like [`SYSINCLUDE_PATHS`], [`LIB_PATHS`], and [`CRT_PREFIX`].
/// This function replaces all occurrences of `{B}` with the provided
/// `base_dir` value.
///
/// # Arguments
///
/// * `template` - A path template string potentially containing one or
///   more `{B}` placeholders.
/// * `base_dir` - The base directory to substitute for each `{B}`
///   occurrence. Typically the return value of [`tcc_lib_path`].
///
/// # Returns
///
/// A new `String` with all `{B}` occurrences replaced by `base_dir`.
/// If `template` contains no `{B}` placeholders, the original string
/// content is returned unchanged (as a new allocation).
///
/// # Examples
///
/// ```
/// use tcc_core::config::expand_path;
///
/// // Single placeholder
/// let result = expand_path("{B}/include", "/usr/local/lib/tcc");
/// assert_eq!(result, "/usr/local/lib/tcc/include");
///
/// // Multiple placeholders in a path list
/// let result = expand_path("{B}/lib:{B}/lib64", "/opt/tcc");
/// assert_eq!(result, "/opt/tcc/lib:/opt/tcc/lib64");
///
/// // No placeholder — passthrough
/// let result = expand_path("/usr/include", "/opt/tcc");
/// assert_eq!(result, "/usr/include");
/// ```
pub fn expand_path(template: &str, base_dir: &str) -> String {
    template.replace("{B}", base_dir)
}

/// Splits a separator-delimited path list into individual path entries.
///
/// Uses the platform-appropriate separator ([`PATHSEP`]):
/// - Unix/POSIX: `:` (colon)
/// - Windows: `;` (semicolon)
///
/// Empty segments (caused by leading, trailing, or consecutive separators)
/// are filtered out and not included in the result.
///
/// # Arguments
///
/// * `paths` - A separator-delimited path string. Typically one of the
///   configuration constants like [`SYSINCLUDE_PATHS`], [`LIB_PATHS`],
///   or [`CRT_PREFIX`], possibly after [`expand_path`] processing.
///
/// # Returns
///
/// A `Vec<String>` containing the individual, non-empty path entries
/// in their original order.
///
/// # Examples
///
/// ```
/// use tcc_core::config::split_paths;
///
/// // Basic splitting
/// let paths = split_paths("/usr/include:/usr/local/include");
/// assert_eq!(paths, vec!["/usr/include", "/usr/local/include"]);
///
/// // Empty segments are filtered
/// let paths = split_paths(":/usr/include::");
/// assert_eq!(paths, vec!["/usr/include"]);
///
/// // Empty input
/// let paths = split_paths("");
/// assert!(paths.is_empty());
/// ```
pub fn split_paths(paths: &str) -> Vec<String> {
    paths
        .split(PATHSEP)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constant value tests ---

    #[test]
    fn test_tcc_version_matches_project() {
        assert_eq!(TCC_VERSION, "0.9.28rc");
    }

    #[test]
    fn test_libtcc1_library_name() {
        assert_eq!(LIBTCC1, "libtcc1.a");
    }

    #[test]
    fn test_ptr_size_is_valid() {
        assert!(
            PTR_SIZE == 2 || PTR_SIZE == 4 || PTR_SIZE == 8,
            "PTR_SIZE must be 2, 4, or 8; got {}",
            PTR_SIZE
        );
    }

    #[test]
    fn test_long_size_is_valid() {
        assert!(
            LONG_SIZE == 4 || LONG_SIZE == 8,
            "LONG_SIZE must be 4 or 8; got {}",
            LONG_SIZE
        );
    }

    #[test]
    fn test_long_size_does_not_exceed_ptr_size() {
        assert!(
            LONG_SIZE <= PTR_SIZE,
            "LONG_SIZE ({}) must not exceed PTR_SIZE ({})",
            LONG_SIZE,
            PTR_SIZE
        );
    }

    #[test]
    fn test_pathsep_is_nonempty() {
        assert!(!PATHSEP.is_empty(), "PATHSEP must be a non-empty string");
        assert!(
            PATHSEP == ":" || PATHSEP == ";",
            "PATHSEP must be ':' or ';'; got '{}'",
            PATHSEP
        );
    }

    #[test]
    fn test_dirsep_is_valid() {
        assert!(
            DIRSEP == '/' || DIRSEP == '\\',
            "DIRSEP must be '/' or '\\\\'; got '{}'",
            DIRSEP
        );
    }

    #[test]
    fn test_tccdir_is_accessible() {
        // TCCDIR is set by build.rs; verify it's a valid string reference
        let _dir: &str = TCCDIR;
    }

    #[test]
    fn test_elf_interp_is_nonempty() {
        assert!(
            !ELF_INTERP.is_empty(),
            "ELF_INTERP must be a non-empty path set by build.rs"
        );
    }

    #[test]
    fn test_sysinclude_paths_is_accessible() {
        let _paths: &str = SYSINCLUDE_PATHS;
    }

    #[test]
    fn test_lib_paths_is_accessible() {
        let _paths: &str = LIB_PATHS;
    }

    #[test]
    fn test_crt_prefix_is_accessible() {
        let _prefix: &str = CRT_PREFIX;
    }

    #[test]
    fn test_sysroot_defaults_to_empty_or_valid() {
        // SYSROOT defaults to "" if not configured
        let _root: &str = SYSROOT;
    }

    #[test]
    fn test_lddir_has_value() {
        // LDDIR defaults to "lib" if not overridden
        assert!(
            !LDDIR.is_empty(),
            "LDDIR should have a non-empty default value"
        );
    }

    #[test]
    fn test_cross_prefix_defaults() {
        // CROSS_PREFIX defaults to "" for native compilation
        let _prefix: &str = CROSS_PREFIX;
    }

    #[test]
    fn test_using_double_for_ldouble_is_bool() {
        // Just verify the constant is accessible and is a bool
        let _val: bool = USING_DOUBLE_FOR_LDOUBLE;
    }

    #[test]
    fn test_tcc_target_triplet_is_nonempty() {
        assert!(
            !TCC_TARGET_TRIPLET.is_empty(),
            "TCC_TARGET_TRIPLET must be a non-empty string set by build.rs"
        );
    }

    #[test]
    fn test_tcc_target_triplet_contains_arch() {
        // The triplet must contain a recognized architecture component
        let known_arches = ["x86_64", "i386", "aarch64", "arm", "riscv64", "unknown"];
        let has_arch = known_arches.iter().any(|arch| TCC_TARGET_TRIPLET.starts_with(arch));
        assert!(
            has_arch,
            "TCC_TARGET_TRIPLET '{}' should start with a known architecture",
            TCC_TARGET_TRIPLET
        );
    }

    #[test]
    fn test_config_tcc_predefs_is_enabled() {
        // CONFIG_TCC_PREDEFS should be true by default
        assert!(CONFIG_TCC_PREDEFS, "CONFIG_TCC_PREDEFS should be enabled by default");
    }

    #[test]
    fn test_config_tcc_semlock_is_bool() {
        // Just verify the constant is accessible and is a bool
        let _val: bool = CONFIG_TCC_SEMLOCK;
    }

    // --- Const helper tests ---

    #[test]
    fn test_parse_size_str_valid_values() {
        assert_eq!(parse_size_str("2"), 2);
        assert_eq!(parse_size_str("4"), 4);
        assert_eq!(parse_size_str("8"), 8);
    }

    #[test]
    fn test_parse_size_str_fallback_empty() {
        assert_eq!(parse_size_str(""), 4);
    }

    #[test]
    fn test_parse_size_str_fallback_unknown() {
        assert_eq!(parse_size_str("x"), 4);
        assert_eq!(parse_size_str("16"), 4); // first byte '1' doesn't match
        assert_eq!(parse_size_str("0"), 4);
    }

    #[test]
    fn test_const_unwrap_option_str_some() {
        assert_eq!(const_unwrap_option_str(Some("hello"), "default"), "hello");
    }

    #[test]
    fn test_const_unwrap_option_str_none() {
        assert_eq!(const_unwrap_option_str(None, "default"), "default");
    }

    #[test]
    fn test_const_unwrap_option_str_empty_some() {
        assert_eq!(const_unwrap_option_str(Some(""), "default"), "");
    }

    // --- Function tests ---

    #[test]
    fn test_tcc_lib_path_with_override() {
        assert_eq!(tcc_lib_path(Some("/custom/path")), "/custom/path");
    }

    #[test]
    fn test_tcc_lib_path_with_empty_override() {
        assert_eq!(tcc_lib_path(Some("")), "");
    }

    #[test]
    fn test_tcc_lib_path_default() {
        assert_eq!(tcc_lib_path(None), TCCDIR);
    }

    #[test]
    fn test_expand_path_single_placeholder() {
        assert_eq!(
            expand_path("{B}/include", "/usr/local/lib/tcc"),
            "/usr/local/lib/tcc/include"
        );
    }

    #[test]
    fn test_expand_path_multiple_placeholders() {
        assert_eq!(
            expand_path("{B}/lib:{B}/lib64", "/opt/tcc"),
            "/opt/tcc/lib:/opt/tcc/lib64"
        );
    }

    #[test]
    fn test_expand_path_no_placeholder() {
        assert_eq!(
            expand_path("/usr/include", "/opt/tcc"),
            "/usr/include"
        );
    }

    #[test]
    fn test_expand_path_empty_template() {
        assert_eq!(expand_path("", "/opt/tcc"), "");
    }

    #[test]
    fn test_expand_path_empty_base_dir() {
        assert_eq!(expand_path("{B}/include", ""), "/include");
    }

    #[test]
    fn test_expand_path_placeholder_only() {
        assert_eq!(expand_path("{B}", "/opt/tcc"), "/opt/tcc");
    }

    #[test]
    fn test_expand_path_adjacent_placeholders() {
        assert_eq!(expand_path("{B}{B}", "/a"), "/a/a");
    }

    #[test]
    fn test_split_paths_colon_separated() {
        let result = split_paths("/usr/include:/usr/local/include");
        // On Unix (test environment), PATHSEP is ":"
        if PATHSEP == ":" {
            assert_eq!(result, vec!["/usr/include", "/usr/local/include"]);
        }
    }

    #[test]
    fn test_split_paths_empty_input() {
        let result = split_paths("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_split_paths_single_entry() {
        let result = split_paths("/usr/include");
        assert_eq!(result, vec!["/usr/include"]);
    }

    #[test]
    fn test_split_paths_filters_empty_segments() {
        if PATHSEP == ":" {
            let result = split_paths(":/usr/include::");
            assert_eq!(result, vec!["/usr/include"]);
        }
    }

    #[test]
    fn test_split_paths_preserves_placeholders() {
        // split_paths should NOT expand {B} — that's expand_path's job
        if PATHSEP == ":" {
            let result = split_paths("{B}/include:{B}/lib");
            assert_eq!(result, vec!["{B}/include", "{B}/lib"]);
        }
    }

    #[test]
    fn test_split_paths_only_separators() {
        if PATHSEP == ":" {
            let result = split_paths(":::");
            assert!(result.is_empty());
        }
    }

    #[test]
    fn test_workflow_expand_then_split() {
        // Verify the typical workflow: expand {B}, then split
        let template = "{B}/include:{B}/lib";
        let expanded = expand_path(template, "/opt/tcc");
        if PATHSEP == ":" {
            let paths = split_paths(&expanded);
            assert_eq!(paths, vec!["/opt/tcc/include", "/opt/tcc/lib"]);
        }
    }
}
