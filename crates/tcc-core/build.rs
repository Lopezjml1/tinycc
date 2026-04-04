// build.rs — Host detection for tcc-core
// Replaces conftest.c from the original C build system.
// Detects host architecture, OS, and compiler characteristics at build time.

fn main() {
    // Detect host architecture
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // Emit cfg flags for architecture-specific code
    match target_arch.as_str() {
        "x86_64" => println!("cargo:rustc-cfg=tcc_target_x86_64"),
        "x86" => println!("cargo:rustc-cfg=tcc_target_i386"),
        "arm" => println!("cargo:rustc-cfg=tcc_target_arm"),
        "aarch64" => println!("cargo:rustc-cfg=tcc_target_arm64"),
        "riscv64" => println!("cargo:rustc-cfg=tcc_target_riscv64"),
        _ => {}
    }

    // Emit cfg flags for OS-specific code
    match target_os.as_str() {
        "linux" => println!("cargo:rustc-cfg=tcc_target_linux"),
        "macos" => println!("cargo:rustc-cfg=tcc_target_macos"),
        "windows" => println!("cargo:rustc-cfg=tcc_target_windows"),
        "freebsd" => println!("cargo:rustc-cfg=tcc_target_freebsd"),
        "openbsd" => println!("cargo:rustc-cfg=tcc_target_openbsd"),
        "netbsd" => println!("cargo:rustc-cfg=tcc_target_netbsd"),
        _ => {}
    }

    // Emit cfg for environment (gnu, musl, msvc)
    match target_env.as_str() {
        "gnu" => println!("cargo:rustc-cfg=tcc_target_env_gnu"),
        "musl" => println!("cargo:rustc-cfg=tcc_target_env_musl"),
        "msvc" => println!("cargo:rustc-cfg=tcc_target_env_msvc"),
        _ => {}
    }

    // Detect pointer width for portability
    let pointer_width = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();
    if pointer_width == "64" {
        println!("cargo:rustc-cfg=tcc_ptr_size_8");
    } else if pointer_width == "32" {
        println!("cargo:rustc-cfg=tcc_ptr_size_4");
    }

    // Re-run if target changes
    println!("cargo:rerun-if-changed=build.rs");
}
