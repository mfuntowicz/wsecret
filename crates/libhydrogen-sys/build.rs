//! Build glue for the pinned libhydrogen C sources, plus the known-answer-test
//! (KAT) harness build.
//!
//! 1. `vendor/hydrogen.c` is compiled into the `hydrogen` static library that
//!    the crate links.
//! 2. `vendor/tests/tests.c` — the pinned upstream `tests/tests.c`, verbatim —
//!    is compiled together with `vendor/hydrogen.c` and linked into a
//!    standalone C test binary (`hydrogen_tests.exe` on Windows). The binary is
//!    placed in the build root (next to the crate's `build/` directory and its
//!    test executables), and the Rust integration test `tests/kat.rs` runs it
//!    and asserts a zero exit status.
//!
//! The KAT binary is built only when it can be executed on this host
//! (`TARGET == HOST`, i.e. no cross-compilation); the `hydrogen` library itself
//! is compiled for the actual (possibly cross-compiled) target as usual.

use std::path::{Path, PathBuf};

fn main() {
    // The pinned sources use `#pragma comment(lib, ...)` for MSVC, which only
    // works when the C code is linked through MSVC link.exe directives; link
    // the dependency explicitly instead of relying on it.
    println!("cargo:rustc-link-lib=advapi32");
    // CryptProtectMemory/CryptUnprotectMemory (DPAPI key-at-rest encryption, §5.3) live in Crypt32.
    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rerun-if-changed=vendor");

    compile_hydrogen_library();
    build_kat_binary();
}

fn compile_hydrogen_library() {
    cc::Build::new()
        .include("vendor")
        .file("vendor/hydrogen.c")
        // `.std("c11")` is REQUIRED: MSVC defaults to C89 and the pinned C uses
        // C99 constructs. Do not force SSE2: MSVC gets the portable gimli core,
        // per implementation plan §3.2 (bit-equality with SSE2 is check K3,
        // planned — not assumed).
        .std("c11")
        .warnings(true)
        .compile("hydrogen");
}

/// Build `hydrogen_tests[.exe]` from `vendor/tests/tests.c` + `vendor/hydrogen.c`
/// and record its absolute path in `OUT_DIR/kat_exe_path.txt` for `tests/kat.rs`.
///
/// The upstream `tests.c` is unmodified and brings its own `main`, so it is
/// compiled as a separate `cc::Build` (own output directory — its objects never
/// collide with the `hydrogen` library objects) and linked directly into an
/// executable rather than archived into the linkable library. The final link is
/// driven through the same C compiler `cc` selected (cl.exe acts as the link
/// driver on MSVC, gcc/clang on GNU-like toolchains) with the exact compile
/// flags `cc` chose, so the C library and the C test binary share one CRT
/// configuration.
fn build_kat_binary() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let marker = out_dir.join("kat_exe_path.txt");

    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    if target != host {
        // Cross-compiled: the binary would not run on this host.
        write_marker(&marker, &format!("skip TARGET ({target}) != HOST ({host}); KAT binary not built"));
        println!(
            "cargo:warning=TARGET ({target}) != HOST ({host}); the libhydrogen KAT binary is not built and the KAT test is skipped"
        );
        return;
    }
    if !Path::new("vendor/tests/tests.c").exists() {
        // The crate builds and links fine without the KAT source; only the
        // harness is skipped (loudly).
        write_marker(&marker, "skip vendor/tests/tests.c is missing");
        println!("cargo:warning=vendor/tests/tests.c is missing; the libhydrogen KAT harness is skipped");
        return;
    }

    // The build root: parent of OUT_DIR (= <profile>/build/<pkg>/out). The exe
    // lands next to the crate's own test executables (<profile>/deps).
    let build_root = out_dir
        .parent()
        .and_then(Path::parent)
        .expect("OUT_DIR has the shape <profile>/build/<pkg>/out")
        .to_path_buf();
    let exe_name = if target.contains("windows") {
        "hydrogen_tests.exe"
    } else {
        "hydrogen_tests"
    };
    let exe_path = build_root.join(exe_name);

    let mut test_build = cc::Build::new();
    test_build
        .include("vendor")
        .file("vendor/tests/tests.c")
        .file("vendor/hydrogen.c")
        .std("c11")
        .warnings(true)
        .opt_level(2)
        .out_dir(out_dir.join("kat"));

    // Compile both translation units to objects (no archive: the upstream test
    // brings its own `main`, so it must never end up in the linkable `hydrogen`
    // library).
    let objects = test_build.compile_intermediates();

    // Link them into the standalone test binary with the same compiler.
    let tool = test_build.get_compiler();
    let mut cmd = tool.to_command();
    if tool.is_like_msvc() {
        // cl.exe acts as the link driver: it forwards .obj/.lib inputs to
        // link.exe. (They must be cl inputs, not after `/link`, or cl sees no
        // input filename at all.)
        cmd.arg(format!("/Fe:{}", exe_path.display()));
        for obj in &objects {
            cmd.arg(obj.as_os_str());
        }
        if target.contains("windows") {
            // Only the RtlGenRandom import is needed by the test binary; the
            // crate's Crypt32 dependency (§5.3) is Rust-side and not used here.
            cmd.arg("advapi32.lib");
        }
    } else {
        cmd.arg("-o").arg(&exe_path);
        for obj in &objects {
            cmd.arg(obj.as_os_str());
        }
        if target.contains("windows") {
            cmd.arg("-ladvapi32");
        }
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn the KAT link step ({cmd:?}): {e}"));
    if !status.success() {
        panic!("the KAT link step failed ({cmd:?}): {status}");
    }
    if !exe_path.exists() {
        panic!("the KAT link step reported success but {exe_path:?} does not exist");
    }

    write_marker(&marker, &exe_path.display().to_string());
}

fn write_marker(marker: &Path, contents: &str) {
    std::fs::write(marker, contents).unwrap_or_else(|e| {
        panic!("failed to write {}: {e}", marker.display());
    });
}
