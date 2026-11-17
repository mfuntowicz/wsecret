//! KAT (known-answer test) runner for the pinned libhydrogen `tests/tests.c`.
//!
//! `build.rs` compiles `vendor/tests/tests.c` + `vendor/hydrogen.c` into a
//! standalone C test binary and records its absolute path in
//! `OUT_DIR/kat_exe_path.txt`. This test runs that binary and fails with its
//! verbatim stdout/stderr if it does not exit successfully.
//!
//! The upstream `tests/tests.c` covers, as fixed-vector or property
//! assertions: `hydro_hash_hash` (and streaming `hydro_hash`), `hydro_kdf_
//! derive_from_key`, `hydro_secretbox` (encrypt/decrypt/probe), `hydro_pwhash_
//! deterministic` (+ create/verify/reencrypt/upgrade/derive_static_key),
//! `hydro_random_buf_deterministic` (plus DRBG bit-balance and `hydro_random_
//! uniform`), `hydro_sign`, `hydro_kx` (N/KK/XX/NK), and core utilities
//! (`hydro_memzero`, `hydro_increment`, `hydro_equal`, `hydro_compare`,
//! `hydro_bin2hex`, `hydro_hex2bin`).

use std::path::PathBuf;
use std::process::Command;

fn kat_binary() -> Option<PathBuf> {
    let marker = PathBuf::from(env!("OUT_DIR")).join("kat_exe_path.txt");
    let contents = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", marker.display()));
    let contents = contents.trim();
    if let Some(reason) = contents.strip_prefix("skip ") {
        eprintln!("KAT harness skipped: {reason}");
        return None;
    }
    let exe = PathBuf::from(contents);
    assert!(
        exe.exists(),
        "the KAT binary is missing at {}; rebuild the crate (the build script should have produced it)",
        exe.display()
    );
    Some(exe)
}

#[test]
fn libhydrogen_upstream_kat() {
    let Some(exe) = kat_binary() else {
        // Not built for this build (cross-compilation or missing source);
        // documented skip, not a silent pass.
        return;
    };

    let out = Command::new(&exe)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", exe.display()));

    // upstream tests.c is assert()-based: a failed vector aborts with a
    // non-zero exit and a diagnostic on stderr; a full pass exits 0 with no
    // output. Print both streams verbatim either way.
    if !out.status.success() {
        eprintln!(
            "=== KAT binary exited with {} ===\n--- stdout (verbatim) ---\n{}\n--- stderr (verbatim) ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        panic!(
            "pinned libhydrogen tests/tests.c KAT FAILED (exit status {})",
            out.status
        );
    }
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "KAT binary passed but produced unexpected output:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
