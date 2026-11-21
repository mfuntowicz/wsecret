//! Quick Access benchmark harness: perf-corpus generation and
//! unlock + names-only index timing (fixtures/quick-access/bench-budgets.json
//! rows `corpus` and `unlock-index`).
//!
//! Usage:
//!
//! ```text
//! cargo run -p wsecret-core --example quick_access_bench -- corpus <store-path>
//! cargo run -p wsecret-core --example quick_access_bench -- unlock-index <store-path> <samples>
//! ```
//!
//! `corpus` creates a NEW store at `<store-path>` (fails if the file already
//! exists) with `ops_limit` 100000 and the fixed synthetic passphrase, then
//! writes exactly 10,000 synthetic text records following the
//! `perf_corpus` recipe of `fixtures/quick-access/manifest.json`:
//!
//! - 9,500 x `perf/group-<g:02d>/item-<i:05d>` — 250 groups (`g` = 0..250)
//!   of 38 items each (`i` = 0..38, restarting per group),
//! - 250 x duplicate-leaf names `perf/dup/<a>/token` (`a` = 0..250): the
//!   leaf `token` repeats across 250 distinct parent paths,
//! - 250 x deep paths `perf/deep/<d>/<d>/.../token` (`d` = 0..250): 12
//!   segments — `perf`, `deep`, nine repetitions of `<d>`, and `token`.
//!
//! On success it prints ONLY the store path and the record count (two lines,
//! no secret material).
//!
//! `unlock-index` runs `<samples>` measurement samples. Per sample it opens
//! the store under the ordinary [`Limits::default`] policy, unlocks it with
//! the fixed passphrase at the store's encoded `ops_limit` (100000 — the KDF
//! cost is never reduced for a benchmark), and builds a names-only index via
//! [`Store::scan`]. Unlock + scan are measured as one [`Instant`]; the store
//! open itself is not timed. Each sample prints exactly one
//! invariant-culture floating-point milliseconds value (`%.3f`, no unit
//! suffix) and nothing else on stdout. The session stays alive through its
//! scan and is dropped before the next sample.
//!
//! This harness stores synthetic data only (`benchmark` values). Errors go to
//! stderr as one short nonsecret line with a nonzero exit.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use wsecret_core::error::CommitFailure;
use wsecret_core::format::OPS_LIMIT_DEFAULT;
use wsecret_core::session::Session;
use wsecret_core::store::{Limits, Store};

/// Fixed synthetic passphrase (manifest `P_A`).
const PASSPHRASE: &[u8] = b"correct horse battery staple";
/// Synthetic record value: short ASCII text, no secret material.
const VALUE: &[u8] = b"benchmark";

/// `perf_corpus` recipe sizes (fixtures/quick-access/manifest.json).
const GROUPS: usize = 250;
const ITEMS_PER_GROUP: usize = 38; // 250 * 38 = 9,500 group items
const DUPS: usize = 250;
const DEEP: usize = 250;
/// Total records written by `corpus`.
const RECORDS: usize = GROUPS * ITEMS_PER_GROUP + DUPS + DEEP; // 10,000
/// Segment repetitions in a deep path: 2 (`perf`, `deep`) + 9 + 1 (`token`).
const DEEP_MIDDLE: usize = 9;

fn main() -> ExitCode {
    // §5.8: process hardening is the FIRST action — before any argument,
    // store, or session work. Fail visibly: no unprotected fallback.
    if let Err(e) = wsecret_core::windows::security::init_process_protection() {
        return fail(format!("process protection init failed: {e}"));
    }
    libhydrogen_sys::init();
    if let Err(e) = wsecret_core::session::initialize_native_memory() {
        return fail(format!("native memory init failed: {e}"));
    }
    if let Err(e) = wsecret_core::windows::security::register_discovered_threads() {
        return fail(format!("native thread registration failed: {e}"));
    }

    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, path] if cmd == "corpus" => corpus(Path::new(path)),
        [cmd, path, samples] if cmd == "unlock-index" => match samples.parse::<usize>() {
            Ok(n) if n >= 1 => unlock_index(Path::new(path), n),
            _ => return usage(),
        },
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => fail(msg),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: quick_access_bench corpus <store-path>");
    eprintln!("       quick_access_bench unlock-index <store-path> <samples>");
    ExitCode::from(2)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("quick_access_bench: {msg}");
    ExitCode::FAILURE
}

/// Short nonsecret rendering of a mutation failure (commit state + error).
fn commit_err(op: &str, f: CommitFailure) -> String {
    format!("{op} failed ({:?}): {}", f.state, f.error)
}

/// The 10,000 `perf_corpus` record names, in write order.
fn corpus_names() -> Vec<Vec<u8>> {
    let mut names = Vec::with_capacity(RECORDS);
    // 9,500 x `perf/group-<g:02d>/item-<i:05d>` (250 groups of 38 items).
    for g in 0..GROUPS {
        for i in 0..ITEMS_PER_GROUP {
            names.push(format!("perf/group-{g:02}/item-{i:05}").into_bytes());
        }
    }
    // 250 x duplicate leaf names `perf/dup/<a>/token`.
    for a in 0..DUPS {
        names.push(format!("perf/dup/{a}/token").into_bytes());
    }
    // 250 x 12-segment deep paths `perf/deep/<d>/<d>/.../token`.
    for d in 0..DEEP {
        let mut name = String::from("perf/deep");
        for _ in 0..DEEP_MIDDLE {
            name.push('/');
            name.push_str(&d.to_string());
        }
        name.push_str("/token");
        names.push(name.into_bytes());
    }
    debug_assert_eq!(names.len(), RECORDS);
    names
}

/// `corpus <store-path>`: create the store and write the perf corpus.
fn corpus(path: &Path) -> Result<(), String> {
    // Exclusive creation: an existing file fails with `StoreExists`.
    let (mut store, header, _receipt) = Store::create(path, OPS_LIMIT_DEFAULT)
        .map_err(|f| commit_err("create", f))?;
    // One unlock for generation: the KDF runs at the header's `ops_limit`
    // (100000), exactly as every later consumer of this store will pay.
    let mut pass = PASSPHRASE.to_vec();
    let session =
        Session::unlock(&header, &mut pass).map_err(|e| format!("unlock: {e}"))?;

    let names = corpus_names();
    for name in &names {
        store
            .append_or_reuse(None, &session, name, VALUE)
            .map_err(|f| commit_err("append", f))?;
    }

    // Only the store path and the record count — no secret material.
    println!("{}", path.display());
    println!("{}", names.len());
    Ok(())
}

/// `unlock-index <store-path> <samples>`: time unlock + names-only index
/// build, one invariant-culture milliseconds sample per stdout line.
fn unlock_index(path: &Path, samples: usize) -> Result<(), String> {
    for _ in 0..samples {
        // Fresh handle per sample, ordinary open policy.
        let (mut store, header) = Store::open_with_limits(path, Limits::default())
            .map_err(|e| format!("open: {e}"))?;
        // `unlock` zeroizes its passphrase buffer, so each sample gets one.
        let mut pass = PASSPHRASE.to_vec();
        let start = Instant::now();
        let session =
            Session::unlock(&header, &mut pass).map_err(|e| format!("unlock: {e}"))?;
        let _index = store
            .scan(&session, None)
            .map_err(|e| format!("scan: {e}"))?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        // The session stays alive through its scan; drop it before the next
        // sample so no session spans two measurements.
        drop(session);
        // Rust float formatting is locale-invariant (`.` decimal separator).
        println!("{ms:.3}");
    }
    Ok(())
}
