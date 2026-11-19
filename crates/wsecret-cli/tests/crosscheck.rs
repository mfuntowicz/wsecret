//! Byte-exact cross-check of `wsecret` against the fixture stores and the
//! real pinned upstream tool (plan §7.2/§7.3 rows C1/C3/C11/C15 + the §4
//! overrides).
//!
//! Surface (every check runs the REAL `wsecret.exe` binary):
//!
//! 1. `dump mykey` → exactly the 32 bytes `00..1f`, no trailing newline
//!    when piped; `dump test` → `hello\n` (6 bytes).
//! 2. `list` + `P_A` → exactly the P_A names in file order; + `P_B` → only
//!    the P_B names; wrong passphrase → empty stdout, exit 0.
//! 3. `show test` on a console → `hello` + terminal newline (the stored
//!    `hello\n` PLUS one terminal LF: two newline advances on screen);
//!    piped → `hello\n` (6 bytes, nothing added).
//! 4. `show mykey` on a console → Base64 + terminal newline; piped → the
//!    raw 32 bytes.
//! 5. `dump test/totp` → the raw 20-byte key (no TOTP transform).
//! 6. `show test/totp` → 6 digits = HOTP(`12345678901234567890`,
//!    `unix_now/30`), equal to the pinned upstream `show` in the same 30 s
//!    window (boundary-retry loop).
//! 7. `show test/totp32` → 6 digits = HOTP of the base32-decoded key.
//! 8. Mutation under `P_A` (`update test` through the real CLI) preserves
//!    every other 512-byte block — and thus the P_B slots — byte-identically
//!    (sha256 per block before/after); P_B still lists/reads afterwards.
//!
//! Oracles: RFC 4226 KATs and a BCrypt HMAC-SHA1 implementation pin the
//! HOTP oracle itself; the Linux-origin fixture was generated AND
//! self-checked record-by-record by the pinned upstream binary
//! (`fixtures/tools/linux_oracle.py`, manifest in `fixtures/MANIFEST.md`).
//!
//! Console runs use a real console (hidden screen buffer, passphrase typed
//! through the console input path — the production `CONIN$` prompt). Piped
//! runs redirect stdout to a file: exact `WriteFile` bytes.

mod harness;

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use harness::{
    base32_decode, blocks, is_console_handle, linux_origin_fixture, oracle_hotp, run_wsecret,
    run_wsecret_lines_env, sha256, slot_of, standin_fixtures, temp_store, upstream_show,
    ChildStdout, ConsoleSession, BASE64_MYKEY, LIST_A, LIST_B, PASS_A, PASS_B, PASS_WRONG,
    VALUE_B1, VALUE_B2, VALUE_B3, VALUE_MYKEY, VALUE_TOMBSTONE, VALUE_TOTP, VALUE_TOTP32,
    VALUE_TEST,
};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Fresh copy of `source` under the per-test temp path.
fn fresh_copy(tag: &str, source: &Path) -> std::path::PathBuf {
    let dest = temp_store(tag);
    let _ = fs::remove_file(&dest);
    fs::copy(source, &dest).expect("copy fixture");
    dest
}

/// The fixture matrix: the REAL upstream-origin store (Linux, pinned
/// upstream binary) plus the wsecret-generated stand-ins of the canonical
/// corpus — all carrying the same record content:
/// `[test, mykey, test/totp, test/totp32, DELETED:test]` (P_A, file order)
/// and `[b1, b2, b3]` (P_B).
fn stores() -> Vec<(String, std::path::PathBuf)> {
    let mut out = vec![("upstream-linux-origin".to_string(), linux_origin_fixture())];
    out.extend(standin_fixtures());
    out
}

// ---------------------------------------------------------------------------
// 1. dump: byte-exact values, no added newline when piped
// ---------------------------------------------------------------------------

#[test]
fn dump_mykey_is_exactly_the_32_bytes_piped() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("dump-mykey-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("dump-mykey-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["dump", "mykey"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            VALUE_MYKEY,
            "{tag}: dump mykey bytes\n got: {:02x?}\nwant: {:02x?}",
            run.stdout,
            VALUE_MYKEY
        );
        assert_eq!(run.stdout.len(), 32, "{tag}: no trailing newline when piped");
    }
}

#[test]
fn dump_test_is_six_bytes_hello_lf_piped() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("dump-test-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("dump-test-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["dump", "test"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            VALUE_TEST,
            "{tag}: dump test bytes\n got: {:?}\nwant: {:?}",
            run.stdout,
            VALUE_TEST
        );
        assert_eq!(run.stdout.len(), 6, "{tag}: exactly six bytes");
    }
}

// ---------------------------------------------------------------------------
// 2. list: file order per partition, wrong passphrase silent
// ---------------------------------------------------------------------------

#[test]
fn list_pa_prints_exactly_the_pa_names_in_file_order() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("list-a-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("list-a-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["list"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            LIST_A,
            "{tag}: list + P_A\n got: {:?}\nwant: {:?}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(LIST_A)
        );
    }
}

#[test]
fn list_pb_prints_only_the_pb_names() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("list-b-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("list-b-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["list"],
            std::str::from_utf8(PASS_B).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            LIST_B,
            "{tag}: list + P_B\n got: {:?}\nwant: {:?}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(LIST_B)
        );
        for name in ["test", "mykey", "test/totp", "test/totp32", "DELETED:test"] {
            assert!(
                !String::from_utf8_lossy(&run.stdout).contains(name),
                "{tag}: P_A name {name} leaked into P_B listing"
            );
        }
    }
}

#[test]
fn list_wrong_passphrase_prints_nothing_and_exits_zero() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("list-wrong-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("list-wrong-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["list"],
            std::str::from_utf8(PASS_WRONG).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: wrong passphrase must exit 0, got {}", run.code);
        assert!(
            run.stdout.is_empty(),
            "{tag}: wrong passphrase must print nothing, got {:?}",
            String::from_utf8_lossy(&run.stdout)
        );
    }
}

// ---------------------------------------------------------------------------
// 3. show test: console = value + terminal newline; piped = exact 6 bytes
// ---------------------------------------------------------------------------

#[test]
fn show_test_piped_is_exactly_hello_lf() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("show-test-pipe-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("show-test-pipe-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["show", "test"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            VALUE_TEST,
            "{tag}: show test piped\n got: {:?}\nwant: {:?}",
            run.stdout,
            VALUE_TEST
        );
        assert_eq!(run.stdout.len(), 6, "{tag}: piped adds no newline");
    }
}

#[test]
fn show_test_console_is_value_plus_terminal_newline() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("show-test-con-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        assert!(
            is_console_handle(session.hidden()),
            "{tag}: precondition — the run must be on a real console"
        );
        let run = run_wsecret(
            &session,
            &store,
            &["show", "test"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::Console,
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        let (rows, cursor_y) = session.read_screen();
        // Console accounting (probe-verified production behavior):
        // - the prompt row `Passphrase: `;
        // - ONE blank row: the prompt region advances twice — the Enter that
        //   submits the passphrase (Windows console line-input) plus the
        //   upstream-parity `"\n"` wsecret writes after the read
        //   (`s_input`, secret.c) — so the command's output starts on row 2;
        // - the value's first 5 bytes `hello` (the stored value is `hello\n`);
        // - the value's own LF and the terminal newline (`isatty(1)` path,
        //   plan §4: 7 bytes `hello`, LF, LF) advance exactly twice more.
        assert_eq!(
            rows,
            vec!["Passphrase:".to_string(), String::new(), "hello".to_string()],
            "{tag}: console rendering of show test (rows {:?})",
            rows
        );
        let hello_row = rows.iter().position(|r| r == "hello").expect("hello row") as i16;
        assert_eq!(
            cursor_y - hello_row,
            2,
            "{tag}: `hello` must be followed by exactly TWO newline advances \
             (the stored LF + the terminal LF)"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. show mykey: console = Base64 + newline; piped = raw 32 bytes
// ---------------------------------------------------------------------------

#[test]
fn show_mykey_piped_is_raw_32_bytes() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("show-mykey-pipe-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("show-mykey-pipe-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["show", "mykey"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(run.stdout, VALUE_MYKEY, "{tag}: show mykey piped must be raw bytes");
        assert_eq!(run.stdout.len(), 32, "{tag}: raw length");
    }
}

#[test]
fn show_mykey_console_is_base64_plus_newline() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("show-mykey-con-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        assert!(
            is_console_handle(session.hidden()),
            "{tag}: precondition — the run must be on a real console"
        );
        let run = run_wsecret(
            &session,
            &store,
            &["show", "mykey"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::Console,
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        let (rows, cursor_y) = session.read_screen();
        // Prompt row, the prompt region's advance row (see the show-test
        // test), then the Base64 line; exactly one terminal newline follows
        // (the binary value is not printable → Base64 + `isatty(1)` LF).
        assert_eq!(
            rows,
            vec![
                "Passphrase:".to_string(),
                String::new(),
                String::from_utf8(BASE64_MYKEY.to_vec()).unwrap()
            ],
            "{tag}: console rendering of show mykey (rows {:?})",
            rows
        );
        let b64_row = rows
            .iter()
            .position(|r| r.as_bytes() == BASE64_MYKEY)
            .expect("base64 row") as i16;
        assert_eq!(
            cursor_y - b64_row,
            1,
            "{tag}: the Base64 line must be followed by exactly ONE terminal newline"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. dump test/totp: the raw key, no TOTP transform
// ---------------------------------------------------------------------------

#[test]
fn dump_totp_is_the_raw_20_byte_key() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("dump-totp-{tag}"), fixture);
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("dump-totp-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["dump", "test/totp"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: exit {}", run.code);
        assert_eq!(
            run.stdout,
            VALUE_TOTP,
            "{tag}: dump test/totp must bypass TOTP and return the raw key\n got: {:?}\nwant: {:?}",
            run.stdout,
            VALUE_TOTP
        );
        assert_eq!(run.stdout.len(), 20, "{tag}: raw key length");
    }
}

// ---------------------------------------------------------------------------
// 6. show test/totp: 6 digits = HOTP(key, now/30), == upstream in-window
// ---------------------------------------------------------------------------

#[test]
fn show_totp_six_digits_match_oracle_and_upstream_same_window() {
    let store = fresh_copy("show-totp", &linux_origin_fixture());
    let session = ConsoleSession::new();
    session.reset();
    let out = temp_store("show-totp-out");

    // Boundary-retry (MiMo §4: TOTP comparisons pin the 30 s window): the
    // window must be stable across the wsecret run AND the upstream run.
    let mut last: Option<(Vec<u8>, Vec<u8>, u64, u64)> = None;
    for _ in 0..5 {
        let t0 = unix_now();
        let run = run_wsecret(
            &session,
            &store,
            &["show", "test/totp"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "exit {}", run.code);
        let upstream = upstream_show("test/totp")
            .expect("WSL upstream oracle unavailable — this check requires the pinned upstream tool");
        let t1 = unix_now();
        if t0 / 30 != t1 / 30 {
            last = Some((run.stdout, upstream, t0, t1));
            continue;
        }
        assert_eq!(
            run.stdout.len(),
            6,
            "show test/totp must emit exactly 6 bytes, got {:?}",
            String::from_utf8_lossy(&run.stdout)
        );
        let want = oracle_hotp(VALUE_TOTP, t0 / 30);
        assert_eq!(
            run.stdout,
            want,
            "TOTP digits disagree with the BCrypt RFC 4226 oracle (counter {})",
            t0 / 30
        );
        assert_eq!(
            run.stdout,
            upstream,
            "TOTP digits disagree with pinned upstream `show` in the same 30 s window (counter {})\n wsecret: {:?}\nupstream: {:?}",
            t0 / 30,
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&upstream)
        );
        return;
    }
    panic!(
        "TOTP window boundary hit on 5 consecutive attempts; last run {:?}",
        last.map(|(w, u, t0, t1)| (
            String::from_utf8_lossy(&w).into_owned(),
            String::from_utf8_lossy(&u).into_owned(),
            t0,
            t1
        ))
    );
}

#[test]
fn show_totp_matches_rfc4226_known_answers() {
    // The HOTP oracle itself is pinned to RFC 4226 Appendix D (C = 0..9).
    const VECTORS: [&str; 10] = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, want) in VECTORS.iter().enumerate() {
        let got = oracle_hotp(VALUE_TOTP, counter as u64);
        assert_eq!(
            std::str::from_utf8(&got).unwrap(),
            *want,
            "RFC 4226 vector C={counter}"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. show test/totp32: HOTP after base32 decode of the stored value
// ---------------------------------------------------------------------------

#[test]
fn show_totp32_six_digits_match_base32_decoded_key_oracle() {
    let decoded = base32_decode(VALUE_TOTP32);
    assert_eq!(decoded, VALUE_TOTP, "the base32 fixture value decodes to the RFC 4226 key");

    let store = fresh_copy("show-totp32", &linux_origin_fixture());
    let session = ConsoleSession::new();
    session.reset();
    let out = temp_store("show-totp32-out");

    let mut last_window = 0u64;
    for _ in 0..5 {
        let t0 = unix_now();
        let run = run_wsecret(
            &session,
            &store,
            &["show", "test/totp32"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "exit {}", run.code);
        let t1 = unix_now();
        if t0 / 30 != t1 / 30 {
            last_window = t0 / 30;
            continue;
        }
        assert_eq!(run.stdout.len(), 6, "show test/totp32 must emit exactly 6 bytes");
        let want = oracle_hotp(&decoded, t0 / 30);
        assert_eq!(
            run.stdout,
            want,
            "totp32 digits disagree with the BCrypt oracle over the base32-decoded key (counter {})",
            t0 / 30
        );
        return;
    }
    panic!("TOTP window boundary hit on 5 consecutive attempts (last counter {last_window})");
}

// ---------------------------------------------------------------------------
// 8. mutation under P_A preserves every other block (P_B slots byte-identical)
// ---------------------------------------------------------------------------

#[test]
fn mutation_under_pa_preserves_pb_slots_byte_identically() {
    for (tag, fixture) in &stores() {
        let store = fresh_copy(&format!("mut-{tag}"), fixture);
        let before: Vec<[u8; 32]> = blocks(&store).iter().map(|b| sha256(b)).collect();
        let pb_slots = [
            slot_of(&store, PASS_B, b"b1") / 512,
            slot_of(&store, PASS_B, b"b2") / 512,
            slot_of(&store, PASS_B, b"b3") / 512,
        ];
        let test_slot = slot_of(&store, PASS_A, b"test") / 512;
        assert_eq!(test_slot, 1, "{tag}: fixture file order — `test` is the first record");

        // Real CLI mutation under P_A: `update test` with a new value on stdin.
        let session = ConsoleSession::new();
        session.reset();
        let out = temp_store(&format!("mut-out-{tag}"));
        let run = run_wsecret(
            &session,
            &store,
            &["update", "test"],
            std::str::from_utf8(PASS_A).unwrap(),
            Some(b"updated\n"),
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: update exit {}", run.code);

        let after = blocks(&store);
        assert_eq!(after.len(), before.len(), "{tag}: no block may be added or lost");
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            let digest = sha256(a);
            if i as u64 == test_slot {
                assert_ne!(*b, digest, "{tag}: block {i} (the `test` slot) must change");
            } else {
                assert_eq!(
                    *b, digest,
                    "{tag}: block {i} must stay byte-identical across a P_A mutation \
                     (P_B slots {pb_slots:?}, digest before {b:02x?}, after {digest:02x?})"
                );
            }
        }

        // The P_B records are still readable with P_B afterwards.
        let run = run_wsecret(
            &session,
            &store,
            &["list"],
            std::str::from_utf8(PASS_B).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: list + P_B after mutation exit {}", run.code);
        assert_eq!(
            run.stdout,
            LIST_B,
            "{tag}: P_B records must survive a P_A mutation unchanged"
        );

        // ...and the mutated value reads back byte-exactly.
        let run = run_wsecret(
            &session,
            &store,
            &["dump", "test"],
            std::str::from_utf8(PASS_A).unwrap(),
            None,
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(run.code, 0, "{tag}: dump after update exit {}", run.code);
        assert_eq!(run.stdout, b"updated\n", "{tag}: dump test after update");
    }
}

// ---------------------------------------------------------------------------
// fixture self-consistency: every store carries the canonical records
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_carries_the_canonical_records() {
    let corpus = stores();
    assert!(
        corpus.len() >= 2,
        "the corpus must contain the real upstream store AND the stand-ins: {corpus:?}"
    );
    for (name, pass, want) in [
        (b"test".as_slice(), PASS_A, VALUE_TEST.to_vec()),
        (b"mykey", PASS_A, VALUE_MYKEY.to_vec()),
        (b"test/totp", PASS_A, VALUE_TOTP.to_vec()),
        (b"test/totp32", PASS_A, VALUE_TOTP32.to_vec()),
        (b"DELETED:test", PASS_A, VALUE_TOMBSTONE.to_vec()),
        (b"b1", PASS_B, VALUE_B1.to_vec()),
        (b"b2", PASS_B, VALUE_B2.to_vec()),
        (b"b3", PASS_B, VALUE_B3.to_vec()),
    ] {
        for (tag, store) in &corpus {
            let s = temp_store(&format!("consistency-{tag}"));
            let _ = fs::remove_file(&s);
            fs::copy(store, &s).expect("copy");
            let session = ConsoleSession::new();
            session.reset();
            let out = temp_store(&format!("consistency-out-{tag}"));
            let run = run_wsecret(
                &session,
                &s,
                &["dump", std::str::from_utf8(name).unwrap()],
                std::str::from_utf8(pass).unwrap(),
                None,
                ChildStdout::CaptureFile(&out),
            );
            assert_eq!(run.code, 0, "{tag}: dump {:?} exit {}", name, run.code);
            assert_eq!(run.stdout, want, "{tag}: dump {:?} bytes", name);
        }
    }
    // Same block count in every store (9 blocks: header + 8 records).
    for (tag, store) in &corpus {
        assert_eq!(blocks(store).len(), 9, "{tag}: 9 blocks (header + 8 records)");
    }
}

// ---------------------------------------------------------------------------
// intentional divergence (general `agent` removed): legacy `SECRET_AGENT`
// ---------------------------------------------------------------------------

/// One `wsecret` run whose child environment carries a legacy
/// `SECRET_AGENT` capability-handle value.
fn legacy_run(
    session: &ConsoleSession, store: &Path, args: &[&str], lines: &[&str], tag: &str,
) -> harness::Run {
    let os = std::ffi::OsStr::new("404");
    let out = temp_store(tag);
    run_wsecret_lines_env(
        session, store, args, lines, None, ChildStdout::CaptureFile(&out), &[("SECRET_AGENT", os)],
    )
}

/// A legacy `SECRET_AGENT` value is inert on every input path: no vault
/// access (completion stays silent and name-free), values stay gated behind
/// the ordinary passphrase, and `init` behaves ordinarily. The managed SSH
/// launch strips the variable from its child (pinned in `p4`/`ssh_agent`).
#[test]
fn legacy_secret_agent_cannot_bypass_ordinary_unlock() {
    let wrong = std::str::from_utf8(PASS_WRONG).unwrap();
    let session = ConsoleSession::new();
    session.reset();
    let store = fresh_copy("legacy-env", &linux_origin_fixture());

    // Completion: silent exit 0, no names (the removed capability path
    // disclosed names at exit 255 here).
    let run = legacy_run(&session, &store, &["show", "help"], &[], "legacy-env-completion");
    assert_eq!(run.code, 0, "completion must stay silent");
    assert!(run.stdout.is_empty() && run.stderr.is_empty(), "completion disclosed output");

    // Values stay gated: wrong passphrase + legacy variable discloses nothing.
    let run = legacy_run(&session, &store, &["show", "test"], &[wrong], "legacy-env-show");
    assert_eq!(run.code, 1, "wrong passphrase must fail closed");
    assert!(run.stdout.is_empty(), "secret disclosed without the passphrase");

    // `init` is inert to the variable: it behaves ordinarily.
    let fresh = temp_store("legacy-env-init");
    let _ = fs::remove_file(&fresh);
    let run = legacy_run(&session, &fresh, &["init"], &[], "legacy-env-init-out");
    assert_eq!(run.code, 0, "init must ignore legacy SECRET_AGENT");
    assert!(fresh.exists(), "init did not create the store");
}
