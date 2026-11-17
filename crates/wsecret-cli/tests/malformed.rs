//! Plan §7.3 rows C9/C10 — the malformed/truncated store rejection matrix —
//! driven through the REAL `wsecret.exe` binary (console passphrase prompt,
//! byte-exact captured stdio) plus the library surface where the observable
//! is a `Result`. Every assertion renders the verbatim bytes on failure.
//!
//! Matrix (assignment "malformed/truncated store rejection matrix"):
//!
//! 1. Header cases (exact upstream messages, typos literal):
//!    version byte 1 → `Fatal: Unkown version 1`; ops_limit 9999 →
//!    `Fatal: Store opslimit is below the minimum of 10000`; 40-byte and
//!    0-byte stores → `Fatal: Unable to read <path>` (all exit 1); a
//!    512-byte store at ops_limit 10000 is ACCEPTED with zero records.
//! 2. Trailing partial blocks: a 300-byte fragment is ignored on read
//!    (upstream-exact tolerance); 513/1025-byte stores are tolerated on
//!    read and REJECTED on mutation (`MALFORMED_STORE`, plan §3.5).
//! 3. Authenticated records with an unbounded name (no NUL in the bounded
//!    data area) or an oversized `slen`: bounded rejection — no overread, no
//!    partial name/value, no mutation.
//! 4. A ciphertext block failing authentication: skipped and preserved as an
//!    opaque block, never deleted; `show K` → `Fatal: Secret K not found`.
//! 5. A duplicated record: first match wins; `list` prints the name twice.
//! 6. ops_limit = 2^64-1: upstream hangs in the KDF; the opt-in
//!    `Limits::max_opslimit` cap rejects with `Error::ResourceLimit`
//!    (RESOURCE_LIMIT = 8) BEFORE any KDF execution (timed).
//! 7. Name byte-class matrix: accept `a`, `a/b`, `héllo`, `~!@#$%^&*()`,
//!    255×`x`; reject `""`, `"a b"`, `"a\tb"`, `"a\nb"` with the exact
//!    upstream name-rule strings.
//! 8. Boundaries: name 255 accepted / 256 rejected; value `473 − len` bytes
//!    accepted / one more rejected; passphrase 127 bytes accepted / 128
//!    rejected (`Input too long!`).
//!
//! Message note (documented collapse, `main.rs` `format_message`): core
//! folds "no bounded NUL" and "oversized slen" into `MalformedRecord`, which
//! the CLI renders as `Invalid secret` — upstream would say
//! `Keys are limited to 255 bytes` for the unbounded-name case and
//! `Invalid secret` only for the oversized-slen exact-match arm.
//!
//! Runs on the x64 Windows host (native `x86_64-pc-windows-msvc`).

mod harness;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use harness::{
    run_wsecret, run_wsecret_lines, temp_store, ChildStdout, ConsoleSession, PASS_A,
};
use wsecret_core::error::Status;
use wsecret_core::format::{
    build_entry_payload, Header, BLOCK, ENTRY_DATA_LEN, ENTRY_PLAIN_LEN, NAME_MAX,
    OPS_LIMIT_DEFAULT, OPS_LIMIT_MIN, VALUE_MAX,
};
use wsecret_core::session::Session;
use wsecret_core::store::{Limits, Store};
use wsecret_core::{CommitState, Error, FormatError};

/// The fixture passphrase (same bytes as [`PASS_A`]).
const PASS_STR: &str = "correct horse battery staple";

/// Fixed fixture master key: crafted stores are fully deterministic.
const MASTER: [u8; 32] = [0x2a; 32];

/// Fast opslimit (the format floor): the KDF cost is not what these rows are
/// about.
const OPS: u64 = OPS_LIMIT_MIN;

/// A second key: records under it fail authentication under [`PASS_STR`]'s
/// session key.
const FOREIGN_KEY: [u8; 32] = [9u8; 32];

// ---------------------------------------------------------------------------
// fixture crafting (pinned libhydrogen C via FFI — the same independent
// oracle pattern as the CLI unit tests' `Oracle`; no cryptography is
// implemented in this Rust test code)
// ---------------------------------------------------------------------------

/// Upstream `s_unlock` derivation for the fixed [`MASTER`].
fn session_key(pass: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    libhydrogen_sys::pwhash_deterministic(
        &mut key,
        pass,
        &libhydrogen_sys::CTX_MASTER,
        &MASTER,
        OPS,
    );
    key
}

fn encrypt(payload: &[u8; ENTRY_PLAIN_LEN], key: &[u8; 32]) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    libhydrogen_sys::secretbox_encrypt(&mut block, payload, &libhydrogen_sys::CTX_SECRET, key);
    block
}

/// One well-formed encrypted 512-byte record block under `key`.
fn record_block(key: &[u8; 32], name: &[u8], value: &[u8]) -> [u8; BLOCK] {
    let payload = build_entry_payload(name, value).expect("valid record payload");
    encrypt(&payload, key)
}

/// An AUTHENTICATED record whose name is NOT NUL-bounded inside the
/// 474-byte data area (upstream `s_keylen` would scan past its buffer). The
/// data leads with the query prefix `poison` so an exact match is possible
/// but invalid.
fn poison_unbounded_name_block(key: &[u8; 32]) -> [u8; BLOCK] {
    let mut payload = [0u8; ENTRY_PLAIN_LEN];
    payload[0..2].copy_from_slice(&0u16.to_le_bytes());
    payload[2..2 + ENTRY_DATA_LEN].fill(b'x'); // no NUL anywhere
    payload[2..8].copy_from_slice(b"poison");
    encrypt(&payload, key)
}

/// An AUTHENTICATED record whose `slen` claims more value bytes than the
/// data area can hold (upstream `s_get_secret` fatals `Invalid secret` on
/// the exact-match arm).
fn poison_oversized_slen_block(key: &[u8; 32], name: &[u8], claimed: u16) -> [u8; BLOCK] {
    let mut payload = [0u8; ENTRY_PLAIN_LEN];
    payload[0..2].copy_from_slice(&claimed.to_le_bytes());
    let data = &mut payload[2..2 + ENTRY_DATA_LEN];
    data[..name.len()].copy_from_slice(name);
    data[name.len()] = 0;
    data[name.len() + 1..].fill(b'v'); // would-be value bytes: must not leak
    encrypt(&payload, key)
}

/// Writes a crafted store: header block + `blocks` + optional trailing
/// `tail` bytes (the trailing-partial-block cases).
fn write_store(path: &Path, blocks: &[[u8; BLOCK]], tail: &[u8]) {
    let _ = fs::remove_file(path);
    let mut bytes = Header::encode_init(MASTER, OPS).to_vec();
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    bytes.extend_from_slice(tail);
    fs::write(path, bytes).expect("write crafted store");
}

// ---------------------------------------------------------------------------
// assertion helpers (verbatim capture on failure)
// ---------------------------------------------------------------------------

/// Byte-exact assertion rendering both sides verbatim (hex + lossy text).
fn assert_bytes(what: &str, got: &[u8], want: &[u8]) {
    assert!(
        got == want,
        "{what} mismatch\n  got  ({}) = {:x?} | {}\n  want ({}) = {:x?} | {}",
        got.len(),
        got,
        String::from_utf8_lossy(got),
        want.len(),
        want,
        String::from_utf8_lossy(want),
    );
}

/// The exact `Fatal: ` line (`args::fatal_line` semantics, transcribed
/// independently: prefix, body truncated to the 256-byte buffer budget,
/// newline).
fn fatal(body: &[u8]) -> Vec<u8> {
    let budget = 256 - 7 - 1;
    let mut line = b"Fatal: ".to_vec();
    line.extend_from_slice(&body[..body.len().min(budget)]);
    line.push(b'\n');
    line
}

/// `Fatal: Unable to read <path>` for this store (upstream `s_fatal("Unable
/// to read %s", s.path)` with the path exactly as `SECRET_STORE` carries it).
fn unable_to_read(path: &Path) -> Vec<u8> {
    let mut body = b"Unable to read ".to_vec();
    body.extend_from_slice(path.as_os_str().as_encoded_bytes());
    fatal(&body)
}

/// Asserts a fatal run: exit 1 and this exact stderr line.
fn assert_fatal(run: &harness::Run, what: &str, want: &[u8]) {
    assert_eq!(
        run.code,
        1,
        "{what}: exit {} (want 1); stderr verbatim: {:?}",
        run.code,
        String::from_utf8_lossy(&run.stderr)
    );
    assert_bytes(what, &run.stderr, want);
}

// ---------------------------------------------------------------------------
// 1. Header cases — exact upstream messages
// ---------------------------------------------------------------------------

#[test]
fn header_version_1_fatals_unkown_version() {
    let store = temp_store("hdr-version");
    let mut block = Header::encode_init(MASTER, OPS);
    block[0] = 1;
    fs::write(&store, block).unwrap();

    let session = ConsoleSession::new();
    let out = temp_store("hdr-version-out");
    // The header fatal happens before any prompt: nothing is typed.
    let run = run_wsecret_lines(&session, &store, &["list"], &[], None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "version-1 fatal line", b"Fatal: Unkown version 1\n");
    assert!(run.stdout.is_empty(), "no stdout on a header fatal; got {:x?}", run.stdout);
}

#[test]
fn header_ops_limit_below_floor_fatals_minimum() {
    let store = temp_store("hdr-ops");
    fs::write(&store, Header::encode_init(MASTER, 9999)).unwrap();

    let session = ConsoleSession::new();
    let out = temp_store("hdr-ops-out");
    let run = run_wsecret_lines(&session, &store, &["list"], &[], None, ChildStdout::CaptureFile(&out));
    assert_fatal(
        &run,
        "opslimit-below-floor fatal line",
        b"Fatal: Store opslimit is below the minimum of 10000\n",
    );
    assert!(run.stdout.is_empty(), "no stdout on a header fatal; got {:x?}", run.stdout);
}

#[test]
fn store_shorter_than_one_block_fatals_unable_to_read() {
    let session = ConsoleSession::new();
    for (tag, bytes) in [("40-byte", vec![0u8; 40]), ("0-byte", Vec::new())] {
        let store = temp_store(&format!("hdr-short-{tag}"));
        fs::write(&store, &bytes).unwrap();
        let out = temp_store(&format!("hdr-short-out-{tag}"));
        let run = run_wsecret_lines(&session, &store, &["list"], &[], None, ChildStdout::CaptureFile(&out));
        assert_fatal(&run, &format!("{tag} store fatal line"), &unable_to_read(&store));
        assert!(run.stdout.is_empty(), "{tag}: no stdout; got {:x?}", run.stdout);
    }
}

#[test]
fn store_exactly_one_block_at_floor_opslimit_accepted_zero_records() {
    let store = temp_store("hdr-ok");
    fs::write(&store, Header::encode_init(MASTER, OPS_LIMIT_MIN)).unwrap();

    let session = ConsoleSession::new();
    let out = temp_store("hdr-ok-out");
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(
        run.code,
        0,
        "512-byte store at ops_limit 10000 must be accepted; stderr verbatim: {:?}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty(), "zero records: empty listing; got {:x?}", run.stdout);
    assert!(run.stderr.is_empty(), "no fatal on an accepted store; got {:x?}", run.stderr);

    // Zero records also means every lookup is upstream's not-found fatal.
    let run = run_wsecret(&session, &store, &["show", "x"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "lookup on the empty store", b"Fatal: Secret x not found\n");
}

// ---------------------------------------------------------------------------
// 2. Trailing partial blocks — read-tolerant, mutation-rejected
// ---------------------------------------------------------------------------

#[test]
fn trailing_300_byte_fragment_ignored_on_read() {
    let store = temp_store("tail-300");
    let key = session_key(PASS_A);
    write_store(
        &store,
        &[record_block(&key, b"alpha", b"one"), record_block(&key, b"beta", b"two")],
        &[0xee; 300],
    );

    let session = ConsoleSession::new();
    let out = temp_store("tail-300-out");
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list ignores the fragment", &run.stdout, b"alpha\nbeta\n");

    let run = run_wsecret(&session, &store, &["show", "beta"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("records stay readable past the fragment", &run.stdout, b"two");
}

#[test]
fn store_513_bytes_tolerated_on_read_rejected_on_mutation() {
    let store = temp_store("tail-513");
    write_store(&store, &[], &[0xee]); // header block + 1 trailing byte

    let session = ConsoleSession::new();
    let out = temp_store("tail-513-out");

    // Read tolerance: an empty listing, exit 0 (upstream-exact).
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert!(run.stdout.is_empty(), "zero records; got {:x?}", run.stdout);

    // Mutation rejection through the full CLI flow. The store is an empty
    // partition for the passphrase, so `set` runs the new-partition
    // confirmation gate: passphrase prompt + retype prompt (two typed lines).
    let before = fs::read(&store).unwrap();
    let run = run_wsecret_lines(
        &session,
        &store,
        &["set", "k"],
        &[PASS_STR, PASS_STR],
        Some(b"v"),
        ChildStdout::CaptureFile(&out),
    );
    assert_fatal(&run, "513-byte mutation fatal line", &unable_to_read(&store));
    assert_bytes("store unchanged after the rejected mutation", &fs::read(&store).unwrap(), &before);

    // Library level: `MALFORMED_STORE` (status 7), pre-write.
    let (mut st, _) = Store::open(&store).unwrap();
    let s = Session::unlock(st.header(), &mut PASS_A.to_vec()).unwrap();
    let failures = [
        st.append_or_reuse(None, &s, b"k", b"v").unwrap_err(),
        st.write_slot(BLOCK as u64, &s, b"k", b"v").unwrap_err(),
    ];
    for failure in failures {
        assert!(
            matches!(failure.error, Error::Format(FormatError::StoreLayout)),
            "want StoreLayout, got {:?}",
            failure.error
        );
        assert_eq!(failure.error.status(), Status::MalformedStore);
        assert_eq!(Status::MalformedStore.code(), 7);
        assert_eq!(failure.state, CommitState::NotCommitted);
    }
}

#[test]
fn store_1025_bytes_tolerated_on_read_rejected_on_mutation() {
    let store = temp_store("tail-1025");
    let key = session_key(PASS_A);
    write_store(&store, &[record_block(&key, b"alpha", b"one")], &[0xee]); // + 1 byte

    let session = ConsoleSession::new();
    let out = temp_store("tail-1025-out");

    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list over the 1025-byte store", &run.stdout, b"alpha\n");

    let before = fs::read(&store).unwrap();
    let run = run_wsecret(&session, &store, &["update", "alpha"], PASS_STR, Some(b"x"), ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "1025-byte mutation fatal line", &unable_to_read(&store));
    assert_bytes("store unchanged after the rejected mutation", &fs::read(&store).unwrap(), &before);

    // Library level: same rejection on the append path.
    let (mut st, _) = Store::open(&store).unwrap();
    let s = Session::unlock(st.header(), &mut PASS_A.to_vec()).unwrap();
    let failure = st.append_or_reuse(None, &s, b"new", b"v").unwrap_err();
    assert!(matches!(failure.error, Error::Format(FormatError::StoreLayout)));
    assert_eq!(failure.error.status(), Status::MalformedStore);
    assert_eq!(failure.state, CommitState::NotCommitted);
}

// ---------------------------------------------------------------------------
// 3. Authenticated records with unbounded name / oversized slen — bounded
// ---------------------------------------------------------------------------

#[test]
fn unbounded_name_record_rejects_bounded() {
    let store = temp_store("poison-nul");
    let key = session_key(PASS_A);
    write_store(
        &store,
        &[
            record_block(&key, b"alpha", b"one"),
            poison_unbounded_name_block(&key),
            record_block(&key, b"beta", b"two"),
        ],
        &[],
    );
    let before = fs::read(&store).unwrap();

    let session = ConsoleSession::new();
    let out = temp_store("poison-nul-out");

    // `list` rejects BOUNDED: fatal, no stdout at all (not even earlier
    // valid names — no partial name of the poison record can leak).
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "bounded list rejection", b"Fatal: Invalid secret\n");
    assert!(run.stdout.is_empty(), "no partial name may leak; got {:x?}", run.stdout);

    // `show` scans PAST the record without overreading it (upstream-exact:
    // the raw match compare fails — the name is not NUL-bounded at the query
    // length — so the record is never decoded).
    let run = run_wsecret(&session, &store, &["show", "poison"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "scan-past not-found", b"Fatal: Secret poison not found\n");

    // Records on both sides stay readable: no overread, no corruption.
    let run = run_wsecret(&session, &store, &["show", "beta"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("record after the poison block", &run.stdout, b"two");

    assert_bytes("store unchanged after every rejection", &fs::read(&store).unwrap(), &before);
}

#[test]
fn oversized_slen_record_rejects_bounded() {
    let store = temp_store("poison-slen");
    let key = session_key(PASS_A);
    write_store(
        &store,
        &[
            record_block(&key, b"alpha", b"one"),
            poison_oversized_slen_block(&key, b"poison", 500),
            record_block(&key, b"beta", b"two"),
        ],
        &[],
    );
    let before = fs::read(&store).unwrap();

    let session = ConsoleSession::new();
    let out = temp_store("poison-slen-out");

    // Exact match → bounded `Invalid secret` (upstream `s_get_secret`'s
    // exact-match arm fatals the same string for an out-of-bounds slen).
    let run = run_wsecret(&session, &store, &["show", "poison"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "bounded show rejection", b"Fatal: Invalid secret\n");
    assert!(run.stdout.is_empty(), "no partial value may leak; got {:x?}", run.stdout);

    // A mutation targeting the record is rejected WITHOUT any write.
    let run = run_wsecret(&session, &store, &["update", "poison"], PASS_STR, Some(b"x"), ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "bounded update rejection", b"Fatal: Invalid secret\n");

    // `list` rejects bounded too (nothing printed).
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "bounded list rejection", b"Fatal: Invalid secret\n");
    assert!(run.stdout.is_empty(), "no partial name may leak; got {:x?}", run.stdout);

    // Non-matching lookups scan past the record (upstream-exact).
    let run = run_wsecret(&session, &store, &["show", "beta"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("record after the poison block", &run.stdout, b"two");

    assert_bytes("store unchanged after every rejection", &fs::read(&store).unwrap(), &before);
}

// ---------------------------------------------------------------------------
// 4. Ciphertext block failing authentication — skipped, preserved, not found
// ---------------------------------------------------------------------------

#[test]
fn auth_failing_block_skipped_and_preserved_not_deleted() {
    let store = temp_store("auth-skip");
    let key = session_key(PASS_A);
    let foreign = record_block(&FOREIGN_KEY, b"K", b"ghost");
    write_store(
        &store,
        &[
            record_block(&key, b"keep", b"one"),
            foreign,
            record_block(&key, b"other", b"two"),
        ],
        &[],
    );

    let session = ConsoleSession::new();
    let out = temp_store("auth-skip-out");

    // Skipped silently on read: it is not a record for this passphrase.
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list skips the auth-failing block", &run.stdout, b"keep\nother\n");

    let run = run_wsecret(&session, &store, &["show", "K"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "opaque block is not a record", b"Fatal: Secret K not found\n");

    // Preserved byte-for-byte across a successful mutation — never deleted.
    let before = fs::read(&store).unwrap();
    let run = run_wsecret(&session, &store, &["set", "fresh"], PASS_STR, Some(b"new"), ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    let after = fs::read(&store).unwrap();
    assert_eq!(after.len(), before.len() + BLOCK, "exactly one appended record");
    assert_bytes(
        "auth-failing block preserved byte-for-byte",
        &after[BLOCK..2 * BLOCK],
        &before[BLOCK..2 * BLOCK],
    );

    // Still skipped after the append.
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list after the append", &run.stdout, b"keep\nother\nfresh\n");
}

// ---------------------------------------------------------------------------
// 5. Duplicated record — first match wins, listed twice
// ---------------------------------------------------------------------------

#[test]
fn duplicated_record_first_match_wins_list_prints_twice() {
    let store = temp_store("dup");
    let key = session_key(PASS_A);
    write_store(
        &store,
        &[record_block(&key, b"dup", b"first"), record_block(&key, b"dup", b"second")],
        &[],
    );

    let session = ConsoleSession::new();
    let out = temp_store("dup-out");

    let run = run_wsecret(&session, &store, &["show", "dup"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("first match wins", &run.stdout, b"first");

    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list prints the duplicate twice", &run.stdout, b"dup\ndup\n");

    // The update lands on the FIRST slot; the second block is untouched.
    let before = fs::read(&store).unwrap();
    let run = run_wsecret(&session, &store, &["update", "dup"], PASS_STR, Some(b"changed"), ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    let after = fs::read(&store).unwrap();
    assert_bytes("second duplicate block preserved", &after[2 * BLOCK..], &before[2 * BLOCK..]);

    let run = run_wsecret(&session, &store, &["show", "dup"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_bytes("updated first slot", &run.stdout, b"changed");
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_bytes("list still prints the name twice", &run.stdout, b"dup\ndup\n");
}

// ---------------------------------------------------------------------------
// 6. ops_limit = 2^64-1 — opt-in cap rejects before any KDF
// ---------------------------------------------------------------------------

#[test]
fn ops_limit_2_pow_64_1_rejected_by_the_opt_in_cap_before_any_kdf() {
    let store = temp_store("ops-max");
    fs::write(&store, Header::encode_init(MASTER, u64::MAX)).unwrap();

    // Upstream-equivalent acceptance: `s_header` only enforces the 10000
    // floor, so the header parses and the store opens. The unbounded CPU
    // cost lives in the KDF (`Session::unlock`) — upstream runs it to
    // completion at 2^64-1 ops (pins a core ~forever). The unlock is
    // deliberately NEVER called in this test.
    let block = Header::encode_init(MASTER, u64::MAX);
    let parsed = Header::parse(&block).expect("upstream accepts any ops_limit >= 10000");
    assert_eq!(parsed.ops_limit, u64::MAX);
    let (_store, header) = Store::open(&store).expect("no cap: opens like upstream");
    assert_eq!(header.ops_limit, u64::MAX);

    // With the opt-in cap (plan §3.4 limits policy, §9 blocker 9) the open
    // itself rejects BEFORE any KDF execution or store-sized allocation:
    // `Error::ResourceLimit` (RESOURCE_LIMIT = status 8), within a bounded
    // time that proves no derivation ran.
    let started = Instant::now();
    let result = Store::open_with_limits(
        &store,
        Limits {
            max_opslimit: Some(OPS_LIMIT_DEFAULT),
            max_store_bytes: None,
        },
    );
    let elapsed = started.elapsed();
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!(
            "the opt-in cap must reject ops_limit = 2^64-1 (the KDF would pin a core ~forever)"
        ),
    };
    assert!(matches!(err, Error::ResourceLimit), "want ResourceLimit, got {err:?}");
    assert_eq!(err.status(), Status::ResourceLimit);
    assert_eq!(Status::ResourceLimit.code(), 8);
    assert!(
        elapsed < Duration::from_secs(5),
        "the cap check must run pre-KDF; took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. Name byte-class matrix
// ---------------------------------------------------------------------------

#[test]
fn name_byte_class_matrix_accepts() {
    let store = temp_store("names-ok");
    let key = session_key(PASS_A);
    write_store(&store, &[record_block(&key, b"seed", b"init")], &[]);

    let session = ConsoleSession::new();
    let out = temp_store("names-ok-out");

    let name255 = "x".repeat(NAME_MAX);
    let names: &[&str] = &["a", "a/b", "héllo", "~!@#$%^&*()", name255.as_str()];
    for name in names {
        let run = run_wsecret(
            &session,
            &store,
            &["set", name],
            PASS_STR,
            Some(b"v"),
            ChildStdout::CaptureFile(&out),
        );
        assert_eq!(
            run.code,
            0,
            "set {name:?} must be accepted; stderr verbatim: {:?}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    // Every accepted name round-trips byte-exact.
    for name in names {
        let run = run_wsecret(&session, &store, &["show", name], PASS_STR, None, ChildStdout::CaptureFile(&out));
        assert_eq!(run.code, 0, "show {name:?}; stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
        assert_bytes(&format!("show {name:?}"), &run.stdout, b"v");
    }

    // `list` prints every accepted name verbatim in file order.
    let mut want = b"seed\n".to_vec();
    for name in names {
        want.extend_from_slice(name.as_bytes());
        want.push(b'\n');
    }
    let run = run_wsecret(&session, &store, &["list"], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("list of the accepted byte classes", &run.stdout, &want);
}

#[test]
fn name_byte_class_matrix_rejects() {
    let store = temp_store("names-bad");
    let key = session_key(PASS_A);
    write_store(&store, &[record_block(&key, b"seed", b"init")], &[]);

    let session = ConsoleSession::new();
    let out = temp_store("names-bad-out");
    let before = fs::read(&store).unwrap();

    let empty = b"Fatal: Empty keys are not allowed\n";
    let special = b"Fatal: Special characaters are not allowed in keys\n";

    // Empty name (raw empty operand).
    let run = run_wsecret(&session, &store, &["set", ""], PASS_STR, Some(b"v"), ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "empty name", empty);

    // Space in the name (raw operand).
    let run = run_wsecret(&session, &store, &["set", "a b"], PASS_STR, Some(b"v"), ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "space name", special);

    // Tab and newline: byte-exact delivery via `--keys-hex` (the rule under
    // test is the byte class, so the operand bytes are delivered exactly,
    // independent of command-line quoting).
    for (label, hex) in [("tab name", "610962"), ("newline name", "610a62")] {
        let run = run_wsecret(
            &session,
            &store,
            &["--keys-hex", "set", hex],
            PASS_STR,
            Some(b"v"),
            ChildStdout::CaptureFile(&out),
        );
        assert_fatal(&run, label, special);
    }

    // Bounded: no rejected name mutated the store.
    assert_bytes("store unchanged after every rejected name", &fs::read(&store).unwrap(), &before);
}

// ---------------------------------------------------------------------------
// 8. Boundary cases
// ---------------------------------------------------------------------------

#[test]
fn name_length_boundary_255_accepted_256_rejected() {
    let store = temp_store("name-len");
    let key = session_key(PASS_A);
    write_store(&store, &[record_block(&key, b"seed", b"init")], &[]);

    let session = ConsoleSession::new();
    let out = temp_store("name-len-out");

    // Exactly 255 bytes: accepted and round-trips.
    let name255 = "x".repeat(NAME_MAX);
    let run = run_wsecret(&session, &store, &["set", &name255], PASS_STR, Some(b"v"), ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "255-byte name must be accepted; stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    let run = run_wsecret(&session, &store, &["show", &name255], PASS_STR, None, ChildStdout::CaptureFile(&out));
    assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
    assert_bytes("255-byte name round-trips", &run.stdout, b"v");

    // 256 bytes: rejected with the exact upstream limit message.
    let before = fs::read(&store).unwrap();
    let name256 = "x".repeat(NAME_MAX + 1);
    let run = run_wsecret(&session, &store, &["set", &name256], PASS_STR, Some(b"v"), ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "256-byte name", b"Fatal: Keys are limited to 255 bytes\n");
    assert_bytes("store unchanged after the rejected name", &fs::read(&store).unwrap(), &before);
}

#[test]
fn value_length_boundary_473_minus_name_len() {
    let store = temp_store("value-len");
    let key = session_key(PASS_A);
    write_store(&store, &[record_block(&key, b"seed", b"init")], &[]);

    let session = ConsoleSession::new();
    let out = temp_store("value-len-out");

    // Plan §1.3: max value = 473 − name length, for any name length.
    for name in ["k", "abcd"] {
        let max = VALUE_MAX - name.len();
        let value = vec![0x41u8; max];
        let run = run_wsecret(&session, &store, &["set", name], PASS_STR, Some(value.as_slice()), ChildStdout::CaptureFile(&out));
        assert_eq!(
            run.code,
            0,
            "set {name} with {max} bytes (473 − len) must be accepted; stderr verbatim: {:?}",
            String::from_utf8_lossy(&run.stderr)
        );
        let run = run_wsecret(&session, &store, &["dump", name], PASS_STR, None, ChildStdout::CaptureFile(&out));
        assert_eq!(run.code, 0, "stderr verbatim: {:?}", String::from_utf8_lossy(&run.stderr));
        assert_bytes(&format!("dump {name} at the size bound"), &run.stdout, &value);

        // One more byte: `Entry too big!`, and the rejection writes nothing.
        let before = fs::read(&store).unwrap();
        let over = vec![0x42u8; max + 1];
        let run = run_wsecret(&session, &store, &["update", name], PASS_STR, Some(over.as_slice()), ChildStdout::CaptureFile(&out));
        assert_fatal(&run, &format!("one-over value for {name}"), b"Fatal: Entry too big!\n");
        assert_bytes("store unchanged after the rejected value", &fs::read(&store).unwrap(), &before);
    }
}

#[test]
fn passphrase_length_boundary_127_accepted_128_input_too_long() {
    let store = temp_store("pass-len");
    let _ = fs::remove_file(&store);
    // Fixture unlocked with a 127-byte passphrase. The console input cap is
    // upstream's `uint8_t pass[128]`: 127 content bytes + newline.
    let pass127 = vec![b'p'; 127];
    let (mut st, header, _) = Store::create(&store, OPS_LIMIT_MIN).expect("create fixture");
    let s = Session::unlock(&header, &mut pass127.clone()).expect("unlock with 127 bytes");
    st.append_or_reuse(None, &s, b"long", b"v").expect("append record");
    drop(s);
    drop(st);

    let session = ConsoleSession::new();
    let out = temp_store("pass-len-out");

    let line127 = "p".repeat(127);
    let run = run_wsecret(&session, &store, &["list"], &line127, None, ChildStdout::CaptureFile(&out));
    assert_eq!(
        run.code,
        0,
        "127-byte passphrase must be accepted; stderr verbatim: {:?}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_bytes("listing under the 127-byte passphrase", &run.stdout, b"long\n");

    let line128 = "p".repeat(128);
    let run = run_wsecret(&session, &store, &["list"], &line128, None, ChildStdout::CaptureFile(&out));
    assert_fatal(&run, "128-byte passphrase", b"Fatal: Input too long!\n");
}
