//! §7.4 crash-consistency rows E4, E5, E6 (plan §5.6 points 4–5 failure
//! model; §7.3 C16 family).
//!
//! Deviation note (assignment wording vs. plan §5.6, recorded in the slice
//! report): the E4/E5 bullets say "before rename … original store remains
//! complete" / "before: complete old store. After: complete new store. Never
//! a 513-byte or partially updated destination; an orphaned ciphertext temp
//! file is permitted". That is the WITHDRAWN atomic-replace model. §5.6
//! point 4 (audit P3/N1) defines the authoritative per-class outcome of the
//! in-place protocol and §7.4 explicitly says kill-mid-write is "per-class
//! outcomes, NOT 'complete old/new', NOT a blanket 'still scannable' claim":
//!
//! - **Overwrite** (replacing an existing 512-byte slot): a crash mid-write
//!   can tear exactly that record; the file length stays 512-aligned; scans
//!   (wsecret AND upstream) skip the torn record.
//! - **Append**: a crash after k bytes (0<k<512) leaves a `512N+k` suffix
//!   (the "orphaned ciphertext" — inside the store, not a temp file: the
//!   in-place protocol creates NO temporary files at all, asserted here as
//!   strictly stronger than "temp file removed/permitted"). Readers tolerate
//!   it; the next mutation REJECTS the store (`MALFORMED_STORE`) until the
//!   suffix is removed — the "reported" aftermath.
//! - **Initialization**: a partial header write leaves an unreadable store.
//!
//! These tests assert exactly those classes, plus the two properties the
//! in-place protocol DOES guarantee and the assignment's wording shares:
//! kills before write initiation leave the store byte-identical ("complete
//! old store"), kills after the flush leave a complete new store, overwrite
//! kills never change the file length (never "513 bytes"), and every
//! unaffected record stays byte-exact and readable by the pinned upstream
//! binary. Durability across POWER LOSS is never claimed: a process kill
//! lets the OS write back the page cache (asserted as visibility), which is
//! a strictly weaker statement.
//!
//! E6 repeats the E4/E5 subset per filesystem and records per-filesystem
//! evidence; filesystems absent from this host are recorded as NO EVIDENCE
//! (no generic power-loss/durability claim is made for them).

mod support;

use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use support::{
    PASS_A, file_hash, file_len, probe_write, temp_dir, unlock, upstream_dump, value_of,
};
use wsecret_core::error::{Status, WARN_ABANDONED_MUTEX};
use wsecret_core::format::OPS_LIMIT_MIN;
use wsecret_core::session::Session;
use wsecret_core::store::Store;
use wsecret_core::{CommitState, Error};

const KILL_EXIT: i32 = 0xE5;
const STATUS_IO: u32 = Status::Io as u32; // 17
const STATUS_MALFORMED: u32 = Status::MalformedStore as u32; // 7
const STATE_UNKNOWN: u32 = CommitState::Unknown as u32;

const KEEP: (&[u8], &[u8]) = (b"keep", b"KEEP-ORIG\n");
const OTHER: (&[u8], &[u8]) = (b"other", b"OTHER-ORIG\n");
const THIRD: (&[u8], &[u8]) = (b"third", b"THIRD-ORIG\n");
/// Seed store: header + 3 records = 4 blocks = 2048 bytes.
const SEED_LEN: u64 = 4 * 512;

/// Creates a fresh store directory with the three seed records under
/// [`PASS_A`] and returns its path.
fn seed(tag: &str) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    let path = dir.join("store.secret");
    let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
    let mut pass = PASS_A.to_vec();
    let session = Session::unlock(&header, &mut pass).expect("unlock");
    for (name, value) in [KEEP, OTHER, THIRD] {
        store
            .append_or_reuse(None, &session, name, value)
            .expect("seed record");
    }
    drop(store);
    (dir, path)
}

/// Runs a `kill <point>` probe write and asserts the process died at the
/// seam (exit [`KILL_EXIT`]).
fn kill_write(path: &Path, name: &[u8], value: &[u8], point: &str) {
    let run = probe_write(
        path,
        PASS_A,
        name,
        value,
        &[String::from("kill"), String::from(point)],
    );
    assert_eq!(
        run.code, KILL_EXIT as u32,
        "probe must be killed at the seam: {run:?}"
    );
}

/// Asserts the store directory holds only the store file (the in-place
/// protocol creates no temporary files — E5's "orphaned temp file" cannot
/// occur and is not merely tolerated).
fn assert_no_stray_files(dir: &Path, store_name: &str) {
    let mut entries: Vec<String> = fs::read_dir(dir)
        .expect("list dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec![store_name.to_string()], "no stray files");
}

// ---------------------------------------------------------------------------
// E4 — injected short write and flush failure
// ---------------------------------------------------------------------------

/// E4 (overwrite class): an injected short write tears ONLY the target slot.
/// Nonzero error, `IO`/`Unknown`; file length stays 512-aligned (never 513);
/// every other record keeps its exact ciphertext and stays readable by the
/// pinned upstream binary; the torn slot is skipped by readers.
#[test]
fn e4_short_write_overwrite_tears_only_the_target_slot() {
    let (dir, path) = seed("e4-ow");
    let before = file_hash(&path);

    let run = probe_write(
        &path,
        PASS_A,
        KEEP.0,
        b"KEEP-NEW\n",
        &[
            String::from("fault"),
            String::from("mid"),
            String::from("short"),
        ],
    );
    assert_eq!(run.code, 2, "short write must fail the mutation: {run:?}");
    assert_eq!(run.status, STATUS_IO, "{run:?}");
    assert_eq!(run.state, STATE_UNKNOWN, "{run:?}");

    // Overwrite class: length unchanged and 512-aligned (§5.6 point 4).
    assert_eq!(file_len(&path), SEED_LEN);
    assert_ne!(
        file_hash(&path),
        before,
        "the target slot was partially written"
    );

    let (mut store, session) = unlock(&path, PASS_A);
    assert!(
        value_of(&mut store, &session, KEEP.0).is_none(),
        "the torn record is skipped by scans"
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    assert_eq!(
        value_of(&mut store, &session, THIRD.0).unwrap().as_slice(),
        THIRD.1
    );
    drop(store);
    drop(session);

    // Readable by upstream: the unaffected records byte-exact, the torn
    // slot reported not-found (its scan skips it too).
    assert_eq!(upstream_dump(&path, OTHER.0, PASS_A).unwrap(), OTHER.1);
    assert_eq!(upstream_dump(&path, THIRD.0, PASS_A).unwrap(), THIRD.1);
    assert!(
        upstream_dump(&path, KEEP.0, PASS_A).is_err(),
        "torn record is gone upstream too"
    );

    assert_no_stray_files(&dir, "store.secret");
}

/// E4 (append class): an injected short write leaves a `512N+256` suffix.
/// Nonzero error, `IO`/`Unknown`; every original record is intact and
/// upstream-readable; readers tolerate the suffix; the next mutation
/// REJECTS the store (`MALFORMED_STORE`) until the suffix is removed.
#[test]
fn e4_short_write_append_leaves_a_tolerated_suffix() {
    let (dir, path) = seed("e4-app");

    let run = probe_write(
        &path,
        PASS_A,
        b"new",
        b"NEW-VAL\n",
        &[
            String::from("fault"),
            String::from("mid"),
            String::from("short"),
        ],
    );
    assert_eq!(run.code, 2, "short write must fail the mutation: {run:?}");
    assert_eq!(run.status, STATUS_IO, "{run:?}");
    assert_eq!(run.state, STATE_UNKNOWN, "{run:?}");

    // Append class (§5.6 point 4): a 512N+k suffix, k = 256.
    assert_eq!(file_len(&path), SEED_LEN + 256);

    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
        KEEP.1
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    assert_eq!(
        value_of(&mut store, &session, THIRD.0).unwrap().as_slice(),
        THIRD.1
    );
    // Reader tolerance: the partial block is ignored, `new` is lost.
    assert!(value_of(&mut store, &session, b"new").is_none());
    // The next mutation rejects the non-512-multiple length.
    let failure = store
        .append_or_reuse(None, &session, b"after", b"x")
        .err()
        .expect("mutation must reject the suffix");
    assert!(
        matches!(failure.error, Error::Format(_)),
        "must be MALFORMED_STORE: {:?}",
        failure.error
    );
    assert_eq!(failure.status() as u32, STATUS_MALFORMED);
    assert_eq!(failure.state, CommitState::NotCommitted);
    drop(store);
    drop(session);

    // Upstream reads the original records and tolerates the suffix too.
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), KEEP.1);
    assert_eq!(upstream_dump(&path, OTHER.0, PASS_A).unwrap(), OTHER.1);

    // Removing the trailing suffix (a user decision, no automatic repair)
    // makes the store mutable again.
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(SEED_LEN)
        .unwrap();
    let (mut store, session) = unlock(&path, PASS_A);
    let receipt = store
        .append_or_reuse(None, &session, b"after", b"x")
        .expect("mutation works after the suffix is removed");
    assert_eq!(receipt.state, CommitState::Committed);

    assert_no_stray_files(&dir, "store.secret");
}

/// E4 (flush failure): the 512-byte write completed but the flush failed →
/// `IO`/`Unknown` (§5.6 point 5 row "INCLUDING flush returning zero"). The
/// record bytes are in the page cache: the new value is VISIBLE (asserted);
/// durability after a crash is filesystem-dependent and NOT claimed.
#[test]
fn e4_flush_failure_reports_unknown_with_visible_write() {
    let (dir, path) = seed("e4-flush");

    let run = probe_write(
        &path,
        PASS_A,
        KEEP.0,
        b"KEEP-NEW\n",
        &[
            String::from("fault"),
            String::from("after"),
            String::from("io"),
        ],
    );
    assert_eq!(run.code, 2, "flush failure must fail the mutation: {run:?}");
    assert_eq!(run.status, STATUS_IO, "{run:?}");
    assert_eq!(run.state, STATE_UNKNOWN, "{run:?}");

    // The write landed: complete store, new record visible.
    assert_eq!(file_len(&path), SEED_LEN);
    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
        b"KEEP-NEW\n"
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), b"KEEP-NEW\n");
    assert_eq!(upstream_dump(&path, THIRD.0, PASS_A).unwrap(), THIRD.1);

    assert_no_stray_files(&dir, "store.secret");
}

// ---------------------------------------------------------------------------
// E5 — hard kills at each injected point
// ---------------------------------------------------------------------------

/// E5 (kill before write initiation): the store is BYTE-IDENTICAL — the
/// "complete old store" property — and upstream reads every record. The
/// killer died holding the writer mutex: the next writer proceeds WITHOUT
/// an integrity claim (`WAIT_ABANDONED`, warning bit 2, §5.6 point 1).
#[test]
fn e5_kill_before_write_leaves_the_complete_old_store() {
    let (dir, path) = seed("e5-before");
    let before = file_hash(&path);
    // A second writer's handle keeps the mutex object alive across the kill
    // so the abandoned ownership is observable (Windows semantics).
    let _mutex_alive = support::keep_mutex_alive(&path);

    kill_write(&path, KEEP.0, b"KEEP-NEW\n", "before");

    assert_eq!(file_hash(&path), before, "store must be byte-identical");
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), KEEP.1);
    assert_eq!(upstream_dump(&path, OTHER.0, PASS_A).unwrap(), OTHER.1);

    // The abandoned mutex is reported to the next writer (warning bit 2).
    let (mut store, session) = unlock(&path, PASS_A);
    let receipt = store
        .append_or_reuse(None, &session, b"after", b"x")
        .expect("next writer proceeds");
    assert_eq!(receipt.state, CommitState::Committed);
    assert_ne!(
        receipt.warnings & WARN_ABANDONED_MUTEX,
        0,
        "WAIT_ABANDONED must be reported: {receipt:?}"
    );

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (kill mid-write, overwrite class): the file length stays 512-aligned
/// — the destination is never "513 bytes" — and only the target slot is
/// torn (per-class outcome of §5.6 point 4; "complete old store" cannot
/// hold mid-write under the in-place protocol — deviation noted above).
#[test]
fn e5_kill_mid_write_overwrite_keeps_length_aligned() {
    let (dir, path) = seed("e5-mid-ow");

    kill_write(&path, KEEP.0, b"KEEP-NEW\n", "mid");

    assert_eq!(file_len(&path) % 512, 0, "length stays 512-aligned");
    assert_eq!(file_len(&path), SEED_LEN);
    let (mut store, session) = unlock(&path, PASS_A);
    assert!(
        value_of(&mut store, &session, KEEP.0).is_none(),
        "torn slot skipped"
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    assert_eq!(
        value_of(&mut store, &session, THIRD.0).unwrap().as_slice(),
        THIRD.1
    );
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, OTHER.0, PASS_A).unwrap(), OTHER.1);
    assert!(upstream_dump(&path, KEEP.0, PASS_A).is_err());

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (kill mid-write, append class): a `512N+256` suffix (the orphaned
/// ciphertext fragment lives INSIDE the store — no temp file exists); all
/// original records stay intact and upstream-readable; the next mutation
/// rejects the store until the suffix is removed (the "reported" aftermath).
#[test]
fn e5_kill_mid_write_append_leaves_an_orphaned_suffix() {
    let (dir, path) = seed("e5-mid-app");

    kill_write(&path, b"new", b"NEW-VAL\n", "mid");

    assert_eq!(file_len(&path), SEED_LEN + 256);
    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
        KEEP.1
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    assert_eq!(
        value_of(&mut store, &session, THIRD.0).unwrap().as_slice(),
        THIRD.1
    );
    let failure = store
        .append_or_reuse(None, &session, b"after", b"x")
        .err()
        .expect("mutation must reject the orphaned suffix");
    assert!(
        matches!(failure.error, Error::Format(_)),
        "must be MALFORMED_STORE: {:?}",
        failure.error
    );
    assert_eq!(failure.status() as u32, STATUS_MALFORMED);
    assert_eq!(failure.state, CommitState::NotCommitted);
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), KEEP.1);

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (kill after the completed write, before the flush, overwrite class):
/// the complete NEW record is visible (process death lets the OS write the
/// page cache back — visibility asserted, power-loss durability NOT
/// claimed). Length stays 512-aligned.
#[test]
fn e5_kill_after_write_before_flush_sees_the_new_record() {
    let (dir, path) = seed("e5-after-ow");

    kill_write(&path, KEEP.0, b"KEEP-NEW\n", "after");

    assert_eq!(file_len(&path), SEED_LEN);
    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
        b"KEEP-NEW\n"
    );
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), b"KEEP-NEW\n");
    assert_eq!(upstream_dump(&path, THIRD.0, PASS_A).unwrap(), THIRD.1);

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (kill after the completed write, before the flush, append class): the
/// file holds the complete new record (`512N+512`), readable in-process and
/// upstream.
#[test]
fn e5_kill_after_write_append_lands_the_complete_record() {
    let (dir, path) = seed("e5-after-app");

    kill_write(&path, b"new", b"NEW-VAL\n", "after");

    assert_eq!(file_len(&path), SEED_LEN + 512);
    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, b"new").unwrap().as_slice(),
        b"NEW-VAL\n"
    );
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, b"new", PASS_A).unwrap(), b"NEW-VAL\n");
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), KEEP.1);

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (kill after the flush): the complete NEW store — every record
/// byte-exact and upstream-readable.
#[test]
fn e5_kill_after_flush_leaves_the_complete_new_store() {
    let (dir, path) = seed("e5-post");

    kill_write(&path, KEEP.0, b"KEEP-NEW\n", "post");

    assert_eq!(file_len(&path), SEED_LEN);
    let (mut store, session) = unlock(&path, PASS_A);
    assert_eq!(
        value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
        b"KEEP-NEW\n"
    );
    assert_eq!(
        value_of(&mut store, &session, OTHER.0).unwrap().as_slice(),
        OTHER.1
    );
    drop(store);
    drop(session);
    assert_eq!(upstream_dump(&path, KEEP.0, PASS_A).unwrap(), b"KEEP-NEW\n");
    assert_eq!(upstream_dump(&path, OTHER.0, PASS_A).unwrap(), OTHER.1);
    assert_eq!(upstream_dump(&path, THIRD.0, PASS_A).unwrap(), THIRD.1);

    assert_no_stray_files(&dir, "store.secret");
}

/// E5 (init class): kills at each point of `init`'s header write leave the
/// §5.6 point 4 "Initialization" states: nothing/`k`-byte file is an
/// unreadable store (the user deletes/retries; no recovery claim), a kill
/// after the completed header write leaves a complete readable store.
#[test]
fn e5_kill_during_init_matches_the_initialization_class() {
    for point in ["before", "mid", "after", "post"] {
        let dir = temp_dir(&format!("e5-init-{point}"));
        let path = dir.join("store.secret");
        let run = probe_write_create(&path, point);
        assert_eq!(run, KILL_EXIT as u32, "init must be killed at {point}");
        let len = file_len(&path);
        match point {
            "before" => assert_eq!(len, 0, "no header written"),
            "mid" => assert_eq!(len, 256, "partial header block"),
            "after" | "post" => assert_eq!(len, 512, "complete header block"),
            _ => unreachable!(),
        }
        // Unreadable until the header block is complete (§5.6 point 4).
        let opened = Store::open(&path);
        if len == 512 {
            opened.expect("complete header is a readable store");
        } else {
            assert!(opened.is_err(), "partial init must be unreadable");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

/// Runs `wsecret-crash-probe create <path> kill <point>` and returns the
/// process exit code.
fn probe_write_create(path: &Path, point: &str) -> u32 {
    let out = std::process::Command::new(support::probe_exe())
        .arg("create")
        .arg(path)
        .arg("kill")
        .arg(point)
        .output()
        .expect("spawn probe");
    out.status.code().expect("exit code") as u32
}

// ---------------------------------------------------------------------------
// E6 — filesystem matrix (per-filesystem evidence; absent = NO EVIDENCE)
// ---------------------------------------------------------------------------

/// One filesystem row of the E6 matrix.
struct FsRow {
    fs: String,
    volumes: Vec<String>,
    evidence: Vec<String>,
}

/// E6: repeats the E4/E5 subset (short-write append, kill-before,
/// kill-after) on every writable volume of each filesystem type present on
/// this host and records the results in `fixtures/e6-filesystem-matrix.json`.
/// Filesystems with no volume here (ReFS, FAT/exFAT) and SMB shares with no
/// provisioned share are recorded as NO EVIDENCE — no generic power-loss or
/// durability claim is made for them.
#[test]
fn e6_filesystem_matrix_records_per_filesystem_evidence() {
    let mut rows: Vec<FsRow> = Vec::new();

    for volume in volume_list() {
        let (fs_name, drive_type) = volume_info(&volume);
        let label = if drive_type == DRIVE_REMOTE {
            format!("{volume} (remote)")
        } else {
            volume.clone()
        };
        if !rows.iter().any(|r| r.fs == fs_name) {
            rows.push(FsRow {
                fs: fs_name.clone(),
                volumes: Vec::new(),
                evidence: Vec::new(),
            });
        }
        let row = rows.iter_mut().find(|r| r.fs == fs_name).unwrap();
        row.volumes.push(label.clone());

        // A writable test directory at the volume root.
        let dir = PathBuf::from(format!("{volume}wsecret-e6-{}", std::process::id()));
        if fs::create_dir_all(&dir).is_err() {
            row.evidence.push(format!(
                "{label}: NO EVIDENCE — no writable test location (root DACL)"
            ));
            continue;
        }
        let path = dir.join("store.secret");
        let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
        let mut pass = PASS_A.to_vec();
        let session = Session::unlock(&header, &mut pass).expect("unlock");
        store
            .append_or_reuse(None, &session, KEEP.0, KEEP.1)
            .expect("seed");

        // (1) short-write append → 512N+256 suffix, originals intact.
        let run = probe_write(
            &path,
            PASS_A,
            b"new",
            b"x",
            &[
                String::from("fault"),
                String::from("mid"),
                String::from("short"),
            ],
        );
        assert_eq!(run.status, STATUS_IO, "{label} short write: {run:?}");
        assert_eq!(run.state, STATE_UNKNOWN, "{label}: {run:?}");
        assert_eq!(
            file_len(&path),
            2 * 512 + 256,
            "{label}: append class suffix"
        );
        row.evidence.push(format!(
            "{label}: short-write append → 512N+256 suffix, original intact"
        ));
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2 * 512)
            .unwrap();

        // (2) kill before write → byte-identical store.
        let before = file_hash(&path);
        kill_write(&path, KEEP.0, b"K2\n", "before");
        assert_eq!(file_hash(&path), before, "{label}: kill-before");
        row.evidence
            .push(format!("{label}: kill before write → store byte-identical"));

        // (3) kill after write (before flush) → complete new record visible.
        kill_write(&path, KEEP.0, b"K3\n", "after");
        drop(store);
        drop(session);
        let (mut store, session) = unlock(&path, PASS_A);
        assert_eq!(
            value_of(&mut store, &session, KEEP.0).unwrap().as_slice(),
            b"K3\n",
            "{label}: kill-after visibility"
        );
        row.evidence.push(format!(
            "{label}: kill after write → complete new record visible (process-kill write-back; NO power-loss durability claim)"
        ));
        drop(store);
        drop(session);

        let _ = fs::remove_dir_all(&dir);
    }

    // Filesystems the assignment names but this host does not provide.
    for (fs_name, why) in [
        ("ReFS", "no ReFS volume on this host"),
        ("FAT32", "no FAT32 volume on this host"),
        ("exFAT", "no exFAT volume on this host"),
    ] {
        if !rows.iter().any(|r| r.fs == fs_name) {
            rows.push(FsRow {
                fs: fs_name.to_string(),
                volumes: Vec::new(),
                evidence: vec![format!("NO EVIDENCE — {why}")],
            });
        }
    }
    let has_remote = rows
        .iter()
        .any(|r| r.volumes.iter().any(|v| v.contains("remote")));
    if !has_remote {
        rows.push(FsRow {
            fs: "SMB".to_string(),
            volumes: Vec::new(),
            evidence: vec![String::from(
                "NO EVIDENCE — no SMB share provisioned on this host (requires rights this environment lacks); the E7 drvfs-redirector row is the recorded cross-protocol evidence",
            )],
        });
    }

    // The matrix is recorded verbatim (test output) and persisted.
    let mut json = String::from("{\n  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        json.push_str("    {\n");
        json.push_str(&format!("      \"filesystem\": \"{}\",\n", row.fs));
        json.push_str(&format!(
            "      \"volumes\": [{}],\n",
            row.volumes
                .iter()
                .map(|v| format!("\"{v}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        json.push_str(&format!(
            "      \"evidence\": [{}]\n",
            row.evidence
                .iter()
                .map(|v| format!("\"{v}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        json.push_str(if i + 1 == rows.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    json.push_str("  ]\n}\n");
    println!("E6 filesystem matrix:\n{json}");
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    fs::write(repo.join("fixtures/e6-filesystem-matrix.json"), &json)
        .expect("record the E6 matrix");

    // The matrix must contain real executed evidence (never vacuous).
    assert!(
        rows.iter()
            .any(|r| r.evidence.iter().any(|e| !e.starts_with("NO EVIDENCE"))),
        "at least one filesystem row must carry executed evidence"
    );
}

// ---------------------------------------------------------------------------
// volume enumeration (Win32)
// ---------------------------------------------------------------------------

const DRIVE_REMOTE: u32 = 4;

/// Mounted volume roots (`X:\`), including remote shares when present.
fn volume_list() -> Vec<String> {
    // SAFETY: pure query returning a drive bitmask.
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    (0..26)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i as u8) as char))
        .collect()
}

/// `(filesystem name, drive type)` for a volume root.
fn volume_info(root: &str) -> (String, u32) {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW};
    let wide: Vec<u16> = std::ffi::OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut fs_name = [0u16; 64];
    // SAFETY: valid NUL-terminated root; valid out-buffers.
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    let fs = if ok != 0 {
        String::from_utf16_lossy(&fs_name)
            .trim_end_matches('\0')
            .to_string()
    } else {
        String::from("unknown")
    };
    // SAFETY: valid NUL-terminated root.
    let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
    (fs, drive_type)
}
