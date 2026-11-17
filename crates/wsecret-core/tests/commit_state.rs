//! §7.4 U5 commit-state fault-injection rows + §7.3 C16b post-commit warning
//! channel (plan §5.6 point 5's exact `(status, CommitState)` table).
//!
//! Injection points map onto §5.6 point 5's trichotomy (the checkpoints are
//! (i) write initiation, (ii) completed write, (iii) successful flush):
//!
//! | seam   | fires at                                   | table row |
//! |--------|--------------------------------------------|-----------|
//! | Before | immediately BEFORE (i)                     | failure before (i) → status, `NotCommitted` |
//! | Mid    | between (i) and (ii) (256 of 512 landed)   | (i)–(ii) → `IO`/`CANCELLED`/`PANIC`, `Unknown` |
//! | After  | between (ii) and (iii) (incl. flush zero)  | (ii)–(iii) → `IO`, `Unknown` |
//! | Post   | immediately AFTER (iii)                    | OK + `Committed`, warning bit 0 (panic) / bit 1 (cancel) |
//!
//! Each row is executed for BOTH mutation classes — overwrite
//! ([`Store::write_slot`]) and append ([`Store::append_or_reuse`]) — plus the
//! `Store::create` init class (C16b). The pre-(i) panic row reports
//! `(Panic, NotCommitted)`: §5.6 row 1's "IO/LOCKED/BUSY/CANCELLED etc." with
//! the store provably unchanged; at the ABI layer §5.6 point 5 maps caught
//! panics to status `PANIC` carrying `commit_state` (the ABI is future work).
//!
//! The seams are process-global one-shots, so every test here holds
//! [`SEAM_LOCK`] across arm → mutate → assert.

mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use support::{file_hash, file_len, temp_dir, unlock, value_of, PASS_A};
use wsecret_core::error::{
    Status, WARN_POST_COMMIT_CANCELLED, WARN_POST_COMMIT_PANIC,
};
use wsecret_core::fault::{self, Fault, Point};
use wsecret_core::format::OPS_LIMIT_MIN;
use wsecret_core::session::Session;
use wsecret_core::store::Store;
use wsecret_core::{CommitFailure, CommitState};

/// Serializes seam use (the armed fault is process-global).
static SEAM_LOCK: Mutex<()> = Mutex::new(());

const STATUS_IO: u32 = Status::Io as u32; // 17
const STATUS_CANCELLED: u32 = Status::Cancelled as u32; // 16
const STATUS_PANIC: u32 = Status::Panic as u32; // 23

const KEEP: (&[u8], &[u8]) = (b"keep", b"KEEP-ORIG\n");

/// A one-record store in a fresh directory; returns (dir, path).
fn seed(tag: &str) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    let path = dir.join("store.secret");
    let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
    let mut pass = PASS_A.to_vec();
    let session = Session::unlock(&header, &mut pass).expect("unlock");
    store
        .append_or_reuse(None, &session, KEEP.0, KEEP.1)
        .expect("seed");
    drop(store);
    (dir, path)
}

/// Locks the seam lock for a WHOLE test: fixture creation mutates and the
/// armed fault is process-global, so both must stay under the lock.
fn seam_lock() -> MutexGuard<'static, ()> {
    SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Arms a one-shot fault; the caller holds [`seam_lock`] for the whole test
/// and calls [`disarm`] after the assertion.
fn arm_seam(point: Point, fault_kind: Fault) {
    fault::arm(point, fault_kind).expect("valid seam combination");
}

fn disarm() {
    fault::disarm();
}

/// Asserts a mutation failure's exact `(status, CommitState)` pair.
fn assert_failure(failure: &CommitFailure, status: u32, state: CommitState, what: &str) {
    assert_eq!(
        failure.status() as u32,
        status,
        "{what}: status mismatch: {failure:?}"
    );
    assert_eq!(failure.state, state, "{what}: commit state mismatch: {failure:?}");
}

// ---------------------------------------------------------------------------
// U5 rows — overwrite class ([`Store::write_slot`])
// ---------------------------------------------------------------------------

#[test]
fn u5_before_checkpoint_i_overwrite() {
    let _all = seam_lock();
    for (fault_kind, status) in [
        (Fault::Io, STATUS_IO),
        (Fault::Cancel, STATUS_CANCELLED),
        (Fault::Panic, STATUS_PANIC),
    ] {
        let (dir, path) = seed(&format!("u5-before-ow-{status}"));
        let (mut store, session) = unlock(&path, PASS_A);
        let before = file_hash(&path);
        {
            arm_seam(Point::BeforeWrite, fault_kind);
            let failure = store
                .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
                .err()
                .expect("must fail before (i)");
            assert_failure(&failure, status, CommitState::NotCommitted, "before (i)");
            disarm();
        }
        assert_eq!(file_hash(&path), before, "store unchanged before (i)");
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn u5_between_i_and_ii_overwrite() {
    let _all = seam_lock();
    for (fault_kind, status) in [
        (Fault::Io, STATUS_IO),
        (Fault::Cancel, STATUS_CANCELLED),
        (Fault::Panic, STATUS_PANIC),
        (Fault::ShortWrite, STATUS_IO),
    ] {
        let (dir, path) = seed(&format!("u5-mid-ow-{status}"));
        let (mut store, session) = unlock(&path, PASS_A);
        {
            arm_seam(Point::MidWrite, fault_kind);
            let failure = store
                .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
                .err()
                .expect("must fail between (i) and (ii)");
            assert_failure(&failure, status, CommitState::Unknown, "(i)–(ii)");
            disarm();
        }
        // Overwrite class: length unchanged and 512-aligned.
        assert_eq!(file_len(&path), 2 * 512);
        if fault_kind == Fault::ShortWrite {
            assert!(
                value_of(&mut store, &session, b"keep").is_none(),
                "short write tears the slot"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn u5_between_ii_and_iii_overwrite() {
    let _all = seam_lock();
    for (fault_kind, status) in [
        (Fault::Io, STATUS_IO), // incl. flush returning zero
        (Fault::Cancel, STATUS_CANCELLED),
        (Fault::Panic, STATUS_PANIC),
    ] {
        let (dir, path) = seed(&format!("u5-after-ow-{status}"));
        let (mut store, session) = unlock(&path, PASS_A);
        {
            arm_seam(Point::AfterWrite, fault_kind);
            let failure = store
                .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
                .err()
                .expect("must fail between (ii) and (iii)");
            assert_failure(&failure, status, CommitState::Unknown, "(ii)–(iii)");
            disarm();
        }
        // The write completed: the new record is visible (page cache);
        // durability after a crash is filesystem-dependent (not claimed).
        assert_eq!(value_of(&mut store, &session, b"keep").unwrap(), b"KEEP-NEW\n");
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn u5_after_checkpoint_iii_overwrite_warning_bits() {
    let _all = seam_lock();
    // Post-commit contained panic → OK/Committed + warning bit 0 (C16b(a)).
    let (dir, path) = seed("u5-post-ow-panic");
    let (mut store, session) = unlock(&path, PASS_A);
    {
        arm_seam(Point::AfterFlush, Fault::Panic);
        let receipt = store
            .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
            .expect("post-commit panic must NOT fail the mutation");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(
            receipt.warnings, WARN_POST_COMMIT_PANIC,
            "exactly warning bit 0: {receipt:?}"
        );
        disarm();
    }
    assert_eq!(value_of(&mut store, &session, b"keep").unwrap(), b"KEEP-NEW\n");
    let _ = fs::remove_dir_all(&dir);

    // Post-commit cancellation → OK/Committed + warning bit 1.
    let (dir, path) = seed("u5-post-ow-cancel");
    let (mut store, session) = unlock(&path, PASS_A);
    {
        arm_seam(Point::AfterFlush, Fault::Cancel);
        let receipt = store
            .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
            .expect("post-commit cancellation must NOT fail the mutation");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(
            receipt.warnings, WARN_POST_COMMIT_CANCELLED,
            "exactly warning bit 1: {receipt:?}"
        );
        disarm();
    }
    assert_eq!(value_of(&mut store, &session, b"keep").unwrap(), b"KEEP-NEW\n");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// U5 rows — append class ([`Store::append_or_reuse`])
// ---------------------------------------------------------------------------

#[test]
fn u5_before_checkpoint_i_append() {
    let _all = seam_lock();
    for (fault_kind, status) in [
        (Fault::Io, STATUS_IO),
        (Fault::Cancel, STATUS_CANCELLED),
        (Fault::Panic, STATUS_PANIC),
    ] {
        let (dir, path) = seed(&format!("u5-before-app-{status}"));
        let (mut store, session) = unlock(&path, PASS_A);
        let before = file_hash(&path);
        {
            arm_seam(Point::BeforeWrite, fault_kind);
            let failure = store
                .append_or_reuse(None, &session, b"new", b"NEW\n")
                .err()
                .expect("must fail before (i)");
            assert_failure(&failure, status, CommitState::NotCommitted, "before (i)");
            disarm();
        }
        assert_eq!(file_hash(&path), before, "nothing appended before (i)");
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn u5_between_i_and_ii_append() {
    let _all = seam_lock();
    for (fault_kind, status) in [
        (Fault::Io, STATUS_IO),
        (Fault::Cancel, STATUS_CANCELLED),
        (Fault::Panic, STATUS_PANIC),
    ] {
        let (dir, path) = seed(&format!("u5-mid-app-{status}"));
        let (mut store, session) = unlock(&path, PASS_A);
        {
            arm_seam(Point::MidWrite, fault_kind);
            let failure = store
                .append_or_reuse(None, &session, b"new", b"NEW\n")
                .err()
                .expect("must fail between (i) and (ii)");
            assert_failure(&failure, status, CommitState::Unknown, "(i)–(ii)");
            disarm();
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // The short-write row's class effect (§5.6 point 4 append class).
    let (dir, path) = seed("u5-mid-app-short");
    let (mut store, session) = unlock(&path, PASS_A);
    {
        arm_seam(Point::MidWrite, Fault::ShortWrite);
        let failure = store
            .append_or_reuse(None, &session, b"new", b"NEW\n")
            .err()
            .expect("short write must fail");
        assert_failure(&failure, STATUS_IO, CommitState::Unknown, "short append");
        disarm();
    }
    assert_eq!(file_len(&path), 2 * 512 + 256, "512N+256 suffix");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn u5_after_checkpoint_iii_append_warning_bits() {
    let _all = seam_lock();
    let (dir, path) = seed("u5-post-app-panic");
    let (mut store, session) = unlock(&path, PASS_A);
    {
        arm_seam(Point::AfterFlush, Fault::Panic);
        let receipt = store
            .append_or_reuse(None, &session, b"new", b"NEW\n")
            .expect("post-commit panic must NOT fail the append");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.warnings, WARN_POST_COMMIT_PANIC);
        disarm();
    }
    assert_eq!(value_of(&mut store, &session, b"new").unwrap(), b"NEW\n");
    let _ = fs::remove_dir_all(&dir);

    let (dir, path) = seed("u5-post-app-cancel");
    let (mut store, session) = unlock(&path, PASS_A);
    {
        arm_seam(Point::AfterFlush, Fault::Cancel);
        let receipt = store
            .append_or_reuse(None, &session, b"new", b"NEW\n")
            .expect("post-commit cancellation must NOT fail the append");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.warnings, WARN_POST_COMMIT_CANCELLED);
        disarm();
    }
    assert_eq!(value_of(&mut store, &session, b"new").unwrap(), b"NEW\n");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// C16b — `Store::create` (init class) + the post-commit warning channel
// ---------------------------------------------------------------------------

#[test]
fn c16b_create_post_commit_warning_bits() {
    let _all = seam_lock();
    // (b) caught panic immediately AFTER checkpoint (iii) of `init`:
    // OK/Committed + warning bit 0; the store holds the complete header.
    let dir = temp_dir("c16b-create-panic");
    let path = dir.join("store.secret");
    {
        arm_seam(Point::AfterFlush, Fault::Panic);
        let (store, header, receipt) =
            Store::create(&path, OPS_LIMIT_MIN).expect("post-commit panic must NOT fail init");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.warnings, WARN_POST_COMMIT_PANIC, "{receipt:?}");
        assert_eq!(header.ops_limit, OPS_LIMIT_MIN);
        drop(store);
        disarm();
    }
    // "the store contains the complete new data": it opens and the header
    // round-trips.
    let (_store, header) = Store::open(&path).expect("complete store after post-commit panic");
    assert_eq!(header.ops_limit, OPS_LIMIT_MIN);
    let _ = fs::remove_dir_all(&dir);

    // Post-commit cancellation → warning bit 1.
    let dir = temp_dir("c16b-create-cancel");
    let path = dir.join("store.secret");
    {
        arm_seam(Point::AfterFlush, Fault::Cancel);
        let (_store, _header, receipt) =
            Store::create(&path, OPS_LIMIT_MIN).expect("post-commit cancel must NOT fail init");
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.warnings, WARN_POST_COMMIT_CANCELLED, "{receipt:?}");
        disarm();
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn c16b_create_failure_rows_use_the_same_table() {
    let _all = seam_lock();
    // Failure before (i): NotCommitted; the leftover file is not a store.
    let dir = temp_dir("c16b-create-before");
    let path = dir.join("store.secret");
    {
        arm_seam(Point::BeforeWrite, Fault::Io);
        let failure = Store::create(&path, OPS_LIMIT_MIN).err().expect("must fail");
        assert_failure(&failure, STATUS_IO, CommitState::NotCommitted, "init before (i)");
        disarm();
    }
    assert!(Store::open(&path).is_err(), "no readable store was created");
    let _ = fs::remove_dir_all(&dir);

    // Short write mid-init: Unknown; a partial header block (unreadable).
    let dir = temp_dir("c16b-create-mid");
    let path = dir.join("store.secret");
    {
        arm_seam(Point::MidWrite, Fault::ShortWrite);
        let failure = Store::create(&path, OPS_LIMIT_MIN).err().expect("must fail");
        assert_failure(&failure, STATUS_IO, CommitState::Unknown, "init (i)–(ii)");
        disarm();
    }
    assert_eq!(file_len(&path), 256, "partial header block");
    assert!(Store::open(&path).is_err(), "partial init is unreadable");
    let _ = fs::remove_dir_all(&dir);

    // Flush failure after the completed header write: Unknown; the complete
    // header is visible (durability not claimed).
    let dir = temp_dir("c16b-create-after");
    let path = dir.join("store.secret");
    {
        arm_seam(Point::AfterWrite, Fault::Io);
        let failure = Store::create(&path, OPS_LIMIT_MIN).err().expect("must fail");
        assert_failure(&failure, STATUS_IO, CommitState::Unknown, "init (ii)–(iii)");
        disarm();
    }
    assert_eq!(file_len(&path), 512, "complete header block");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// sanity: the table's success row (no fault) is `OK`/`Committed`
// ---------------------------------------------------------------------------

#[test]
fn u5_no_fault_is_committed() {
    let (dir, path) = seed("u5-nofault");
    let (mut store, session) = unlock(&path, PASS_A);
    let _g = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let receipt = store
        .write_slot(512, &session, b"keep", b"KEEP-NEW\n")
        .expect("clean write");
    assert_eq!(receipt.state, CommitState::Committed);
    assert_eq!(receipt.warnings, 0);
    drop(store);
    drop(session);
    let (_store, _header) = Store::open(&path).expect("store stays valid");
    let _ = fs::remove_dir_all(&dir);
}
