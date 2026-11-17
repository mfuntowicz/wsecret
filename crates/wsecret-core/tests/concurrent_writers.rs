//! §7.4 concurrent-writer rows E1, E2, E3, E7 (plan §5.6 points 1–2, 6b).
//!
//! Deviation note (assignment wording vs. plan §5.6, recorded in the slice
//! report): the assignment's E-bullets describe the WITHDRAWN atomic-replace
//! design ("between snapshot and rename", "temporary file", "513-byte
//! destination"). The authoritative §5.6 protocol is ONE in-place 512-byte
//! slot write with a named-mutex critical section and 6b secure-reopen
//! revalidation; §7.4's E-rows were rewritten to the per-class torn-record
//! model ("NOT 'complete old/new'"). These tests assert the §5.6/§7.4 model
//! and cover every scenario the E-bullets enumerate, mapped onto it:
//!
//! - E1 → two cross-process wsecret writers for different records under
//!   passphrases A and B: one completes while the other returns `Busy`
//!   (StoreBusy, Status 14) + `NotCommitted`; the loser is retried; both
//!   updates land and every unrelated 512-byte block is byte-identical.
//! - E2 → the same store through path aliases (extended, lowercase,
//!   forward-slash): one canonical `Global\wsecret-store-*` mutex identity
//!   serializes the writers (`Busy` under overlap); no lost update.
//! - E3 → external replacement of the destination between the scan
//!   ("snapshot") and the write: `Conflict` (StoreConflict, Status 15) +
//!   `NotCommitted` via §5.6 6b secure-reopen; the writer does NOT touch the
//!   external replacement; no temporary file exists at all (the in-place
//!   protocol creates none — strictly stronger than "temp file removed").
//! - E7 → a non-cooperating upstream POSIX writer (pinned `secret` binary
//!   over the WSL drvfs redirector) against the same store while a wsecret
//!   writer mutex is held: upstream's write SUCCEEDS — the Windows mutex
//!   does not serialize POSIX writers; the scan-before-lock stale-slot lost
//!   update is demonstrated deterministically. No SMB share is provisioned
//!   on this host (no rights to create one): the SMB-specific claim is NOT
//!   made; the drvfs redirector case is the recorded evidence.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use support::{
    block_hashes, probe_write, slot_of, spawn_hold, temp_dir, temp_scratch, unlock, value_of,
    wait_for, TwoPartition, PASS_A, PASS_B, REC_A1, REC_A2, REC_A3, REC_B1, REC_B2, REC_B3, BLOCK,
};
use wsecret_core::error::Status;
use wsecret_core::windows::file as winfile;
use wsecret_core::windows::security::writer_mutex_name;
use wsecret_core::{CommitState, Error, Store};

const STATE_NOT_COMMITTED: u32 = CommitState::NotCommitted as u32;
const STATE_COMMITTED: u32 = CommitState::Committed as u32;
const STATUS_BUSY: u32 = Status::Busy as u32; // 14 — plan §5.6 "BUSY"
const STATUS_CONFLICT: u32 = Status::Conflict as u32; // 15 — plan §5.6 6b "CONFLICT"

/// Asserts that exactly `slots` (byte offsets) changed between two
/// per-block hash lists.
fn assert_only_blocks_changed(before: &[[u8; 32]], after: &[[u8; 32]], slots: &[u64]) {
    assert_eq!(before.len(), after.len(), "block count must not change");
    let mut expect: Vec<usize> = slots.iter().map(|s| (s / BLOCK as u64) as usize).collect();
    expect.sort_unstable();
    let mut changed: Vec<usize> = (0..before.len()).filter(|&i| before[i] != after[i]).collect();
    changed.sort_unstable();
    assert_eq!(changed, expect, "exactly the given slots may change");
}

/// E1: two Windows writers, different records under A and B. The winner's
/// write runs inside its mutex-held critical section; the colliding loser
/// fails with `Busy`/`NotCommitted`. After the retry both updates are in the
/// store and ALL unrelated ciphertext is byte-identical.
#[test]
fn e1_concurrent_writers_one_wins_one_busy_then_retry() {
    let fx = TwoPartition::new("e1");
    let before = block_hashes(&fx.path);

    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    let slot_a1 = slot_of(&mut store, &s_a, b"a1").expect("a1 slot");
    drop(store);
    drop(s_a);
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    let slot_b1 = slot_of(&mut store, &s_b, b"b1").expect("b1 slot");
    drop(store);
    drop(s_b);

    // Winner: writer A holds `Global\wsecret-store-*` across its critical
    // section (scan → encrypt → write) and completes only after release.
    let ready = temp_scratch("e1-ready");
    let release = temp_scratch("e1-release");
    let win_path = fx.path.clone();
    let (ready_r, release_r) = (ready.clone(), release.clone());
    let winner = std::thread::spawn(move || {
        probe_write(
            &win_path,
            PASS_A,
            b"a1",
            b"A-one-new\n",
            &[
                String::from("hold"),
                ready_r.display().to_string(),
                release_r.display().to_string(),
            ],
        )
    });
    wait_for(&ready);

    // Loser: writer B for a DIFFERENT record under a different passphrase
    // collides with the held mutex → StoreBusy, store unchanged.
    let loser = probe_write(&fx.path, PASS_B, b"b1", b"B-one-new\n", &[]);
    assert_eq!(loser.status, STATUS_BUSY, "loser must get BUSY: {loser:?}");
    assert_eq!(loser.state, STATE_NOT_COMMITTED, "{loser:?}");

    // Release the winner; its write commits.
    fs::write(&release, b"go").unwrap();
    let win = winner.join().expect("winner thread");
    assert_eq!(win.status, 0, "winner must commit: {win:?}");
    assert_eq!(win.state, STATE_COMMITTED, "{win:?}");

    // Retry the loser: now it completes too.
    let retry = probe_write(&fx.path, PASS_B, b"b1", b"B-one-new\n", &[]);
    assert_eq!(retry.status, 0, "retried loser must commit: {retry:?}");
    assert_eq!(retry.state, STATE_COMMITTED, "{retry:?}");

    // Both updates present; exactly the two updated slots changed.
    let after = block_hashes(&fx.path);
    assert_only_blocks_changed(&before, &after, &[slot_a1, slot_b1]);

    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(value_of(&mut store, &s_a, b"a1").unwrap(), b"A-one-new\n");
    assert_eq!(value_of(&mut store, &s_a, b"a2").unwrap(), REC_A2.1);
    assert_eq!(value_of(&mut store, &s_a, b"a3").unwrap(), REC_A3.1);
    drop(store);
    drop(s_a);
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(value_of(&mut store, &s_b, b"b1").unwrap(), b"B-one-new\n");
    assert_eq!(value_of(&mut store, &s_b, b"b2").unwrap(), REC_B2.1);
    assert_eq!(value_of(&mut store, &s_b, b"b3").unwrap(), REC_B3.1);
}

/// E1 raced variant: two writers launched simultaneously with retries —
/// every attempt reports Committed or Busy, and after the retries both
/// updates are present with all unrelated ciphertext preserved (no lost
/// update regardless of who won each round).
#[test]
fn e1_raced_writers_never_lose_updates() {
    let fx = TwoPartition::new("e1-race");
    let before = block_hashes(&fx.path);

    let path_a = fx.path.clone();
    let path_b = fx.path.clone();
    let handle_a = std::thread::spawn(move || {
        for _ in 0..50 {
            let run = probe_write(&path_a, PASS_A, b"a1", b"A-one-new\n", &[]);
            match run.status {
                0 => return,
                STATUS_BUSY => continue,
                other => panic!("unexpected writer status {other}: {run:?}"),
            }
        }
        panic!("writer A never completed");
    });
    let handle_b = std::thread::spawn(move || {
        for _ in 0..50 {
            let run = probe_write(&path_b, PASS_B, b"b1", b"B-one-new\n", &[]);
            match run.status {
                0 => return,
                STATUS_BUSY => continue,
                other => panic!("unexpected writer status {other}: {run:?}"),
            }
        }
        panic!("writer B never completed");
    });
    handle_a.join().unwrap();
    handle_b.join().unwrap();

    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(value_of(&mut store, &s_a, b"a1").unwrap(), b"A-one-new\n");
    drop(store);
    drop(s_a);
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(value_of(&mut store, &s_b, b"b1").unwrap(), b"B-one-new\n");
    drop(store);
    drop(s_b);

    // Only the two updated record blocks may differ (header and the four
    // unrelated records keep their exact ciphertext).
    let after = block_hashes(&fx.path);
    let changed: Vec<usize> = (0..before.len())
        .filter(|&i| before[i] != after[i])
        .collect();
    assert_eq!(changed.len(), 2, "exactly two blocks may change: {changed:?}");
}

/// E2: one canonical writer-mutex identity across path aliases, and the
/// aliases serialize cross-process writers (or conflict) with no lost
/// update.
#[test]
fn e2_alias_paths_share_one_canonical_writer_mutex() {
    let fx = TwoPartition::new("e2");

    // The canonical final path (and thus the `Global\wsecret-store-<hash>`
    // name) must be identical for every alias of the same file.
    let win = fx.path.display().to_string();
    let aliases: [PathBuf; 4] = [
        fx.path.clone(),
        Path::new(&format!("\\\\?\\{win}")).to_path_buf(),
        Path::new(&win.to_lowercase()).to_path_buf(),
        Path::new(&win.replace('\\', "/")).to_path_buf(),
    ];
    let mut names = Vec::new();
    for alias in &aliases {
        let file = fs::File::open(alias)
            .unwrap_or_else(|e| panic!("alias {alias:?} must open the same store: {e}"));
        let canonical = winfile::final_path(&file).expect("canonical final path");
        names.push(writer_mutex_name(&canonical));
    }
    for name in &names[1..] {
        assert_eq!(*name, names[0], "alias must map to the canonical mutex name");
    }

    // Cross-process serialization through an alias: the extended-path writer
    // collides with a holder that opened the plain path.
    let ready = temp_scratch("e2-ready");
    let release = temp_scratch("e2-release");
    let mut holder = spawn_hold(&fx.path, &ready, &release);
    wait_for(&ready);
    let alias = &aliases[1];
    let loser = probe_write(alias, PASS_A, b"a1", b"A-one-new\n", &[]);
    assert_eq!(loser.status, STATUS_BUSY, "alias writer must serialize: {loser:?}");
    assert_eq!(loser.state, STATE_NOT_COMMITTED, "{loser:?}");
    fs::write(&release, b"go").unwrap();
    assert!(holder.wait().expect("hold child").success());

    // Retry through the alias: commits; no lost update anywhere else.
    let before = block_hashes(&fx.path);
    let retry = probe_write(alias, PASS_A, b"a1", b"A-one-new\n", &[]);
    assert_eq!(retry.status, 0, "alias retry must commit: {retry:?}");
    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    let slot_a1 = slot_of(&mut store, &s_a, b"a1").expect("a1 slot");
    drop(store);
    drop(s_a);
    let after = block_hashes(&fx.path);
    assert_only_blocks_changed(&before, &after, &[slot_a1]);
    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(value_of(&mut store, &s_a, b"a1").unwrap(), b"A-one-new\n");
}

/// E3: external replacement of the destination between the writer's scan
/// ("snapshot") and its write → `Conflict`/`NotCommitted` (§5.6 6b
/// secure-reopen), the external replacement is NOT overwritten, and no
/// temporary file exists (the in-place protocol creates none).
#[test]
fn e3_external_replacement_conflicts_without_overwriting() {
    // A dedicated directory so "no temporary file" is a real assertion.
    let dir = temp_dir("e3");
    let path = dir.join("store.secret");
    let (_store, _header, _) =
        Store::create(&path, wsecret_core::format::OPS_LIMIT_MIN).expect("create");
    let (mut store, header) = Store::open(&path).expect("open");
    let mut pass = PASS_A.to_vec();
    let session = wsecret_core::session::Session::unlock(&header, &mut pass).expect("unlock");
    store
        .append_or_reuse(None, &session, b"keep", b"original\n")
        .expect("seed record");
    // Snapshot: the writer has scanned and selected its slot.
    let slot = slot_of(&mut store, &session, b"keep").expect("slot");

    // External replacement between snapshot and write (delete + recreate).
    let replacement_bytes = b"EXTERNAL REPLACEMENT - not a wsecret store".to_vec();
    let moved = dir.join("moved-away.secret");
    fs::rename(&path, &moved).expect("external rename");
    fs::write(&path, &replacement_bytes).expect("external replacement");

    let failure = store
        .write_slot(slot, &session, b"keep", b"new value\n")
        .err()
        .expect("replacement must conflict");
    assert!(
        matches!(failure.error, Error::Conflict),
        "must be Conflict: {:?}",
        failure.error
    );
    assert_eq!(failure.status() as u32, STATUS_CONFLICT);
    assert_eq!(failure.state, CommitState::NotCommitted);

    // The external replacement is untouched.
    assert_eq!(
        fs::read(&path).expect("read replacement"),
        replacement_bytes,
        "writer must not overwrite the external replacement"
    );

    // The writer is invalidated: every further mutation conflicts too.
    let again = store.write_slot(slot, &session, b"keep", b"new value\n");
    assert!(matches!(
        again.err().expect("invalidated").error,
        Error::Conflict
    ));

    // No temporary file was ever created (in-place protocol): the directory
    // holds exactly the two files the test itself created.
    let mut entries: Vec<String> = fs::read_dir(&dir)
        .expect("list dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["moved-away.secret", "store.secret"]);

    let _ = fs::remove_dir_all(&dir);
}

/// E3 variant: a rename-swap (the replacement arrives under the recorded
/// name while the writer's handle still names the old file) is caught by the
/// same 6b secure-reopen check.
#[test]
fn e3_rename_swap_conflicts() {
    let dir = temp_dir("e3swap");
    let path = dir.join("store.secret");
    let (_store, _header, _) =
        Store::create(&path, wsecret_core::format::OPS_LIMIT_MIN).expect("create");
    let (mut store, header) = Store::open(&path).expect("open");
    let mut pass = PASS_A.to_vec();
    let session = wsecret_core::session::Session::unlock(&header, &mut pass).expect("unlock");
    store
        .append_or_reuse(None, &session, b"keep", b"original\n")
        .expect("seed");
    let slot = slot_of(&mut store, &session, b"keep").expect("slot");

    // Rename-swap: the path now names a DIFFERENT file.
    let swapped = dir.join("swapped-in.secret");
    fs::write(&swapped, b"SWAPPED").expect("write swap");
    fs::rename(&swapped, &path).expect("rename-swap over the store");

    let failure = store
        .write_slot(slot, &session, b"keep", b"new value\n")
        .err()
        .expect("swap must conflict");
    assert!(matches!(failure.error, Error::Conflict));
    assert_eq!(failure.status() as u32, STATUS_CONFLICT);
    assert_eq!(failure.state, CommitState::NotCommitted);
    assert_eq!(fs::read(&path).unwrap(), b"SWAPPED", "swap untouched");
    let _ = fs::remove_dir_all(&dir);
}

/// E3 variant: a same-file header rewrite (the identity is unchanged, so
/// only the 6b header-binding check can catch it) also conflicts.
#[test]
fn e3_in_place_header_rewrite_conflicts() {
    let dir = temp_dir("e3hdr");
    let path = dir.join("store.secret");
    let (_store, _header, _) =
        Store::create(&path, wsecret_core::format::OPS_LIMIT_MIN).expect("create");
    let (mut store, header) = Store::open(&path).expect("open");
    let mut pass = PASS_A.to_vec();
    let session = wsecret_core::session::Session::unlock(&header, &mut pass).expect("unlock");
    store
        .append_or_reuse(None, &session, b"keep", b"original\n")
        .expect("seed");
    let slot = slot_of(&mut store, &session, b"keep").expect("slot");

    // Rewrite the header through a second handle (same file, same identity).
    let mut raw = fs::read(&path).unwrap();
    raw[10] ^= 0xff; // flip one master-key byte
    fs::write(&path, &raw).expect("header rewrite");

    let failure = store
        .write_slot(slot, &session, b"keep", b"new value\n")
        .err()
        .expect("header rewrite must conflict");
    assert!(matches!(failure.error, Error::Conflict));
    assert_eq!(failure.status() as u32, STATUS_CONFLICT);
    assert_eq!(failure.state, CommitState::NotCommitted);
    let _ = fs::remove_dir_all(&dir);
}

/// E7: a non-cooperating upstream POSIX writer against the same store.
///
/// (a) The wsecret writer mutex does NOT serialize the upstream writer: the
/// pinned upstream `secret set` succeeds while a wsecret writer holds
/// `Global\wsecret-store-*` for the same store.
/// (b) The documented single-writer violation is demonstrated: a wsecret
/// writer whose scan predates its critical section (snap) overwrites the
/// record the upstream writer appended meanwhile — the stale-slot lost
/// update §5.6 point 2 warns about. No claim is made that Windows mutexes
/// serialize POSIX upstream writers.
///
/// SMB: no share is provisioned on this test host (creating one requires
/// rights this environment lacks). The upstream side runs over the WSL drvfs
/// redirector; the SMB-specific behavior is RECORDED AS UNEVIDENCED, not
/// assumed.
#[test]
fn e7_non_cooperating_upstream_writer_violates_single_writer() {
    if !support::upstream_available() {
        panic!("E7 requires the WSL upstream oracle environment (wsl.exe)");
    }
    let fx = TwoPartition::new("e7");

    // (a) upstream writes while the wsecret writer mutex is held.
    let ready = temp_scratch("e7-ready");
    let release = temp_scratch("e7-release");
    let mut holder = spawn_hold(&fx.path, &ready, &release);
    wait_for(&ready);
    let code = support::upstream_set(&fx.path, b"unew", PASS_A, b"U-new\n");
    assert_eq!(
        code, 0,
        "upstream writer must NOT be blocked by the wsecret writer mutex"
    );
    fs::write(&release, b"go").unwrap();
    assert!(holder.wait().expect("hold child").success());

    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(
        value_of(&mut store, &s_a, b"unew").expect("upstream record"),
        b"U-new\n",
        "upstream's record is in the store (no serialization happened)"
    );
    assert_eq!(value_of(&mut store, &s_a, b"a1").unwrap(), REC_A1.1);
    drop(store);
    drop(s_a);

    // (b) stale-slot lost update: the wsecret writer snapped its append
    // offset BEFORE its critical section; upstream appended at the same
    // offset meanwhile; the wsecret write lands on the upstream record.
    let ready = temp_scratch("e7-ready2");
    let release = temp_scratch("e7-release2");
    let mut args = vec![String::from("snap")];
    args.push(String::from("hold"));
    args.push(ready.display().to_string());
    args.push(release.display().to_string());
    let path = fx.path.clone();
    let snapper =
        std::thread::spawn(move || probe_write(&path, PASS_A, b"wnew", b"W-val\n", &args));
    wait_for(&ready);
    let code = support::upstream_set(&fx.path, b"unew2", PASS_A, b"U2\n");
    assert_eq!(code, 0, "upstream append during the wsecret critical section");
    fs::write(&release, b"go").unwrap();
    let run = snapper.join().expect("snapper");
    assert_eq!(run.status, 0, "stale writer completes: {run:?}");

    // The lost update: the upstream record is GONE (overwritten by the
    // stale-slot write) — the documented conflict, not prevented.
    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(
        value_of(&mut store, &s_a, b"wnew").expect("wsecret record"),
        b"W-val\n"
    );
    assert!(
        value_of(&mut store, &s_a, b"unew2").is_none(),
        "the upstream record was lost to the stale-slot overwrite (documented violation)"
    );
    // The rest of the store is intact.
    assert_eq!(value_of(&mut store, &s_a, b"a1").unwrap(), REC_A1.1);
    assert_eq!(value_of(&mut store, &s_a, b"unew").unwrap(), b"U-new\n");
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(value_of(&mut store, &s_b, b"b1").unwrap(), REC_B1.1);
    assert_eq!(value_of(&mut store, &s_b, b"b2").unwrap(), REC_B2.1);
    assert_eq!(value_of(&mut store, &s_b, b"b3").unwrap(), REC_B3.1);
}
