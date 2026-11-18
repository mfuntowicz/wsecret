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
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use support::{
    BLOCK, PASS_A, PASS_B, REC_A1, REC_A2, REC_A3, REC_B1, REC_B2, REC_B3, TwoPartition,
    block_hashes, probe_write, slot_of, spawn_hold, temp_dir, temp_scratch, unlock, value_of,
    wait_for,
};
use wsecret_core::error::Status;
use wsecret_core::windows::file as winfile;
use wsecret_core::windows::security::{
    IdentityLock, MutexOutcome, WriterMutex, identity_lock_name, writer_mutex_name,
};
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
    let mut changed: Vec<usize> = (0..before.len())
        .filter(|&i| before[i] != after[i])
        .collect();
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
    assert_eq!(
        value_of(&mut store, &s_a, b"a1").unwrap().as_slice(),
        b"A-one-new\n"
    );
    assert_eq!(
        value_of(&mut store, &s_a, b"a2").unwrap().as_slice(),
        REC_A2.1
    );
    assert_eq!(
        value_of(&mut store, &s_a, b"a3").unwrap().as_slice(),
        REC_A3.1
    );
    drop(store);
    drop(s_a);
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(
        value_of(&mut store, &s_b, b"b1").unwrap().as_slice(),
        b"B-one-new\n"
    );
    assert_eq!(
        value_of(&mut store, &s_b, b"b2").unwrap().as_slice(),
        REC_B2.1
    );
    assert_eq!(
        value_of(&mut store, &s_b, b"b3").unwrap().as_slice(),
        REC_B3.1
    );
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
    assert_eq!(
        value_of(&mut store, &s_a, b"a1").unwrap().as_slice(),
        b"A-one-new\n"
    );
    drop(store);
    drop(s_a);
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(
        value_of(&mut store, &s_b, b"b1").unwrap().as_slice(),
        b"B-one-new\n"
    );
    drop(store);
    drop(s_b);

    // Only the two updated record blocks may differ (header and the four
    // unrelated records keep their exact ciphertext).
    let after = block_hashes(&fx.path);
    let changed: Vec<usize> = (0..before.len())
        .filter(|&i| before[i] != after[i])
        .collect();
    assert_eq!(
        changed.len(),
        2,
        "exactly two blocks may change: {changed:?}"
    );
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
        assert_eq!(
            *name, names[0],
            "alias must map to the canonical mutex name"
        );
    }

    // Cross-process serialization through an alias: the extended-path writer
    // collides with a holder that opened the plain path.
    let ready = temp_scratch("e2-ready");
    let release = temp_scratch("e2-release");
    let mut holder = spawn_hold(&fx.path, &ready, &release);
    wait_for(&ready);
    let alias = &aliases[1];
    let loser = probe_write(alias, PASS_A, b"a1", b"A-one-new\n", &[]);
    assert_eq!(
        loser.status, STATUS_BUSY,
        "alias writer must serialize: {loser:?}"
    );
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
    assert_eq!(
        value_of(&mut store, &s_a, b"a1").unwrap().as_slice(),
        b"A-one-new\n"
    );
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
        value_of(&mut store, &s_a, b"unew")
            .expect("upstream record")
            .as_slice(),
        b"U-new\n",
        "upstream's record is in the store (no serialization happened)"
    );
    assert_eq!(
        value_of(&mut store, &s_a, b"a1").unwrap().as_slice(),
        REC_A1.1
    );
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
    assert_eq!(
        code, 0,
        "upstream append during the wsecret critical section"
    );
    fs::write(&release, b"go").unwrap();
    let run = snapper.join().expect("snapper");
    assert_eq!(run.status, 0, "stale writer completes: {run:?}");

    // The lost update: the upstream record is GONE (overwritten by the
    // stale-slot write) — the documented conflict, not prevented.
    let (mut store, s_a) = unlock(&fx.path, PASS_A);
    assert_eq!(
        value_of(&mut store, &s_a, b"wnew")
            .expect("wsecret record")
            .as_slice(),
        b"W-val\n"
    );
    assert!(
        value_of(&mut store, &s_a, b"unew2").is_none(),
        "the upstream record was lost to the stale-slot overwrite (documented violation)"
    );
    // The rest of the store is intact.
    assert_eq!(
        value_of(&mut store, &s_a, b"a1").unwrap().as_slice(),
        REC_A1.1
    );
    assert_eq!(
        value_of(&mut store, &s_a, b"unew").unwrap().as_slice(),
        b"U-new\n"
    );
    let (mut store, s_b) = unlock(&fx.path, PASS_B);
    assert_eq!(
        value_of(&mut store, &s_b, b"b1").unwrap().as_slice(),
        REC_B1.1
    );
    assert_eq!(
        value_of(&mut store, &s_b, b"b2").unwrap().as_slice(),
        REC_B2.1
    );
    assert_eq!(
        value_of(&mut store, &s_b, b"b3").unwrap().as_slice(),
        REC_B3.1
    );
}

// ---------------------------------------------------------------------------
// WS-03: writer-mutex / per-identity lock DACL contract — Windows kernel
// readback (exact user + SYSTEM rights, including the absence of any
// additional grant) and the failing-create error scenario (OS errors are
// preserved; `Busy` means contention and nothing else).
// ---------------------------------------------------------------------------

fn wide_name(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Checks explicit ACEs on the kernel object, not the implicit READ_CONTROL
/// and WRITE_DAC rights Windows gives the object's owner.
fn assert_exact_user_system_dacl(name: &str) {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
        GetSecurityDescriptorDacl, IsWellKnownSid, PSECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, SYNCHRONIZE};
    use windows_sys::Win32::System::Threading::{MUTEX_MODIFY_STATE, OpenMutexW};

    let user = winfile::current_user_sid().expect("current user SID");
    let wide = wide_name(name);
    // The creator can inspect the DACL via the owner's implicit READ_CONTROL.
    // Readback does not need the wait/modify rights used by the writers.
    // SAFETY: `wide` is NUL-terminated; the handle is checked below.
    let handle = unsafe { OpenMutexW(READ_CONTROL, 0, wide.as_ptr()) };
    assert!(
        !handle.is_null(),
        "OpenMutexW({name}) failed: {}",
        std::io::Error::last_os_error()
    );
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: output pointers are valid; `sd` is freed after the walk.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    // SAFETY: GetSecurityInfo returned its own descriptor; it no longer
    // needs this owned handle, even if a later assertion fails.
    unsafe { CloseHandle(handle) };
    assert_eq!(status, 0, "GetSecurityInfo({name}) failed: {status}");
    {
        let mut present = 0;
        let mut queried: *mut ACL = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `sd` is the live self-relative descriptor returned above.
        let ok =
            unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut queried, &mut defaulted) };
        assert!(
            ok != 0 && present != 0 && !queried.is_null() && queried == dacl,
            "{name}: DACL must be present and self-consistent"
        );
        let count = unsafe { (*dacl).AceCount } as u32;
        assert_eq!(count, 2, "{name}: expected just the user and SYSTEM ACEs");
        let (mut saw_user, mut saw_system) = (false, false);
        for index in 0..count {
            let mut raw: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index < AceCount`; `raw` is checked below.
            assert!(unsafe { GetAce(dacl, index, &mut raw) } != 0 && !raw.is_null());
            // SAFETY: every ACE starts with ACE_HEADER. Only interpret the
            // standard allow-ACE layout after checking its type.
            assert_eq!(
                unsafe { (*raw.cast::<ACE_HEADER>()).AceType },
                0,
                "{name}: not an allow ACE"
            );
            let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: the kernel supplied a standard allow ACE containing a SID.
            let (mask, sid) =
                unsafe { ((*ace).Mask, std::ptr::addr_of_mut!((*ace).SidStart).cast()) };
            assert_eq!(
                mask,
                SYNCHRONIZE | MUTEX_MODIFY_STATE,
                "{name}: unexpected ACE mask"
            );
            let len = unsafe { GetLengthSid(sid) } as usize;
            assert!(
                (1..=SECURITY_MAX_SID_SIZE as usize).contains(&len),
                "{name}: invalid SID length"
            );
            // SAFETY: `sid` and its `len` bytes are part of the live descriptor.
            let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) };
            if !saw_user && bytes == user.as_slice() {
                saw_user = true;
            } else if !saw_system && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
                saw_system = true;
            } else {
                panic!("{name}: unexpected or duplicate trustee {bytes:?}");
            }
        }
        assert!(saw_user && saw_system, "{name}: missing user or SYSTEM ACE");
    }
    // SAFETY: `sd` was allocated by GetSecurityInfo.
    unsafe {
        LocalFree(sd);
    }
}

/// WS-03 kernel readback: the writer mutex and the per-identity lock carry
/// EXACTLY the user+SYSTEM `SYNCHRONIZE | MUTEX_MODIFY_STATE` DACL, and the
/// kernel's own view proves there is no additional ACE.
#[test]
fn mutex_kernel_dacl_readback_is_exactly_user_and_system() {
    let path = format!(r"C:\wsecret-test\ws03-dacl-readback-{}", std::process::id());
    let path = path.as_bytes();
    let held = WriterMutex::acquire(path).expect("writer mutex");
    assert_eq!(held.outcome(), MutexOutcome::Acquired);
    let name = writer_mutex_name(path);
    assert_exact_user_system_dacl(&name);
    drop(held);

    let public = fixture_public_key(0x24);
    let held = IdentityLock::acquire(&public).expect("identity lock");
    assert_eq!(held.outcome(), MutexOutcome::Acquired);
    let name = identity_lock_name(&public).expect("identity lock name");
    assert_exact_user_system_dacl(&name);
    drop(held);
}

// Keep independent test processes out of one another's Global namespace.
fn fixture_public_key(tag: u8) -> [u8; 32] {
    let mut key = [tag; 32];
    key[..4].copy_from_slice(&std::process::id().to_le_bytes());
    key
}

/// Pin a mutex with a protected empty DACL: the owner may request READ_CONTROL
/// but neither it nor any other writer receives mutex-operation rights.
fn squat_with_empty_dacl(name: &str) -> OwnedHandle {
    use windows_sys::Win32::Security::{
        ACL, ACL_REVISION, InitializeAcl, InitializeSecurityDescriptor, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl,
    };
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::System::Threading::CreateMutexExW;

    // A present, empty (not NULL) ACL has only the header. Use DWORD storage
    // for InitializeAcl's alignment requirement.
    let mut acl = [0u32; size_of::<ACL>().div_ceil(4)];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: the stack buffer is aligned, writable, and has room for an ACL header.
    assert!(unsafe { InitializeAcl(acl_ptr, size_of_val(&acl) as u32, ACL_REVISION) } != 0);
    let mut sd = SECURITY_DESCRIPTOR::default();
    let sd_ptr = std::ptr::from_mut(&mut sd).cast();
    // SAFETY: `sd` is a correctly typed SECURITY_DESCRIPTOR (revision 1) and
    // `acl` outlives it through the function.
    unsafe {
        assert!(
            InitializeSecurityDescriptor(sd_ptr, 1) != 0,
            "InitializeSecurityDescriptor failed"
        );
        assert!(
            SetSecurityDescriptorControl(sd_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0,
            "SetSecurityDescriptorControl failed"
        );
        assert!(
            SetSecurityDescriptorDacl(sd_ptr, 1, acl_ptr, 0) != 0,
            "SetSecurityDescriptorDacl failed"
        );
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };
    let wide = wide_name(name);
    // SAFETY: `sa` and `wide` are valid; `acl`/`sd` live through the call.
    let handle = unsafe { CreateMutexExW(&sa, wide.as_ptr(), 0, READ_CONTROL) };
    assert!(
        !handle.is_null(),
        "fixture CreateMutexExW({name}) failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: this unique, non-null handle is ours; it was never waited on.
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

/// WS-03 failing-create error scenario: when mutex creation/opening fails
/// (here: the name pinned by a protected empty DACL), acquisition surfaces the
/// preserved OS error (`ERROR_ACCESS_DENIED`) as `Error::Io` — never
/// `Error::Busy`, which is reserved for contention.
#[test]
fn mutex_create_failure_preserves_os_error_and_is_never_busy() {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    // Writer mutex.
    let path = format!(
        r"C:\wsecret-test\ws03-failing-create-{}",
        std::process::id()
    );
    let path = path.as_bytes();
    let squat = squat_with_empty_dacl(&writer_mutex_name(path));
    let err = WriterMutex::acquire(path)
        .err()
        .expect("squatting DACL must fail the create/open");
    assert!(
        matches!(&err, Error::Io(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)),
        "OS error must be preserved: {err:?}"
    );
    assert!(
        !matches!(err, Error::Busy),
        "create failure must not masquerade as contention"
    );
    // With the name free again the same acquisition succeeds.
    drop(squat);
    drop(WriterMutex::acquire(path).expect("writer mutex after squat release"));

    // Per-identity lock: same contract. A distinct key from the readback
    // test so the two tests never contend for one kernel name.
    let public = fixture_public_key(0x25);
    let squat = squat_with_empty_dacl(&identity_lock_name(&public).expect("name"));
    let err = IdentityLock::acquire(&public)
        .err()
        .expect("squatting DACL must fail the create/open");
    assert!(
        matches!(&err, Error::Io(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)),
        "OS error must be preserved: {err:?}"
    );
    assert!(
        !matches!(err, Error::Busy),
        "create failure must not masquerade as contention"
    );
    drop(squat);
    drop(IdentityLock::acquire(&public).expect("identity lock after squat release"));
}
