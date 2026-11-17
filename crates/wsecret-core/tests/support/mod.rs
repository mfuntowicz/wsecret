//! Shared helpers for the §7.4 E-row concurrency/crash-consistency suites
//! (`concurrent_writers.rs`, `crash_consistency.rs`, `commit_state.rs`).
//!
//! Everything here drives the REAL production code paths: `wsecret-core`
//! mutations in-process, cross-process writers through the
//! `wsecret-crash-probe` helper binary, and the pinned upstream `secret`
//! binary through WSL (`upstream_drv.py`) for the "readable by upstream"
//! evidence the E-rows require.

// Shared by several test binaries, each using a different subset.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use wsecret_core::format::OPS_LIMIT_MIN;
use wsecret_core::session::Session;
use wsecret_core::store::Store;

/// Partition-A passphrase (fixture convention, plan §7.2).
pub const PASS_A: &[u8] = b"correct horse battery staple";
/// Partition-B passphrase.
pub const PASS_B: &[u8] = b"second";

/// 512-byte block size (plan §1.1).
pub const BLOCK: usize = 512;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique per-test store path in the system temp directory.
pub fn temp_store(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wsecret-e-{}-{}-{nanos}-{tag}.secret",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// A unique per-test scratch path (markers, external replacements).
pub fn temp_scratch(tag: &str) -> PathBuf {
    temp_store(tag).with_extension("scratch")
}

/// The `wsecret-crash-probe` helper binary (built with the workspace).
pub fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wsecret-crash-probe"))
}

/// sha256 of each 512-byte block of the file (whole file; a trailing partial
/// block is hashed as-is so suffix growth is visible).
pub fn block_hashes(path: &Path) -> Vec<[u8; 32]> {
    let bytes = std::fs::read(path).expect("read store");
    bytes
        .chunks(BLOCK)
        .map(|c| {
            let mut h = Sha256::new();
            h.update(c);
            h.finalize().into()
        })
        .collect()
}

/// sha256 of the whole file.
pub fn file_hash(path: &Path) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(std::fs::read(path).expect("read store"));
    h.finalize().into()
}

/// File length in bytes.
pub fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).expect("stat store").len()
}

/// A fresh empty directory under the system temp dir (for tests that assert
/// on directory contents, e.g. E3's "no temporary file" check).
pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = temp_scratch(tag);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The slot of `name` in the store, if the session can decrypt it.
pub fn slot_of(store: &mut Store, session: &Session, name: &[u8]) -> Option<u64> {
    match store.find(session, name, false).expect("find") {
        wsecret_core::store::ScanOutcome::Found { slot, .. } => Some(slot),
        wsecret_core::store::ScanOutcome::NotFound { .. } => None,
    }
}

/// The decrypted value of `name`, if present.
pub fn value_of(store: &mut Store, session: &Session, name: &[u8]) -> Option<Vec<u8>> {
    match store.find(session, name, false).expect("find") {
        wsecret_core::store::ScanOutcome::Found { value, .. } => Some(value),
        wsecret_core::store::ScanOutcome::NotFound { .. } => None,
    }
}

/// The two-partition fixture (plan §7.2 shape, small values for readable
/// assertions): `a1`,`a2`,`a3` under [`PASS_A`], `b1`,`b2`,`b3` under
/// [`PASS_B`], created at the opslimit floor for fast test KDFs.
pub struct TwoPartition {
    pub path: PathBuf,
}

/// Values of the fixture records (the "unrelated ciphertext" set).
pub const REC_A1: (&[u8], &[u8]) = (b"a1", b"A-one\n");
pub const REC_A2: (&[u8], &[u8]) = (b"a2", b"A-two\n");
pub const REC_A3: (&[u8], &[u8]) = (b"a3", b"A-three\n");
pub const REC_B1: (&[u8], &[u8]) = (b"b1", b"B-one\n");
pub const REC_B2: (&[u8], &[u8]) = (b"b2", b"B-two\n");
pub const REC_B3: (&[u8], &[u8]) = (b"b3", b"B-three\n");

impl TwoPartition {
    pub fn new(tag: &str) -> TwoPartition {
        let path = temp_store(tag);
        let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create store");
        let mut pass_a = PASS_A.to_vec();
        let s_a = Session::unlock(&header, &mut pass_a).expect("unlock A");
        for (name, value) in [REC_A1, REC_A2, REC_A3] {
            store
                .append_or_reuse(None, &s_a, name, value)
                .expect("write A record");
        }
        let mut pass_b = PASS_B.to_vec();
        let s_b = Session::unlock(&header, &mut pass_b).expect("unlock B");
        for (name, value) in [REC_B1, REC_B2, REC_B3] {
            store
                .append_or_reuse(None, &s_b, name, value)
                .expect("write B record");
        }
        drop(store);
        TwoPartition { path }
    }
}

impl Drop for TwoPartition {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Unlocks a session for `pass` against the store at `path` (fresh handle).
pub fn unlock(path: &Path, pass: &[u8]) -> (Store, Session) {
    let (store, header) = Store::open(path).expect("open store");
    let mut pass = pass.to_vec();
    let session = Session::unlock(&header, &mut pass).expect("unlock session");
    (store, session)
}

// ---------------------------------------------------------------------------
// cross-process probe plumbing
// ---------------------------------------------------------------------------

/// One completed probe run.
#[derive(Debug)]
pub struct ProbeRun {
    pub code: u32,
    /// `OK <state> <warnings>` or `ERR <status> <state>`.
    pub status: u32,
    pub state: u32,
    pub warnings: u32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `wsecret-crash-probe write <store> <pass> <name> <value> <extra…>`
/// to completion and parses its one-line report.
pub fn probe_write(
    store: &Path,
    pass: &[u8],
    name: &[u8],
    value: &[u8],
    extra: &[String],
) -> ProbeRun {
    let mut args = vec![
        String::from("write"),
        store.display().to_string(),
        hex(pass),
        hex(name),
        hex(value),
    ];
    args.extend(extra.iter().cloned());
    let out = Command::new(probe_exe())
        .args(&args)
        .output()
        .expect("spawn probe");
    parse_probe(out.status.code().unwrap_or(-1) as u32, &out.stdout, &out.stderr)
}

fn parse_probe(code: u32, stdout: &[u8], stderr: &[u8]) -> ProbeRun {
    let stdout = String::from_utf8_lossy(stdout).into_owned();
    let stderr = String::from_utf8_lossy(stderr).into_owned();
    let mut parts = stdout.split_whitespace();
    let kind = parts.next().unwrap_or("");
    let (status, state, warnings) = match kind {
        "OK" => {
            let state = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let warnings = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            (0, state, warnings)
        }
        "ERR" => {
            let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let state = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            (status, state, 0)
        }
        _ => (0, 0, 0),
    };
    ProbeRun {
        code,
        status,
        state,
        warnings,
        stdout,
        stderr,
    }
}

/// `wsecret-crash-probe hold <store> <ready> <release>` as a spawned child
/// (the caller watches the ready marker and later creates the release file).
pub fn spawn_hold(store: &Path, ready: &Path, release: &Path) -> std::process::Child {
    Command::new(probe_exe())
        .arg("hold")
        .arg(store)
        .arg(ready)
        .arg(release)
        .spawn()
        .expect("spawn probe hold")
}

/// Waits (≤ 30 s) until `marker` exists.
pub fn wait_for(marker: &Path) {
    for _ in 0..6000 {
        if marker.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("marker {marker:?} never appeared");
}

/// Hex-encodes bytes for probe/driver argv.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A non-owning open handle to the store's `Global\wsecret-store-*` writer
/// mutex. Windows destroys a named mutex when its LAST handle closes, so a
/// killed owner's `WAIT_ABANDONED` is observable only while some other
/// writer still holds a handle — this guard models that surviving writer.
pub struct MutexKeepAlive(windows_sys::Win32::Foundation::HANDLE);

/// Keeps the store's writer-mutex kernel object alive across a kill.
pub fn keep_mutex_alive(store: &Path) -> MutexKeepAlive {
    use std::os::windows::ffi::OsStrExt;
    let file = std::fs::File::open(store).expect("open store for canonical path");
    let canonical = wsecret_core::windows::file::final_path(&file).expect("canonical final path");
    let name = wsecret_core::windows::security::writer_mutex_name(&canonical);
    let wide: Vec<u16> = std::ffi::OsStr::new(&name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: null security attributes + a valid name; the handle is checked.
    let handle = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null(),
            0,
            wide.as_ptr(),
        )
    };
    assert!(!handle.is_null(), "CreateMutexW for the keep-alive failed");
    MutexKeepAlive(handle)
}

impl Drop for MutexKeepAlive {
    fn drop(&mut self) {
        // SAFETY: owned handle.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

// ---------------------------------------------------------------------------
// pinned-upstream driver (WSL; the E4/E5 "readable by upstream" evidence and
// the E7 non-cooperating POSIX writer)
// ---------------------------------------------------------------------------

/// The WSL-side driver script (repo path, mounted at `/mnt/<drive>/…`).
fn driver_script() -> String {
    let repo = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR")
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf();
    // F:\Workspace\wsecret → /mnt/f/Workspace/wsecret
    let win = repo.display().to_string();
    let mut chars = win.chars();
    let drive = chars.next().unwrap().to_ascii_lowercase();
    let rest: String = chars.collect();
    let rest = rest.strip_prefix(':').unwrap_or(&rest).replace('\\', "/");
    format!("/mnt/{drive}{rest}")
}

/// True when WSL can run the pinned upstream binary (the oracle environment
/// used by `crates/wsecret-cli/tests/harness`). Tests record, not assume.
pub fn upstream_available() -> bool {
    Command::new("wsl.exe")
        .args(["--", "echo", "WSL-OK"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `secret dump NAME` against `store` via the pinned upstream binary.
/// `Ok(bytes)` when the record exists; `Err(())` when upstream reports it
/// missing (exit != 0).
pub fn upstream_dump(store: &Path, name: &[u8], pass: &[u8]) -> Result<Vec<u8>, ()> {
    let hex_out = upstream_run(&[
        "dump",
        &win_path(store),
        &hex(name),
        &hex(pass),
    ])?;
    let hex_out = hex_out.trim();
    Ok((0..hex_out.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_out[i..i + 2], 16).expect("hex"))
        .collect())
}

/// `secret set NAME` (value on stdin) via the pinned upstream binary — the
/// non-cooperating POSIX writer for E7. Returns the upstream exit code.
pub fn upstream_set(store: &Path, name: &[u8], pass: &[u8], value: &[u8]) -> i32 {
    upstream_run_code(&["set", &win_path(store), &hex(name), &hex(pass), &hex(value)])
}

/// `secret update NAME` (value on stdin) via the pinned upstream binary.
pub fn upstream_update(store: &Path, name: &[u8], pass: &[u8], value: &[u8]) -> i32 {
    upstream_run_code(&["update", &win_path(store), &hex(name), &hex(pass), &hex(value)])
}

fn win_path(p: &Path) -> String {
    // Forward slashes: `wsl.exe` argument forwarding eats backslashes.
    p.display().to_string().replace('\\', "/")
}

fn upstream_run(args: &[&str]) -> Result<String, ()> {
    let mut full = vec![
        String::from("--"),
        String::from("python3"),
        format!("{}/crates/wsecret-core/tests/support/upstream_drv.py", driver_script()),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = Command::new("wsl.exe").args(&full).output().expect("spawn wsl.exe");
    if !out.status.success() {
        eprintln!(
            "upstream_drv {:?} failed ({})\nstdout: {}\nstderr: {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn upstream_run_code(args: &[&str]) -> i32 {
    let mut full = vec![
        String::from("--"),
        String::from("python3"),
        format!("{}/crates/wsecret-core/tests/support/upstream_drv.py", driver_script()),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = Command::new("wsl.exe").args(&full).output().expect("spawn wsl.exe");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !stderr.trim().is_empty() {
        eprintln!("upstream_drv stderr: {stderr}");
    }
    if !out.status.success() {
        eprintln!(
            "upstream_drv {:?} failed ({})\nstdout: {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stdout),
        );
        return -1;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("driver prints exit code")
}
