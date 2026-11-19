//! Test harness for the byte-exact upstream cross-check tests.
//!
//! Two mechanisms, both driving the REAL `wsecret.exe` binary:
//!
//! 1. **Console session** ([`ConsoleSession`]): the tests run inside a real
//!    console. Passphrases are typed into the console input buffer with
//!    `WriteConsoleInputW` — the production prompt path (`CONIN$`, echo
//!    suppressed, `ReadConsoleW` line input), exactly like a user typing at
//!    a prompt (the harness waits for the child's echo-off before typing, so
//!    nothing is echoed back into the screen). Command output is captured
//!    byte-exact by redirecting the child's stdout to a file (`WriteFile`,
//!    no text mode), or — for terminal-rendering checks — as a real console
//!    child writing to the console screen buffer, which is read back
//!    verbatim. The console's DEFAULT screen buffer is never switched away
//!    from (probe-verified: `SetConsoleActiveScreenBuffer` in the parent
//!    breaks every subsequent `CreateProcessW` with
//!    `STATUS_DLL_INIT_FAILED`; a screen-buffer handle passed as std stdout
//!    breaks child init the same way) — the console-child shape passes
//!    `CONIN$`/`CONOUT$` through `SetStdHandle` and the standard-handle
//!    inheritance mechanism, exactly as a real console child receives them.
//!
//! 2. **Reference oracles** (no wsecret code involved): RFC 4226 HOTP via
//!    `BCrypt` HMAC-SHA1 (keyed independently of wsecret) and SHA-256 via
//!    `BCrypt`, plus the real pinned upstream `secret` binary running on
//!    Linux (WSL) for the same-window parity check (`upstream_show`).
//!
//! Fixture stores: `fixtures/stores/upstream-linux-origin.secret` — REAL
//! upstream-origin, generated on Linux by the pinned upstream binary per
//! `fixtures/stores/upstream-linux-origin.manifest.json` — plus the
//! wsecret-generated stand-ins of `fixtures/stores/` (same records, fresh
//! randomness; ciphertext equality is not a compatibility property).

#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_ALG_HANDLE_HMAC_FLAG, BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH,
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WriteFile,
};
use windows_sys::Win32::System::Console::{
    AllocConsole, CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_ECHO_INPUT,
    FillConsoleOutputCharacterW, FlushConsoleInputBuffer, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetStdHandle, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT_RECORD,
    KEY_EVENT_RECORD_0, ReadConsoleOutputCharacterW, WriteConsoleInputW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use wsecret_core::session::Session;
use wsecret_core::store::{ScanOutcome, Store};

// ---------------------------------------------------------------------------
// fixture constants (plan §7.2 / §4 overrides)
// ---------------------------------------------------------------------------

pub const PASS_A: &[u8] = b"correct horse battery staple";
pub const PASS_B: &[u8] = b"second";
pub const PASS_WRONG: &[u8] = b"not the passphrase";

/// `test` = `hello\n` (six bytes; the stored value carries the trailing LF).
pub const VALUE_TEST: &[u8] = b"hello\n";
/// `mykey` = the 32 bytes `00..1f`.
pub const VALUE_MYKEY: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
/// `test/totp` = ASCII `12345678901234567890` (RFC 4226 key, 20 bytes).
pub const VALUE_TOTP: &[u8] = b"12345678901234567890";
/// `test/totp32` = base32 of the same key plus a trailing LF (decoding stops
/// at `\n`, upstream `s_totp32`).
pub const VALUE_TOTP32: &[u8] = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
/// Tombstone `DELETED:test` = `old\n`.
pub const VALUE_TOMBSTONE: &[u8] = b"old\n";
/// `b1` (P_B partition) = `beta one\n`.
pub const VALUE_B1: &[u8] = b"beta one\n";
/// `b2` (P_B partition) = `beta two\n`.
pub const VALUE_B2: &[u8] = b"beta two\n";
/// `b3` (P_B partition) = the 256 bytes `00..ff`.
pub const VALUE_B3: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// File order of the P_A records of the fixture store.
pub const LIST_A: &[u8] = b"test\nmykey\ntest/totp\ntest/totp32\nDELETED:test\n";
/// File order of the P_B records (canonical corpus layout).
pub const LIST_B: &[u8] = b"b1\nb2\nb3\n";

/// `mykey` rendered as Base64 (console rendering of non-printable values).
pub const BASE64_MYKEY: &[u8] = b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The REAL Linux-origin fixture: generated on Linux (WSL) by the pinned
/// upstream `secret` binary following the exact command sequence recorded in
/// `fixtures/stores/manifest.json`, self-checked record by record by the
/// generator (`fixtures/tools/linux_oracle.py`).
pub fn linux_origin_fixture() -> PathBuf {
    workspace_root()
        .join("fixtures")
        .join("stores")
        .join("upstream-linux-origin.secret")
}

/// The wsecret-generated stand-ins of the canonical corpus (same records,
/// fresh randomness — ciphertext equality is not a compatibility property).
pub fn standin_fixtures() -> Vec<(String, PathBuf)> {
    let dir = workspace_root().join("fixtures").join("stores");
    let mut out = Vec::new();
    for name in ["linux-origin.secret", "mac-origin.secret"] {
        let path = dir.join(name);
        if path.exists() {
            out.push((name.to_string(), path));
        }
    }
    out
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// A fresh per-test store copy under the system temp dir (plan C11 fixture
/// reset rule: each mutating scenario starts from a fresh store).
pub fn temp_store(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "wsecret-xcheck-{tag}-{}.secret",
        std::process::id()
    ))
}

/// The `wsecret` binary under test (built before integration tests run).
pub fn wsecret_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wsecret"))
}

// ---------------------------------------------------------------------------
// fixture and mutation helpers (wsecret-core, the library under test)
// ---------------------------------------------------------------------------

/// Builds a fixture store with the exact record content of the canonical
/// corpus (`fixtures/stores/manifest.json`): P_A partition first in file
/// order, then the P_B partition. Fallback builder for hosts where the
/// committed stand-ins are absent.
pub fn build_fixture(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture dir");
    }
    let _ = fs::remove_file(path);
    let (mut store, _, _) = Store::create(path, 100_000).expect("create fixture store");
    let mut a = Session::unlock(store.header(), &mut PASS_A.to_vec()).expect("unlock P_A");
    for (name, value) in [
        (b"test".as_slice(), VALUE_TEST),
        (b"mykey", VALUE_MYKEY),
        (b"test/totp", VALUE_TOTP),
        (b"test/totp32", VALUE_TOTP32),
        (b"DELETED:test", VALUE_TOMBSTONE),
    ] {
        store
            .append_or_reuse(None, &a, name, value)
            .expect("append P_A record");
    }
    let mut b = Session::unlock(store.header(), &mut PASS_B.to_vec()).expect("unlock P_B");
    store
        .append_or_reuse(None, &b, b"b1", VALUE_B1)
        .expect("append P_B record");
    store
        .append_or_reuse(None, &b, b"b2", VALUE_B2)
        .expect("append P_B record");
    store
        .append_or_reuse(None, &b, b"b3", VALUE_B3)
        .expect("append P_B record");
    a.lock();
    b.lock();
    drop(store);
}

/// Every 512-byte block of the store, in file order.
pub fn blocks(path: &Path) -> Vec<[u8; 512]> {
    let raw = fs::read(path).expect("read store");
    assert_eq!(
        raw.len() % 512,
        0,
        "store length must be block-aligned: {}",
        raw.len()
    );
    raw.chunks_exact(512)
        .map(|c| {
            let mut b = [0u8; 512];
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// Byte offset of the first record with this exact name (P_B passphrases
/// locate the P_B slots).
pub fn slot_of(path: &Path, pass: &[u8], name: &[u8]) -> u64 {
    let (mut store, header) = Store::open(path).expect("open store");
    let mut session = Session::unlock(&header, &mut pass.to_vec()).expect("unlock");
    let slot = match store.find(&session, name, false).expect("find") {
        ScanOutcome::Found { slot, .. } => slot,
        other => panic!(
            "record {:?} not found: {other:?}",
            String::from_utf8_lossy(name)
        ),
    };
    session.lock();
    slot
}

// ---------------------------------------------------------------------------
// reference oracles (independent of wsecret)
// ---------------------------------------------------------------------------

/// RFC 4226 HOTP with RFC 6238 dynamic truncation, computed through BCrypt's
/// HMAC-SHA1 (no wsecret code involved).
pub fn oracle_hotp(key: &[u8], counter: u64) -> [u8; 6] {
    let h = hmac_sha1(key, &counter.to_be_bytes());
    let offset = (h[19] & 0x0f) as usize;
    let v = (u32::from_be_bytes([h[offset], h[offset + 1], h[offset + 2], h[offset + 3]])
        & 0x7fff_ffff)
        % 1_000_000;
    let s = format!("{v:06}");
    let mut out = [0u8; 6];
    out.copy_from_slice(s.as_bytes());
    out
}

/// HMAC-SHA1 via BCrypt.
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    bcryp_hash("SHA1", Some(key), msg, &mut out);
    out
}

/// SHA-256 via BCrypt.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    bcryp_hash("SHA256", None, data, &mut out);
    out
}

fn bcryp_hash(alg: &str, hmac_key: Option<&[u8]>, data: &[u8], out: &mut [u8]) {
    fn check(status: i32, what: &str) {
        if status != 0 {
            panic!("BCrypt {what} failed: {status:#x}");
        }
    }
    let alg_wide: Vec<u16> = OsStr::new(alg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: all handles are created and destroyed within this function;
    // buffers out-live every call below.
    unsafe {
        let mut alg_handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        let flags = if hmac_key.is_some() {
            BCRYPT_ALG_HANDLE_HMAC_FLAG
        } else {
            0
        };
        check(
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                alg_wide.as_ptr(),
                std::ptr::null(),
                flags,
            ),
            "OpenAlgorithmProvider",
        );
        let obj_len = property_u32(alg_handle as _, BCRYPT_OBJECT_LENGTH);
        let mut obj = vec![0u8; obj_len as usize];
        let mut hash: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let (key_ptr, key_len) = match hmac_key {
            Some(k) => (k.as_ptr(), k.len() as u32),
            None => (std::ptr::null(), 0),
        };
        check(
            BCryptCreateHash(
                alg_handle,
                &mut hash,
                obj.as_mut_ptr(),
                obj_len,
                key_ptr,
                key_len,
                0,
            ),
            "CreateHash",
        );
        if !data.is_empty() {
            check(
                BCryptHashData(hash, data.as_ptr(), data.len() as u32, 0),
                "HashData",
            );
        }
        check(
            BCryptFinishHash(hash, out.as_mut_ptr(), out.len() as u32, 0),
            "FinishHash",
        );
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    }
}

fn property_u32(
    handle: windows_sys::Win32::Security::Cryptography::BCRYPT_HANDLE,
    name: windows_sys::core::PCWSTR,
) -> u32 {
    let mut value = 0u32;
    let mut got = 0u32;
    // SAFETY: `handle` is live; `value` out-lives the call.
    let status = unsafe {
        BCryptGetProperty(
            handle,
            name,
            &mut value as *mut u32 as *mut u8,
            4,
            &mut got,
            0,
        )
    };
    if status != 0 {
        panic!("BCryptGetProperty failed: {status:#x}");
    }
    value
}

/// Minimal RFC 4648 base32 decode (for the `test/totp32` key derivation).
pub fn base32_decode(input: &[u8]) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'2'..=b'7' => u32::from(c - b'2') + 26,
            _ => panic!("invalid base32 byte {c:#x}"),
        }
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        if c == b'\n' || c == b'=' {
            break;
        }
        acc = (acc << 5) | value(c);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// upstream (Linux/WSL) oracle
// ---------------------------------------------------------------------------

/// Runs the pinned upstream `secret show NAME` on the Linux fixture in the
/// same 30 s window and returns its exact stdout bytes. `None` when no WSL
/// oracle is available on this host (the caller reports the skip loudly).
pub fn upstream_show(name: &str) -> Option<Vec<u8>> {
    let hex = upstream_oracle(&["show", name])?;
    let hex = hex.trim();
    assert!(hex.len() % 2 == 0, "oracle returned odd hex: {hex:?}");
    Some(
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect(),
    )
}

/// Repository-local oracle script expressed as a WSL mount path. Running the
/// checked-in file directly prevents a stale ~/.cache script from selecting
/// different upstream sources than the current checkout.
fn oracle_script() -> String {
    let win = workspace_root()
        .join("fixtures")
        .join("tools")
        .join("linux_oracle.py");
    let text = win.display().to_string();
    let mut chars = text.chars();
    let drive = chars.next().expect("drive letter").to_ascii_lowercase();
    let rest: String = chars.collect();
    let rest = rest.strip_prefix(':').unwrap_or(&rest).replace('\\', "/");
    format!("/mnt/{drive}{rest}")
}

fn upstream_oracle(args: &[&str]) -> Option<String> {
    let mut probe = Command::new("wsl.exe");
    probe.args(["--", "echo", "WSL-OK"]);
    if probe.output().map(|o| !o.status.success()).unwrap_or(true) {
        return None;
    }
    let mut script = format!("python3 {}", oracle_script());
    for a in args {
        script.push(' ');
        script.push_str(a);
    }
    let mut cmd = Command::new("wsl.exe");
    cmd.args(["--", "bash", "-lc", &script]);
    let out = cmd.output().expect("spawn wsl.exe oracle");
    if !out.status.success() {
        panic!(
            "upstream oracle {:?} failed ({})\nstdout: {}\nstderr: {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// console session (real console: typed prompts + screen read-back)
// ---------------------------------------------------------------------------

/// Serializes all console use: typing and screen-buffer switching are
/// per-console, so one test at a time.
static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

/// A real console session. The console's DEFAULT screen buffer is used and
/// never switched away from: probe-verified on this host that
/// `SetConsoleActiveScreenBuffer` in the parent breaks every subsequent
/// `CreateProcessW` with `STATUS_DLL_INIT_FAILED` (0xC0000142) — see
/// `fixtures/MANIFEST.md`. Each run marks the current cursor position first
/// and reads back only what the child wrote after the mark.
///
/// Passphrases are typed into the console input buffer exactly as a user
/// would; prompts and terminal-rendered output land on the console's own
/// screen buffer, which is read back verbatim (a real `CONIN$`/`CONOUT$`
/// console child — the production interaction).
pub struct ConsoleSession {
    _guard: std::sync::MutexGuard<'static, ()>,
    conout: HANDLE,
    conin: HANDLE,
}

impl ConsoleSession {
    pub fn new() -> ConsoleSession {
        let guard = CONSOLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // A console is required for the prompt path; create one when the
        // test process has none (headless hosts).
        let mut conin = open_conin();
        if conin == INVALID_HANDLE_VALUE {
            // SAFETY: AllocConsole attaches a fresh console to this process.
            unsafe {
                AllocConsole();
            }
            conin = open_conin();
        }
        if conin == INVALID_HANDLE_VALUE {
            panic!("no console available for prompt tests: {}", last_error());
        }
        let conout = open_conout();
        if conout == INVALID_HANDLE_VALUE {
            panic!(
                "no console output available for prompt tests: {}",
                last_error()
            );
        }
        ConsoleSession {
            _guard: guard,
            conout,
            conin,
        }
    }

    /// The console screen buffer handle (a real console handle:
    /// `GetConsoleMode` succeeds on it).
    pub fn hidden(&self) -> HANDLE {
        self.conout
    }

    /// Blank the whole screen buffer (cursor untouched): the next run's
    /// output is exactly the non-blank rows, which is scroll-proof (a
    /// scrolled buffer shifts content and cursor together).
    pub fn reset(&self) {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: live handle, out-param.
        unsafe {
            if GetConsoleScreenBufferInfo(self.conout, &mut info) == 0 {
                panic!("GetConsoleScreenBufferInfo failed: {}", last_error());
            }
            let total = info.dwSize.X as u32 * info.dwSize.Y as u32;
            let mut written = 0u32;
            if FillConsoleOutputCharacterW(
                self.conout,
                u16::from(b' '),
                total,
                COORD { X: 0, Y: 0 },
                &mut written,
            ) == 0
            {
                panic!("FillConsoleOutputCharacterW failed: {}", last_error());
            }
        }
    }

    /// Types one line (terminated by Enter) into the console input buffer.
    pub fn type_line(&self, text: &str) {
        type_line(self.conin, text);
    }

    /// Types one line WITHOUT flushing the input buffer first (multi-prompt
    /// flows: a previously typed line may still be queued for the child).
    pub fn type_line_queued(&self, text: &str) {
        type_line_queued(self.conin, text);
    }

    /// The run's console rows (trailing blanks per row trimmed, blank rows
    /// between content rows kept) and the cursor row RELATIVE to the first
    /// content row (counts trailing newline advances).
    pub fn read_screen(&self) -> (Vec<String>, i16) {
        read_screen_since(self.conout)
    }
}

impl Drop for ConsoleSession {
    fn drop(&mut self) {
        // SAFETY: live console handles owned by this value.
        unsafe {
            CloseHandle(self.conout);
            CloseHandle(self.conin);
        }
    }
}

fn open_conin() -> HANDLE {
    open_console_device("CONIN$")
}

fn open_conout() -> HANDLE {
    open_console_device("CONOUT$")
}

pub fn open_console_device(name: &str) -> HANDLE {
    let w: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `w` is a NUL-terminated device name; the result is checked.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    h
}

/// The run's console rows after a [`ConsoleSession::reset`] fill: the
/// contiguous span of non-blank rows (blank rows between content rows are
/// kept), plus the cursor row RELATIVE to the first content row.
fn read_screen_since(handle: HANDLE) -> (Vec<String>, i16) {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: live handle, out-param.
    unsafe {
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            panic!("GetConsoleScreenBufferInfo failed: {}", last_error());
        }
    }
    let rows = info.dwSize.Y as usize;
    let cols = info.dwSize.X as usize;
    let mut lines = Vec::with_capacity(rows);
    for y in 0..rows {
        let mut buf = vec![0u16; cols];
        let mut got = 0u32;
        // SAFETY: live handle, valid buffer.
        let ok = unsafe {
            ReadConsoleOutputCharacterW(
                handle,
                buf.as_mut_ptr(),
                cols as u32,
                COORD { X: 0, Y: y as i16 },
                &mut got,
            )
        };
        if ok == 0 {
            panic!("ReadConsoleOutputCharacterW failed: {}", last_error());
        }
        let text: String = buf[..got as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('\u{fffd}'))
            .collect();
        lines.push(text.trim_end().to_string());
    }
    // The run's span: first to last non-blank row (everything else is the
    // pre-run fill).
    let first = lines.iter().position(|l| !l.is_empty());
    let Some(first) = first else {
        return (Vec::new(), 0);
    };
    let last = lines.iter().rposition(|l| !l.is_empty()).unwrap_or(first);
    (
        lines[first..=last].to_vec(),
        info.dwCursorPosition.Y - first as i16,
    )
}

fn type_line(conin: HANDLE, text: &str) {
    // Drop any stale input left over from a previous run (upstream never
    // flushes; wsecret's type-ahead preservation applies to the USER, not to
    // the test harness between independent commands).
    // SAFETY: live console input handle.
    unsafe {
        FlushConsoleInputBuffer(conin);
    }
    type_line_queued(conin, text);
}

/// The un-flushed half of [`type_line`]: a follow-up line for the SAME run
/// (e.g. the new-partition confirmation retype) must not discard the
/// previous line before the child consumes it.
fn type_line_queued(conin: HANDLE, text: &str) {
    // Type exactly when the child has echo suppressed — the production
    // sequence is prompt → clear `ENABLE_ECHO_INPUT` → read. Injecting
    // earlier would be echoed by the console host (including the Enter),
    // adding a stray newline advance to the prompt row; a real user cannot
    // beat that window, and the mode check makes the harness deterministic.
    wait_for_echo_off(conin);
    let mut events = Vec::new();
    for ch in text.encode_utf16() {
        events.push(key_event(ch, true));
    }
    events.push(key_event(u16::from(b'\r'), true));
    // Writing into a full input buffer blocks (or fails) until the reader
    // consumes; run it off-thread so a stalled child cannot hang the test.
    // `HANDLE` is not `Send`, so the value crosses as its raw integer form.
    let conin_value = conin as usize;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let conin = conin_value as HANDLE;
        for event in events {
            write_input_event(conin, event);
        }
        let _ = tx.send(());
    });
    if rx.recv_timeout(Duration::from_secs(30)).is_err() {
        panic!("console typing stalled (child never read its passphrase prompt)");
    }
}

/// Waits until the child has disabled `ENABLE_ECHO_INPUT` on the console
/// input buffer (the exact moment it is about to read the prompt).
fn wait_for_echo_off(conin: HANDLE) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut mode = 0u32;
        // SAFETY: live console input handle, out-param.
        let ok = unsafe { GetConsoleMode(conin, &mut mode) };
        if ok != 0 && mode & ENABLE_ECHO_INPUT == 0 {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "child never reached its echo-suppressed prompt (console mode {mode:#x}); \
                 expected a `Passphrase: ` prompt"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn key_event(ch: u16, down: bool) -> INPUT_RECORD {
    INPUT_RECORD {
        EventType: 1, // KEY_EVENT
        Event: INPUT_RECORD_0 {
            KeyEvent: KEY_EVENT_RECORD {
                bKeyDown: i32::from(down),
                wRepeatCount: 1,
                wVirtualKeyCode: if ch == u16::from(b'\r') { 0x0d } else { 0 },
                wVirtualScanCode: 0,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: ch },
                dwControlKeyState: 0,
            },
        },
    }
}

fn write_input_event(conin: HANDLE, event: INPUT_RECORD) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut written = 0u32;
        // SAFETY: live console input handle; `event` is a valid record.
        let ok = unsafe { WriteConsoleInputW(conin, &event, 1, &mut written) };
        if ok != 0 && written == 1 {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("WriteConsoleInputW failed: {}", last_error());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// child process plumbing
// ---------------------------------------------------------------------------

/// One completed `wsecret` run. `stdout` is the exact redirected stdout
/// bytes (console runs return the empty vec — their output is read back from
/// the screen buffer instead).
pub struct Run {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Where the child's stdout goes.
#[derive(Clone, Copy)]
pub enum ChildStdout<'a> {
    /// Redirected to this file: exact bytes (the `WriteFile` path).
    CaptureFile(&'a Path),
    /// The hidden console screen buffer: terminal rendering.
    Console,
}

/// Runs `wsecret ARGS` against `store`, typing `passphrase` at the real
/// console prompt (`CONIN$`, the production input path).
pub fn run_wsecret(
    session: &ConsoleSession,
    store: &Path,
    args: &[&str],
    passphrase: &str,
    stdin: Option<&[u8]>,
    stdout: ChildStdout<'_>,
) -> Run {
    run_wsecret_lines(session, store, args, &[passphrase], stdin, stdout)
}

/// [`run_wsecret`] with one typed line per console prompt.
///
/// Two shapes (probe-verified on this host, see `fixtures/MANIFEST.md`):
///
/// - [`ChildStdout::CaptureFile`]: exact redirected I/O — stdin/stdout/stderr
///   are explicit handles on the child's inherit list.
/// - [`ChildStdout::Console`]: the REAL console-child shape — the child
///   attaches to our console and receives `CONIN$`/`CONOUT$` through the
///   standard-handle mechanism (`SetStdHandle`, probe-verified).
///
/// `lines` may be EMPTY for runs that must exit without reading `CONIN$`
/// (store-header fatals happen before any prompt — typing there would stall
/// forever). Follow-up lines are queued without flushing the input buffer so
/// an already-typed line cannot be discarded before the child consumes it
/// (multi-prompt flows: passphrase + the new-partition confirmation retype).
pub fn run_wsecret_lines(
    session: &ConsoleSession,
    store: &Path,
    args: &[&str],
    lines: &[&str],
    stdin: Option<&[u8]>,
    stdout: ChildStdout<'_>,
) -> Run {
    run_wsecret_lines_env(session, store, args, lines, stdin, stdout, &[])
}

/// [`run_wsecret_lines`] with extra child-environment entries applied AFTER
/// the built-in `SECRET_STORE` pin and `SECRET_AGENT` scrub. The fail-closed
/// regressions use this to place a legacy `SECRET_AGENT` value in the child
/// and prove it cannot bypass the ordinary unlock.
pub fn run_wsecret_lines_env(
    session: &ConsoleSession,
    store: &Path,
    args: &[&str],
    lines: &[&str],
    stdin: Option<&[u8]>,
    stdout: ChildStdout<'_>,
    extra_env: &[(&str, &OsStr)],
) -> Run {
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    env.retain(|(k, _)| k != "SECRET_STORE" && k != "SECRET_AGENT");
    env.push((
        OsString::from("SECRET_STORE"),
        store.as_os_str().to_os_string(),
    ));
    for (name, value) in extra_env {
        env.push((OsString::from(name), value.to_os_string()));
    }
    let env_block = env_block(&env);

    let (process, handles) = match stdout {
        ChildStdout::Console => {
            assert!(
                stdin.is_none(),
                "console runs carry no redirected stdin (the child reads its console)"
            );
            session.reset();
            let conin = open_console_device("CONIN$");
            let conout = session.hidden();
            unsafe {
                use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
                SetHandleInformation(conin, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            }
            let restore = swap_std_handles(conin, conout);
            let process = create_console_process(&wsecret_exe(), args, &env_block);
            restore();
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(conin);
            }
            (process, Vec::new())
        }
        ChildStdout::CaptureFile(path) => {
            let err_path =
                std::env::temp_dir().join(format!("wsecret-xcheck-err-{}.bin", std::process::id()));
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(&err_path);
            let stdout_handle = open_file(path, true);
            let stderr_handle = open_file(&err_path, true);
            let stdin_handle = make_stdin(stdin.unwrap_or(&[]));
            let inherit = vec![stdin_handle, stdout_handle, stderr_handle];
            let process = create_process(&wsecret_exe(), args, &env_block, inherit.clone());
            (process, inherit)
        }
    };

    // The console prompt is the real production input path; type one line
    // per prompt (none for no-prompt runs).
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            session.type_line(line);
        } else {
            session.type_line_queued(line);
        }
    }

    // SAFETY: live process handle.
    let wait = unsafe { WaitForSingleObject(process, 60_000) };
    if wait != WAIT_OBJECT_0 {
        // SAFETY: live process handle.
        unsafe { TerminateProcess(process, 99) };
        panic!("wsecret {args:?} did not exit within 60 s");
    }
    let mut code = 0u32;
    // SAFETY: live process handle.
    unsafe {
        GetExitCodeProcess(process, &mut code);
        CloseHandle(process);
    }
    for handle in handles {
        // SAFETY: live handles created above.
        unsafe { CloseHandle(handle) };
    }

    let (stdout, stderr) = match stdout {
        ChildStdout::CaptureFile(path) => {
            let err_path =
                std::env::temp_dir().join(format!("wsecret-xcheck-err-{}.bin", std::process::id()));
            let out = fs::read(path).expect("read captured stdout");
            let err = fs::read(&err_path).unwrap_or_default();
            let _ = fs::remove_file(&err_path);
            (out, err)
        }
        // Console output lives on the screen buffer; read it back from there.
        ChildStdout::Console => (Vec::new(), Vec::new()),
    };
    Run {
        code,
        stdout,
        stderr,
    }
}

/// Replaces this process's standard handles for the duration of a spawn and
/// returns a closure restoring them (probe-verified: console children adopt
/// `CONIN$`/`CONOUT$` through `GetStdHandle`, no inherit list needed).
fn swap_std_handles(conin: HANDLE, conout: HANDLE) -> impl FnOnce() {
    use windows_sys::Win32::System::Console::{
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
    };
    // SAFETY: `GetStdHandle`/`SetStdHandle` operate on this process's slots.
    let (old_in, old_out, old_err) = unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        )
    };
    // SAFETY: slot writes are plain handle swaps.
    unsafe {
        SetStdHandle(STD_INPUT_HANDLE, conin);
        SetStdHandle(STD_OUTPUT_HANDLE, conout);
        SetStdHandle(STD_ERROR_HANDLE, conout);
    }
    move || {
        // SAFETY: restoring this process's own saved handles.
        unsafe {
            SetStdHandle(STD_INPUT_HANDLE, old_in);
            SetStdHandle(STD_OUTPUT_HANDLE, old_out);
            SetStdHandle(STD_ERROR_HANDLE, old_err);
        }
    }
}

/// The console-child spawn: no std-handle override, no inherit list — the
/// child attaches to this console and gets `CONIN$`/`CONOUT$` through the
/// standard-handle mechanism.
fn create_console_process(exe: &Path, args: &[&str], env_block: &[u16]) -> HANDLE {
    let mut cmdline = quote(exe.as_os_str());
    for a in args {
        cmdline.push(u16::from(b' '));
        cmdline.extend(quote(OsStr::new(a)));
    }
    cmdline.push(0);
    let app: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: NUL-terminated wide buffers; no attribute list, no std handles.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            env_block.as_ptr() as *const _,
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: live thread handle from a successful creation.
    unsafe {
        CloseHandle(pi.hThread);
    }
    if ok == 0 {
        panic!("CreateProcessW({exe:?} {args:?}) failed: {}", last_error());
    }
    pi.hProcess
}

/// A child stdin pipe pre-filled with `data` (write end closed: EOF).
/// Returns the child-side (inheritable) read handle.
pub fn make_stdin(data: &[u8]) -> HANDLE {
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: out-params receive fresh handles.
    unsafe {
        if CreatePipe(&mut read, &mut write, std::ptr::null(), 0) == 0 {
            panic!("CreatePipe(stdin) failed: {}", last_error());
        }
    }
    if !data.is_empty() {
        write_all(write, data);
    }
    // SAFETY: live handle.
    unsafe {
        CloseHandle(write);
    }
    let child_end = dup_inheritable(read);
    // SAFETY: live handle.
    unsafe {
        CloseHandle(read);
    }
    child_end
}

fn write_all(handle: HANDLE, mut data: &[u8]) {
    while !data.is_empty() {
        let mut written = 0u32;
        // SAFETY: live handle, valid buffer.
        let ok = unsafe {
            WriteFile(
                handle,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            panic!("WriteFile failed: {}", last_error());
        }
        data = &data[written as usize..];
    }
}

pub fn open_file(path: &Path, write: bool) -> HANDLE {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    let w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let access = if write { GENERIC_WRITE } else { GENERIC_READ };
    // SAFETY: NUL-terminated path; the handle is checked below.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            2, // CREATE_ALWAYS
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        panic!("CreateFileW({path:?}) failed: {}", last_error());
    }
    // Handles on the `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` must be inheritable.
    // SAFETY: live handle.
    unsafe {
        if SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            panic!("SetHandleInformation failed: {}", last_error());
        }
    }
    h
}

pub fn dup_inheritable(src: HANDLE) -> HANDLE {
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: both processes are the current process; `src` is live.
    unsafe {
        if DuplicateHandle(
            GetCurrentProcess(),
            src,
            GetCurrentProcess(),
            &mut dup,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            panic!("DuplicateHandle failed: {}", last_error());
        }
    }
    dup
}

fn last_error() -> i32 {
    // SAFETY: pure query.
    unsafe { GetLastError() as i32 }
}

/// `GetConsoleMode` succeeds on the handle: it really is a console handle
/// (upstream `isatty(1)` equivalent). Asserted by the console-rendering
/// tests so "on a console" claims cannot silently degrade to pipe behavior.
pub fn is_console_handle(handle: HANDLE) -> bool {
    let mut mode = 0u32;
    // SAFETY: live handle, out-param.
    unsafe { GetConsoleMode(handle, &mut mode) != 0 }
}

/// `CreateProcessW` with `STARTF_USESTDHANDLES` and an explicit inherit
/// handle list: exactly the listed handles reach the child.
pub fn create_process(
    exe: &Path,
    args: &[&str],
    env_block: &[u16],
    inherit: Vec<HANDLE>,
) -> HANDLE {
    let mut cmdline = quote(exe.as_os_str());
    for a in args {
        cmdline.push(u16::from(b' '));
        cmdline.extend(quote(OsStr::new(a)));
    }
    cmdline.push(0);
    let app: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut attr_size = 0usize;
    // SAFETY: sizing call (documented two-step pattern).
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    }
    let words = attr_size.div_ceil(std::mem::size_of::<usize>());
    let mut attr_buf = vec![0usize; words];
    let attr_list = attr_buf.as_mut_ptr()
        as windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: freshly allocated, sized per the OS request.
    unsafe {
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) == 0 {
            panic!("InitializeProcThreadAttributeList failed: {}", last_error());
        }
        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherit.as_ptr() as *const _,
            inherit.len() * std::mem::size_of::<HANDLE>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            panic!("UpdateProcThreadAttribute failed: {}", last_error());
        }
    }

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = inherit[0];
    si.StartupInfo.hStdOutput = inherit[1];
    si.StartupInfo.hStdError = inherit[2];
    si.lpAttributeList = attr_list;

    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: all buffers are valid NUL-terminated wide strings; the
    // attribute list covers exactly the inherit handles.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_ptr() as *const _,
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: initialized list.
    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        CloseHandle(pi.hThread);
    }
    if ok == 0 {
        panic!("CreateProcessW({exe:?} {args:?}) failed: {}", last_error());
    }
    pi.hProcess
}

fn quote(arg: &OsStr) -> Vec<u16> {
    let w: Vec<u16> = arg.encode_wide().collect();
    let special = w.is_empty() || w.iter().any(|&c| matches!(c, 9 | 10 | 11 | 32 | 34));
    if !special {
        return w;
    }
    let mut out = vec![u16::from(b'"')];
    let mut backslashes = 0usize;
    for c in w {
        match c {
            92 => backslashes += 1,
            34 => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push(u16::from(b'\\'));
                }
                out.push(c);
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push(u16::from(b'\\'));
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push(u16::from(b'\\'));
    }
    out.push(u16::from(b'"'));
    out
}

pub fn env_block(vars: &[(OsString, OsString)]) -> Vec<u16> {
    let mut entries: Vec<Vec<u16>> = vars
        .iter()
        .map(|(k, v)| {
            let mut e: Vec<u16> = OsStr::new(k).encode_wide().collect();
            e.push(u16::from(b'='));
            e.extend(OsStr::new(v).encode_wide());
            e
        })
        .collect();
    entries.sort_by_key(|e| {
        let eq = e
            .iter()
            .position(|&c| c == u16::from(b'='))
            .unwrap_or(e.len());
        e[..eq]
            .iter()
            .map(|&c| if (65..=90).contains(&c) { c + 32 } else { c })
            .collect::<Vec<u16>>()
    });
    let mut block = Vec::new();
    for e in entries {
        block.extend_from_slice(&e);
        block.push(0);
    }
    block.push(0);
    block
}
