//! Native-only agent-capability bridge (plan §3.4): `AgentCapability` and
//! `AgentPipe` for the trusted-agent handoff protocol (plan §5.2/§5.8).
//!
//! This module is one of the two sanctioned `unsafe` modules (the other is
//! `libhydrogen-sys`); the CLI crate contains **no** unsafe code and drives
//! the protocol only through the safe facades below. No message byte ever
//! appears in a public signature: the 81-byte message
//! (`WSECRET1` ‖ 41-byte header ‖ 32-byte key, plan §5.2 step 4) is built,
//! written, peeked and validated entirely inside this module.
//!
//! Wire contract (plan §1.9/§5.2, the Windows adaptation of upstream
//! `s_agent`/`s_ask_agent`):
//!
//! - **Launch**: [`AgentCapability::from_session`] drains the key out of an
//!   unlocked [`Session`] into a secure buffer; [`AgentPipe::create`] makes a
//!   non-inheritable pipe whose security descriptor carries a
//!   **proper empty DACL** (an empty DACL denies every new open — a NULL
//!   DACL would grant everyone, plan §5.2 step 5; the probe-verified
//!   server-side named-pipe realization of that rule is documented on
//!   [`AgentPipe`]); the message is written
//!   into the pipe buffer **before** the child exists, so the buffered bytes
//!   are ready for a non-blocking peek on day one;
//!   [`AgentPipe::mark_read_inheritable`] marks only the read handle
//!   inheritable, and [`spawn_trusted_child`] passes that handle through
//!   `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (plus deliberately duplicated std
//!   handles — nothing else inherits) and closes the launcher's own pipe
//!   handles immediately after `CreateProcessW`.
//! - **Acquisition**: [`AgentPipe::peek_adopt`] / [`adopt_from_handle_value`]
//!   peek the buffered message
//!   **without consuming it** (upstream `MSG_PEEK` semantics — every
//!   descendant of the trusted shell can adopt the key), requires exactly 81
//!   bytes available, checks the `WSECRET1` magic and compares the embedded
//!   header to the store header just read in constant time
//!   ([`libhydrogen_sys::equal`]). A match adopts the 32-byte key into a
//!   session marked [`UnlockEvidence::AgentAuthorized`]; any mismatch
//!   zeroizes the peek buffer and returns `Ok(None)` — the caller falls back
//!   to the passphrase path (upstream: mismatch zeroes the key and re-prompts).
//!
//! # Narrowed assurance (audit P13) — READ THIS
//!
//! Header equality alone authorizes the adopting process *without* any record
//! decryption. A forged message carrying an attacker key therefore makes all
//! existing records fail authentication, but the adopter will happily ENCRYPT
//! newly entered secrets (`set`/`new`) under the attacker's key and derive
//! deterministic secrets from it. The launching environment and the inherited
//! handle are consequently **trusted inputs**: a malicious launcher can
//! capture future secret entries. This is upstream's exact behavior (its
//! `s_ask_agent` does the same). It is NOT evidence that an unrelated process
//! can acquire the real pipe: the pipe DACL denies every new open and handle
//! numbers are meaningless outside the inheriting process tree.
//!
//! # Teardown (plan §5.2)
//!
//! Each process zeroizes its session and closes its handles on
//! return/unwind ([`AgentCapability`] and [`AgentPipe`] zeroize/close on
//! drop, [`Session::lock`] is idempotent); the pipe dies when the last handle
//! closes, destroying the buffered message with it. Shell exit is NOT
//! revocation for detached descendants, and there is no idle timeout
//! (upstream has none; a timeout would not revoke copies already made).

use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, InitializeAcl,
    PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_PIPE,
    GetFileType, GetFullPathNameW, OPEN_EXISTING, PIPE_ACCESS_OUTBOUND, SYNCHRONIZE, SearchPathW,
    WriteFile,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
    INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::security::{ProcessBirthSecurity, verify_birth_objects};
use crate::error::Error;
use crate::format::{HEADER_LEN, Header};
use crate::session::{SecretBytes, Session, UnlockEvidence};

/// The agent transport environment variable (plan §5.2; upstream `S_ENV_AGENT`).
pub const ENV_AGENT: &str = "SECRET_AGENT";

/// Agent magic: 8 ASCII bytes `WSECRET1` (plan §5.2 step 4).
pub const AGENT_MAGIC: [u8; 8] = *b"WSECRET1";
/// Full agent message: magic (8) + upstream header (41) + key (32).
pub const AGENT_MSG_LEN: usize = 8 + HEADER_LEN + 32;
/// Offset of the 41-byte upstream header inside the message.
pub const AGENT_HEADER_OFF: usize = 8;
/// Offset of the 32-byte derived key inside the message.
pub const AGENT_KEY_OFF: usize = 8 + HEADER_LEN;

/// Explicit 41-byte header encoding (plan §1.2/§5.2 step 4: "explicit byte
/// encoding; no struct serialization"): `version[1] master[32] ops_limit[8 LE]`
/// — byte-identical to the first 41 bytes of the store's header block, which
/// is what upstream `s_ask_agent` compares against.
fn encode_header(header: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = header.version;
    out[1..33].copy_from_slice(&header.master);
    out[33..41].copy_from_slice(&header.ops_limit.to_le_bytes());
    out
}

/// A one-shot, zeroizing copy of an unlocked session key plus the exact store
/// header (plan §3.4: opaque capability; no message bytes in any public
/// signature).
///
/// Created with [`AgentCapability::from_session`] (which drains the session)
/// and consumed **by value** by [`AgentCapability::write_to_pipe`]. The
/// secure buffer is zeroized on drop on every outcome — success, partial
/// write or error — and the error never carries key material.
pub struct AgentCapability {
    /// `WSECRET1` ‖ 41-byte header ‖ 32-byte key, in a locked secure buffer.
    msg: SecretBytes,
}

impl AgentCapability {
    /// Moves the key out of `session` into this capability's secure buffer
    /// (plan §3.4). The session is left **locked/drained** — `&mut` makes the
    /// move sound. On failure the session is untouched; on success it is
    /// drained before this function returns.
    pub fn from_session(session: &mut Session) -> Result<AgentCapability, Error> {
        if session.is_locked() {
            return Err(Error::Locked);
        }
        let header = session.header().clone();
        // Transient plaintext copy of the key (per-operation decrypt window).
        let key = session.with_key(|k| *k)?;
        let mut msg = SecretBytes::new(AGENT_MSG_LEN)?;
        {
            let buf = msg.as_mut_slice();
            buf[0..8].copy_from_slice(&AGENT_MAGIC);
            buf[AGENT_HEADER_OFF..AGENT_HEADER_OFF + HEADER_LEN]
                .copy_from_slice(&encode_header(&header));
            buf[AGENT_KEY_OFF..AGENT_KEY_OFF + 32].copy_from_slice(&key);
        }
        // `key` (a plain stack copy) is erased before returning.
        let mut key = key;
        libhydrogen_sys::memzero(&mut key);
        // Drain the source session: the capability now owns the only copy.
        session.lock();
        Ok(AgentCapability { msg })
    }

    /// Writes the capability message into the pipe buffer and **consumes the
    /// capability by value** (plan §3.4 one-shot rule): on every outcome the
    /// capability's secure buffer is zeroized on drop and the error carries
    /// no key material. The write must deliver EXACTLY [`AGENT_MSG_LEN`]
    /// bytes (plan §5.2 step 6: "require exact write").
    ///
    /// The pipe is consumed and handed back so the launcher keeps owning the
    /// handles it still needs (mark-read-inheritable → spawn → close): the
    /// security-relevant rule — the capability is consumed BY VALUE, so a
    /// second write is impossible — holds exactly as specified. On write
    /// failure the pipe is dropped with the error (handles closed, buffered
    /// message destroyed: plan §5.2 "Launch failure → close both ends").
    pub fn write_to_pipe(self, pipe: AgentPipe) -> Result<AgentPipe, Error> {
        match pipe.write_exact(self.msg.as_slice()) {
            // `self` drops on both paths — buffer zeroized.
            Ok(()) => Ok(pipe),
            Err(e) => {
                drop(pipe);
                Err(e)
            }
        }
    }

    /// The exact 81-byte message (in-module use and tests only — never
    /// exposed in a public signature).
    #[cfg(test)]
    fn message(&self) -> &[u8] {
        self.msg.as_slice()
    }
}

impl Drop for AgentCapability {
    fn drop(&mut self) {
        // `SecretBytes::drop` zeroizes too; `clear` makes the intent explicit.
        self.msg.clear();
    }
}

/// An opaque, platform-owned pipe wrapper (plan §3.4): created only by
/// [`AgentPipe::create`], carrying a **proper empty DACL**. It owns both pipe
/// handles and closes them on drop.
///
/// # Why a server-side named pipe (probe-verified, 2026-11-17)
///
/// Plan §5.2 step 5 asks for `CreatePipe` with "a proper empty DACL — empty
/// denies all **new** opens; null grants everyone". Two Windows realities
/// make the literal recipe impossible (verified by direct probe on this
/// host):
///
/// 1. `CreatePipe` **access-checks the passed `SECURITY_ATTRIBUTES` at
///    creation**: an empty DACL denies the creator too — `CreatePipe` returns
///    `ERROR_ACCESS_DENIED` and NO handles (null DACL succeeds). The DACL is
///    not merely "deny future opens"; it is checked before the handles exist.
/// 2. Anonymous-pipe handles are opened without `WRITE_DAC`, and pipe objects
///    do not support `DuplicateHandle` access upgrades (`ERROR_ACCESS_DENIED`)
///    — so the DACL can never be tightened after creation either.
///
/// The one probe-verified realization of the plan's security GOAL is a
/// server-side named pipe: its creation handle can carry `WRITE_DAC`
/// (`READ_CONTROL` is rejected in `dwOpenMode`; `PIPE_ACCESS_OUTBOUND |
/// WRITE_DAC` succeeds), the client (read) end is opened through the pipe's
/// default descriptor BEFORE the tighten, and `SetSecurityInfo(
/// DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, empty
/// ACL)` then replaces the DACL with the **proper empty DACL** — exactly the
/// plan's "empty denies all new opens": a probe `CreateFileW` on the name
/// afterwards fails with `ERROR_ACCESS_DENIED` even for the creator, while
/// already-open handles keep working (I/O performs no new access checks).
/// Probe also verified: 81 bytes written before the launcher closes the
/// server end remain `PeekNamedPipe`-visible (`got=81 avail=81`) afterwards,
/// i.e. in the exact post-spawn state, and the peek remains non-consuming.
///
/// The name is unguessable (`wsecret-<pid>-<counter>`) and its only secret
/// role is squatting resistance before the tighten; the empty DACL is what
/// denies new opens. A NULL DACL (the plan's explicit anti-goal) would grant
/// everyone.
pub struct AgentPipe {
    /// Read end (the child's inherited handle).
    read: HANDLE,
    /// Write end; closed by the launcher as soon as the child exists.
    write: HANDLE,
}

impl AgentPipe {
    /// Creates the pipe for the agent handoff (plan §5.2 step 5): both
    /// handles non-inheritable, empty DACL in force before this returns.
    /// See the type docs for the probe-verified named-pipe realization.
    pub fn create() -> Result<AgentPipe, Error> {
        // Zero-ACE ACL: just the ACL header (`InitializeAcl` writes a valid
        // empty ACL; no ACE is ever added).
        let mut acl = [0u8; 8];
        // SAFETY: 8 bytes is exactly the ACL header; revision matches.
        if unsafe { InitializeAcl(acl.as_mut_ptr() as *mut ACL, acl.len() as u32, ACL_REVISION) }
            == 0
        {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        // Unique unguessable pipe name (squatter resistance before tighten).
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: process-id query, no preconditions.
        let pid = unsafe { GetCurrentProcessId() };
        let name_str = format!(r"\\.\pipe\wsecret-{pid}-{seq}");
        let mut name: Vec<u16> = std::ffi::OsStr::new(&name_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Server end = write end, opened with PIPE_ACCESS_OUTBOUND | WRITE_DAC
        // (probe: adding READ_CONTROL to dwOpenMode is ERROR_INVALID_PARAMETER).
        const WRITE_DAC: u32 = 0x0004_0000;
        let write = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND | WRITE_DAC,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,           // max instances
                4096,        // out buffer (holds the 81-byte message)
                4096,        // in buffer
                0,           // default timeout
                ptr::null(), // default security descriptor
            )
        };
        if write == INVALID_HANDLE_VALUE {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        // Client end = read end, opened through the DEFAULT descriptor while
        // the name is known only to this process (pre-tighten window).
        let read = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if read == INVALID_HANDLE_VALUE {
            let e = io::Error::last_os_error();
            unsafe { CloseHandle(write) };
            return Err(Error::Io(e));
        }

        // Tighten: replace the DACL with the PROPER EMPTY DACL (probe:
        // SetSecurityInfo returns 0 via the WRITE_DAC handle; a fresh open of
        // the name afterwards is denied even for the creator).
        // SAFETY: `acl` is the just-initialized zero-ACE ACL; `write` holds
        // WRITE_DAC by construction above.
        let status = unsafe {
            SetSecurityInfo(
                write,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl.as_ptr() as *const ACL,
                ptr::null(),
            )
        };
        if status != 0 {
            let e = io::Error::from_raw_os_error(status as i32);
            unsafe {
                CloseHandle(write);
                CloseHandle(read);
            }
            return Err(Error::Io(e));
        }
        // The name has served its purpose; scrub the local copy.
        for c in &mut name {
            *c = 0;
        }
        Ok(AgentPipe { read, write })
    }

    fn write_exact(&self, msg: &[u8]) -> Result<(), Error> {
        debug_assert_eq!(msg.len(), AGENT_MSG_LEN);
        if msg.len() != AGENT_MSG_LEN {
            return Err(Error::Agent(crate::error::AgentError::Unavailable));
        }
        let mut written: u32 = 0;
        // SAFETY: `self.write` is a live pipe write handle owned by `self`;
        // `msg` is valid for the requested length.
        let ok = unsafe {
            WriteFile(
                self.write,
                msg.as_ptr(),
                msg.len() as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 || written as usize != msg.len() {
            return Err(Error::Agent(crate::error::AgentError::Unavailable));
        }
        Ok(())
    }

    /// Marks ONLY the read handle inheritable (plan §5.2 step 6); the write
    /// handle stays non-inheritable and is never listed. Per the
    /// `UpdateProcThreadAttribute` contract, handles passed through
    /// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` must be marked inheritable — the
    /// handle LIST itself is what guarantees "nothing else inherits".
    pub fn mark_read_inheritable(&mut self) -> Result<(), Error> {
        // SAFETY: `self.read` is a live pipe handle owned by `self`.
        if unsafe { SetHandleInformation(self.read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0
        {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// The read handle value (the number advertised as `SECRET_AGENT`).
    pub fn handle_value(&self) -> usize {
        self.read as usize
    }

    /// True when `handle` is an anonymous-pipe handle (plan §5.2 acquisition
    /// step 4: `GetFileType == FILE_TYPE_PIPE`).
    pub fn is_pipe_handle(handle: usize) -> bool {
        // SAFETY: `GetFileType` only queries the caller-supplied handle
        // value; it returns `FILE_TYPE_UNKNOWN` on an invalid handle.
        unsafe { GetFileType(handle as HANDLE) == FILE_TYPE_PIPE }
    }

    /// Peeks the buffered agent message without consuming it and, on magic +
    /// constant-time header match, adopts the key into a fresh session
    /// (upstream `MSG_PEEK` semantics; plan §5.2 acquisition step 5). `Ok(None)`
    /// on any mismatch (wrong length, wrong magic, header inequality) — the
    /// caller falls back to the passphrase path. No message or key bytes
    /// cross this signature (plan §3.4 N4).
    pub fn peek_adopt(&self, expected_header: &Header) -> Result<Option<Session>, Error> {
        match peek_key(self.read as usize, expected_header)? {
            Some(key) => Ok(Some(session_from_key(expected_header, key)?)),
            None => Ok(None),
        }
    }
}

impl Drop for AgentPipe {
    fn drop(&mut self) {
        // SAFETY: live handles owned by this value, closed exactly once
        // (`spawn_trusted_child` consumes the pipe and lets this drop run
        // right after `CreateProcessW`).
        unsafe {
            if !self.read.is_null() {
                CloseHandle(self.read);
            }
            if !self.write.is_null() {
                CloseHandle(self.write);
            }
        }
        self.read = ptr::null_mut();
        self.write = ptr::null_mut();
    }
}

/// Core of the acquisition path (plan §5.2 steps 3–6), private: the peeked
/// key never crosses this module's public surface (plan §3.4 N4 — no message
/// or key bytes in any public signature). Peek does NOT consume:
/// repeated/descendant use works, exactly like upstream's `recv(MSG_PEEK)`.
fn peek_key(handle: usize, expected_header: &Header) -> Result<Option<[u8; 32]>, Error> {
    let mut msg = SecretBytes::new(AGENT_MSG_LEN)?;
    let mut bytes_read: u32 = 0;
    let mut total_avail: u32 = 0;
    // SAFETY: `handle` is a caller-supplied pipe handle; `msg` is a valid
    // 81-byte buffer for the peek.
    let ok = unsafe {
        PeekNamedPipe(
            handle as HANDLE,
            msg.as_mut_slice().as_mut_ptr() as *mut _,
            AGENT_MSG_LEN as u32,
            &mut bytes_read,
            &mut total_avail,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // Unreadable/non-pipe handle: no agent (upstream: a recv that cannot
        // deliver exactly the message is "no match").
        msg.clear();
        return Ok(None);
    }
    if bytes_read as usize != AGENT_MSG_LEN || total_avail as usize != AGENT_MSG_LEN {
        msg.clear();
        return Ok(None);
    }
    let magic_ok = libhydrogen_sys::equal(&msg.as_slice()[0..8], &AGENT_MAGIC);
    let header_ok = libhydrogen_sys::equal(
        &msg.as_slice()[AGENT_HEADER_OFF..AGENT_HEADER_OFF + HEADER_LEN],
        &encode_header(expected_header),
    );
    if !magic_ok || !header_ok {
        msg.clear();
        return Ok(None);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&msg.as_slice()[AGENT_KEY_OFF..AGENT_KEY_OFF + 32]);
    msg.clear();
    Ok(Some(key))
}

/// Acquisition entry for the CLI: pipe-type check (plan §5.2 step 4) plus
/// [`peek_key`], then key adoption into a session marked
/// [`UnlockEvidence::AgentAuthorized`] (upstream `pass_ok = match`). The raw
/// handle value arrives from the `SECRET_AGENT` decimal; `Ok(None)` on any
/// mismatch means "fall back to the passphrase path". No key bytes cross
/// this signature (plan §3.4 N4).
pub fn adopt_from_handle_value(
    handle: usize,
    expected_header: &Header,
) -> Result<Option<Session>, Error> {
    if handle == 0 || !AgentPipe::is_pipe_handle(handle) {
        return Ok(None);
    }
    match peek_key(handle, expected_header)? {
        Some(key) => Ok(Some(session_from_key(expected_header, key)?)),
        None => Ok(None),
    }
}

/// Builds a fresh session from a header + adopted key, marked
/// [`UnlockEvidence::AgentAuthorized`]. The caller's key copy is zeroized
/// before returning on every path (internal to this module: the key never
/// reaches a public signature, plan §3.4 N4).
fn session_from_key(header: &Header, mut key: [u8; 32]) -> Result<Session, Error> {
    let result = Session::from_parts(header.clone(), key);
    libhydrogen_sys::memzero(&mut key);
    let mut s = result?;
    s.set_evidence(UnlockEvidence::AgentAuthorized);
    Ok(s)
}

/// Strict unsigned-decimal parser for the `SECRET_AGENT` value (plan §5.2
/// acquisition step 3): rejects signs, whitespace, trailing characters,
/// empty strings, zero, and values that do not fit a pointer-sized `HANDLE`
/// (upstream `strtol` semantics, tightened).
pub fn parse_env_handle(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = value.parse().ok()?;
    if n == 0 {
        return None;
    }
    usize::try_from(n).ok()
}

/// Constant-time comparison of the two sessions' derived keys (the upstream
/// `s_get_secret` retype check: `hydro_equal(&s.x.key, &check, ...)`). Key
/// material stays inside transient secure buffers that are zeroized on every
/// return path.
pub fn sessions_same_key(a: &Session, b: &Session) -> Result<bool, Error> {
    let mut ka = SecretBytes::new(32)?;
    a.with_key(|k| ka.as_mut_slice().copy_from_slice(k))?;
    let mut kb = SecretBytes::new(32)?;
    b.with_key(|k| kb.as_mut_slice().copy_from_slice(k))?;
    let same = libhydrogen_sys::equal(ka.as_slice(), kb.as_slice());
    // `ka`/`kb` drop here: zeroized on every path.
    Ok(same)
}

/// Resolves an executable to its full path (plan §5.2 step 2). A name with a
/// path separator is normalized with `GetFullPathNameW`; otherwise the
/// standard executable search runs (`SearchPathW` with `.exe`, covering the
/// current directory first). The result is passed as explicit
/// `lpApplicationName`, avoiding `CreateProcessW` command-line parsing
/// ambiguity.
pub fn resolve_executable(name: &std::ffi::OsStr) -> io::Result<std::ffi::OsString> {
    let w: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
    let body = &w[..w.len() - 1];
    let has_sep = body
        .iter()
        .any(|&c| c == u16::from(b'\\') || c == u16::from(b'/'));
    const EXE_EXT: [u16; 5] = [0x002E, 0x0065, 0x0078, 0x0065, 0]; // ".exe\0"

    // `GetFullPathNameW`/`SearchPathW` return the required length (incl. NUL)
    // when the buffer is too small; 32768 wide chars is the NT path maximum.
    let mut buf = vec![0u16; 32768];
    // SAFETY: `w` and `buf` are valid NUL-terminated/`n`-sized buffers.
    let n = unsafe {
        if has_sep {
            GetFullPathNameW(
                w.as_ptr(),
                buf.len() as u32,
                buf.as_mut_ptr(),
                ptr::null_mut(),
            )
        } else {
            SearchPathW(
                ptr::null(),
                w.as_ptr(),
                EXE_EXT.as_ptr(),
                buf.len() as u32,
                buf.as_mut_ptr(),
                ptr::null_mut(),
            )
        }
    };
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= buf.len() {
        return Err(io::Error::from_raw_os_error(234)); // ERROR_MORE_DATA
    }
    buf.truncate(n as usize);
    Ok(std::ffi::OsString::from_wide(&buf))
}

/// A spawned agent-shell child reduced to `SYNCHRONIZE |
/// PROCESS_QUERY_LIMITED_INFORMATION` (plan §5.8 point 4: no full-access
/// wsecret-child handle survives in the launcher). Waits and reads the exit
/// status through the reduced handle only.
pub struct AgentChild {
    handle: HANDLE,
    pid: u32,
    tid: u32,
    #[cfg(feature = "fault-injection")]
    original_process_handle: usize,
    #[cfg(feature = "fault-injection")]
    original_thread_handle: usize,
}

impl AgentChild {
    /// Process ID of the protected child (birth-protection observation).
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Primary thread ID of the protected child.
    pub fn primary_thread_id(&self) -> u32 {
        self.tid
    }

    /// P4h evidence: original full-access handle values (now closed) and the
    /// retained reduced handle. The acceptance helper checks the launcher
    /// handle table to prove the originals are absent.
    #[cfg(feature = "fault-injection")]
    pub fn handle_evidence_for_test(&self) -> (usize, usize, usize) {
        (
            self.original_process_handle,
            self.original_thread_handle,
            self.handle as usize,
        )
    }

    /// Waits for the child to exit and returns its exit code (upstream
    /// `execvp` semantics: the shell's exit status becomes wsecret's).
    pub fn wait_for_exit(self) -> Result<i32, Error> {
        // SAFETY: `self.handle` is a live process handle with SYNCHRONIZE.
        let wait = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let mut code: u32 = 0;
        // SAFETY: live handle with PROCESS_QUERY_LIMITED_INFORMATION.
        if unsafe { GetExitCodeProcess(self.handle, &mut code) } == 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(code as i32)
    }
}

impl Drop for AgentChild {
    fn drop(&mut self) {
        // SAFETY: live handle owned by this value.
        unsafe {
            if !self.handle.is_null() {
                CloseHandle(self.handle);
            }
        }
        self.handle = ptr::null_mut();
    }
}

/// `CommandLineToArgvW`-compatible argument quoting (the child CRT re-parses
/// `lpCommandLine`): empty/whitespace/quote-containing arguments are wrapped
/// in quotes; backslashes before a quote (and trailing backslashes) are
/// doubled.
fn quote_arg(arg: &std::ffi::OsStr) -> Vec<u16> {
    let w: Vec<u16> = arg.encode_wide().collect();
    let special = w.is_empty()
        || w.iter().any(|&c| {
            c == u16::from(b' ')
                || c == u16::from(b'\t')
                || c == u16::from(b'"')
                || c == u16::from(b'\n')
                || c == u16::from(b'\x0b')
        });
    if !special {
        return w;
    }
    let mut out = Vec::with_capacity(w.len() + 2);
    out.push(u16::from(b'"'));
    let mut bs = 0usize;
    for &c in &w {
        if c == u16::from(b'\\') {
            bs += 1;
            continue;
        }
        if c == u16::from(b'"') {
            // Double the pending backslashes, then escape the quote itself.
            for _ in 0..(bs * 2 + 1) {
                out.push(u16::from(b'\\'));
            }
            bs = 0;
            out.push(c);
            continue;
        }
        for _ in 0..bs {
            out.push(u16::from(b'\\'));
        }
        bs = 0;
        out.push(c);
    }
    for _ in 0..(bs * 2) {
        out.push(u16::from(b'\\'));
    }
    out.push(u16::from(b'"'));
    out
}

/// Builds the `CREATE_UNICODE_ENVIRONMENT` block: the current environment
/// verbatim (`SECRET_STORE` and everything else preserved) with
/// `SECRET_AGENT=<decimal>` added, entries sorted case-insensitively as the
/// `CreateProcessW` contract requires. Hidden `=C:`-style drive-cwd entries
/// are preserved. The block is returned as owned wide chars (double-NUL
/// terminated).
fn build_env_block(handle_value: usize) -> io::Result<Vec<u16>> {
    // SAFETY: returns a block owned by the process until freed below.
    let raw = unsafe { GetEnvironmentStringsW() };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut entries: Vec<Vec<u16>> = Vec::new();
    let mut p = raw;
    // SAFETY: `raw` is the documented double-NUL-terminated environment block.
    unsafe {
        loop {
            let mut len = 0usize;
            while *p.add(len) != 0 {
                len += 1;
            }
            if len == 0 {
                break;
            }
            let entry = std::slice::from_raw_parts(p, len).to_vec();
            entries.push(entry);
            p = p.add(len + 1);
        }
        FreeEnvironmentStringsW(raw);
    }
    // Replace `SECRET_AGENT` (the launcher refuses to start when it is
    // already set, so this is an append in practice).
    let name_w: Vec<u16> = std::ffi::OsStr::new(ENV_AGENT).encode_wide().collect();
    entries.retain(|e| {
        let n = e
            .iter()
            .position(|&c| c == u16::from(b'='))
            .unwrap_or(e.len());
        !(n == name_w.len() && fold_case(&e[..n]) == fold_case(&name_w))
    });
    let mut agent = name_w;
    agent.push(u16::from(b'='));
    agent.extend(handle_value.to_string().encode_utf16());
    entries.push(agent);
    // Case-insensitive Unicode order (fold A-Z, compare ordinally).
    entries.sort_by(|a, b| fold_case(a).cmp(&fold_case(b)));

    let mut block: Vec<u16> = Vec::new();
    for e in &entries {
        block.extend_from_slice(e);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn fold_case(w: &[u16]) -> Vec<u16> {
    w.iter()
        .map(|&c| {
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c) {
                c + 0x20
            } else {
                c
            }
        })
        .collect()
}

/// Spawns the trusted child (plan §5.2 steps 7–9 + §5.8 point 4), consuming
/// the pipe: the launcher's own pipe handles are closed immediately after
/// `CreateProcessW` (on failure too — the buffered message dies with the
/// pipe), and the returned [`AgentChild`] holds ONLY a
/// `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` duplicate of the child
/// process handle — the full-access process and thread handles from
/// `PROCESS_INFORMATION` are closed before returning.
///
/// The child inherits exactly the agent read handle and the deliberately
/// duplicated std handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; the
/// environment carries `SECRET_AGENT=<decimal handle>` and preserves
/// everything else (including `SECRET_STORE`).
pub fn spawn_trusted_child(
    application: &std::ffi::OsStr,
    argv: &[&std::ffi::OsStr],
    pipe: AgentPipe,
) -> Result<AgentChild, io::Error> {
    // Command line: argv[0] as typed + arguments, properly quoted.
    let mut cmdline: Vec<u16> = Vec::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            cmdline.push(u16::from(b' '));
        }
        cmdline.extend(quote_arg(a));
    }
    cmdline.push(0);
    let app_w: Vec<u16> = application
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let env_block = build_env_block(pipe.handle_value())?;
    // Construct birth descriptors BEFORE any raw handle/list allocations so a
    // descriptor failure cannot leak those resources.
    let birth = ProcessBirthSecurity::new()
        .map_err(|_| io::Error::other("process hardening descriptor construction failed"))?;

    // Deliberately duplicated std handles: the copies are created inheritable
    // (the originals may not be) and are exactly what the child's std slots
    // receive. NULL/invalid std handles are passed through as NULL.
    let mut std_dups: Vec<HANDLE> = Vec::with_capacity(3);
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: standard handle query.
        let orig = unsafe { GetStdHandle(which) };
        if orig.is_null() || orig == INVALID_HANDLE_VALUE {
            std_dups.push(ptr::null_mut());
            continue;
        }
        let mut dup: HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentProcess()` pseudo-handle targets our own
        // process; `dup` receives a fresh inheritable copy of `orig`.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                orig,
                GetCurrentProcess(),
                &mut dup,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            for h in std_dups.drain(..) {
                // SAFETY: live duplicate handles created above.
                unsafe {
                    if !h.is_null() {
                        CloseHandle(h);
                    }
                }
            }
            return Err(e);
        }
        std_dups.push(dup);
    }

    // The inheritance list: agent read handle + the non-NULL std duplicates.
    let mut inherit: Vec<HANDLE> = Vec::with_capacity(4);
    inherit.push(pipe.read);
    inherit.extend(std_dups.iter().copied().filter(|h| !h.is_null()));

    // Attribute list (one attribute: PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
    let mut attr_size: usize = 0;
    // SAFETY: sizing call — the documented two-step pattern.
    unsafe {
        InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size);
    }
    if attr_size == 0 {
        let e = io::Error::last_os_error();
        close_all(&std_dups);
        return Err(e);
    }
    // `LPPROC_THREAD_ATTRIBUTE_LIST` needs pointer alignment.
    let words = attr_size.div_ceil(std::mem::size_of::<usize>());
    let mut attr_buf: Vec<usize> = vec![0; words];
    let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST = attr_buf.as_mut_ptr() as *mut _;
    // SAFETY: `attr_buf` is a freshly allocated buffer of the size the OS
    // requested.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        let e = io::Error::last_os_error();
        close_all(&std_dups);
        return Err(e);
    }
    // SAFETY: the handle list outlives the call; all entries are inheritable
    // non-pseudo handles.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherit.as_ptr() as *const _,
            inherit.len() * std::mem::size_of::<HANDLE>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if updated == 0 {
        let e = io::Error::last_os_error();
        // SAFETY: initialized list.
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        close_all(&std_dups);
        return Err(e);
    }

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = std_dups[0];
    si.StartupInfo.hStdOutput = std_dups[1];
    si.StartupInfo.hStdError = std_dups[2];
    si.lpAttributeList = attr_list;

    let process_attributes = birth.process_attributes();
    let thread_attributes = birth.thread_attributes();
    let mut pi = windows_sys::Win32::System::Threading::PROCESS_INFORMATION::default();
    // SAFETY: `app_w`/`cmdline`/`env_block` are valid NUL-terminated wide
    // buffers (cmdline is mutable, as the API requires); the attribute list
    // covers exactly the inherit handles. Both birth descriptors outlive the
    // call. `bInheritHandles = TRUE` combined with the handle list means
    // EXACTLY the listed handles are inherited.
    let created = unsafe {
        CreateProcessW(
            app_w.as_ptr(),
            cmdline.as_mut_ptr(),
            &process_attributes,
            &thread_attributes,
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_ptr() as *const _,
            ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // Immediately close the launcher's pipe handles (plan §5.2 step 9): the
    // child's inherited read handle keeps the buffered message alive.
    drop(pipe);
    // SAFETY: initialized list; the std duplicates are done being used here.
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    close_all(&std_dups);
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = verify_birth_objects(pi.hProcess, pi.hThread) {
        // A child without the exact birth descriptors is never allowed to run
        // further or enter the trusted zone.
        // SAFETY: both full-access handles were just returned by CreateProcessW.
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        return Err(error);
    }

    // Handle hygiene (plan §5.8 point 4): duplicate the child handle down to
    // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, then close the
    // full-access originals (process AND thread).
    let mut reduced: HANDLE = ptr::null_mut();
    // SAFETY: `pi.hProcess` is a live full-access handle; the duplicate is
    // created with exactly the reduced rights and is non-inheritable.
    let dup_ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            pi.hProcess,
            GetCurrentProcess(),
            &mut reduced,
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            0,
        )
    };
    if dup_ok == 0 {
        let error = io::Error::last_os_error();
        // Do not leave an unobserved trusted child running when the launcher
        // cannot retain even its reduced wait handle.
        // SAFETY: both full-access originals are still live here.
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        return Err(error);
    }
    // SAFETY: close both full-access originals after the reduced duplicate
    // exists; the launcher never retains them.
    unsafe {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    Ok(AgentChild {
        handle: reduced,
        pid: pi.dwProcessId,
        tid: pi.dwThreadId,
        #[cfg(feature = "fault-injection")]
        original_process_handle: pi.hProcess as usize,
        #[cfg(feature = "fault-injection")]
        original_thread_handle: pi.hThread as usize,
    })
}

fn close_all(handles: &[HANDLE]) {
    for &h in handles {
        // SAFETY: live handles created by this function, closed once.
        unsafe {
            if !h.is_null() {
                CloseHandle(h);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::OPS_LIMIT_MIN;

    fn test_header() -> Header {
        Header {
            version: 0,
            master: [7u8; 32],
            ops_limit: OPS_LIMIT_MIN,
        }
    }

    fn test_session() -> Session {
        Session::from_parts(test_header(), [9u8; 32]).expect("session")
    }

    #[test]
    fn message_is_exactly_81_bytes_with_explicit_layout() {
        let mut session = test_session();
        let cap = AgentCapability::from_session(&mut session).expect("capability");
        let msg = cap.message();
        assert_eq!(msg.len(), AGENT_MSG_LEN);
        assert_eq!(AGENT_MSG_LEN, 81);
        assert_eq!(&msg[0..8], b"WSECRET1");
        // 41-byte upstream header, explicit encoding:
        assert_eq!(msg[8], 0); // version
        assert_eq!(&msg[9..41], &[7u8; 32][..]); // master
        assert_eq!(&msg[41..49], &OPS_LIMIT_MIN.to_le_bytes()[..]); // ops_limit LE
        assert_eq!(&msg[49..81], &[9u8; 32][..]); // key
    }

    #[test]
    fn from_session_drains_the_source_session() {
        let mut session = test_session();
        assert!(!session.is_locked());
        let cap = AgentCapability::from_session(&mut session).expect("capability");
        assert!(session.is_locked());
        // One-shot: a drained session cannot produce a second capability.
        assert!(matches!(
            AgentCapability::from_session(&mut session),
            Err(Error::Locked)
        ));
        drop(cap);
    }

    #[test]
    fn peek_matches_without_consuming() {
        let pipe = AgentPipe::create().expect("pipe");
        let mut session = test_session();
        let cap = AgentCapability::from_session(&mut session).expect("cap");
        let pipe = cap.write_to_pipe(pipe).expect("write");

        let key = peek_key(pipe.handle_value(), &test_header())
            .expect("peek")
            .expect("match");
        assert_eq!(&key[..], &[9u8; 32][..]);
        // Peek does not consume: repeated/descendant use works (upstream
        // MSG_PEEK semantics).
        let again = peek_key(pipe.handle_value(), &test_header())
            .expect("peek2")
            .expect("match2");
        assert_eq!(&again[..], &key[..]);
        // The session-adopting facade returns a live session with that key.
        let adopted = pipe
            .peek_adopt(&test_header())
            .expect("adopt")
            .expect("adopt match");
        assert!(!adopted.is_locked());
    }

    #[test]
    fn peek_rejects_a_different_header() {
        let pipe = AgentPipe::create().expect("pipe");
        let mut session = test_session();
        let cap = AgentCapability::from_session(&mut session).expect("cap");
        let pipe = cap.write_to_pipe(pipe).expect("write");

        let mut other = test_header();
        other.master[1] ^= 0xff;
        assert_eq!(peek_key(pipe.handle_value(), &other).expect("peek"), None);
        assert!(pipe.peek_adopt(&other).expect("adopt").is_none());
    }

    #[test]
    fn forged_message_with_wrong_magic_rejects() {
        let pipe = AgentPipe::create().expect("pipe");
        let mut forged = [0u8; AGENT_MSG_LEN];
        forged[0..8].copy_from_slice(b"NOPE1234");
        forged[AGENT_HEADER_OFF..AGENT_HEADER_OFF + HEADER_LEN]
            .copy_from_slice(&encode_header(&test_header()));
        assert!(pipe.write_exact(&forged).is_ok());
        assert_eq!(
            peek_key(pipe.handle_value(), &test_header()).expect("peek"),
            None
        );
    }

    #[test]
    fn forged_message_is_narrowed_assurance() {
        // Audit P13, documented end to end: a message carrying a correct
        // header and an ATTACKER key is adopted (header equality is the only
        // authorization), existing records stay unreadable, and NEW secrets
        // get encrypted under the attacker key.
        let pipe = AgentPipe::create().expect("pipe");
        let real = test_header();
        let mut forged = [0u8; AGENT_MSG_LEN];
        forged[0..8].copy_from_slice(&AGENT_MAGIC);
        forged[AGENT_HEADER_OFF..AGENT_HEADER_OFF + HEADER_LEN]
            .copy_from_slice(&encode_header(&real));
        forged[AGENT_KEY_OFF..AGENT_KEY_OFF + 32].copy_from_slice(&[0x41; 32]);
        assert!(pipe.write_exact(&forged).is_ok());

        let adopted = peek_key(pipe.handle_value(), &real)
            .expect("peek")
            .expect("header matched");
        assert_eq!(&adopted[..], &[0x41; 32][..]); // attacker key adopted

        let attacker = session_from_key(&real, adopted).expect("attacker session");
        let victim = Session::from_parts(real.clone(), [9u8; 32]).expect("victim session");

        // Existing records (encrypted under the victim key) fail
        // authentication for the attacker session...
        let mut victim_ct = [0u8; 512];
        let mut plain = [0u8; 476];
        plain[0..2].copy_from_slice(&3u16.to_le_bytes());
        plain[2] = b'k';
        plain[3] = 0;
        plain[4..7].copy_from_slice(b"old");
        victim
            .with_key(|k| {
                libhydrogen_sys::secretbox_encrypt(
                    &mut victim_ct,
                    &plain,
                    &libhydrogen_sys::CTX_SECRET,
                    k,
                )
            })
            .expect("victim encrypt");
        let mut out = [0u8; 476];
        let decryptable = attacker
            .with_key(|k| {
                libhydrogen_sys::secretbox_decrypt(
                    &mut out,
                    &victim_ct,
                    &libhydrogen_sys::CTX_SECRET,
                    k,
                )
            })
            .expect("attacker decrypt call");
        assert!(!decryptable, "victim record must not authenticate");

        // ...while NEW secrets are encrypted under the attacker key.
        let mut attacker_ct = [0u8; 512];
        attacker
            .with_key(|k| {
                libhydrogen_sys::secretbox_encrypt(
                    &mut attacker_ct,
                    &plain,
                    &libhydrogen_sys::CTX_SECRET,
                    k,
                )
            })
            .expect("attacker encrypt");
        assert_ne!(victim_ct, attacker_ct);
        let mut out2 = [0u8; 476];
        let ok = attacker
            .with_key(|k| {
                libhydrogen_sys::secretbox_decrypt(
                    &mut out2,
                    &attacker_ct,
                    &libhydrogen_sys::CTX_SECRET,
                    k,
                )
            })
            .expect("attacker decrypt own record");
        assert!(ok, "new records are readable only with the attacker key");
    }

    #[test]
    fn teardown_zeroizes_the_message_buffer() {
        let mut session = test_session();
        let cap = AgentCapability::from_session(&mut session).expect("cap");
        assert_eq!(cap.message().len(), AGENT_MSG_LEN);
        // The zeroization mechanism (`SecretBytes::clear`, also run on drop):
        let mut cap = cap;
        cap.msg.clear();
        assert!(cap.msg.as_slice().is_empty());
        assert_eq!(cap.msg.len(), 0);
        drop(cap);
        // Session teardown: the source session is drained at capability
        // creation and its at-rest key is erased on drop.
        assert!(session.is_locked());
    }
    #[test]
    fn sessions_same_key_compares_derived_keys() {
        let a = Session::from_parts(test_header(), [1u8; 32]).expect("a");
        let b = Session::from_parts(test_header(), [1u8; 32]).expect("b");
        let c = Session::from_parts(test_header(), [2u8; 32]).expect("c");
        assert!(sessions_same_key(&a, &b).expect("eq"));
        assert!(!sessions_same_key(&a, &c).expect("ne"));
    }

    #[test]
    fn pipe_type_check_distinguishes_pipes_from_files() {
        assert!(!AgentPipe::is_pipe_handle(0));
        let pipe = AgentPipe::create().expect("pipe");
        assert!(AgentPipe::is_pipe_handle(pipe.handle_value()));
    }

    #[test]
    fn quote_arg_matches_command_line_to_argvw_rules() {
        use std::ffi::OsStr;
        assert_eq!(
            quote_arg(OsStr::new("plain")),
            "plain".encode_utf16().collect::<Vec<u16>>()
        );
        assert_eq!(
            quote_arg(OsStr::new("")),
            "\"\"".encode_utf16().collect::<Vec<u16>>()
        );
        assert_eq!(
            quote_arg(OsStr::new("a b")),
            "\"a b\"".encode_utf16().collect::<Vec<u16>>()
        );
        assert_eq!(
            quote_arg(OsStr::new("say \"hi\"")),
            "\"say \\\"hi\\\"\"".encode_utf16().collect::<Vec<u16>>()
        );
        // No whitespace/quote: passes through unquoted even with a trailing
        // backslash (CommandLineToArgvW needs no doubling outside quotes).
        assert_eq!(
            quote_arg(OsStr::new("tr\\")),
            "tr\\".encode_utf16().collect::<Vec<u16>>()
        );
        // Trailing backslash INSIDE quotes doubles (classic rule).
        assert_eq!(
            quote_arg(OsStr::new("a b\\")),
            "\"a b\\\\\"".encode_utf16().collect::<Vec<u16>>()
        );
    }
}
