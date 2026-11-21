//! Native-only hardened process launching (plan §5.2/§5.8): trusted
//! executable resolution, birth-hardened `CreateProcessW`, and child
//! wait/teardown for `wsecret ssh agent`.
//!
//! This module is one of the two sanctioned `unsafe` modules (the other is
//! `libhydrogen-sys`); the CLI crate contains **no** unsafe code and drives
//! everything through the safe facades below.
//!
//! The former vault-agent capability transport is gone: no capability
//! message is ever built, no untrusted handle value is ever adopted, and no
//! session key crosses this module. [`spawn_ssh_child`] inherits only the
//! deliberately duplicated standard handles, advertises `SSH_AUTH_SOCK`
//! naming the VERIFIED Windows OpenSSH agent endpoint, and strips the legacy
//! `SECRET_AGENT` entry from the child environment.
//!
//! Surface:
//!
//! - [`resolve_executable`]: policy-checked resolution of the child program
//!   (trusted bare names and explicit fully qualified paths only — no PATH,
//!   no current directory, no namespace paths).
//! - [`spawn_ssh_child`]: birth-hardened spawn — `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
//!   limits inheritance to the duplicated std handles, the birth descriptors
//!   are verified before the child may run, and the launcher keeps only a
//!   `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` handle.
//! - [`create_anonymous_channel`] + [`spawn_broker_child`]: the
//!   `wsecret-broker` private channel — two anonymous pipes, the child
//!   inheriting EXACTLY the two broker-side handles (no std handles, no
//!   named endpoint), same birth hardening and reduced handle hygiene.
//! - [`AgentChild`]: wait for the child and read its exit status through the
//!   reduced handle.

use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetHandleInformation, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SYNCHRONIZE,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::security::{ProcessBirthSecurity, verify_birth_objects};
use crate::error::Error;

/// The legacy vault-agent environment variable (upstream `S_ENV_AGENT`).
/// The vault agent is gone; the name is kept only so [`spawn_ssh_child`] can
/// guarantee it never reaches the SSH child.
pub const ENV_AGENT: &str = "SECRET_AGENT";
/// The endpoint variable consumed by Win32 OpenSSH clients. Its value is the
/// VERIFIED full named-pipe path (e.g. `\\.\pipe\openssh-ssh-agent`), passed
/// verbatim — never shortened (WS-04).
pub const ENV_SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// `ERROR_INVALID_NAME` (123): every policy rejection of a requested name
/// (relative/current-dir, namespace/UNC, drive-relative, alternate data
/// streams, reserved device names, trailing dots/spaces, interior NULs).
const ERROR_INVALID_NAME: i32 = 123;
/// `ERROR_FILE_NOT_FOUND` (2): no candidate executable exists.
const ERROR_FILE_NOT_FOUND: i32 = 2;
/// `ERROR_ACCESS_DENIED` (5): the requested path exists but is a directory.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_MORE_DATA` (234): a WinAPI length-reporting buffer was too small.
const ERROR_MORE_DATA: i32 = 234;

/// The trusted bare-name roots (WS-02): the Windows system directory exactly
/// as `GetSystemDirectoryW` reports it, plus the two system subdirectories
/// that carry Microsoft's own PowerShell and OpenSSH command suites. Every
/// root is absolute and machine-owned; nothing else is ever searched for a
/// bare name — no `SearchPathW`, no `PATH`, no current directory, no
/// application directory.
fn trusted_exec_dirs() -> io::Result<Vec<std::path::PathBuf>> {
    // 32768 wide chars is the NT path maximum. `GetSystemDirectoryW` returns
    // the required length (incl. NUL) when the buffer is too small.
    let mut buf = vec![0u16; 32768];
    // SAFETY: `buf` is a valid writable buffer of `buf.len()` wide chars.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= buf.len() {
        return Err(io::Error::from_raw_os_error(ERROR_MORE_DATA));
    }
    buf.truncate(n as usize);
    let sys = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buf));
    if !sys.is_absolute() {
        // Unreachable for a real system directory; fail closed rather than
        // ever search a relative root.
        return Err(io::Error::from_raw_os_error(ERROR_INVALID_NAME));
    }
    Ok(vec![
        sys.clone(),
        sys.join("WindowsPowerShell").join("v1.0"),
        sys.join("OpenSSH"),
    ])
}

/// Win32 path separator (`\` or `/`).
fn is_sep(c: u16) -> bool {
    c == u16::from(b'\\') || c == u16::from(b'/')
}

/// Rejects ambiguous Win32 shapes inside one path component: empty
/// components, `.`/`..` (current/parent directory), trailing dots or spaces
/// (Win32 strips them during normalization), and DOS device names.
fn check_component(comp: &[u16]) -> Result<(), io::Error> {
    let bad = io::Error::from_raw_os_error(ERROR_INVALID_NAME);
    if comp.is_empty() {
        return Err(bad);
    }
    // A trailing dot or space is stripped by Win32 normalization (ambiguous);
    // this also rejects `.`, `..`, `...` — current/parent-dir references and
    // dot-only components.
    let last = comp[comp.len() - 1];
    if last == u16::from(b'.') || last == u16::from(b' ') {
        return Err(bad);
    }
    if is_device_name(comp) {
        return Err(bad);
    }
    Ok(())
}

/// The DOS device names that Win32 maps into the device namespace wherever
/// they appear in a path — also immediately followed by an extension
/// (`NUL.txt` IS the NUL device). Checked case-insensitively on the stem
/// before the first dot (`foo.NUL` is an ordinary name; `NUL.txt` is not).
fn is_device_name(comp: &[u16]) -> bool {
    let stem_len = comp
        .iter()
        .position(|&c| c == u16::from(b'.'))
        .unwrap_or(comp.len());
    let mut stem = comp[..stem_len].to_vec();
    for c in &mut stem {
        if (u16::from(b'a')..=u16::from(b'z')).contains(c) {
            *c -= 0x20;
        }
    }
    const ASCII_DEVICES: [&[u8]; 25] = [
        b"CON", b"PRN", b"AUX", b"NUL", b"CLOCK$", b"CONIN$", b"CONOUT$", b"COM1", b"COM2",
        b"COM3", b"COM4", b"COM5", b"COM6", b"COM7", b"COM8", b"COM9", b"LPT1", b"LPT2", b"LPT3",
        b"LPT4", b"LPT5", b"LPT6", b"LPT7", b"LPT8", b"LPT9",
    ];
    if let Some(name) = stem
        .iter()
        .map(|&c| u8::try_from(c).ok())
        .collect::<Option<Vec<u8>>>()
    {
        if ASCII_DEVICES.iter().any(|d| *d == name.as_slice()) {
            return true;
        }
    }
    // Superscript-digit aliases Win32 also maps to the COM/LPT devices.
    const SUPERSCRIPT_DEVICES: [&[u16]; 6] = [
        &[0x43, 0x4F, 0x4D, 0x00B9], // COM¹
        &[0x43, 0x4F, 0x4D, 0x00B2], // COM²
        &[0x43, 0x4F, 0x4D, 0x00B3], // COM³
        &[0x4C, 0x50, 0x54, 0x00B9], // LPT¹
        &[0x4C, 0x50, 0x54, 0x00B2], // LPT²
        &[0x4C, 0x50, 0x54, 0x00B3], // LPT³
    ];
    SUPERSCRIPT_DEVICES.iter().any(|d| *d == stem.as_slice())
}

/// The candidate file names for a validated name/path under the explicit
/// `lpApplicationName` contract ("This parameter must include the file name
/// extension; no default extension is assumed"): an already-extended final
/// component is taken exactly as typed; an extension-less one may denote the
/// `.exe` of the same stem (the upstream `execvp`-style convenience), tried
/// after the exact name.
fn extension_candidates(path: &[u16]) -> Vec<Vec<u16>> {
    let comp_start = path
        .iter()
        .rposition(|&c| is_sep(c))
        .map(|i| i + 1)
        .unwrap_or(0);
    if path[comp_start..].contains(&u16::from(b'.')) {
        return vec![path.to_vec()];
    }
    let mut exe = path.to_vec();
    exe.extend_from_slice(&[
        u16::from(b'.'),
        u16::from(b'e'),
        u16::from(b'x'),
        u16::from(b'e'),
    ]);
    vec![path.to_vec(), exe]
}

/// `GetFileAttributesW` tri-state: `None` = absent/unopenable,
/// `Some(is_directory)`.
fn file_kind(path: &[u16]) -> Option<bool> {
    let terminated: Vec<u16> = path.iter().copied().chain(std::iter::once(0)).collect();
    // SAFETY: `terminated` is a NUL-terminated wide string.
    let attrs = unsafe { GetFileAttributesW(terminated.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        None
    } else {
        Some(attrs & FILE_ATTRIBUTE_DIRECTORY != 0)
    }
}

/// Resolves the trusted-agent executable to a fully qualified path (plan
/// §5.2 step 2, WS-02 hardening). The result is passed as explicit
/// `lpApplicationName`, which per the `CreateProcessW` contract "must include
/// the file name extension; no default extension is assumed" and is never
/// searched; a partial name "uses the current drive and current directory" to
/// complete itself, so partial names are rejected outright here.
///
/// Policy:
///
/// - **Bare names** (`cmd`, `powershell.exe`, …) are looked up ONLY in the
///   WinAPI-derived trusted directories ([`trusted_exec_dirs`]: the system
///   directory and its `WindowsPowerShell\v1.0` / `OpenSSH` system
///   subdirectories). `SearchPathW`, `PATH`, the current directory and the
///   application directory are never consulted.
/// - **Explicit local fully qualified paths** (`C:\dir\helper.exe`, also with
///   forward slashes) are accepted after shape validation and existence
///   checks, normalized to backslashes.
/// - **Everything else is rejected** with `ERROR_INVALID_NAME`: relative and
///   current-dir paths (`.\x`, `..\x`, `sub\x`, `.`, `..`), namespace and UNC
///   paths (`\\?\`, `\\.\`, `\??\`, `\\server\share`, `\Device\…`, and any
///   other leading-separator form), partial drive paths (`C:x`, `C:`),
///   alternate data streams (`x.exe:stream`), reserved device names
///   (`NUL`, `CON`, `COM1`, `NUL.txt`, …), trailing dots/spaces (Win32 strips
///   them — ambiguous), empty components and interior NULs.
///
/// Existence is validated HERE — before the caller opens the store, unlocks
/// and prompts for the passphrase — for bare and explicit names alike. The
/// check is advisory against later races (the file can still change before
/// `CreateProcessW` opens it), but a missing or directory-shaped target fails
/// before any secret is derived and before any prompt is shown.
pub fn resolve_executable(name: &std::ffi::OsStr) -> io::Result<std::ffi::OsString> {
    let w: Vec<u16> = name.encode_wide().collect();
    if w.is_empty() || w.contains(&0) {
        // Empty name, or an interior NUL (a command line cannot faithfully
        // carry one — everything after it would be truncated).
        return Err(io::Error::from_raw_os_error(ERROR_INVALID_NAME));
    }

    let invalid = || io::Error::from_raw_os_error(ERROR_INVALID_NAME);
    let qualified = w.contains(&u16::from(b':'));
    // Validated path shape, normalized to backslashes (bare names keep their
    // single component here).
    let mut normalized: Vec<u16> = Vec::with_capacity(w.len() + 2);
    if qualified {
        // A colon means a path form. Exactly one `X:\` / `X:/` drive-absolute
        // prefix is accepted; everything else is ambiguous.
        let drive = w[0];
        let ascii_alpha = (u16::from(b'A')..=u16::from(b'Z')).contains(&drive)
            || (u16::from(b'a')..=u16::from(b'z')).contains(&drive);
        let prefix_ok = w.len() >= 3
            && ascii_alpha
            && w[1] == u16::from(b':')
            && is_sep(w[2])
            && !w[2..].contains(&u16::from(b':'));
        if !prefix_ok {
            // `C:x` (drive-relative), `C:`, `x:y`, `x.exe:stream` (ADS), and
            // the namespace forms (`\\?\C:\…`, `\??\C:\…`) whose colon is
            // not at index 1 all land here.
            return Err(invalid());
        }
        normalized.extend_from_slice(&w[..2]); // `X:` exactly as typed
        let rest = &w[3..];
        let mut start = 0usize;
        let mut components: Vec<&[u16]> = Vec::new();
        for (i, &c) in rest.iter().enumerate() {
            if is_sep(c) {
                components.push(&rest[start..i]);
                start = i + 1;
            }
        }
        components.push(&rest[start..]);
        for comp in components {
            check_component(comp)?;
            normalized.push(u16::from(b'\\'));
            normalized.extend_from_slice(comp);
        }
    } else if w.iter().any(|&c| is_sep(c)) {
        // No drive colon but separators: relative (`sub\x`, `.\x`, `..\x`),
        // root-relative (`\x`), UNC (`\\server\…`) and namespace forms — all
        // current-drive/current-directory dependent or namespace-ambiguous.
        return Err(invalid());
    } else {
        // Bare name: a single validated component, trusted-directory search
        // below.
        check_component(&w)?;
        normalized.extend_from_slice(&w);
    }

    if qualified {
        // Explicit path: candidates in place; `Some(true)` (a directory) is
        // "exists but is not an executable".
        let mut saw_directory = false;
        for cand in extension_candidates(&normalized) {
            match file_kind(&cand) {
                Some(false) => return Ok(std::ffi::OsString::from_wide(&cand)),
                Some(true) => saw_directory = true,
                None => {}
            }
        }
        return Err(if saw_directory {
            io::Error::from_raw_os_error(ERROR_ACCESS_DENIED)
        } else {
            io::Error::last_os_error()
        });
    }

    // Bare name: only the trusted OS directories, in fixed order.
    for dir in trusted_exec_dirs()? {
        for cand in extension_candidates(&normalized) {
            let mut full: Vec<u16> = dir.as_os_str().encode_wide().collect();
            if !full.is_empty() && !is_sep(full[full.len() - 1]) {
                full.push(u16::from(b'\\'));
            }
            full.extend_from_slice(&cand);
            if let Some(false) = file_kind(&full) {
                return Ok(std::ffi::OsString::from_wide(&full));
            }
        }
    }
    Err(io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND))
}

/// A spawned child process reduced to `SYNCHRONIZE |
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

/// One environment-block mutation applied on top of the current process
/// environment, which is copied verbatim (`SECRET_STORE` and everything else
/// preserved; hidden `=C:`-style drive-cwd entries included).
enum EnvChange<'a> {
    /// Sets `name=value`, replacing any existing entry of the same name.
    Set(&'a std::ffi::OsStr, &'a std::ffi::OsStr),
    /// Removes every entry of the given name (used to guarantee that
    /// `SECRET_AGENT` never reaches a child that must not see it).
    Remove(&'a std::ffi::OsStr),
}

/// Builds the `CREATE_UNICODE_ENVIRONMENT` block: the current environment
/// verbatim with `changes` applied in order, entries sorted case-insensitively
/// as the `CreateProcessW` contract requires. The block is returned as owned
/// wide chars (double-NUL terminated).
fn build_env_block(changes: &[EnvChange<'_>]) -> io::Result<Vec<u16>> {
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
    // Apply each change in order: drop every same-named entry first, then
    // append the replacement (if any).
    for change in changes {
        let (name, value) = match change {
            EnvChange::Set(name, value) => (name, Some(*value)),
            EnvChange::Remove(name) => (name, None),
        };
        let name_w: Vec<u16> = name.encode_wide().collect();
        entries.retain(|e| {
            let n = e
                .iter()
                .position(|&c| c == u16::from(b'='))
                .unwrap_or(e.len());
            !(n == name_w.len() && fold_case(&e[..n]) == fold_case(&name_w))
        });
        if let Some(value) = value {
            let mut entry = name_w;
            entry.push(u16::from(b'='));
            entry.extend(value.encode_wide());
            entries.push(entry);
        }
    }
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

/// What one trusted spawn may hand the child (plan §5.8 point 4 hardening
/// applies to BOTH variants: the birth descriptors are verified and the
/// launcher keeps only the reduced child handle).
pub enum InheritSpec {
    /// `wsecret ssh agent`: ONLY the deliberately duplicated standard
    /// handles (unchanged behavior).
    StdHandles,
    /// `wsecret-broker`: EXACTLY the two private anonymous-pipe handles of
    /// the inherited channel (command read end + response write end). NO
    /// standard handle is inherited (`STARTF_USESTDHANDLES` with NULLs);
    /// there is no named endpoint anywhere.
    BrokerChannel {
        /// Broker end of the command channel (reads requests).
        cmd_rd: HANDLE,
        /// Broker end of the response channel (writes responses).
        resp_wr: HANDLE,
    },
}

/// Spawns the `wsecret ssh agent` child (WS-04): the child receives ONLY the
/// deliberately duplicated ordinary standard handles plus `SSH_AUTH_SOCK`
/// naming the VERIFIED Windows OpenSSH agent endpoint, passed verbatim as the
/// complete pipe path (`\\.\pipe\openssh-ssh-agent` — Win32 OpenSSH clients
/// hand the value to `CreateFileW` unchanged, openssh-portable
/// `contrib/win32/win32compat/fileio.c:fileio_connect`, so it must never be
/// shortened). No vault capability exists anywhere in this path: any legacy
/// `SECRET_AGENT` entry is stripped from the inherited environment ("never
/// `SECRET_AGENT` or vault capability"). Birth hardening and handle hygiene
/// follow plan §5.8 point 4: the birth descriptors are verified and the
/// launcher keeps only the reduced child handle.
pub fn spawn_ssh_child(
    application: &std::ffi::OsStr,
    argv: &[&std::ffi::OsStr],
    ssh_auth_sock: &std::ffi::OsStr,
) -> Result<AgentChild, io::Error> {
    let env_block = build_env_block(&[
        EnvChange::Remove(std::ffi::OsStr::new(ENV_AGENT)),
        EnvChange::Set(std::ffi::OsStr::new(ENV_SSH_AUTH_SOCK), ssh_auth_sock),
    ])?;
    spawn_child_core(application, argv, env_block, InheritSpec::StdHandles)
}

/// The parent end of a private broker channel: write commands
/// ([`BrokerChannelParent::cmd_wr`]) and read responses
/// ([`BrokerChannelParent::resp_rd`]). The ends are NON-inheritable — only
/// the broker-side pair ever crosses a process boundary.
pub struct BrokerChannelParent {
    cmd_wr: HANDLE,
    resp_rd: HANDLE,
}

impl BrokerChannelParent {
    /// Command-channel write end (parent writes requests).
    pub fn cmd_wr(&self) -> HANDLE {
        self.cmd_wr
    }

    /// Response-channel read end (parent reads responses).
    pub fn resp_rd(&self) -> HANDLE {
        self.resp_rd
    }
}

impl Drop for BrokerChannelParent {
    fn drop(&mut self) {
        // SAFETY: live handles owned by this value, closed once.
        unsafe {
            if !self.cmd_wr.is_null() {
                CloseHandle(self.cmd_wr);
            }
            if !self.resp_rd.is_null() {
                CloseHandle(self.resp_rd);
            }
        }
        self.cmd_wr = std::ptr::null_mut();
        self.resp_rd = std::ptr::null_mut();
    }
}

/// The broker end of a private broker channel (exactly two INHERITABLE
/// handles). Hand both values to the child via argv, then pass the whole
/// pair to [`spawn_broker_child`], which consumes and closes them.
pub struct BrokerChannelChild {
    cmd_rd: HANDLE,
    resp_wr: HANDLE,
}

impl BrokerChannelChild {
    /// Command-channel read handle VALUE for the child's `--rd-handle`.
    pub fn rd_value(&self) -> usize {
        self.cmd_rd as usize
    }

    /// Response-channel write handle VALUE for the child's `--wr-handle`.
    pub fn wr_value(&self) -> usize {
        self.resp_wr as usize
    }
}

impl Drop for BrokerChannelChild {
    fn drop(&mut self) {
        // SAFETY: live handles owned by this value, closed once.
        unsafe {
            if !self.cmd_rd.is_null() {
                CloseHandle(self.cmd_rd);
            }
            if !self.resp_wr.is_null() {
                CloseHandle(self.resp_wr);
            }
        }
        self.cmd_rd = std::ptr::null_mut();
        self.resp_wr = std::ptr::null_mut();
    }
}

/// Creates one private anonymous-pipe channel pair (plan: "private inherited
/// anonymous-pipe channel; no named endpoint"): two `CreatePipe` calls, the
/// parent ends made NON-inheritable and the broker ends INHERITABLE.
///
/// The broker ends keep their handle values across `CreateProcessW`
/// inheritance, so the exact values from [`BrokerChannelChild::rd_value`] /
/// [`BrokerChannelChild::wr_value`] go on the child's command line.
pub fn create_anonymous_channel() -> io::Result<(BrokerChannelParent, BrokerChannelChild)> {
    let (cmd_rd, cmd_wr) = anonymous_pipe()?;
    let (resp_rd, resp_wr) = anonymous_pipe()?;
    // The parent ends must NOT be inheritable; the broker ends MUST be.
    // SAFETY: all four handles are live here; SetHandleInformation only
    // toggles the inherit attribute.
    let ok = unsafe {
        SetHandleInformation(cmd_wr, HANDLE_FLAG_INHERIT, 0)
            & SetHandleInformation(resp_rd, HANDLE_FLAG_INHERIT, 0)
            & SetHandleInformation(cmd_rd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            & SetHandleInformation(resp_wr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        close_all(&[cmd_rd, cmd_wr, resp_rd, resp_wr]);
        return Err(e);
    }
    Ok((
        BrokerChannelParent {
            cmd_wr,
            resp_rd,
        },
        BrokerChannelChild { cmd_rd, resp_wr },
    ))
}

fn anonymous_pipe() -> io::Result<(HANDLE, HANDLE)> {
    let mut rd: HANDLE = std::ptr::null_mut();
    let mut wr: HANDLE = std::ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    // SAFETY: both out-handles receive fresh pipe ends.
    if unsafe { CreatePipe(&mut rd, &mut wr, &attributes, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((rd, wr))
}

/// Spawns a `wsecret-broker` child over a private channel (WS: "private
/// inherited anonymous-pipe channel"): the child inherits EXACTLY the two
/// pipe handles of `child` — verified inheritable `FILE_TYPE_PIPE` ends,
/// distinct and non-null — and NO standard handle (`STARTF_USESTDHANDLES`
/// with NULLs; the broker owns its own console). The environment is passed
/// verbatim (`SECRET_STORE` and everything else preserved). Birth hardening
/// is unchanged: descriptors verified before the child runs and the launcher
/// keeps only `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`.
///
/// The pair is consumed (the broker-side ends are closed in the parent right
/// after the spawn).
pub fn spawn_broker_child(
    application: &std::ffi::OsStr,
    argv: &[&std::ffi::OsStr],
    child: BrokerChannelChild,
) -> Result<AgentChild, io::Error> {
    for handle in [child.cmd_rd, child.resp_wr] {
        if handle.is_null() {
            return Err(io::Error::other("broker channel handles must be non-null"));
        }
        // SAFETY: query-only checks on caller-owned handles.
        let mut flags: u32 = 0;
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & HANDLE_FLAG_INHERIT == 0 {
            return Err(io::Error::other("broker channel handle must be inheritable"));
        }
    }
    if child.cmd_rd == child.resp_wr {
        return Err(io::Error::other("broker channel handles must be distinct"));
    }
    let env_block = build_env_block(&[])?;
    let spec = InheritSpec::BrokerChannel {
        cmd_rd: child.cmd_rd,
        resp_wr: child.resp_wr,
    };
    spawn_child_core(application, argv, env_block, spec)
}

/// Shared child-spawn body. `env_block` is the exact
/// `CREATE_UNICODE_ENVIRONMENT` block. The child inherits ONLY the handles
/// allowed by `spec` — the deliberately duplicated standard handles
/// ([`InheritSpec::StdHandles`]) or exactly the two channel pipe handles
/// ([`InheritSpec::BrokerChannel`]).
fn spawn_child_core(
    application: &std::ffi::OsStr,
    argv: &[&std::ffi::OsStr],
    env_block: Vec<u16>,
    spec: InheritSpec,
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

    // Construct birth descriptors BEFORE any raw handle/list allocations so a
    // descriptor failure cannot leak those resources.
    let birth = ProcessBirthSecurity::new()
        .map_err(|_| io::Error::other("process hardening descriptor construction failed"))?;

    // The inheritance allowlist and std slots are decided by the spec.
    let mut std_dups: Vec<HANDLE> = Vec::with_capacity(3);
    let mut inherit: Vec<HANDLE> = Vec::with_capacity(3);
    match spec {
        InheritSpec::StdHandles => {
            // Deliberately duplicated std handles: the copies are created
            // inheritable (the originals may not be) and are exactly what
            // the child's std slots receive. NULL/invalid std handles
            // contribute nothing to the allowlist.
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
                    close_all(&std_dups);
                    return Err(e);
                }
                std_dups.push(dup);
            }
            // Only the duplicated std handles belong in the allowlist.
            inherit.extend(std_dups.iter().copied().filter(|h| !h.is_null()));
        }
        InheritSpec::BrokerChannel { cmd_rd, resp_wr } => {
            // EXACTLY the two private channel pipe handles (already verified
            // inheritable by [`spawn_broker_child`]); std slots stay NULL
            // (`STARTF_USESTDHANDLES` with nulls below), so no std handle
            // and nothing else crosses the boundary.
            std_dups.extend([ptr::null_mut(), ptr::null_mut(), ptr::null_mut()]);
            inherit.push(cmd_rd);
            inherit.push(resp_wr);
        }
    }
    let use_std_handles = !inherit.is_empty();

    // Reserve one attribute slot. With nothing to inherit, keep the list
    // initialized but omit HANDLE_LIST: a zero-length value is invalid.
    let mut attr_size = 0;
    // SAFETY: documented sizing call; the first call fails by design.
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size) };
    if attr_size == 0 {
        let e = io::Error::last_os_error();
        close_all(&std_dups);
        return Err(e);
    }
    let words = attr_size.div_ceil(std::mem::size_of::<usize>());
    let mut attr_buf = Vec::<usize>::with_capacity(words);
    let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST = attr_buf.as_mut_ptr().cast();
    // SAFETY: the aligned allocation has at least `attr_size` writable bytes
    // and remains in place until after DeleteProcThreadAttributeList.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        let e = io::Error::last_os_error();
        close_all(&std_dups);
        return Err(e);
    }
    if !inherit.is_empty() {
        // SAFETY: all entries are inheritable non-pseudo handles. The array
        // is not modified or dropped before the attribute list is destroyed.
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
    }

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    if use_std_handles {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = std_dups[0];
        si.StartupInfo.hStdOutput = std_dups[1];
        si.StartupInfo.hStdError = std_dups[2];
    }
    si.lpAttributeList = attr_list;

    let process_attributes = birth.process_attributes();
    let thread_attributes = birth.thread_attributes();
    let mut pi = windows_sys::Win32::System::Threading::PROCESS_INFORMATION::default();
    // SAFETY: `app_w`/`cmdline`/`env_block` are valid NUL-terminated wide
    // buffers (cmdline is mutable, as the API requires). The full extended
    // startup structure, its attribute list and both birth descriptors
    // outlive the call. Inherit only the explicitly listed handles, or
    // disable inheritance altogether when there are none.
    let created = unsafe {
        CreateProcessW(
            app_w.as_ptr(),
            cmdline.as_mut_ptr(),
            &process_attributes,
            &thread_attributes,
            if inherit.is_empty() { 0 } else { 1 },
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_ptr() as *const _,
            ptr::null(),
            ptr::from_ref(&si).cast::<STARTUPINFOW>(),
            &mut pi,
        )
    };
    let create_error = (created == 0).then(io::Error::last_os_error);
    // SAFETY: the initialized list and its backing allocation are still live.
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    drop(attr_buf);
    close_all(&std_dups);
    if let Some(error) = create_error {
        return Err(error);
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

    // ---- executable resolution policy (WS-02) ------------------------------

    #[test]
    fn resolver_bare_names_trust_only_winapi_trusted_dirs() {
        let dirs = trusted_exec_dirs().expect("trusted dirs");
        assert_eq!(dirs.len(), 3);
        for dir in &dirs {
            assert!(dir.is_absolute(), "trusted root must be absolute: {dir:?}");
        }
        let sys = dirs[0].clone();
        assert!(dirs[1].starts_with(&sys));
        assert!(dirs[1].ends_with(std::path::Path::new("WindowsPowerShell").join("v1.0")));
        assert!(dirs[2].starts_with(&sys));
        assert!(dirs[2].ends_with("OpenSSH"));

        // A bare system name resolves INSIDE the system directory, with or
        // without the typed extension.
        let cmd = resolve_executable(std::ffi::OsStr::new("cmd")).expect("resolve `cmd`");
        let cmd_path = std::path::Path::new(&cmd);
        assert_eq!(cmd_path.file_name().unwrap().to_string_lossy(), "cmd.exe");
        assert_eq!(cmd_path.parent().unwrap(), sys.as_path());
        assert_eq!(
            resolve_executable(std::ffi::OsStr::new("cmd.exe")).expect("resolve `cmd.exe`"),
            cmd
        );
    }

    #[test]
    fn resolver_bare_names_never_search_untrusted_locations() {
        // A real decoy file in a non-trusted directory must NOT be found by
        // bare name: no PATH, no temp, no current-directory search.
        let name = format!("wsecret-resolver-decoy-{}.exe", std::process::id());
        let decoy = std::env::temp_dir().join(&name);
        std::fs::write(&decoy, b"decoy").expect("write decoy");
        let err = resolve_executable(std::ffi::OsStr::new(&name)).expect_err("bare decoy");
        assert_eq!(err.raw_os_error(), Some(ERROR_FILE_NOT_FOUND));
        let _ = std::fs::remove_file(&decoy);
    }

    #[test]
    fn resolver_accepts_explicit_fully_qualified_paths() {
        let dir = std::env::temp_dir();
        let stem = format!("wsecret-resolver-fq-{}", std::process::id());
        let exe = dir.join(format!("{stem}.exe"));
        std::fs::write(&exe, b"decoy").expect("write decoy");
        // As typed...
        assert_eq!(
            resolve_executable(exe.as_os_str()).expect("fq"),
            exe.clone().into_os_string()
        );
        // ...forward slashes normalize to backslashes...
        let forward = exe.to_string_lossy().replace('\\', "/");
        assert_eq!(
            resolve_executable(std::ffi::OsStr::new(&forward)).expect("fq forward"),
            exe.clone().into_os_string()
        );
        // ...an extension-less request finds the existing `.exe` of the stem
        // (lpApplicationName assumes no default extension)...
        let noext = dir.join(&stem);
        assert_eq!(
            resolve_executable(noext.as_os_str()).expect("fq stem"),
            exe.clone().into_os_string()
        );
        // ...and an exactly named extension-less file resolves as typed.
        let raw = dir.join(format!("{stem}-raw"));
        std::fs::write(&raw, b"decoy").expect("write raw");
        assert_eq!(
            resolve_executable(raw.as_os_str()).expect("fq raw"),
            raw.clone().into_os_string()
        );
        let _ = std::fs::remove_file(&exe);
        let _ = std::fs::remove_file(&raw);
    }

    #[test]
    fn resolver_rejects_relative_and_current_dir_forms() {
        for bad in [
            "",
            ".",
            "..",
            ".\\x.exe",
            "..\\x.exe",
            "sub\\x.exe",
            "sub/x.exe",
            ".hidden\\x.exe",
        ] {
            let err = resolve_executable(std::ffi::OsStr::new(bad)).expect_err(bad);
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME), "{bad:?}");
        }
    }

    #[test]
    fn resolver_rejects_namespace_unc_and_nt_paths() {
        for bad in [
            "\\\\?\\C:\\x.exe",
            "\\\\.\\C:\\x.exe",
            "\\??\\C:\\x.exe",
            "\\\\server\\share\\x.exe",
            "//?/C:/x.exe",
            "\\Device\\HarddiskVolume1\\x.exe",
            "\\x.exe",
            "/x.exe",
        ] {
            let err = resolve_executable(std::ffi::OsStr::new(bad)).expect_err(bad);
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME), "{bad:?}");
        }
    }

    #[test]
    fn resolver_rejects_drive_relative_streams_and_interior_nuls() {
        for bad in [
            "C:x.exe",
            "C:",
            "C:/",
            "x.exe:stream",
            "x:y",
            "C:\\x.exe:stream",
            "C:\\x.exe:",
        ] {
            let err = resolve_executable(std::ffi::OsStr::new(bad)).expect_err(bad);
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME), "{bad:?}");
        }
        // Interior NULs cannot cross a `CreateProcessW` command line, but the
        // API boundary must reject them explicitly.
        let with_nul = [u16::from(b'a'), 0, u16::from(b'b')];
        let path_with_nul = [
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            0,
            u16::from(b'x'),
        ];
        for bad in [&with_nul[..], &path_with_nul[..]] {
            let s = std::ffi::OsString::from_wide(bad);
            let err = resolve_executable(&s).expect_err("interior NUL");
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME));
        }
    }

    #[test]
    fn resolver_rejects_reserved_device_names() {
        for bad in [
            "NUL",
            "CON",
            "con.txt",
            "COM1",
            "com9.exe",
            "LPT9",
            "NUL.exe",
            "CONIN$",
            "CONOUT$",
            "CLOCK$",
            "C:\\temp\\NUL",
            "C:\\temp\\aux.data",
        ] {
            let err = resolve_executable(std::ffi::OsStr::new(bad)).expect_err(bad);
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME), "{bad:?}");
        }
        // Near-misses are ordinary names — rejected only as "not found".
        for name in ["console.exe", "COM10", "LPT0", "NULLED"] {
            let err = resolve_executable(std::ffi::OsStr::new(name)).expect_err(name);
            assert_eq!(err.raw_os_error(), Some(ERROR_FILE_NOT_FOUND), "{name:?}");
        }
    }

    #[test]
    fn resolver_rejects_ambiguous_trailing_dots_spaces_and_segments() {
        for bad in [
            "cmd.exe.",
            "cmd.exe ",
            "C:\\temp\\x.exe.",
            "C:\\temp\\x.exe ",
            "C:\\temp\\.\\x.exe",
            "C:\\temp\\..\\x.exe",
            "C:\\temp\\....\\x.exe",
            "C:\\temp\\\\x.exe",
            "C:\\",
        ] {
            let err = resolve_executable(std::ffi::OsStr::new(bad)).expect_err(bad);
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_NAME), "{bad:?}");
        }
    }

    #[test]
    fn resolver_validates_existence_for_explicit_paths() {
        let dir =
            std::env::temp_dir().join(format!("wsecret-resolver-exists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scenario dir");
        // Missing file in an existing directory: ERROR_FILE_NOT_FOUND.
        let missing = dir.join("wstest-absent.exe");
        let err = resolve_executable(missing.as_os_str()).expect_err("missing");
        assert_eq!(err.raw_os_error(), Some(ERROR_FILE_NOT_FOUND));
        // Extension-less request where neither candidate exists.
        let err =
            resolve_executable(dir.join("wstest-absent").as_os_str()).expect_err("missing stem");
        assert_eq!(err.raw_os_error(), Some(ERROR_FILE_NOT_FOUND));
        // A directory is "exists but is not an executable": ERROR_ACCESS_DENIED.
        let err = resolve_executable(dir.as_os_str()).expect_err("directory");
        assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
