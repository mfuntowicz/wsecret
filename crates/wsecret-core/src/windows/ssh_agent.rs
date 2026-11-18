//! Ed25519 client for the local Microsoft OpenSSH Authentication Agent.
//!
//! Before sending even a frame length, authenticate the *connected handle*:
//! the pipe must be owned by LocalSystem, only privileged principals may
//! create server instances, and the instance's server PID must match the
//! running, own-process `ssh-agent` service. A PID alone can be reused.
//! A busy open may wait for an instance. Once connected, all I/O uses that
//! same handle; no probe writes or reconnections.
//!
//! The service [opens the client's process token by PID][agent]; it does
//! not need the ability to act as the client through the pipe. The client
//! uses identification-only SQOS. The service owns any key storage it performs.
//!
//! [agent]: https://github.com/PowerShell/openssh-portable/blob/0172cc6adb99d8b4324b8f0391b5b1fd6f39b2c6/contrib/win32/win32compat/ssh-agent/agent.c

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, IsValidAcl,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID, SID, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_CREATE_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_TYPE_PIPE, FILE_WRITE_DATA, GetFileType,
    OPEN_EXISTING, READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_STATUS_PROCESS, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::w;

use crate::error::{AgentError, Error};
use crate::session::SecretBytes;

/// The only accepted `SSH_AUTH_SOCK` spelling.
pub const DEFAULT_SSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

const PIPE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const PIPE_CLIENT_ACCESS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL;

const MAX_FRAME: usize = 256 * 1024;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;

fn unavailable() -> Error {
    Error::Agent(AgentError::Unavailable)
}

fn mismatch() -> Error {
    Error::Agent(AgentError::ProtocolMismatch)
}

/// No normalization or custom (including remote) agent endpoints.
pub fn is_canonical_endpoint(endpoint: &str) -> bool {
    endpoint == DEFAULT_SSH_AGENT_PIPE
}

/// One Ed25519 identity returned by `SSH2_AGENT_IDENTITIES_ANSWER`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshAgentIdentity {
    pub public: [u8; 32],
    pub comment: Vec<u8>,
}

/// RAII wrapper for an SCM/service handle.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: owned live SCM or service handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Request status only. Do not open the LocalSystem process itself.
fn query_service_status() -> io::Result<SERVICE_STATUS_PROCESS> {
    // SAFETY: null names select the local active services database.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(io::Error::last_os_error());
    }
    let scm = ScHandle(scm);
    // SAFETY: local SCM handle and static NUL-terminated service name.
    let service = unsafe { OpenServiceW(scm.0, w!("ssh-agent"), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ScHandle(service);
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: `status` is a valid `SERVICE_STATUS_PROCESS` and `needed` a
    // valid u32; the buffer/size pair matches the struct exactly.
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

/// Stateless client; each request authenticates its own connection.
#[derive(Debug)]
pub struct SshAgentClient;

impl SshAgentClient {
    pub fn new() -> Self {
        Self
    }

    /// Rejects unsupported endpoints before opening a handle.
    pub fn for_endpoint(endpoint: &str) -> Result<Self, Error> {
        if is_canonical_endpoint(endpoint) {
            Ok(Self)
        } else {
            Err(Error::Agent(AgentError::EnvParse))
        }
    }

    /// Canonical pipe path for the child's `SSH_AUTH_SOCK`.
    pub fn pipe_name(&self) -> &str {
        DEFAULT_SSH_AGENT_PIPE
    }

    /// Preflight before unlocking or launching. Sends nothing.
    pub fn verify_service(&self) -> Result<(), Error> {
        VerifiedPipe::open().map(drop)
    }

    /// Adds an Ed25519 secret (`seed || public`). Erases the caller's slice
    /// whether or not framing, locked allocation, or the exchange succeeds.
    pub fn add_ed25519(&self, secret: &mut [u8], comment: &[u8]) -> Result<(), Error> {
        let payload = add_request_frame(secret, comment, SecretBytes::new)?;
        expect_success(&VerifiedPipe::open()?.exchange(payload.as_slice())?)
    }

    /// Removes one Ed25519 identity by public key. No private material is
    /// needed for this request.
    pub fn remove_ed25519(&self, public: &[u8; 32]) -> Result<(), Error> {
        let blob = key_blob(public);
        let mut payload = vec![0u8; 1 + 4 + blob.len()];
        payload[0] = SSH2_AGENTC_REMOVE_IDENTITY;
        put_string(&mut payload, &mut 1, &blob)?;
        expect_success(&VerifiedPipe::open()?.exchange(&payload)?)
    }

    /// Lists Ed25519 identities currently held by the agent.
    pub fn identities(&self) -> Result<Vec<SshAgentIdentity>, Error> {
        let response = VerifiedPipe::open()?.exchange(&[SSH2_AGENTC_REQUEST_IDENTITIES])?;
        parse_identities(&response)
    }

    /// Signs `data` with the named Ed25519 key and returns the 64-byte
    /// signature. The Microsoft agent performs the private-key operation.
    pub fn sign_ed25519(&self, public: &[u8; 32], data: &[u8]) -> Result<[u8; 64], Error> {
        let payload = sign_request_frame(public, data)?;
        let response = VerifiedPipe::open()?.exchange(&payload)?;
        parse_signature(&response)
    }
}

impl Default for SshAgentClient {
    fn default() -> Self {
        Self::new()
    }
}

fn add_request_frame(
    secret: &mut [u8],
    comment: &[u8],
    allocate: impl FnOnce(usize) -> Result<SecretBytes, Error>,
) -> Result<SecretBytes, Error> {
    const FIXED: usize = 1 + 4 + 11 + 4 + 32 + 4 + 64 + 4;
    let result = if secret.len() != 64 || comment.len() > MAX_FRAME - FIXED {
        Err(mismatch())
    } else {
        allocate(FIXED + comment.len()).and_then(|mut payload| {
            let buf = payload.as_mut_slice();
            buf[0] = SSH2_AGENTC_ADD_IDENTITY;
            let mut pos = 1;
            put_string(buf, &mut pos, b"ssh-ed25519")?;
            put_string(buf, &mut pos, &secret[32..])?;
            put_string(buf, &mut pos, secret)?;
            put_string(buf, &mut pos, comment)?;
            Ok(payload)
        })
    };
    libhydrogen_sys::memzero(secret);
    result
}

/// Builds one `SSH2_AGENTC_SIGN_REQUEST` frame: `string key_blob`,
/// `string data`, `uint32 flags` (flags fixed to 0), and nothing after.
fn sign_request_frame(public: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    let blob = key_blob(public);
    let mut payload = vec![0u8; 1 + 4 + blob.len() + 4 + data.len() + 4];
    payload[0] = SSH2_AGENTC_SIGN_REQUEST;
    let mut pos = 1;
    put_string(&mut payload, &mut pos, &blob)?;
    put_string(&mut payload, &mut pos, data)?;
    // The trailing uint32 is the flags field, already reserved above.
    payload[pos..pos + 4].copy_from_slice(&0u32.to_be_bytes());
    Ok(payload)
}

/// Constructed only after authentication. Consumed by a single exchange.
struct VerifiedPipe(File);

impl VerifiedPipe {
    fn open() -> Result<Self, Error> {
        let mut busy_since = None;
        loop {
            // Open local NPFS directly, not a per-logon DOS device alias.
            // SAFETY: static NUL-terminated path, no inheritance or template.
            let raw = unsafe {
                CreateFileW(
                    w!(r"\\?\GLOBALROOT\Device\NamedPipe\openssh-ssh-agent"),
                    PIPE_CLIENT_ACCESS,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                // SAFETY: take sole ownership of this successful, synchronous open.
                return Self::authenticate(unsafe { File::from_raw_handle(raw) });
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
                return Err(error.into());
            }

            // A successful wait doesn't reserve an instance. Share one time
            // budget across races with other clients, without asking the server
            // for its default timeout (0).
            let elapsed = busy_since.get_or_insert_with(Instant::now).elapsed();
            let remaining_ms = PIPE_BUSY_TIMEOUT.saturating_sub(elapsed).as_millis() as u32;
            if remaining_ms == 0 {
                return Err(error.into());
            }
            // WaitNamedPipeW takes a \\server\pipe\name, not the NT device path.
            // This local name is only a readiness hint: the next open and all
            // authentication still go through the fixed NPFS path above.
            // SAFETY: static NUL-terminated name and a finite timeout.
            if unsafe { WaitNamedPipeW(w!(r"\\.\pipe\openssh-ssh-agent"), remaining_ms) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
    }

    fn authenticate(file: File) -> Result<Self, Error> {
        let handle = file.as_raw_handle();
        let mut peer_pid = 0;
        // SAFETY: `file` owns this handle; `peer_pid` is a live output.
        if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
            || unsafe { GetNamedPipeServerProcessId(handle, &mut peer_pid) } == 0
            || !trusted_pipe_security(handle)
        {
            return Err(unavailable());
        }
        let service = query_service_status()?;
        if !service_matches(&service, peer_pid) {
            return Err(unavailable());
        }
        Ok(Self(file))
    }

    fn exchange(mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.is_empty() || payload.len() > MAX_FRAME {
            return Err(mismatch());
        }
        let mut header = (payload.len() as u32).to_be_bytes();
        // Write the locked add-key payload directly, never via a frame copy.
        self.0.write_all(&header)?;
        self.0.write_all(payload)?;
        self.0.read_exact(&mut header)?;
        let response_len = u32::from_be_bytes(header) as usize;
        if response_len == 0 || response_len > MAX_FRAME {
            return Err(mismatch());
        }
        let mut response = vec![0u8; response_len];
        self.0.read_exact(&mut response)?;
        Ok(response)
    }
}

fn service_matches(service: &SERVICE_STATUS_PROCESS, peer_pid: u32) -> bool {
    peer_pid != 0
        && service.dwServiceType == SERVICE_WIN32_OWN_PROCESS
        && service.dwCurrentState == SERVICE_RUNNING
        && service.dwProcessId == peer_pid
}

fn trusted_pipe_security(handle: HANDLE) -> bool {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: owner and ACL borrow from the single returned descriptor.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return false;
    }
    // SAFETY: the descriptor and its contents remain live until LocalFree.
    let trusted = unsafe { trusted_pipe_descriptor(owner, acl) };
    unsafe { LocalFree(descriptor) };
    trusted
}

/// Named-pipe instances share a security descriptor. System ownership is
/// insufficient if an ordinary user can create another instance or edit its
/// security. Accept ordinary client rights; reserve all others to SYSTEM/BA.
///
/// # Safety
/// Both pointers are null or point into a live OS-returned security descriptor.
unsafe fn trusted_pipe_descriptor(owner: PSID, acl: *const ACL) -> bool {
    const CLIENT_RIGHTS: u32 =
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_CREATE_PIPE_INSTANCE;
    const SID_OFFSET: usize = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    const SID_HEADER: usize = offset_of!(SID, SubAuthority);
    if owner.is_null() || unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } == 0 {
        return false;
    }
    if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return false;
    }
    for i in 0..u32::from(unsafe { (*acl).AceCount }) {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 {
            return false;
        }
        // Only standard allow/deny ACEs are needed for the OpenSSH DACL.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        match header.AceType {
            1 => continue, // ACCESS_DENIED_ACE_TYPE grants nothing.
            0 => {}        // ACCESS_ALLOWED_ACE_TYPE.
            _ => return false,
        }
        let size = usize::from(header.AceSize);
        if size < SID_OFFSET + SID_HEADER {
            return false;
        }
        let mask = unsafe { (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask };
        if mask & !CLIENT_RIGHTS != 0 {
            // Check the variable-length SID fits this ACE before comparing it.
            let sid = unsafe { raw.cast::<u8>().add(SID_OFFSET) }.cast::<SID>();
            let count = usize::from(unsafe { (*sid).SubAuthorityCount });
            if count > (size - SID_OFFSET - SID_HEADER) / size_of::<u32>() {
                return false;
            }
            if unsafe { IsWellKnownSid(sid.cast(), WinLocalSystemSid) } == 0
                && unsafe { IsWellKnownSid(sid.cast(), WinBuiltinAdministratorsSid) } == 0
            {
                return false;
            }
        }
    }
    true
}

fn put_string(out: &mut [u8], pos: &mut usize, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len()).map_err(|_| mismatch())?;
    let end = pos.checked_add(4 + value.len()).ok_or_else(mismatch)?;
    if end > out.len() {
        return Err(mismatch());
    }
    out[*pos..*pos + 4].copy_from_slice(&len.to_be_bytes());
    *pos += 4;
    out[*pos..end].copy_from_slice(value);
    *pos = end;
    Ok(())
}

fn take_string<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8], Error> {
    if *pos + 4 > input.len() {
        return Err(mismatch());
    }
    let len = u32::from_be_bytes(input[*pos..*pos + 4].try_into().expect("four bytes")) as usize;
    *pos += 4;
    let end = pos.checked_add(len).ok_or_else(mismatch)?;
    if end > input.len() {
        return Err(mismatch());
    }
    let value = &input[*pos..end];
    *pos = end;
    Ok(value)
}

fn take_u32(input: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > input.len() {
        return Err(mismatch());
    }
    let value = u32::from_be_bytes(input[*pos..*pos + 4].try_into().expect("four bytes"));
    *pos += 4;
    Ok(value)
}

fn key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(public);
    blob
}

/// Maps a response body to success. `SSH_AGENT_FAILURE` (5) and any other
/// body both surface as `ProtocolMismatch` — the agent refused or the frame
/// is not the expected reply.
fn expect_success(response: &[u8]) -> Result<(), Error> {
    if response == [SSH_AGENT_SUCCESS] {
        Ok(())
    } else {
        Err(mismatch())
    }
}

fn parse_identities(response: &[u8]) -> Result<Vec<SshAgentIdentity>, Error> {
    if response.first().copied() != Some(SSH2_AGENT_IDENTITIES_ANSWER) {
        return Err(mismatch());
    }
    let mut pos = 1;
    let count = take_u32(response, &mut pos)? as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let blob = take_string(response, &mut pos)?;
        let comment = take_string(response, &mut pos)?.to_vec();
        let mut blob_pos = 0;
        let kind = take_string(blob, &mut blob_pos)?;
        if kind == b"ssh-ed25519" {
            let public = take_string(blob, &mut blob_pos)?;
            if public.len() != 32 || blob_pos != blob.len() {
                return Err(mismatch());
            }
            out.push(SshAgentIdentity {
                public: public.try_into().expect("32 bytes checked"),
                comment,
            });
        }
    }
    if pos != response.len() {
        return Err(mismatch());
    }
    Ok(out)
}

fn parse_signature(response: &[u8]) -> Result<[u8; 64], Error> {
    if response.first().copied() != Some(SSH2_AGENT_SIGN_RESPONSE) {
        return Err(mismatch());
    }
    let mut pos = 1;
    let blob = take_string(response, &mut pos)?;
    if pos != response.len() {
        return Err(mismatch());
    }
    let mut blob_pos = 0;
    let kind = take_string(blob, &mut blob_pos)?;
    if kind != b"ssh-ed25519" {
        return Err(mismatch());
    }
    let signature = take_string(blob, &mut blob_pos)?;
    if signature.len() != 64 || blob_pos != blob.len() {
        return Err(mismatch());
    }
    Ok(signature.try_into().expect("64 bytes checked"))
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::OwnedHandle;

    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};
    use windows_sys::Win32::System::Services::{SERVICE_STOPPED, SERVICE_WIN32_SHARE_PROCESS};

    use super::*;

    fn append_string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    #[test]
    fn only_canonical_endpoint_is_accepted() {
        let rejected = [
            "",
            "openssh-ssh-agent",
            r"\\?\pipe\openssh-ssh-agent",
            r"\\.\pipe\OPENSSH-SSH-AGENT",
            r"\\.\pipe\openssh-ssh-agent ",
            r"\\.\pipe\openssh-ssh-agent\",
            r"\\.\pipe\openssh-ssh-agent.~",
            r"\\.\pipe\other-agent",
            r"\\server\pipe\openssh-ssh-agent",
            r"\\localhost\pipe\openssh-ssh-agent",
            r"\\127.0.0.1\pipe\openssh-ssh-agent",
            r"\\.\pipe\wsecret-1234-1",
        ];
        for endpoint in rejected {
            assert!(!is_canonical_endpoint(endpoint), "accepted {endpoint:?}");
            match SshAgentClient::for_endpoint(endpoint) {
                Err(Error::Agent(AgentError::EnvParse)) => {}
                Err(other) => panic!("{endpoint:?}: wrong error kind: {other:?}"),
                Ok(_) => panic!("{endpoint:?}: accepted noncanonical endpoint"),
            }
        }
        assert!(is_canonical_endpoint(DEFAULT_SSH_AGENT_PIPE));
        let client =
            SshAgentClient::for_endpoint(DEFAULT_SSH_AGENT_PIPE).expect("canonical endpoint");
        assert_eq!(client.pipe_name(), DEFAULT_SSH_AGENT_PIPE);
    }

    #[test]
    fn binding_requires_a_matching_running_own_process() {
        let mut status = SERVICE_STATUS_PROCESS {
            dwCurrentState: SERVICE_RUNNING,
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwProcessId: 123,
            ..Default::default()
        };
        assert!(service_matches(&status, 123));
        assert!(!service_matches(&status, 456));
        status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        assert!(!service_matches(&status, 123));
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = SERVICE_STOPPED;
        assert!(!service_matches(&status, 123));
        status.dwCurrentState = SERVICE_RUNNING;
        status.dwProcessId = 0;
        assert!(!service_matches(&status, 0));
    }

    #[test]
    fn binding_requires_system_ownership_and_restricted_instance_creation() {
        // Even an administrator running this test must not mask an open that
        // asks for more rights than the installed Authenticated Users ACE.
        const { assert!(PIPE_CLIENT_ACCESS & !0x0012_019b == 0) };
        // In-memory descriptors only: no service registration or named listener.
        for (sddl, expected) in [
            (
                w!("O:SYG:SYD:P(A;;0x12019b;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)"),
                true,
            ),
            (
                w!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)"),
                true,
            ),
            (w!("O:BUD:P(A;;GA;;;SY)(A;;0x12019b;;;AU)"), false),
            (w!("O:SYD:P(A;;0x12019f;;;AU)"), false), // includes CREATE_PIPE_INSTANCE
            (w!("O:SYD:P(A;;GW;;;AU)"), false),
            (w!("O:SYD:P(A;;WD;;;AU)"), false), // can change the DACL
            (w!("O:SY"), false),                // no DACL
        ] {
            let mut sd = ptr::null_mut();
            let mut owner = ptr::null_mut();
            let mut acl = ptr::null_mut();
            let mut present = 0;
            let mut defaulted = 0;
            // SAFETY: static SDDL literals and live, correctly typed outputs.
            unsafe {
                assert_ne!(
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl,
                        SDDL_REVISION_1,
                        &mut sd,
                        ptr::null_mut(),
                    ),
                    0
                );
                assert_ne!(
                    GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted),
                    0
                );
                assert_ne!(
                    GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted),
                    0
                );
                if present == 0 {
                    acl = ptr::null_mut();
                }
                let trusted = trusted_pipe_descriptor(owner, acl);
                LocalFree(sd);
                assert_eq!(trusted, expected);
            }
        }
    }

    #[test]
    fn rejected_disk_endpoint_leaves_sentinel_empty() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_DELETE_ON_CLOSE;

        let path =
            std::env::temp_dir().join(format!("wsecret-ssh-sentinel-{}", std::process::id()));
        // Exclusive creation: never open or truncate a pre-existing file.
        let sentinel = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&path)
            .expect("private sentinel file");
        assert!(matches!(
            SshAgentClient::for_endpoint(&path.to_string_lossy()),
            Err(Error::Agent(AgentError::EnvParse))
        ));
        let destination = sentinel.try_clone().expect("duplicate sentinel handle");
        let result = VerifiedPipe::authenticate(destination)
            .and_then(|pipe| pipe.exchange(b"synthetic sentinel"));
        assert!(matches!(result, Err(Error::Agent(AgentError::Unavailable))));
        assert_eq!(sentinel.metadata().expect("sentinel length").len(), 0);
    }

    #[test]
    fn invalid_destination_receives_zero_bytes() {
        // A private anonymous pipe, not a listener on any agent name. Feed
        // its actual handle through the same authentication and I/O path.
        let (mut reader, writer) = io::pipe().expect("private sentinel pipe");
        let destination = File::from(OwnedHandle::from(writer));
        let result = VerifiedPipe::authenticate(destination)
            .and_then(|pipe| pipe.exchange(b"synthetic sentinel"));
        assert!(matches!(result, Err(Error::Agent(AgentError::Unavailable))));
        assert_eq!(reader.read(&mut [0u8; 1]).expect("sentinel read"), 0);
    }

    #[test]
    fn add_key_erases_input_when_locked_allocation_fails() {
        let mut key = [0x5a; 64];
        let result = add_request_frame(&mut key, b"synthetic", |_| Err(Error::NoMemory));
        assert!(matches!(result, Err(Error::NoMemory)));
        assert_eq!(key, [0; 64]);
    }

    #[test]
    fn sign_request_frame_is_exact_wire_format() {
        // Regression for the double flags word: the frame is exactly
        // type + key_blob + data + flags, with the flags word in place and no
        // trailing bytes.
        let public = [3u8; 32];
        let data: &[u8] = b"payload";
        let frame = sign_request_frame(&public, data).expect("frame");
        let blob_len = 4 + 11 + 4 + 32;
        assert_eq!(frame.len(), 1 + 4 + blob_len + 4 + data.len() + 4);
        assert_eq!(frame[0], SSH2_AGENTC_SIGN_REQUEST);
        let blob = key_blob(&public);
        let mut pos = 1;
        assert_eq!(
            take_string(&frame, &mut pos).expect("blob"),
            blob.as_slice()
        );
        assert_eq!(take_string(&frame, &mut pos).expect("data"), data);
        assert_eq!(take_u32(&frame, &mut pos).expect("flags"), 0);
        assert_eq!(pos, frame.len(), "no trailing bytes after flags");
    }

    #[test]
    fn key_blob_has_exact_ssh_ed25519_layout() {
        let public = [7u8; 32];
        let blob = key_blob(&public);
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..], &public);
    }

    #[test]
    fn identities_parser_skips_other_key_types_and_rejects_trailing_bytes() {
        let mut response = vec![SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 2];
        let mut rsa_blob = Vec::new();
        append_string(&mut rsa_blob, b"ssh-rsa");
        append_string(&mut rsa_blob, b"ignored-public");
        append_string(&mut response, &rsa_blob);
        append_string(&mut response, b"ignored");
        let blob = key_blob(&[9u8; 32]);
        append_string(&mut response, &blob);
        append_string(&mut response, b"comment");
        let parsed = parse_identities(&response).expect("parse identities");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].public, [9u8; 32]);
        assert_eq!(parsed[0].comment, b"comment");

        let mut bad = response;
        bad.push(0);
        assert!(parse_identities(&bad).is_err());
    }

    #[test]
    fn signature_parser_requires_exact_ed25519_blob() {
        let signature = [0x5au8; 64];
        let mut response = vec![SSH2_AGENT_SIGN_RESPONSE];
        let mut blob = Vec::new();
        append_string(&mut blob, b"ssh-ed25519");
        append_string(&mut blob, &signature);
        append_string(&mut response, &blob);
        assert_eq!(parse_signature(&response).expect("signature"), signature);

        let mut bad = response;
        bad.push(0);
        assert!(parse_signature(&bad).is_err());
    }

    /// Non-mutating success case; the CLI suite covers real add/sign/remove.
    #[test]
    fn live_verified_round_trip_when_agent_running() {
        let status = match query_service_status() {
            Ok(status) => status,
            Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
                eprintln!("skipping: no ssh-agent service registered on this host");
                return;
            }
            Err(error) => panic!("cannot query ssh-agent service: {error}"),
        };
        if status.dwCurrentState != SERVICE_RUNNING {
            eprintln!("skipping: ssh-agent service is not running");
            return;
        }
        let client = SshAgentClient::new();
        // Two real, read-only exchanges exercise adjacent authenticated opens.
        // Neither connection is just a probe that closes without a request.
        for _ in 0..2 {
            client
                .identities()
                .expect("identities request over its verified handle");
        }
    }
}
