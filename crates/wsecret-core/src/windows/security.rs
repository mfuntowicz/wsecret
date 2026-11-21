//! Windows security primitives used by this slice: the
//! `Global\wsecret-store-<64 hex>` writer mutex and its DACL (plan §3.5,
//! §5.6 point 1), the `Global\wsecret-sshkey-<64 hex>` per-identity lock for
//! `SshLaunch` (WS-03), and the shared aligned DACL machinery both use.
//!
//! Store-file DACLs plus the plan §5.8 process/thread protection boundary:
//! startup hardening, `OWNER_RIGHTS`, hardened thread creation, unlock
//! admission, and the continuous residency watchdog.

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_MORE_FILES, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, AddAccessDeniedAce,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, InitializeAcl, InitializeSecurityDescriptor,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateEventW, CreateMutexExW, CreateThread, ExitProcess, GetCurrentProcess,
    GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, GetProcessIdOfThread, INFINITE,
    LPTHREAD_START_ROUTINE, MUTEX_MODIFY_STATE, OpenThread, PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS,
    PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_LIMITED_INFORMATION,
    PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, ReleaseMutex,
    ResumeThread, SetEvent, THREAD_ALL_ACCESS, THREAD_DIRECT_IMPERSONATION, THREAD_GET_CONTEXT,
    THREAD_IMPERSONATE, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME,
    THREAD_SET_CONTEXT, THREAD_SET_INFORMATION, THREAD_SET_LIMITED_INFORMATION,
    THREAD_SET_THREAD_TOKEN, THREAD_SUSPEND_RESUME, THREAD_TERMINATE, TerminateThread,
    WaitForSingleObject,
};

use crate::error::Error;

/// `InitializeSecurityDescriptor`'s revision argument (winnt.h constant; the
/// value is not re-exported by windows-sys 0.61).
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// Mutex outcome after acquisition: `WAIT_OBJECT_0` vs `WAIT_ABANDONED`
/// (spec §5.6 point 1: abandoned → proceed WITHOUT integrity claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutexOutcome {
    /// Clean acquisition (`WAIT_OBJECT_0`).
    Acquired,
    /// Previous owner died holding the mutex (`WAIT_ABANDONED`): the caller
    /// proceeds but must not claim store integrity.
    Abandoned,
}

impl MutexOutcome {
    fn from_abandoned(abandoned: bool) -> Self {
        if abandoned {
            MutexOutcome::Abandoned
        } else {
            MutexOutcome::Acquired
        }
    }
}

fn hex_name(prefix: &str, digest: &[u8; 32]) -> String {
    let mut name = String::from(prefix);
    use std::fmt::Write as _;
    for b in digest {
        let _ = write!(name, "{b:02x}");
    }
    name
}

/// Derives `Global\wsecret-store-<64 hex>` from the canonical final path
/// bytes with `hydro_hash_hash` under context `WSTLOCK1` (spec §5.6 point 1;
/// the hash is a namespace encoding, not a secret).
pub fn writer_mutex_name(canonical_path: &[u8]) -> String {
    const CTX_WSTLOCK1: [u8; 8] = *b"WSTLOCK1";
    let mut digest = [0u8; 32];
    libhydrogen_sys::hash(&mut digest, canonical_path, &CTX_WSTLOCK1);
    hex_name("Global\\wsecret-store-", &digest)
}

/// DWORD-aligned heap storage for kernel SID/ACL data. The SID and ACL
/// structures require 4-byte alignment, which `Vec<u8>`/`[u8; N]` do not
/// promise; the allocation address is also stable when the owning struct
/// moves, so a `SECURITY_DESCRIPTOR` may keep pointing into it until drop
/// (WS-03: the previous stack-array backing moved when the owner was
/// returned by value, leaving the descriptor's DACL pointer dangling before
/// `CreateMutexExW`).
struct AlignedBuf {
    words: Vec<u32>,
    len: usize,
}

impl AlignedBuf {
    /// `len` zeroed bytes of DWORD-aligned storage.
    fn new_zeroed(len: usize) -> Self {
        Self {
            words: vec![0u32; len.div_ceil(4)],
            len,
        }
    }

    /// An aligned copy of `bytes`.
    fn copy_of(bytes: &[u8]) -> Self {
        let mut buf = Self::new_zeroed(bytes.len());
        buf.as_mut_slice().copy_from_slice(bytes);
        buf
    }

    /// Shortens the logical length after an API reports the used size.
    /// `len` must not exceed the current length.
    fn truncate(&mut self, len: usize) {
        assert!(len <= self.len);
        self.len = len;
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `words` is a valid allocation of `4 * words.len()` bytes,
        // and `len <= 4 * words.len()` by construction.
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr() as *const u8
    }

    /// PSID view for the Windows SID APIs.
    fn as_psid(&self) -> PSID {
        self.words.as_ptr() as PSID
    }

    fn len(&self) -> usize {
        self.len
    }
}

/// 8-byte ACL header + two standard allow/deny ACEs, each at most
/// `ACE_HEADER + ACCESS_MASK + SECURITY_MAX_SID_SIZE` bytes.
const MUTEX_ACL_LEN: usize = 8 + 2 * (8 + SECURITY_MAX_SID_SIZE as usize);

// Request only the rights the DACL grants. CreateMutexW would request
// MUTEX_ALL_ACCESS when a cooperating writer already has the mutex open.
// READ_CONTROL is included on both sides so the post-acquire DACL /
// effective-permission verification (below) can read the object's security
// descriptor; it is a read-only right and widens nothing writable.
const MUTEX_ACCESS: u32 = SYNCHRONIZE | MUTEX_MODIFY_STATE | READ_CONTROL;

/// The user+SYSTEM `SYNCHRONIZE | MUTEX_MODIFY_STATE | READ_CONTROL` DACL
/// shared by the store writer mutex and the per-identity lock (spec §5.6
/// point 1; WS-03).
/// Every SID/ACL buffer is a [`AlignedBuf`] heap allocation whose address is
/// stable while this value lives, and the descriptor is built against those
/// final addresses, so [`MutexSecurity::attributes`] remains valid until
/// drop regardless of how often the owner moves.
struct MutexSecurity {
    _user_sid: AlignedBuf,
    _system_sid: AlignedBuf,
    acl: AlignedBuf,
    sd: SECURITY_DESCRIPTOR,
}

/// Builds the mutex DACL: current user + SYSTEM, `SYNCHRONIZE |
/// MUTEX_MODIFY_STATE`, DACL-protected so no inheritable ACE from the
/// `Global\` namespace can merge an extra grant in (spec §5.6 point 1).
fn mutex_security() -> io::Result<MutexSecurity> {
    let user_sid = AlignedBuf::copy_of(&super::file::current_user_sid()?);
    let mut system_sid = AlignedBuf::new_zeroed(SECURITY_MAX_SID_SIZE as usize);
    let mut sys_len = system_sid.len() as u32;
    // SAFETY: buffer is valid for a maximum-size SID; the resulting length is
    // checked by the call's return value.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            system_sid.as_mut_ptr() as PSID,
            &mut sys_len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    system_sid.truncate(sys_len as usize);

    // Assemble the owner first so every pointer the descriptor records is
    // already the final heap address (Vec allocations do not move with the
    // owning struct).
    let mut sec = MutexSecurity {
        _user_sid: user_sid,
        _system_sid: system_sid,
        acl: AlignedBuf::new_zeroed(MUTEX_ACL_LEN),
        sd: SECURITY_DESCRIPTOR::default(),
    };
    // SAFETY: the ACL buffer is writable, DWORD-aligned, and sized for the
    // two ACEs added below (maximum-size SIDs included).
    if unsafe {
        InitializeAcl(
            sec.acl.as_mut_ptr() as *mut ACL,
            sec.acl.len() as u32,
            ACL_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SID pointers are valid; the ACL was just initialized and the
    // SID buffers outlive the ACE copies they seed.
    if unsafe {
        AddAccessAllowedAce(
            sec.acl.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            MUTEX_ACCESS,
            sec._user_sid.as_psid(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        AddAccessAllowedAce(
            sec.acl.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            MUTEX_ACCESS,
            sec._system_sid.as_psid(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `sd` is a correctly typed SECURITY_DESCRIPTOR; revision 1.
    if unsafe {
        InitializeSecurityDescriptor(
            &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Birth descriptors do not receive SetSecurityInfo's separate
    // PROTECTED_DACL flag, so the descriptor itself must carry the bit: it
    // is what guarantees "no additional grants" survives kernel-side
    // inheritance processing at object creation.
    // SAFETY: `sd` is initialized and the control mask is exact.
    if unsafe {
        SetSecurityDescriptorControl(
            &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sec.acl` is the final heap allocation and stays alive with
    // `sec`; the descriptor keeps pointing at it until drop.
    if unsafe {
        SetSecurityDescriptorDacl(
            &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
            1,
            sec.acl.as_ptr() as *const ACL,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sec)
}

impl MutexSecurity {
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &self.sd as *const SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
            bInheritHandle: 0,
        }
    }
}

/// Validates the writer-mutex security contract on the ACQUIRED handle
/// before any write may use the mutex ("validate the writer mutex ACL and
/// effective permissions before enabling writes"):
///
/// - `CreateMutexExW` requests exactly [`MUTEX_ACCESS`], so a successful
///   open proves those rights (and nothing more) were granted to us — the
///   effective-permission side;
/// - `GetSecurityInfo` succeeding proves `READ_CONTROL` was effectively
///   granted through the object's DACL;
/// - the DACL itself must be present, `SE_DACL_PROTECTED` (no inheritable
///   grant merged in), and consist of EXACTLY the two allow ACEs this module
///   creates (current user, then SYSTEM, each with exactly [`MUTEX_ACCESS`]).
///
/// A pre-existing named mutex (another writer, or a squatted
/// `Global\wsecret-store-*` name created with a hostile DACL) is validated
/// on EVERY acquisition, not just creation: the kernel ignores the caller's
/// security attributes when the object already exists, so only read-back
/// proves whose DACL is in force for the whole critical section (the ACL
/// "lifetime" of the held mutex). Any deviation fails closed before writes.
fn verify_mutex_security(handle: HANDLE) -> io::Result<()> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the output pointers are valid; the returned descriptor is
    // freed below with LocalFree after all borrowed ACL pointers are done.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let result = (|| {
        let mut present = 0;
        let mut queried_dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `sd` is the live self-relative descriptor returned above.
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut queried_dacl, &mut defaulted) }
            == 0
            || present == 0
            || queried_dacl.is_null()
            || queried_dacl != dacl
        {
            return Err(io::Error::from_raw_os_error(5));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `sd` remains live; outputs are correctly typed.
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::from_raw_os_error(5));
        }
        let user = AlignedBuf::copy_of(&super::file::current_user_sid()?);
        let system = well_known_sid(WinLocalSystemSid)?;
        let expected = [user, system];
        // SAFETY: the ACL header is part of the live returned descriptor.
        if unsafe { (*dacl).AceCount } as usize != expected.len() {
            return Err(io::Error::from_raw_os_error(5));
        }
        for (index, sid) in expected.iter().enumerate() {
            let mut raw: *mut c_void = ptr::null_mut();
            // SAFETY: index is bounded by AceCount checked above.
            if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 || raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the prefix used
            // here (Header, Mask, SidStart).
            let ace = raw as *const ACCESS_ALLOWED_ACE;
            // SAFETY: `ace` points to one complete standard access ACE.
            if unsafe { (*ace).Header.AceType } != 0 /* ACCESS_ALLOWED_ACE_TYPE */
                || unsafe { (*ace).Mask } != MUTEX_ACCESS
            {
                return Err(io::Error::from_raw_os_error(5));
            }
            // SAFETY: SidStart begins the variable-length SID in the ACE.
            if unsafe { EqualSid(&(*ace).SidStart as *const u32 as PSID, sid.as_psid()) } == 0 {
                return Err(io::Error::from_raw_os_error(5));
            }
        }
        Ok(())
    })();
    // SAFETY: `sd` was allocated by GetSecurityInfo.
    unsafe {
        LocalFree(sd);
    }
    result
}

/// Held `Global\wsecret-store-<64 hex>` writer mutex (RAII release on drop).
/// Windows mutex ownership is thread-bound: acquire and drop it on the same
/// thread.
pub struct WriterMutex {
    handle: HANDLE,
    /// True when acquisition was `WAIT_ABANDONED`.
    pub abandoned: bool,
}

/// Creates/opens the named mutex `name` non-inheritably with the user+SYSTEM
/// DACL, validates the DACL/effective-permission contract on the acquired
/// handle, and takes ownership with a zero-timeout wait. Returns
/// `(handle, abandoned)`.
///
/// Error contract (WS-03): [`Error::Busy`] ONLY on contention
/// (`WAIT_TIMEOUT`); creation/open/wait failures preserve their OS error in
/// [`Error::Io`] and are never reported as `Busy`. A handle whose security
/// descriptor fails [`verify_mutex_security`] is closed and reported as
/// [`Error::MemoryProtection`] — writes stay disabled (fail closed). An
/// older same-user writer whose DACL predates the `READ_CONTROL` grant also
/// fails closed here (the open requests `READ_CONTROL`).
fn acquire_mutex_handle(name: &str) -> Result<(HANDLE, bool), Error> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let sec = mutex_security().map_err(Error::Io)?;
    let sa = sec.attributes();
    // SAFETY: `sa` and `wide` are valid; the handle is checked below. The
    // kernel copies the security descriptor at creation, and `sec` keeps its
    // aligned SID/ACL backing alive until this call returns.
    let handle = unsafe { CreateMutexExW(&sa, wide.as_ptr(), 0, MUTEX_ACCESS) };
    if handle.is_null() {
        // Creation/open failure (a squatted name with a hostile DACL, a name
        // collision with a foreign object type, ...): the OS error is the
        // diagnosis. This is NOT contention.
        return Err(Error::Io(io::Error::last_os_error()));
    }
    // Writer-mutex ACL + effective-permission validation BEFORE this handle
    // can gate any write. The kernel ignores `sa` when the named object
    // pre-exists, so read-back is the only proof of whose DACL is in force.
    if verify_mutex_security(handle).is_err() {
        // SAFETY: owned handle; the security contract failed, so the object
        // is unusable — close and fail closed before any write.
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(Error::MemoryProtection);
    }
    // SAFETY: fresh valid handle; zero timeout = non-blocking acquire.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => Ok((handle, false)),
        // The previous owner died holding it: we own it now, without an
        // integrity claim.
        WAIT_ABANDONED => Ok((handle, true)),
        WAIT_TIMEOUT => {
            // Contention: the ONLY `Error::Busy` source. We never own it, so
            // release nothing, just close the handle.
            // SAFETY: owned, unowned-by-us handle.
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(Error::Busy)
        }
        // WAIT_FAILED or any unexpected status: preserve the OS error
        // (captured before CloseHandle can overwrite it).
        wait => {
            debug_assert_eq!(wait, WAIT_FAILED, "unexpected wait status");
            let error = io::Error::last_os_error();
            // SAFETY: owned, unowned-by-us handle.
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(Error::Io(error))
        }
    }
}

/// Releases and closes a mutex handle owned by the calling thread.
fn release_mutex_handle(handle: HANDLE) {
    // SAFETY: owned handle; release then close; never panics.
    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }
}

impl WriterMutex {
    /// Creates/opens `Global\wsecret-store-<64 hex>` non-inheritably with the
    /// user+SYSTEM DACL and waits with zero timeout (spec §5.6 point 1).
    ///
    /// [`Error::Busy`] ONLY on contention (another owner holds the mutex);
    /// creation/wait failures preserve their OS error in [`Error::Io`].
    pub fn acquire(canonical_path: &[u8]) -> Result<WriterMutex, Error> {
        let (handle, abandoned) = acquire_mutex_handle(&writer_mutex_name(canonical_path))?;
        Ok(WriterMutex { handle, abandoned })
    }

    /// The acquisition outcome (for the §5.6 integrity claim).
    pub fn outcome(&self) -> MutexOutcome {
        MutexOutcome::from_abandoned(self.abandoned)
    }
}

impl Drop for WriterMutex {
    fn drop(&mut self) {
        release_mutex_handle(self.handle);
    }
}

/// Derives the `Global\wsecret-sshkey-<64 hex>` per-identity lock name for
/// `SshLaunch` (WS-03): `hydro_hash_hash` over `current_user_sid() ||
/// public_key` under context `WSSHKEY1`. Hashing the user SID in keeps
/// same-public-key identities of different users disjoint in the `Global\`
/// namespace; the name depends on neither session nor store and carries no
/// key material (hash output only).
pub fn identity_lock_name(public_key: &[u8; 32]) -> Result<String, Error> {
    const CTX_WSSHKEY1: [u8; 8] = *b"WSSHKEY1";
    let mut scope = super::file::current_user_sid().map_err(Error::Io)?;
    scope.extend_from_slice(public_key);
    let mut digest = [0u8; 32];
    libhydrogen_sys::hash(&mut digest, &scope, &CTX_WSSHKEY1);
    Ok(hex_name("Global\\wsecret-sshkey-", &digest))
}

/// Held per-identity `Global\wsecret-sshkey-<64 hex>` lock for `SshLaunch`
/// (RAII release on drop). Windows mutex ownership is thread-bound: acquire
/// and drop it on the same thread.
pub struct IdentityLock {
    handle: HANDLE,
    /// True when acquisition was `WAIT_ABANDONED`.
    pub abandoned: bool,
}

impl IdentityLock {
    /// Takes the per-identity lock keyed by the Ed25519 public key
    /// ([`identity_lock_name`]) with a zero-timeout wait: exclusive and
    /// immediate.
    ///
    /// [`Error::Busy`] ONLY on contention (another holder owns the lock);
    /// creation/wait failures preserve their OS error in [`Error::Io`].
    pub fn acquire(public_key: &[u8; 32]) -> Result<IdentityLock, Error> {
        let (handle, abandoned) = acquire_mutex_handle(&identity_lock_name(public_key)?)?;
        Ok(IdentityLock { handle, abandoned })
    }

    /// The acquisition outcome (same contract as [`WriterMutex::outcome`]).
    pub fn outcome(&self) -> MutexOutcome {
        MutexOutcome::from_abandoned(self.abandoned)
    }
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        release_mutex_handle(self.handle);
    }
}

// ---------------------------------------------------------------------------
// Plan §5.8: process/thread DACLs, admission, and residency monitoring.
// ---------------------------------------------------------------------------

const PROCESS_DENY: u32 = PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_VM_OPERATION
    | PROCESS_CREATE_THREAD
    | PROCESS_DUP_HANDLE
    | PROCESS_SET_INFORMATION
    | PROCESS_SET_LIMITED_INFORMATION
    | PROCESS_QUERY_INFORMATION
    | PROCESS_CREATE_PROCESS
    | WRITE_DAC
    | WRITE_OWNER;
const PROCESS_OWNER_ALLOW: u32 =
    SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
const THREAD_DENY: u32 = THREAD_GET_CONTEXT
    | THREAD_SET_CONTEXT
    | THREAD_SUSPEND_RESUME
    | THREAD_RESUME
    | THREAD_SET_INFORMATION
    | THREAD_SET_LIMITED_INFORMATION
    | THREAD_QUERY_INFORMATION
    | THREAD_SET_THREAD_TOKEN
    | THREAD_IMPERSONATE
    | THREAD_DIRECT_IMPERSONATION
    | THREAD_TERMINATE
    | WRITE_DAC
    | WRITE_OWNER;
const THREAD_OWNER_ALLOW: u32 = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;

/// Process-exit status used by the independent watchdog-death monitor.
/// Test-only observers use this to distinguish fail-closed containment from
/// an ordinary command failure.
pub const WATCHDOG_DEATH_EXIT_CODE: u32 = 0xe000_0001;
const WATCHDOG_POLL_MS: u64 = 250;
const HEARTBEAT_MS: u64 = 50;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    Process,
    Thread,
}

impl ObjectKind {
    fn deny(self) -> u32 {
        match self {
            ObjectKind::Process => PROCESS_DENY,
            ObjectKind::Thread => THREAD_DENY,
        }
    }

    fn owner_allow(self) -> u32 {
        match self {
            ObjectKind::Process => PROCESS_OWNER_ALLOW,
            ObjectKind::Thread => THREAD_OWNER_ALLOW,
        }
    }

    fn full_control(self) -> u32 {
        match self {
            ObjectKind::Process => PROCESS_ALL_ACCESS,
            ObjectKind::Thread => THREAD_ALL_ACCESS,
        }
    }
}

/// Owns every buffer referenced by the absolute security descriptor. The ACL
/// and SID allocations are [`AlignedBuf`] heap buffers with stable addresses
/// when this value moves (WS-03: same safe DACL machinery as the mutexes).
struct ObjectSecurity {
    _user_sid: AlignedBuf,
    _owner_rights_sid: AlignedBuf,
    _system_sid: AlignedBuf,
    _admins_sid: AlignedBuf,
    acl: AlignedBuf,
    sd: SECURITY_DESCRIPTOR,
}

fn well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> io::Result<AlignedBuf> {
    let mut sid = AlignedBuf::new_zeroed(SECURITY_MAX_SID_SIZE as usize);
    let mut len = sid.len() as u32;
    // SAFETY: `sid` is large enough for every well-known SID used here.
    if unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr() as PSID, &mut len) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    sid.truncate(len as usize);
    Ok(sid)
}

impl ObjectSecurity {
    fn new(kind: ObjectKind) -> io::Result<Self> {
        Self::new_with_owner_rights(kind, true)
    }

    fn new_with_owner_rights(kind: ObjectKind, include_owner_rights: bool) -> io::Result<Self> {
        // Assemble the owner first so every pointer the descriptor records is
        // already the final heap address (WS-03, same as `mutex_security`).
        let mut sec = Self {
            _user_sid: AlignedBuf::copy_of(&super::file::current_user_sid()?),
            _owner_rights_sid: well_known_sid(WinCreatorOwnerRightsSid)?,
            _system_sid: well_known_sid(WinLocalSystemSid)?,
            _admins_sid: well_known_sid(WinBuiltinAdministratorsSid)?,
            // 8-byte ACL header + four standard ACEs, each at most
            // `ACE_HEADER + ACCESS_MASK + SECURITY_MAX_SID_SIZE` bytes.
            acl: AlignedBuf::new_zeroed(8 + 4 * (8 + SECURITY_MAX_SID_SIZE as usize)),
            sd: SECURITY_DESCRIPTOR::default(),
        };
        // SAFETY: the ACL buffer is writable, DWORD-aligned, and large enough
        // for four maximum-size ACEs.
        if unsafe {
            InitializeAcl(
                sec.acl.as_mut_ptr() as *mut ACL,
                sec.acl.len() as u32,
                ACL_REVISION,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Deny first: Windows evaluates ACEs in order and SetSecurityInfo does
        // not canonicalize the caller's ordering.
        // SAFETY: all SID pointers remain live for the whole construction.
        if unsafe {
            AddAccessDeniedAce(
                sec.acl.as_mut_ptr() as *mut ACL,
                ACL_REVISION,
                kind.deny(),
                sec._user_sid.as_psid(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut allowed = Vec::with_capacity(3);
        if include_owner_rights {
            allowed.push((&sec._owner_rights_sid, kind.owner_allow()));
        }
        allowed.push((&sec._system_sid, kind.full_control()));
        allowed.push((&sec._admins_sid, kind.full_control()));
        for (sid, mask) in allowed {
            // SAFETY: initialized ACL; each SID is valid and outlives the call.
            if unsafe {
                AddAccessAllowedAce(
                    sec.acl.as_mut_ptr() as *mut ACL,
                    ACL_REVISION,
                    mask,
                    sid.as_psid(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        // SAFETY: `sd` has the exact SECURITY_DESCRIPTOR layout.
        if unsafe {
            InitializeSecurityDescriptor(
                &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut c_void,
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Birth descriptors do not receive SetSecurityInfo's separate
        // PROTECTED_DACL flag, so the descriptor itself must carry the bit.
        // SAFETY: `sd` is initialized and the control mask is exact.
        if unsafe {
            SetSecurityDescriptorControl(
                &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut c_void,
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sec.acl` is the final heap allocation and stays alive with
        // `sec`; the descriptor keeps pointing at it until drop.
        if unsafe {
            SetSecurityDescriptorDacl(
                &mut sec.sd as *mut SECURITY_DESCRIPTOR as *mut c_void,
                1,
                sec.acl.as_ptr() as *const ACL,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(sec)
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &self.sd as *const SECURITY_DESCRIPTOR as *mut c_void,
            bInheritHandle: 0,
        }
    }
}

#[cfg(feature = "fault-injection")]
fn injected_security_failure() -> bool {
    std::env::var_os("WSECRET_TEST_FAIL_SET_SECURITY_INFO").is_some()
}

#[cfg(not(feature = "fault-injection"))]
fn injected_security_failure() -> bool {
    false
}

fn apply_security(handle: HANDLE, security: &ObjectSecurity) -> io::Result<()> {
    if injected_security_failure() {
        return Err(io::Error::from_raw_os_error(5));
    }
    // SAFETY: `handle` is a live kernel object and `security` owns a valid
    // absolute descriptor for the duration of the call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            security.acl.as_ptr() as *mut ACL,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Verifies the exact four-ACE contract, not merely that a DACL exists.
fn verify_security(handle: HANDLE, kind: ObjectKind) -> io::Result<()> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the output pointers are valid; the returned descriptor is freed
    // below with LocalFree after all borrowed ACL pointers are finished.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let result = (|| {
        let mut present = 0;
        let mut queried_dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `sd` is the live self-relative descriptor returned above.
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut queried_dacl, &mut defaulted) }
            == 0
            || present == 0
            || queried_dacl.is_null()
            || queried_dacl != dacl
        {
            return Err(io::Error::from_raw_os_error(5));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `sd` remains live; outputs are correctly typed.
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::from_raw_os_error(5));
        }
        let user = AlignedBuf::copy_of(&super::file::current_user_sid()?);
        let owner = well_known_sid(WinCreatorOwnerRightsSid)?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
        let expected = [
            (1u8, user, kind.deny()),
            (0u8, owner, kind.owner_allow()),
            (0u8, system, kind.full_control()),
            (0u8, admins, kind.full_control()),
        ];
        // SAFETY: the ACL header is part of the live returned descriptor.
        if unsafe { (*dacl).AceCount } as usize != expected.len() {
            return Err(io::Error::from_raw_os_error(5));
        }
        for (index, (ace_type, sid, mask)) in expected.into_iter().enumerate() {
            let mut raw: *mut c_void = ptr::null_mut();
            // SAFETY: index is bounded by AceCount checked above.
            if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 || raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the prefix used
            // here (Header, Mask, SidStart).
            let ace = raw as *const ACCESS_ALLOWED_ACE;
            // SAFETY: `ace` points to one complete standard access ACE.
            if unsafe { (*ace).Header.AceType } != ace_type || unsafe { (*ace).Mask } != mask {
                return Err(io::Error::from_raw_os_error(5));
            }
            // SAFETY: SidStart begins the variable-length SID in the ACE.
            if unsafe { EqualSid(&(*ace).SidStart as *const u32 as PSID, sid.as_psid()) } == 0 {
                return Err(io::Error::from_raw_os_error(5));
            }
        }
        Ok(())
    })();
    // SAFETY: `sd` was allocated by GetSecurityInfo.
    unsafe {
        LocalFree(sd);
    }
    result
}

fn harden_object(handle: HANDLE, kind: ObjectKind) -> io::Result<()> {
    let security = ObjectSecurity::new(kind)?;
    apply_security(handle, &security)?;
    verify_security(handle, kind)
}

/// P4b negative control only: installs the process deny DACL WITHOUT the
/// OWNER_RIGHTS ACE so the test can prove that ACE causes the WRITE_DAC
/// denial. Never available in a production build.
#[cfg(feature = "fault-injection")]
pub fn harden_process_without_owner_rights_for_test() -> Result<(), Error> {
    let security = ObjectSecurity::new_with_owner_rights(ObjectKind::Process, false)
        .map_err(|_| Error::MemoryProtection)?;
    apply_security(unsafe { GetCurrentProcess() }, &security).map_err(|_| Error::MemoryProtection)
}

fn duplicate_current_thread() -> io::Result<HANDLE> {
    let mut handle = ptr::null_mut();
    // SAFETY: both process pseudo-handles are valid; the thread pseudo-handle
    // is duplicated into a real, non-inheritable handle owned by this process.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &mut handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

fn duplicate_thread_for_registry(handle: HANDLE) -> io::Result<OwnedHandle> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: duplicates an existing thread handle within this process; the
    // resulting handle is independently owned by the registry.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful DuplicateHandle transferred a fresh owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

fn enumerate_threads() -> io::Result<Vec<u32>> {
    // SAFETY: snapshot query has no preconditions.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateToolhelp32Snapshot transfers ownership.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    thread_ids_in_snapshot(&snapshot)
}

fn thread_ids_in_snapshot(snapshot: &OwnedHandle) -> io::Result<Vec<u32>> {
    let pid = unsafe { GetCurrentProcessId() };
    let current = unsafe { GetCurrentThreadId() };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry` is initialized with its required size.
    if unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut saw_current = false;
    loop {
        // Toolhelp can return a shorter structure. Neither ID is evidence
        // about this process unless the entry includes the owner PID.
        if (entry.dwSize as usize)
            < std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID) + size_of::<u32>()
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if entry.th32OwnerProcessID == pid {
            out.push(entry.th32ThreadID);
            saw_current |= entry.th32ThreadID == current;
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        // SAFETY: the snapshot and entry remain live.
        if unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(error); // A partial snapshot is not proof of protection.
            }
            return if saw_current {
                Ok(out)
            } else {
                Err(io::Error::from(io::ErrorKind::InvalidData))
            };
        }
    }
}

fn harden_thread_handle(tid: u32) -> io::Result<OwnedHandle> {
    // Thread IDs can be recycled between the system snapshot and OpenThread.
    let handle =
        unsafe {
            OpenThread(
                SYNCHRONIZE | WRITE_DAC | READ_CONTROL | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                tid,
            )
        };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenThread returned an owned, non-inheritable handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    if unsafe { GetProcessIdOfThread(handle.as_raw_handle()) } != unsafe { GetCurrentProcessId() } {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    harden_object(handle.as_raw_handle(), ObjectKind::Thread)?;
    Ok(handle)
}

fn thread_is_live(handle: &OwnedHandle) -> io::Result<bool> {
    // SAFETY: zero-timeout wait on an owned thread handle; WAIT_TIMEOUT means
    // the kernel object is still live, WAIT_OBJECT_0 proves exit.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Checks an ID from a snapshot without treating an already-exited thread as
/// an unregistered live thread. A missing/reused ID is ignored only when the
/// kernel cannot open it or reports it exited.
fn thread_id_is_live(tid: u32) -> io::Result<bool> {
    let handle = unsafe { OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, 0, tid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(87) {
            // ERROR_INVALID_PARAMETER: the ID no longer names a live object.
            return Ok(false);
        }
        return Err(error);
    }
    // SAFETY: OpenThread returned an owned handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    thread_is_live(&handle)
}

/// Registers an owned, hardened thread handle. If the ID was recycled, the
/// old kernel object must be proven exited before it can be replaced.
fn register_thread_handle(tid: u32, handle: OwnedHandle) -> Result<u64, Error> {
    let mut guard = state();
    if let Some((_, existing)) = guard.threads.get(&tid) {
        match thread_is_live(existing) {
            Ok(true) => {} // duplicate registration of the same live thread
            Ok(false) => {
                guard.threads.remove(&tid);
            }
            Err(_) => return Err(Error::MemoryProtection),
        }
    }
    guard.next_registration = guard.next_registration.wrapping_add(1);
    let registration = guard.next_registration;
    guard.threads.insert(tid, (registration, handle));
    Ok(registration)
}

struct ProtectionState {
    /// Every registered thread has an owned kernel handle, so an exited ID
    /// can be pruned positively without trusting numeric-ID reuse or a racy
    /// snapshot of currently existing IDs.
    threads: HashMap<u32, (u64, OwnedHandle)>,
    next_registration: u64,
    sessions: Vec<Weak<crate::session::SessionKey>>,
    active_sessions: usize,
    pending_acquisitions: usize,
    operations: usize,
    poisoned: bool,
    watchdog_running: bool,
    watchdog_id: Option<u32>,
    /// Retired threads remain joinable so the next acquisition can wait for
    /// their trampolines to unregister and exit before admission.
    watchdog_threads: Option<(HardenedThread, HardenedThread)>,
    generation: u64,
}

impl ProtectionState {
    fn new() -> Self {
        Self {
            threads: HashMap::new(),
            next_registration: 0,
            sessions: Vec::new(),
            active_sessions: 0,
            pending_acquisitions: 0,
            operations: 0,
            poisoned: false,
            watchdog_running: false,
            watchdog_id: None,
            watchdog_threads: None,
            generation: 0,
        }
    }
}

static STATE: LazyLock<Mutex<ProtectionState>> =
    LazyLock::new(|| Mutex::new(ProtectionState::new()));
static INIT_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static INIT: LazyLock<Result<(), u32>> =
    LazyLock::new(|| startup_hardening().map_err(|error| error.raw_os_error().unwrap_or(5) as u32));

/// Makes thread discovery/registration and key-use admission mutually
/// exclusive: a registration never interleaves with an admission snapshot or
/// reservation, and no admission snapshot can observe a half-finished
/// registration. Lock order: `ADMISSION` before the state mutex. The watchdog
/// deliberately takes neither admission lock (it must keep heart-beating
/// within the monitor bound); registration rejects active work, so detection
/// never has a partial registration to observe. Never hold it while dropping
/// an armed closing `OperationGuard`: its release takes this same lock via
/// `close_operation_guard`.
static ADMISSION: Mutex<()> = Mutex::new(());

fn state() -> MutexGuard<'static, ProtectionState> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn admission() -> MutexGuard<'static, ()> {
    ADMISSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn startup_hardening() -> io::Result<()> {
    let process = unsafe { GetCurrentProcess() };
    apply_security(process, &ObjectSecurity::new(ObjectKind::Process)?)?;
    // Restrict the calling thread before spending time reading the process
    // descriptor back. Both descriptors must still verify before admission.
    let current = duplicate_current_thread()?;
    // SAFETY: `current` is an owned duplicate of the calling thread.
    let current = unsafe { OwnedHandle::from_raw_handle(current) };
    harden_object(current.as_raw_handle(), ObjectKind::Thread)?;
    verify_security(process, ObjectKind::Process)?;

    let current_id = unsafe { GetCurrentThreadId() };
    let threads = enumerate_threads()?;
    let mut registrations = Vec::with_capacity(threads.len());
    registrations.push((current_id, current));
    for &tid in &threads {
        if tid != current_id {
            registrations.push((tid, harden_thread_handle(tid)?));
        }
    }
    state().threads.clear();
    for (tid, handle) in registrations {
        register_thread_handle(tid, handle)
            .map_err(|_| io::Error::other("thread registration failed"))?;
    }
    Ok(())
}

/// Applies the §5.8 process and every-thread DACLs before any secret material
/// exists. Every CLI invocation calls this before argument dispatch. Library
/// hosts must call it before their first session operation; without a
/// successful call, production session creation fails closed.
pub fn init_process_protection() -> Result<(), Error> {
    INIT_ATTEMPTED.store(true, Ordering::Release);
    match LazyLock::force(&INIT) {
        Ok(()) => Ok(()),
        Err(_) => Err(Error::MemoryProtection),
    }
}

fn initialized() -> bool {
    INIT_ATTEMPTED.load(Ordering::Acquire) && matches!(*INIT, Ok(()))
}

fn uninitialized_is_test_only() -> bool {
    cfg!(any(test, feature = "fault-injection"))
}

fn ensure_initialized() -> Result<(), Error> {
    if initialized() {
        return Ok(());
    }
    // Ordinary unit/integration fixture processes do not opt into the P4
    // boundary. That bypass exists only in test builds; production callers
    // get no silent unprotected fallback.
    if !INIT_ATTEMPTED.load(Ordering::Acquire) && uninitialized_is_test_only() {
        return Ok(());
    }
    Err(Error::MemoryProtection)
}

fn ensure_current_registered() -> Result<(), Error> {
    if !initialized() {
        return ensure_initialized();
    }
    let tid = unsafe { GetCurrentThreadId() };
    if state().threads.contains_key(&tid) {
        Ok(())
    } else {
        Err(Error::MemoryProtection)
    }
}

fn ensure_all_registered() -> Result<(), Error> {
    if !initialized() {
        return ensure_initialized();
    }
    let threads = enumerate_threads().map_err(|_| Error::MemoryProtection)?;
    let mut guard = state();
    // Prune only kernel-confirmed exits. Snapshot absence is not evidence:
    // a concurrent registration may postdate the snapshot, while a retained
    // handle positively distinguishes a live object from a recycled ID.
    let mut liveness_failed = false;
    guard.threads.retain(|_, (_, handle)| match thread_is_live(handle) {
        Ok(true) => true,
        Ok(false) => false,
        Err(_) => {
            liveness_failed = true;
            false
        }
    });
    if liveness_failed {
        return Err(Error::MemoryProtection);
    }
    for &tid in &threads {
        if guard.threads.contains_key(&tid) {
            continue;
        }
        // A snapshot can include a thread that has already unregistered and
        // exited. That is not an unregistered LIVE thread; prove exit before
        // rejecting it, and fail closed on any live/unknown result.
        if thread_id_is_live(tid).map_err(|_| Error::MemoryProtection)? {
            return Err(Error::MemoryProtection);
        }
    }
    Ok(())
}

/// A host-thread registration. Dropping it unregisters the calling thread;
/// hosts must keep it alive until that thread exits.
pub struct RegisteredThread {
    tid: u32,
    registration: u64,
}

impl Drop for RegisteredThread {
    fn drop(&mut self) {
        let mut guard = state();
        if guard
            .threads
            .get(&self.tid)
            .is_some_and(|(registration, _)| *registration == self.registration)
        {
            guard.threads.remove(&self.tid);
        }
    }
}

/// Hardens and registers an existing host-created calling thread. This is the
/// host alternative to [`spawn_hardened_thread`].
pub fn register_hardened_thread() -> Result<RegisteredThread, Error> {
    ensure_initialized()?;
    if !initialized() {
        return Err(Error::MemoryProtection);
    }
    let handle = duplicate_current_thread().map_err(|_| Error::MemoryProtection)?;
    // SAFETY: `handle` is an owned duplicate of the calling thread.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    harden_object(handle.as_raw_handle(), ObjectKind::Thread)
        .map_err(|_| Error::MemoryProtection)?;
    let tid = unsafe { GetCurrentThreadId() };
    let registration = register_thread_handle(tid, handle)?;
    Ok(RegisteredThread { tid, registration })
}

/// Hardens and registers threads created by native Windows libraries while
/// the process is locked and quiescent. This is for explicit host native
/// initialization (console/WebAuthn/COM), never for excusing a thread found
/// during secret use: any live session, acquisition, operation, or poisoned
/// state fails closed. A final snapshot ensures a thread created concurrently
/// with registration is still rejected by the next admission check.
pub fn register_discovered_threads() -> Result<(), Error> {
    ensure_initialized()?;
    if !initialized() {
        return Err(Error::MemoryProtection);
    }
    // Registration and admission are mutually exclusive for the whole
    // discovery: no admission snapshot can observe this registration halfway.
    let _admission = admission();
    retire_watchdog_for_discovery()?;
    let threads = enumerate_threads().map_err(|_| Error::MemoryProtection)?;
    let guard = state();
    if guard.poisoned
        || guard.active_sessions != 0
        || guard.pending_acquisitions != 0
        || guard.operations != 0
    {
        return Err(Error::MemoryProtection);
    }
    drop(guard);
    for tid in threads {
        if !state().threads.contains_key(&tid) {
            match harden_thread_handle(tid) {
                Ok(handle) => {
                    register_thread_handle(tid, handle)?;
                }
                Err(_) if !thread_id_is_live(tid).map_err(|_| Error::MemoryProtection)? => {
                    // A native thread exited between snapshot and open.
                }
                Err(_) => return Err(Error::MemoryProtection),
            }
        }
    }
    ensure_all_registered()
}

/// Hardens and registers threads created by native Windows libraries while a
/// session is resident but the process sits between key-use requests: the
/// quiescent gap a broker serve loop observes. Unlike
/// [`register_discovered_threads`] this never retires or joins a running
/// watchdog — key residency keeps it heart-beating — and it tolerates
/// `active_sessions > 0`. It is ONLY for those quiescent gaps where no key
/// use is in flight, never during key use: a poisoned state, an in-flight
/// acquisition, or an in-flight key operation still fails closed, and a
/// thread discovered while secrets are live is a poisoning condition for the
/// watchdog, not a registration opportunity. A final `ensure_all_registered`
/// ensures a thread created concurrently with registration is still rejected
/// by the next admission check.
pub fn register_discovered_threads_for_session() -> Result<(), Error> {
    ensure_initialized()?;
    if !initialized() {
        return Err(Error::MemoryProtection);
    }
    // Same exclusion as `register_discovered_threads`: this discovery runs
    // atomically with respect to every admission path.
    let _admission = admission();
    let threads = enumerate_threads().map_err(|_| Error::MemoryProtection)?;
    let guard = state();
    if guard.poisoned || guard.pending_acquisitions != 0 || guard.operations != 0 {
        return Err(Error::MemoryProtection);
    }
    drop(guard);
    for tid in threads {
        if !state().threads.contains_key(&tid) {
            match harden_thread_handle(tid) {
                Ok(handle) => {
                    register_thread_handle(tid, handle)?;
                }
                Err(_) if !thread_id_is_live(tid).map_err(|_| Error::MemoryProtection)? => {
                    // A native thread exited between snapshot and open.
                }
                Err(_) => return Err(Error::MemoryProtection),
            }
        }
    }
    ensure_all_registered()
}

/// A thread born with the hardened descriptor. Closing the handle does not
/// unregister a live thread; its entry trampoline unregisters on exit.
pub struct HardenedThread {
    handle: HANDLE,
    tid: u32,
}

// SAFETY: the value owns a kernel thread handle, which may be waited on or
// closed from any thread. The entry trampoline owns registration teardown.
unsafe impl Send for HardenedThread {}

impl HardenedThread {
    pub fn id(&self) -> u32 {
        self.tid
    }

    pub fn join(mut self) -> Result<(), Error> {
        // SAFETY: live owned thread handle.
        let wait = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(Error::MemoryProtection);
        }
        // SAFETY: owned handle; Drop sees the null and does not close twice.
        unsafe {
            CloseHandle(self.handle);
        }
        self.handle = ptr::null_mut();
        Ok(())
    }
}

impl Drop for HardenedThread {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: owned handle; closing does not terminate the thread.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

struct ThreadJob {
    job: Box<dyn FnOnce() + Send + 'static>,
    registration: u64,
}

unsafe extern "system" fn hardened_thread_entry(parameter: *mut c_void) -> u32 {
    // SAFETY: CreateThread received exactly one Box<ThreadJob> pointer; the
    // trampoline takes ownership exactly once.
    let job = unsafe { Box::from_raw(parameter as *mut ThreadJob) };
    let tid = unsafe { GetCurrentThreadId() };
    let registration = job.registration;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (job.job)();
    }));
    let mut guard = state();
    if guard
        .threads
        .get(&tid)
        .is_some_and(|(token, _)| *token == registration)
    {
        guard.threads.remove(&tid);
    }
    0
}

/// The only wsecret-owned thread-creation path: the thread is created
/// suspended with its hardened descriptor, verified, registered, then resumed.
pub fn spawn_hardened_thread<F>(job: F) -> Result<HardenedThread, Error>
where
    F: FnOnce() + Send + 'static,
{
    ensure_initialized()?;
    if !initialized() {
        return Err(Error::MemoryProtection);
    }
    let security = ObjectSecurity::new(ObjectKind::Thread).map_err(|_| Error::MemoryProtection)?;
    let attributes = security.attributes();
    let raw_parameter = Box::into_raw(Box::new(ThreadJob {
        job: Box::new(job),
        registration: 0,
    }));
    let mut tid = 0u32;
    let entry: LPTHREAD_START_ROUTINE = Some(hardened_thread_entry);
    // SAFETY: the job Box is kept alive until a running thread takes ownership;
    // CREATE_SUSPENDED guarantees it cannot run before verification below.
    let handle = unsafe {
        CreateThread(
            &attributes,
            0,
            entry,
            raw_parameter.cast(),
            CREATE_SUSPENDED,
            &mut tid,
        )
    };
    if handle.is_null() {
        // SAFETY: no thread exists to own the job allocation.
        unsafe {
            drop(Box::from_raw(raw_parameter as *mut ThreadJob));
        }
        return Err(Error::MemoryProtection);
    }
    let prepared = duplicate_thread_for_registry(handle)
        .map_err(|_| Error::MemoryProtection)
        .and_then(|registry| register_thread_handle(tid, registry))
        .and_then(|registration| {
            // SAFETY: the thread is still suspended, so its job cannot race
            // this token write before the trampoline starts.
            unsafe {
                (*raw_parameter).registration = registration;
            }
            verify_security(handle, ObjectKind::Thread).map_err(|_| Error::MemoryProtection)
        });
    if prepared.is_err() || unsafe { ResumeThread(handle) } == u32::MAX {
        // The thread is still suspended (or resume failed before execution).
        // SAFETY: owned full-access handle returned by CreateThread.
        unsafe {
            TerminateThread(handle, 1);
            CloseHandle(handle);
        }
        state().threads.remove(&tid);
        // SAFETY: the trampoline never took ownership while suspended.
        unsafe {
            drop(Box::from_raw(raw_parameter as *mut ThreadJob));
        }
        return Err(Error::MemoryProtection);
    }
    // Ownership of the job passed to the trampoline through `into_raw`.
    Ok(HardenedThread { handle, tid })
}

struct Heartbeat(HANDLE);

// SAFETY: event handles are kernel objects valid for waits/signals on any
// thread in the owning process; the Arc closes the handle after both threads.
unsafe impl Send for Heartbeat {}
unsafe impl Sync for Heartbeat {}

impl Heartbeat {
    fn new() -> io::Result<Self> {
        // Auto-reset: each heartbeat releases exactly one monitor wait.
        // SAFETY: null attributes/name request an unnamed, non-inherited event.
        let handle = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn signal(&self) {
        // SAFETY: live event handle owned by the Arc.
        unsafe {
            SetEvent(self.0);
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        // SAFETY: owned event handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

static WATCHDOG_START: Mutex<()> = Mutex::new(());

fn running_generation(generation: u64) -> bool {
    let guard = state();
    guard.watchdog_running && guard.generation == generation
}

fn clear_all_session_keys() {
    let sessions: Vec<Arc<crate::session::SessionKey>> = {
        let mut guard = state();
        guard.sessions.retain(|weak| weak.strong_count() > 0);
        guard.sessions.iter().filter_map(Weak::upgrade).collect()
    };
    for session in sessions {
        session.clear_for_watchdog();
    }
}

fn watchdog_loop(generation: u64, heartbeat: Arc<Heartbeat>) {
    let mut tick = 0u64;
    loop {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("WSECRET_TEST_KILL_WATCHDOG").is_some() {
            // Simulate unexpected watchdog death WITHOUT clearing the running
            // flag. The independent monitor must contain this via ExitProcess.
            return;
        }

        let active_work = {
            let mut guard = state();
            if guard.generation != generation || !guard.watchdog_running {
                return;
            }
            if !guard.poisoned && guard.active_sessions == 0 && guard.pending_acquisitions == 0 {
                guard.watchdog_running = false;
                drop(guard);
                heartbeat.signal();
                return;
            }
            // Residual-thread detection covers active work only: a key-use
            // operation or an in-flight acquisition/KDF. A thread appearing
            // while the process is idle between requests is not a poisoning
            // condition — the host serve loop hardens and registers it via
            // `register_discovered_threads_for_session` in that quiescent gap,
            // and admission (`begin_secret_acquisition`, `publish_session`)
            // still fails closed on any unregistered thread.
            guard.operations != 0 || guard.pending_acquisitions != 0
        };

        // Five 50 ms heartbeat ticks make one 250 ms admission poll. Detection
        // is bounded by that poll; erasure additionally waits for real work.
        if active_work && tick % 5 == 0 && ensure_all_registered().is_err() {
            state().poisoned = true;
        }

        let drain_complete = {
            let guard = state();
            guard.poisoned && guard.pending_acquisitions == 0 && guard.operations == 0
        };
        if drain_complete {
            clear_all_session_keys();
            state().watchdog_running = false;
            heartbeat.signal();
            return;
        }

        heartbeat.signal();
        std::thread::sleep(Duration::from_millis(HEARTBEAT_MS));
        tick = tick.wrapping_add(1);
    }
}

fn monitor_loop(generation: u64, heartbeat: Arc<Heartbeat>) {
    loop {
        if !running_generation(generation) {
            return;
        }
        // SAFETY: live event handle; the timeout is the §5.8 fail-closed
        // watchdog-death bound. The monitor never touches session state.
        let wait = unsafe { WaitForSingleObject(heartbeat.0, WATCHDOG_POLL_MS as u32) };
        if wait == WAIT_OBJECT_0 {
            continue;
        }
        if !running_generation(generation) {
            return;
        }
        if wait == WAIT_TIMEOUT {
            // SAFETY: immediate process-wide containment; no Rust destructors
            // or session locks are needed by this independent monitor.
            unsafe { ExitProcess(WATCHDOG_DEATH_EXIT_CODE) }
        }
        // WAIT_FAILED (or any unexpected status) is also fail-closed.
        // SAFETY: same containment path as a heartbeat timeout.
        unsafe { ExitProcess(WATCHDOG_DEATH_EXIT_CODE) }
    }
}

/// Joins a stopped watchdog pair before a later admission snapshot. Their
/// trampolines unregister just before returning to the OS; detaching these
/// handles would let a lock/unlock restart observe those residual threads as
/// unregistered and poison an otherwise clean epoch.
fn retire_watchdog() -> Result<(), Error> {
    let threads = {
        let mut guard = state();
        if guard.watchdog_running {
            None
        } else {
            guard.watchdog_threads.take()
        }
    };
    if let Some((watchdog, monitor)) = threads {
        watchdog.join()?;
        monitor.join()?;
    }
    Ok(())
}

/// Discovery while locked must retire a stopping watchdog before taking its
/// snapshot. Wait for a quiescent stop, join the pair, and never race their
/// final unregistration with native-thread discovery.
fn retire_watchdog_for_discovery() -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (running, threads) = {
            let mut guard = state();
            if guard.poisoned
                || guard.active_sessions != 0
                || guard.pending_acquisitions != 0
                || guard.operations != 0
            {
                return Err(Error::MemoryProtection);
            }
            let running = guard.watchdog_running;
            let threads = if running {
                None
            } else {
                guard.watchdog_threads.take()
            };
            (running, threads)
        };
        if let Some((watchdog, monitor)) = threads {
            watchdog.join()?;
            monitor.join()?;
            return Ok(());
        }
        if !running {
            // This same locked observation proves there is no retained pair
            // to join; never re-read `watchdog_running` for a second decision.
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::MemoryProtection);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn start_watchdog() -> Result<(), Error> {
    let _start = WATCHDOG_START
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The acquisition is already reserved by the caller. If the previous
    // watchdog stopped between that reservation and this start, retire its
    // handles now instead of overwriting them or admitting residual threads.
    if !state().watchdog_running {
        retire_watchdog()?;
    }
    let generation = {
        let mut guard = state();
        if guard.watchdog_running {
            return Ok(());
        }
        guard.generation = guard.generation.wrapping_add(1);
        guard.watchdog_running = true;
        guard.generation
    };
    let heartbeat = match Heartbeat::new() {
        Ok(event) => Arc::new(event),
        Err(_) => {
            state().watchdog_running = false;
            return Err(Error::MemoryProtection);
        }
    };
    let watchdog_heartbeat = Arc::clone(&heartbeat);
    let watchdog =
        match spawn_hardened_thread(move || watchdog_loop(generation, watchdog_heartbeat)) {
            Ok(thread) => thread,
            Err(error) => {
                state().watchdog_running = false;
                return Err(error);
            }
        };
    let watchdog_id = watchdog.id();
    let monitor_heartbeat = Arc::clone(&heartbeat);
    let monitor = match spawn_hardened_thread(move || monitor_loop(generation, monitor_heartbeat)) {
        Ok(thread) => thread,
        Err(error) => {
            state().watchdog_running = false;
            heartbeat.signal();
            let _ = watchdog.join();
            return Err(error);
        }
    };
    // Keep both handles joinable for the next lock/unlock restart. Their
    // trampolines unregister themselves; the event remains alive through the
    // closures' Arc references.
    let mut guard = state();
    guard.watchdog_id = Some(watchdog_id);
    debug_assert!(guard.watchdog_threads.is_none());
    guard.watchdog_threads = Some((watchdog, monitor));
    Ok(())
}

/// Marks the interval from passphrase acquisition through KDF/publication.
/// Nested guards are intentional: the CLI covers prompting and `Session`
/// independently covers library callers and the KDF itself.
pub struct AcquisitionGuard {
    armed: bool,
}

impl Drop for AcquisitionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Mirror of `close_operation_guard` for the acquisition interval:
        // `ADMISSION` excludes registration and every new admission, the
        // reservation falls, and only then is the thread registry verified —
        // so a thread created during a short KDF (even one appearing after
        // `publish_session` returned) poisons here instead of escaping into
        // the idle gap between watchdog polls.
        let _admission = admission();
        {
            let mut guard = state();
            guard.pending_acquisitions = guard.pending_acquisitions.saturating_sub(1);
        }
        if ensure_all_registered().is_err() {
            state().poisoned = true;
        }
    }
}

/// Starts residency monitoring before a passphrase/KDF is touched.
pub fn begin_secret_acquisition() -> Result<AcquisitionGuard, Error> {
    ensure_initialized()?;
    if !initialized() {
        return Ok(AcquisitionGuard { armed: false });
    }
    ensure_current_registered()?;
    // The admission lock covers the reservation through watchdog start, so no
    // registration can interleave with this acquisition's admission snapshot.
    let _admission = admission();
    // Reserve the acquisition BEFORE retiring/admitting. The old watchdog
    // can no longer stop between the admission snapshot and start_watchdog.
    {
        let mut guard = state();
        if guard.poisoned {
            return Err(Error::MemoryProtection);
        }
        guard.pending_acquisitions += 1;
    }
    let result = (|| {
        retire_watchdog()?;
        ensure_all_registered()?;
        start_watchdog()
    })();
    if let Err(error) = result {
        let mut guard = state();
        guard.pending_acquisitions = guard.pending_acquisitions.saturating_sub(1);
        drop(guard);
        return Err(error);
    }
    Ok(AcquisitionGuard { armed: true })
}

/// A live session's contribution to residency. Dropping the lease (from
/// `Session::lock` or session destruction) lets the watchdog stop after all
/// acquisitions and sessions have drained.
pub(crate) struct ResidencyLease {
    _private: (),
}

impl Drop for ResidencyLease {
    fn drop(&mut self) {
        let mut guard = state();
        guard.active_sessions = guard.active_sessions.saturating_sub(1);
    }
}

/// Publishes a newly derived key only if admission is still clean. A poisoned
/// in-flight unlock therefore never creates a session.
pub(crate) fn publish_session(
    key: &Arc<crate::session::SessionKey>,
) -> Result<ResidencyLease, Error> {
    // Publication and registration are mutually exclusive: the admission
    // snapshot below cannot run halfway through a discovery.
    let _admission = admission();
    if ensure_all_registered().is_err() {
        // Derived key material exists at publication time: a failed admission
        // poisons the process so the watchdog drain clears this key and every
        // existing session instead of leaving them resident.
        state().poisoned = true;
        return Err(Error::MemoryProtection);
    }
    let mut guard = state();
    if guard.poisoned {
        return Err(Error::MemoryProtection);
    }
    guard.sessions.push(Arc::downgrade(key));
    guard.active_sessions += 1;
    Ok(ResidencyLease { _private: () })
}

/// Holds one in-flight key-use operation open. `SecretBytes` owns this guard
/// so its drop runs after the transient plaintext has been erased.
pub(crate) struct OperationGuard {
    armed: bool,
    /// True for a plain (non-batched) operation: its release closes with an
    /// admission-held snapshot ([`close_operation_guard`]), covering the same
    /// create→drain race the batch closing snapshot covers. A batched nested
    /// operation is covered by its batch's closing drop and only decrements.
    closing: bool,
}

/// Releases one counted key operation with the closing admission snapshot:
/// `ADMISSION` excludes registration and every new admission, the operation
/// count falls, and only then is the thread registry verified. The idle regime
/// therefore starts AFTER the verification — a thread created before or during
/// the operation and still live and unregistered poisons the process instead
/// of escaping into the idle gap between watchdog polls, and one created after
/// is caught by the next admission snapshot or the serve loop's registration.
fn close_operation_guard() {
    let _admission = admission();
    {
        let mut guard = state();
        guard.operations = guard.operations.saturating_sub(1);
    }
    if ensure_all_registered().is_err() {
        state().poisoned = true;
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.closing {
            close_operation_guard();
        } else {
            let mut guard = state();
            guard.operations = guard.operations.saturating_sub(1);
        }
    }
}

thread_local! {
    /// `OperationBatch` depth on this thread. Nonzero means one full
    /// admission already covers every nested key-use operation of the request,
    /// so those skip the per-operation ToolHelp snapshot while still counting.
    static BATCH_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Admits one key-use operation. Once poisoned, every new operation fails with
/// `MEMORY_PROTECTION`; already-running operations drain normally.
///
/// Outside an `OperationBatch` the caller gets a full admission: the
/// `ADMISSION` lock excludes concurrent registration and `ensure_all_registered`
/// rejects any live unregistered thread BEFORE the operation is counted, so a
/// thread racing secret use fails closed without waiting for the watchdog; the
/// guard's release closes with the matching snapshot (`close_operation_guard`).
/// Inside a batch the batch's own admission covers the request and only the
/// cheap per-thread and poison checks repeat; the batch's closing drop runs
/// the one closing snapshot for the whole request.
pub(crate) fn begin_key_operation() -> Result<OperationGuard, Error> {
    ensure_initialized()?;
    if !initialized() {
        return Ok(OperationGuard {
            armed: false,
            closing: false,
        });
    }
    ensure_current_registered()?;
    if BATCH_DEPTH.with(|depth| depth.get() > 0) {
        // Covered by the batch's admission: no snapshot, but the operation
        // still counts, so registration stays rejected and the watchdog's
        // active-work detection stays armed for the whole request. Release is
        // a plain decrement; the batch's closing drop snapshots.
        let mut guard = state();
        if guard.poisoned {
            return Err(Error::MemoryProtection);
        }
        guard.operations += 1;
        return Ok(OperationGuard {
            armed: true,
            closing: false,
        });
    }
    // Held across the snapshot AND the increment: registration can neither
    // interleave with the snapshot nor slip in between snapshot and counting.
    let _admission = admission();
    ensure_all_registered()?;
    let mut guard = state();
    if guard.poisoned {
        return Err(Error::MemoryProtection);
    }
    guard.operations += 1;
    Ok(OperationGuard {
        armed: true,
        closing: true,
    })
}

/// A whole-request key-use batch. Its single admission covers every nested
/// `begin_key_operation` on the same thread (they skip the per-operation
/// ToolHelp snapshot), while the held operation guard keeps `operations`
/// nonzero for the entire request: registration is rejected throughout and the
/// watchdog's active-work residual-thread detection stays armed. The drop of
/// the LAST live batch closes the request with an admission-held closing
/// snapshot, so a thread created after the batch's admission but never
/// observed by a watchdog poll is caught at request end instead of escaping
/// into the idle regime unnoticed. Not `Send` or `Sync`: batch depth is
/// thread-local and the batch must drain on its own thread.
pub struct OperationBatch {
    /// Released at an exact point inside [`Drop::drop`]: `ManuallyDrop`
    /// suppresses the automatic field drop so the operation count cannot fall
    /// before the closing sequence decides it should.
    _operation: ManuallyDrop<OperationGuard>,
    _not_send: PhantomData<*const ()>,
}

impl Drop for OperationBatch {
    fn drop(&mut self) {
        // Peek before mutating: depth 1 means this drop takes the thread's
        // last live batch to zero. Depth is thread-local and only this thread
        // mutates it, so nothing can change it between peek and decrement.
        let last = BATCH_DEPTH
            .try_with(|depth| depth.get() <= 1)
            // TLS gone at thread teardown: fail closed through the closing
            // path rather than skip it.
            .unwrap_or(true);
        // Depth first: the closing helper runs after the decrement (this is
        // thread-local bookkeeping; the security-relevant ordering lives
        // inside `close_operation_guard`).
        let _ = BATCH_DEPTH.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
        // Normalize the wrapped guard's release to the role this drop plays,
        // so out-of-order nested drops cannot misroute it: the drop that takes
        // depth to zero releases through `close_operation_guard` (admission-
        // held closing snapshot), any earlier one only decrements.
        self._operation.closing = last;
        // SAFETY: `_operation` is owned by this batch and is released here
        // exactly once; `ManuallyDrop` suppressed the automatic field drop.
        unsafe { ManuallyDrop::drop(&mut self._operation) };
    }
}

/// Starts a key-use batch covering one request (e.g. one broker List/Copy/Code
/// dispatch). The full admission runs exactly once here; nested key operations
/// on this thread are admitted by the batch until it is dropped, and the last
/// drop closes the request with a closing snapshot. See [`OperationBatch`].
pub fn begin_operation_batch() -> Result<OperationBatch, Error> {
    // At batch depth 0 this is a full admission (snapshot under `ADMISSION`).
    let operation = begin_key_operation()?;
    BATCH_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
    Ok(OperationBatch {
        _operation: ManuallyDrop::new(operation),
        _not_send: PhantomData,
    })
}

/// Whether the process-wide residual-thread detector has poisoned secret use.
pub fn process_is_poisoned() -> bool {
    initialized() && state().poisoned
}

#[cfg(feature = "fault-injection")]
pub fn watchdog_thread_id_for_test() -> Option<u32> {
    state().watchdog_id
}

#[cfg(feature = "fault-injection")]
pub fn residency_snapshot_for_test() -> (usize, usize, usize, bool, bool) {
    let guard = state();
    (
        guard.active_sessions,
        guard.pending_acquisitions,
        guard.operations,
        guard.poisoned,
        guard.watchdog_running,
    )
}

#[cfg(feature = "fault-injection")]
pub fn operation_batch_depth_for_test() -> usize {
    BATCH_DEPTH.with(|depth| depth.get())
}

/// Owns the process and thread descriptors supplied to CreateProcessW.
pub(crate) struct ProcessBirthSecurity {
    process: ObjectSecurity,
    thread: ObjectSecurity,
}

impl ProcessBirthSecurity {
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            process: ObjectSecurity::new(ObjectKind::Process)
                .map_err(|_| Error::MemoryProtection)?,
            thread: ObjectSecurity::new(ObjectKind::Thread).map_err(|_| Error::MemoryProtection)?,
        })
    }

    pub(crate) fn process_attributes(&self) -> SECURITY_ATTRIBUTES {
        self.process.attributes()
    }

    pub(crate) fn thread_attributes(&self) -> SECURITY_ATTRIBUTES {
        self.thread.attributes()
    }
}

pub(crate) fn verify_birth_objects(process: HANDLE, thread: HANDLE) -> io::Result<()> {
    verify_security(process, ObjectKind::Process)?;
    verify_security(thread, ObjectKind::Thread)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_without_thread_entries_cannot_admit_a_session() {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        // SAFETY: successful creation transfers ownership to the test.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        assert!(thread_ids_in_snapshot(&snapshot).is_err());
    }

    #[test]
    fn mutex_name_is_stable_and_64_hex() {
        let n1 = writer_mutex_name(b"C:\\Users\\x\\.secret");
        let n2 = writer_mutex_name(b"C:\\Users\\x\\.secret");
        assert_eq!(n1, n2);
        assert!(n1.starts_with("Global\\wsecret-store-"));
        assert_eq!(n1.len(), "Global\\wsecret-store-".len() + 64);
        assert!(
            n1["Global\\wsecret-store-".len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
        // Different path -> different name.
        assert_ne!(n1, writer_mutex_name(b"C:\\Users\\x\\.other"));
    }

    #[test]
    fn mutex_busy_when_held_by_another_thread() {
        let path = b"C:\\wsecret-test\\store-mutex-busy".to_vec();
        let held = WriterMutex::acquire(&path).expect("first acquisition");
        assert_eq!(held.outcome(), MutexOutcome::Acquired);
        // Windows mutexes are owned per-thread, so the competing acquisition
        // must happen on another thread (and is released there).
        let path2 = path.clone();
        let result = std::thread::spawn(move || {
            // Attempting to acquire while `held` owns it: Busy.
            let failed = matches!(WriterMutex::acquire(&path2), Err(Error::Busy));
            // After the owner releases (below), this thread can hold it.
            failed
        })
        .join()
        .unwrap();
        assert!(result);
        drop(held);
        let ok = std::thread::spawn(move || WriterMutex::acquire(&path).is_ok())
            .join()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn identity_lock_name_is_stable_per_key_and_hides_key_material() {
        let key = [0xa5u8; 32];
        let n1 = identity_lock_name(&key).expect("name");
        let n2 = identity_lock_name(&key).expect("name");
        assert_eq!(n1, n2);
        assert!(n1.starts_with("Global\\wsecret-sshkey-"));
        assert_eq!(n1.len(), "Global\\wsecret-sshkey-".len() + 64);
        assert!(
            n1["Global\\wsecret-sshkey-".len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
        // Keyed by the public key: one flipped bit gives a different name.
        let mut other = key;
        other[31] ^= 1;
        assert_ne!(n1, identity_lock_name(&other).expect("name"));
        // No key material in the object name: neither the raw public key nor
        // its hex encoding appears in it (the name is a hash).
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!n1.contains(&hex));
        assert!(!n1.as_bytes().windows(32).any(|w| w == key));
    }

    #[test]
    fn identity_lock_busy_when_held_by_another_thread() {
        let key = [0x5au8; 32];
        let held = IdentityLock::acquire(&key).expect("first acquisition");
        assert_eq!(held.outcome(), MutexOutcome::Acquired);
        // Windows mutexes are owned per-thread, so the competing acquisition
        // must happen on another thread: contention is `Error::Busy` there.
        let failed =
            std::thread::spawn(move || matches!(IdentityLock::acquire(&key), Err(Error::Busy)))
                .join()
                .unwrap();
        assert!(failed, "contending acquisition must be Busy");
        drop(held);
        let ok = std::thread::spawn(move || IdentityLock::acquire(&key).is_ok())
            .join()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn session_gap_registration_fails_closed_without_process_protection() {
        // The quiescent-gap registration API must never provide a silent
        // unprotected fallback: a test process that never opted into the §5.8
        // boundary (and any production caller before `init_process_protection`)
        // gets MEMORY_PROTECTION. The fixture must stay uninitialized for this
        // assertion to be meaningful; no other unit test may initialize the
        // process-wide boundary in this binary (that belongs to role
        // subprocesses).
        assert!(!initialized());
        assert!(matches!(
            register_discovered_threads_for_session(),
            Err(Error::MemoryProtection)
        ));
    }

    #[test]
    fn operation_batch_nests_and_drains_in_the_fixture_process() {
        // Fixture processes without the §5.8 boundary admit unarmed batches;
        // nesting must track depth and drain cleanly even when the batches are
        // dropped out of stack order.
        assert!(!initialized());
        let outer = begin_operation_batch().expect("outer batch");
        let inner = begin_operation_batch().expect("inner batch");
        drop(outer);
        drop(inner);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn operation_batch_depth_gates_the_admission_snapshot() {
        assert!(!initialized());
        assert_eq!(operation_batch_depth_for_test(), 0);
        let outer = begin_operation_batch().expect("outer batch");
        assert_eq!(operation_batch_depth_for_test(), 1);
        {
            let _inner = begin_operation_batch().expect("inner batch");
            assert_eq!(operation_batch_depth_for_test(), 2);
            // Nested operations skip the snapshot but still admit and count.
            let _op = begin_key_operation().expect("nested operation");
            assert_eq!(operation_batch_depth_for_test(), 2);
        }
        assert_eq!(operation_batch_depth_for_test(), 1);
        drop(outer);
        assert_eq!(operation_batch_depth_for_test(), 0);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn last_batch_drop_runs_the_closing_path_in_order() {
        assert!(!initialized());
        let outer = begin_operation_batch().expect("outer batch");
        let inner = begin_operation_batch().expect("inner batch");
        // Out-of-order drops: whichever drop takes depth to zero runs the
        // admission-held closing sequence (depth decrement, operation-guard
        // release, closing snapshot); the earlier one drains as a nested
        // batch. Both drops must be safe in either order.
        drop(outer);
        assert_eq!(operation_batch_depth_for_test(), 1);
        drop(inner);
        assert_eq!(operation_batch_depth_for_test(), 0);
        // In the fixture the closing snapshot is the uninitialized admission
        // check; it must not poison (a real snapshot belongs to role
        // subprocesses with `init_process_protection`).
        assert!(!state().poisoned);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn armed_guard_releases_decrement_and_closing_snapshots() {
        assert!(!initialized());
        // Drive the armed release paths directly (fixture admissions return
        // unarmed guards). This is the ONLY test that moves `operations`, so
        // the count assertions stay exact under parallel test threads: the
        // nested release decrements only, the closing release additionally
        // runs `close_operation_guard` (whose snapshot is the uninitialized
        // no-op admission check here and must not poison).
        state().operations = 1;
        drop(OperationGuard {
            armed: true,
            closing: false,
        });
        assert_eq!(residency_snapshot_for_test().2, 0);
        state().operations = 1;
        drop(OperationGuard {
            armed: true,
            closing: true,
        });
        assert_eq!(residency_snapshot_for_test().2, 0);
        assert!(!state().poisoned);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn armed_acquisition_guard_release_drains_without_fixture_poison() {
        assert!(!initialized());
        // Synthetic armed acquisition guard (fixture admissions are unarmed):
        // the release decrements `pending_acquisitions` and runs the closing
        // drain, whose snapshot in the uninitialized fixture is the no-op
        // admission check and must not poison. Only this test moves
        // `pending_acquisitions`, so the count assertion is exact.
        state().pending_acquisitions = 1;
        drop(AcquisitionGuard { armed: true });
        assert_eq!(residency_snapshot_for_test().1, 0);
        assert!(!state().poisoned);
    }
}
