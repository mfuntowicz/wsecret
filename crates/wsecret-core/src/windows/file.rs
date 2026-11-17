//! Windows store-file I/O: open/create, positioned reads/writes, byte-range
//! locks (`LockFileEx`), `FlushFileBuffers`, file identity and canonical path
//! (plan §3.5, §5.5, §5.6).
//!
//! This module is one of the two sanctioned `unsafe` modules (the other is
//! `libhydrogen-sys`); every `unsafe` block is confined to raw Win32 calls and
//! the safe wrappers below are the only entry points used by the rest of the
//! crate.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_BEGIN, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers, GetFileInformationByHandle, GetFileSizeEx,
    GetFinalPathNameByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    ReadFile, SetFilePointerEx, UnlockFileEx, WriteFile,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Identity of an open store file (spec §5.6 6b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// `dwVolumeSerialNumber`.
    pub volume_serial: u32,
    /// `nFileIndexHigh`/`nFileIndexLow` joined.
    pub file_index: u64,
    /// `nNumberOfLinks` (multi-link stores reject mutation per spec §3.5).
    pub links: u32,
}

fn last_error() -> io::Error {
    // SAFETY: GetLastError is a pure query of the calling thread's state.
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn open_raw(path: &Path, access: u32, disposition: u32, dir: bool) -> io::Result<HANDLE> {
    let w = wide(path);
    let mut flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    if dir {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    // SAFETY: `w` is a valid NUL-terminated wide string; a null security
    // attribute requests the caller's default; the returned handle is checked
    // against INVALID_HANDLE_VALUE before being wrapped.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            disposition,
            flags,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(h)
}

fn wrap(h: HANDLE) -> File {
    // SAFETY: the handle was just created/opened successfully; ownership
    // transfers to the File, which closes it on drop.
    unsafe { File::from_raw_handle(h as _) }
}

/// Opens an existing store file read/write (sharing includes
/// `FILE_SHARE_DELETE`) with `FILE_FLAG_OPEN_REPARSE_POINT`; a reparse point
/// (symlink/junction) is rejected rather than followed (spec §5.5).
pub fn open_store(path: &Path) -> io::Result<File> {
    open_with(path, GENERIC_READ | GENERIC_WRITE, false)
}

/// Opens an existing store file read-only. Same sharing/reparse semantics as
/// [`open_store`].
pub fn open_store_read(path: &Path) -> io::Result<File> {
    open_with(path, GENERIC_READ, false)
}

/// Opens an existing directory (parent reparse-point checks, spec §5.5).
pub fn open_dir(path: &Path) -> io::Result<File> {
    open_with(path, GENERIC_READ, true)
}

fn open_with(path: &Path, access: u32, dir: bool) -> io::Result<File> {
    const OPEN_EXISTING: u32 = 3;
    let h = open_raw(path, access, OPEN_EXISTING, dir)?;
    if is_reparse_point(h) {
        // SAFETY: `h` is a valid owned handle not yet wrapped.
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(h);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "reparse points are not accepted for store paths",
        ));
    }
    Ok(wrap(h))
}

/// Creates a new store file exclusively (`CREATE_NEW`), non-inheritable.
pub fn create_store(path: &Path) -> io::Result<File> {
    const CREATE_NEW: u32 = 1;
    let h = open_raw(path, GENERIC_READ | GENERIC_WRITE, CREATE_NEW, false)?;
    Ok(wrap(h))
}

fn is_reparse_point(h: HANDLE) -> bool {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is valid writable memory of the right size.
    let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
    ok != 0 && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

/// `GetFileInformationByHandle` identity for conflict checks (spec §5.6 6b).
pub fn identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the raw handle is valid for the lifetime of `file`; `info` is
    // valid writable memory.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        links: info.nNumberOfLinks,
    })
}

/// The normalized final path of the open file as UTF-8 bytes
/// (`GetFinalPathNameByHandleW`, `VOLUME_NAME_DOS | FILE_NAME_NORMALIZED`).
/// This is the canonical path identity that the writer-mutex name hashes
/// (spec §5.6 point 1), so path aliases converge on one mutex.
pub fn final_path(file: &File) -> io::Result<Vec<u8>> {
    let h = file.as_raw_handle() as HANDLE;
    // Size query (returns the required length including the NUL).
    // SAFETY: size probe with a null buffer, documented call pattern.
    let needed = unsafe { GetFinalPathNameByHandleW(h, ptr::null_mut(), 0, 0) };
    if needed == 0 {
        return Err(last_error());
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `buf` is valid writable memory of `needed` UTF-16 units.
    let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), needed, 0) };
    if n == 0 || n >= needed {
        return Err(last_error());
    }
    // `n` is the copied length excluding the terminating NUL.
    Ok(String::from_utf16_lossy(&buf[..n as usize]).into_bytes())
}

/// Moves the file pointer to an absolute offset (positioned I/O on a
/// synchronous handle; all reads/writes here are serialized by `&mut` store
/// access and the writer mutex).
fn set_pos(file: &File, offset: u64) -> io::Result<()> {
    // SAFETY: valid handle; a null new-position pointer is allowed.
    let ok = unsafe {
        SetFilePointerEx(
            file.as_raw_handle() as HANDLE,
            offset as i64,
            ptr::null_mut(),
            FILE_BEGIN,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Reads at `offset` into `buf`, looping like upstream `s_read`.
/// `Ok(false)` = end of file before `buf` was completely filled (a trailing
/// partial block, tolerated by readers per spec §1.1).
pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<bool> {
    set_pos(file, offset)?;
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut n: u32 = 0;
        // SAFETY: `buf` is valid writable memory; the call is synchronous.
        let ok = unsafe {
            ReadFile(
                file.as_raw_handle() as HANDLE,
                buf[filled..].as_mut_ptr(),
                (buf.len() - filled) as u32,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        if n == 0 {
            break; // EOF
        }
        filled += n as usize;
    }
    Ok(filled == buf.len())
}

/// Writes `buf` at `offset`, looping like upstream `s_write`, and returns the
/// total byte count accepted by the OS. `Err` is returned only when NOTHING
/// was written; a silent short count (partial write, e.g. disk full
/// mid-buffer) is `Ok(n)` with `n < buf.len()`.
///
/// Commit-state mapping (spec §5.6 point 5): every failure from this call —
/// including the internal `SetFilePointerEx`, which is strictly
/// pre-initiation — is mapped to `CommitState::Unknown` by the caller
/// (conservative direction: the store may hold a written prefix; a false
/// `NotCommitted` would invite a blind retry that duplicates an appended
/// record). No defined fault-injection row (spec §7.3 C16 family)
/// distinguishes the seek failure from the write failure, so the blanket
/// `Unknown` mapping is kept.
pub fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<usize> {
    set_pos(file, offset)?;
    let mut done = 0usize;
    while done < buf.len() {
        let mut n: u32 = 0;
        // SAFETY: `buf` is valid readable memory; the call is synchronous.
        let ok = unsafe {
            WriteFile(
                file.as_raw_handle() as HANDLE,
                buf[done..].as_ptr(),
                (buf.len() - done) as u32,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            if done == 0 {
                return Err(last_error());
            }
            break; // partial write already accepted
        }
        if n == 0 {
            break;
        }
        done += n as usize;
    }
    Ok(done)
}

/// `FlushFileBuffers` (spec §5.6 point 5 checkpoint (iii): nonzero = success).
pub fn flush(file: &File) -> bool {
    // SAFETY: valid owned handle.
    unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) != 0 }
}

fn overlapped_at(offset: u64) -> OVERLAPPED {
    let mut ov = OVERLAPPED::default();
    ov.Anonymous.Anonymous.Offset = offset as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    ov
}

/// Exclusive non-blocking byte-range lock (upstream `fcntl(F_SETLK)` write
/// lock over exactly one 512-byte record). A conflict surfaces as an `Err`
/// for which [`is_lock_violation`] holds (→ `Unable to lock %s`).
pub fn lock_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let mut ov = overlapped_at(offset);
    // SAFETY: `ov` is a correctly laid out OVERLAPPED; FAIL_IMMEDIATELY with
    // EXCLUSIVE matches upstream's non-blocking F_WRLCK semantics.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Releases a [`lock_range`] lock (the OS also releases at handle close).
pub fn unlock_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let mut ov = overlapped_at(offset);
    // SAFETY: valid handle + OVERLAPPED; the range matches the lock call.
    let ok = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// True when the error means "the target region is already locked"
/// (`ERROR_LOCK_VIOLATION`; `ERROR_IO_PENDING` is the overlapped spelling of
/// the same non-blocking lock failure and is accepted as such).
pub fn is_lock_violation(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == ERROR_LOCK_VIOLATION as i32 || code == ERROR_IO_PENDING as i32
    )
}

/// File length in bytes.
pub fn file_len(file: &File) -> io::Result<u64> {
    let mut size: i64 = 0;
    // SAFETY: `size` is valid writable memory.
    let ok = unsafe { GetFileSizeEx(file.as_raw_handle() as HANDLE, &mut size) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(size as u64)
}

/// The current process token's user SID as raw bytes (used by
/// [`super::security`] for object DACLs).
pub fn current_user_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: pseudo-handle for the current process; the token handle is
    // checked and wrapped before use.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let token = wrap(token);
    let mut needed: u32 = 0;
    // SAFETY: documented size-probe with a null buffer.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is valid writable memory of exactly `needed` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error());
    }
    // TOKEN_USER holds one SID_AND_ATTRIBUTES whose Sid pointer refers into
    // `buf` itself; copy the SID bytes out before `buf` is dropped.
    // SAFETY: `buf` holds at least one full TOKEN_USER (checked by the call's
    // success with the exact `needed` size).
    let sid = unsafe { *(buf.as_ptr() as *const TOKEN_USER) }.User.Sid as PSID;
    if sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "token has no user SID",
        ));
    }
    // SAFETY: `sid` points into `buf` and is a valid SID.
    let len = unsafe { GetLengthSid(sid) } as usize;
    if len == 0 {
        return Err(last_error());
    }
    // SAFETY: `sid` is valid for `len` bytes within `buf`.
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, len) }.to_vec())
}
