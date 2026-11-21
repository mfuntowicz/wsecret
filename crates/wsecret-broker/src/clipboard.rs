//! Broker-owned secure clipboard (plan: "secure clipboard
//! exclusions/ownership/expiry"; user brief: 30-second timeout, exclusion
//! formats installed while the clipboard is held and BEFORE the secret
//! format is published, binary values refused with a typed error).
//!
//! Policy, all inside ONE `OpenClipboard` hold:
//!
//! 1. the value must be valid UTF-8 text without interior NUL, otherwise
//!    [`WireStatus::ValueNotText`] and NOTHING is published (a binary value
//!    can never be "copied" as an opaque blob; `wsecret dump` remains the
//!    binary path);
//! 2. `EmptyClipboard`;
//! 3. the three exclusion formats — `ExcludeClipboardContentFromMonitorProcessing`,
//!    `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard` — each
//!    published with a serialized 4-byte `DWORD` zero payload, so the value
//!    is excluded from clipboard history and cloud clipboard sync;
//! 4. THEN the secret formats: `WSecret/Bytes` (exact raw bytes) and
//!    `CF_UNICODETEXT` (UTF-16 + NUL).
//!
//! Ownership and expiry: the broker records `GetClipboardSequenceNumber`
//! right after publishing. The hardened expiry thread and the lock/
//! disconnect teardown clear the clipboard ONLY while that sequence number
//! is unchanged — an external overwrite (the user copied something else)
//! is left alone. Value copies expire after [`CLIPBOARD_TTL_MS`] (30 s per
//! the user brief); OTP copies expire at the earlier of that and the code
//! window (the caller passes the effective TTL).
//!
//! Contention: `OpenClipboard` is retried at most 5 × 50 ms, then
//! [`WireStatus::ClipboardError`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Ole::{CF_UNICODETEXT, OleInitialize, OleUninitialize};
use windows_sys::w;

use wsecret_core::windows::security::{self, HardenedThread};

use crate::protocol::{WireStatus, CLIPBOARD_TTL_MS};

/// OpenClipboard contention bound: 5 attempts, 50 ms apart.
const OPEN_RETRIES: u32 = 5;
const OPEN_RETRY_WAIT_MS: u64 = 50;

/// Registered format names (the MS-documented history/cloud exclusions and
/// the exact-bytes companion format). `w!` yields `PCWSTR` (`*const u16`).
const FMT_EXCLUDE_MONITOR: *const u16 = w!("ExcludeClipboardContentFromMonitorProcessing");
const FMT_NO_HISTORY: *const u16 = w!("CanIncludeInClipboardHistory");
const FMT_NO_CLOUD: *const u16 = w!("CanUploadToCloudClipboard");
const FMT_WSECRET_BYTES: *const u16 = w!("WSecret/Bytes");
/// Private nonsecret format used only to initialize the write path while locked.
const FMT_INIT: *const u16 = w!("WSecret/Initialize");
/// Hash context for clipboard-content ownership checks.
const CTX_CLIP: &[u8; 8] = b"WSCLIP01";

/// Hash of an exact clipboard value, used in addition to the sequence number
/// so system-generated formats do not make cleanup abandon the secret.
fn value_hash(value: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    libhydrogen_sys::hash(&mut hash, value, CTX_CLIP);
    hash
}

/// Recorded ownership of the last published secret.
struct OwnedClip {
    /// `GetClipboardSequenceNumber` captured right after publishing.
    sequence: u32,
    /// Hash of the exact text bytes published, used to distinguish our value
    /// from a later replacement even when Windows adds formats.
    value_hash: [u8; 32],
    /// Clear-at deadline.
    expires: Instant,
}

struct Inner {
    owned: Mutex<Option<OwnedClip>>,
    wake: Condvar,
    stop: AtomicBool,
}

/// The broker's secure clipboard: publish with exclusions + TTL, clear on
/// expiry/lock/disconnect while still owned.
pub struct SecureClipboard {
    inner: Arc<Inner>,
    ole_initialized: bool,
}

impl SecureClipboard {
    /// Creates the clipboard state (no thread yet).
    pub fn new() -> SecureClipboard {
        SecureClipboard {
            inner: Arc::new(Inner {
                owned: Mutex::new(None),
                wake: Condvar::new(),
                stop: AtomicBool::new(false),
            }),
            ole_initialized: false,
        }
    }

    /// Initializes OLE, clipboard formats and the user32 clipboard path while
    /// the broker is locked. No existing clipboard content is read or replaced;
    /// a private zero-valued format initializes `SetClipboardData` without
    /// publishing secret material. The caller follows with native-thread
    /// registration before any secret operation.
    pub fn initialize(&mut self) -> Result<(), WireStatus> {
        if !self.ole_initialized {
            // SAFETY: reserved parameter is NULL; success initializes this
            // thread's OLE apartment exactly once.
            let hr = unsafe { OleInitialize(std::ptr::null()) };
            if hr < 0 {
                return Err(WireStatus::ClipboardError);
            }
            self.ole_initialized = true;
        }
        let _ = registered_formats();
        // SAFETY: query-only sequence read; no clipboard content is accessed.
        let _ = unsafe { GetClipboardSequenceNumber() };
        let _hold = open_clipboard()?;
        // Exercise the read/lock cleanup path without changing clipboard data.
        let current = unsafe { GetClipboardData(CF_UNICODETEXT as u32) };
        if !current.is_null() {
            // SAFETY: query only; no content is modified.
            let ptr = unsafe { GlobalLock(current) };
            if !ptr.is_null() {
                let _ = unsafe { GlobalSize(current) };
                unsafe {
                    GlobalUnlock(current);
                }
            }
        }
        let format = unsafe { RegisterClipboardFormatW(FMT_INIT) };
        let mem = global_from_bytes(&0u32.to_le_bytes())?;
        // SAFETY: clipboard held; a zero DWORD is the only published content.
        if unsafe { SetClipboardData(format, mem) }.is_null() {
            // SAFETY: SetClipboardData failed, so the block is still ours.
            unsafe {
                GlobalFree(mem);
            }
            return Err(WireStatus::ClipboardError);
        }
        Ok(())
    }

    /// Spawns the hardened expiry thread (1 s slices: clears the clipboard
    /// at TTL while still owned). One thread per broker process.
    pub fn spawn_expiry_thread(&self) -> Result<HardenedThread, WireStatus> {
        let inner = Arc::clone(&self.inner);
        security::spawn_hardened_thread(move || {
            loop {
                let guard = inner.owned.lock().unwrap_or_else(|e| e.into_inner());
                if inner.stop.load(Ordering::Acquire) {
                    return;
                }
                let now = Instant::now();
                let expired_sequence = guard
                    .as_ref()
                    .filter(|owned| now >= owned.expires)
                    .map(|owned| owned.sequence);
                if let Some(sequence) = expired_sequence {
                    drop(guard);
                    clear_if_owned_expected(&inner, Some(sequence));
                    continue;
                }
                let wait = guard
                    .as_ref()
                    .map(|owned| owned.expires.saturating_duration_since(now))
                    .unwrap_or(Duration::MAX);
                // No periodic polling: sleep while unowned, wake on publish,
                // shutdown, or the actual expiry deadline.
                let _ = inner.wake.wait_timeout(guard, wait);
            }
        })
        .map_err(|_| WireStatus::ClipboardError)
    }

    /// Publishes `value` to the clipboard with the exclusion formats first
    /// and the secret formats last, all within one hold. `ttl` is the
    /// effective residency (30 s for values; min(30 s, code window) for
    /// OTP codes). Fails with [`WireStatus::ValueNotText`] without touching
    /// the clipboard for binary/unrepresentable values.
    pub fn publish(&self, value: &[u8], ttl: Duration) -> Result<(), WireStatus> {
        // Text-only rule (user brief): valid UTF-8, no interior NUL.
        let text = std::str::from_utf8(value).map_err(|_| WireStatus::ValueNotText)?;
        if value.contains(&0) {
            return Err(WireStatus::ValueNotText);
        }
        let formats = registered_formats();
        let mut blocks = Vec::with_capacity(5);
        for &format in &formats[..3] {
            allocate_publication(&mut blocks, format, &0u32.to_le_bytes(), false)?;
        }
        // Exact raw bytes companion (only ever alongside CF_UNICODETEXT).
        allocate_publication(&mut blocks, formats[3], value, true)?;
        // Encode directly into the publication allocation; no plaintext
        // UTF-16 Vec survives success, failure, or lock.
        allocate_text_publication(&mut blocks, text)?;

        let _hold = match open_clipboard() {
            Ok(hold) => hold,
            Err(error) => {
                free_publications(&mut blocks);
                return Err(error);
            }
        };
        // SAFETY: clipboard held; failure must abort before publishing
        // exclusions or either secret format.
        if unsafe { EmptyClipboard() } == 0 {
            free_publications(&mut blocks);
            return Err(WireStatus::ClipboardError);
        }
        // Exclusions were staged first and are published BEFORE either secret.
        let mut secret_published = false;
        let mut failure = None;
        for block in &mut blocks {
            // SAFETY: clipboard held; each block is a live movable allocation.
            if unsafe { SetClipboardData(block.format, block.mem) }.is_null() {
                failure = Some(WireStatus::ClipboardError);
                break;
            }
            // Ownership transferred to the system.
            block.mem = std::ptr::null_mut();
            secret_published |= block.secret;
        }
        if let Some(error) = failure {
            // Roll back any partially published secret while still held.
            // SAFETY: same clipboard hold; failed SetClipboardData calls did
            // not transfer their blocks, which are freed below.
            let rollback_failed = unsafe { EmptyClipboard() } == 0;
            free_publications(&mut blocks);
            if rollback_failed && secret_published {
                // If rollback itself is blocked, retain ownership so the
                // expiry/lock cleanup retries instead of abandoning plaintext.
                let sequence = unsafe { GetClipboardSequenceNumber() };
                *self.inner.owned.lock().unwrap_or_else(|e| e.into_inner()) = Some(OwnedClip {
                    sequence,
                    value_hash: value_hash(value),
                    expires: Instant::now() + ttl.min(Duration::from_millis(CLIPBOARD_TTL_MS as u64)),
                });
                self.inner.wake.notify_one();
            }
            return Err(error);
        }
        free_publications(&mut blocks); // all blocks transferred; defensive no-op
        let sequence = unsafe { GetClipboardSequenceNumber() };
        let ttl = ttl.min(Duration::from_millis(CLIPBOARD_TTL_MS as u64));
        *self.inner.owned.lock().unwrap_or_else(|e| e.into_inner()) = Some(OwnedClip {
            sequence,
            value_hash: value_hash(value),
            expires: Instant::now() + ttl,
        });
        self.inner.wake.notify_one();
        Ok(())
    }

    /// Clears the clipboard if the broker still owns the last published
    /// secret (sequence unchanged). Called at TTL, at `Lock` and at the
    /// disconnect teardown.
    pub fn clear_if_owned(&self) {
        clear_if_owned(&self.inner);
    }

    /// Stops the expiry thread at teardown.
    pub fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake.notify_one();
    }
}

impl Drop for SecureClipboard {
    fn drop(&mut self) {
        if self.ole_initialized {
            // SAFETY: balances the successful OleInitialize on this thread.
            unsafe { OleUninitialize() };
            self.ole_initialized = false;
        }
    }
}

fn clear_if_owned(inner: &Inner) {
    clear_if_owned_expected(inner, None);
}

/// Checks that the current raw clipboard value is still the value we
/// published. Sequence changes from system-generated formats are harmless;
/// a different value is never treated as ours.
fn clipboard_value_matches(expected: &[u8; 32]) -> bool {
    // SAFETY: format query and handle lifetime are valid while held.
    let handle = unsafe { GetClipboardData(RegisterClipboardFormatW(FMT_WSECRET_BYTES)) };
    if handle.is_null() {
        return false;
    }
    // SAFETY: handle is a movable global allocation; size is queried before
    // reading its bytes.
    let size = unsafe { GlobalSize(handle) };
    if size == 0 {
        return false;
    }
    // SAFETY: lock provides a readable pointer to exactly `size` bytes.
    let ptr = unsafe { GlobalLock(handle) };
    if ptr.is_null() {
        return false;
    }
    let actual = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), size) };
    let actual_hash = value_hash(actual);
    let matches = libhydrogen_sys::equal(&actual_hash, expected);
    // SAFETY: unlock balances the successful lock.
    unsafe {
        GlobalUnlock(handle);
    }
    matches
}

fn clear_if_owned_expected(inner: &Inner, expected_sequence: Option<u32>) {
    let mut guard = inner.owned.lock().unwrap_or_else(|e| e.into_inner());
    let Some(owned) = guard.take() else {
        return;
    };
    if expected_sequence.is_some_and(|sequence| sequence != owned.sequence) {
        // A newer publication replaced the expired item before cleanup.
        *guard = Some(owned);
        return;
    }
    let Ok(_hold) = open_clipboard() else {
        *guard = Some(owned); // contention: retry at the next expiry/lock.
        return;
    };
    if clipboard_value_matches(&owned.value_hash) {
        // SAFETY: clipboard remains held for the clear. Preserve ownership on
        // failure so a later expiry/lock retries instead of losing the secret.
        if unsafe { EmptyClipboard() } == 0 {
            *guard = Some(owned);
        }
    }
}

/// Opens the clipboard with the bounded retry policy (5 × 50 ms).
fn open_clipboard() -> Result<ClipboardHold, WireStatus> {
    for attempt in 0..OPEN_RETRIES {
        // SAFETY: NULL owner window — the broker is a console process; the
        // call takes no borrowed pointers.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
            return Ok(ClipboardHold);
        }
        if attempt + 1 < OPEN_RETRIES {
            std::thread::sleep(Duration::from_millis(OPEN_RETRY_WAIT_MS));
        }
    }
    Err(WireStatus::ClipboardError)
}

/// RAII `CloseClipboard`.
struct ClipboardHold;

impl Drop for ClipboardHold {
    fn drop(&mut self) {
        close_clipboard();
    }
}

fn close_clipboard() {
    // SAFETY: matches one successful OpenClipboard.
    unsafe {
        CloseClipboard();
    }
}

/// Registers (idempotently) the three exclusion formats and `WSecret/Bytes`.
fn registered_formats() -> [u32; 4] {
    // SAFETY: all four names are static NUL-terminated wide strings; the
    // returned atoms are stable for the process lifetime.
    unsafe {
        [
            RegisterClipboardFormatW(FMT_EXCLUDE_MONITOR),
            RegisterClipboardFormatW(FMT_NO_HISTORY),
            RegisterClipboardFormatW(FMT_NO_CLOUD),
            RegisterClipboardFormatW(FMT_WSECRET_BYTES),
        ]
    }
}

/// `GlobalAlloc(GMEM_MOVEABLE)` + copy. The block is unlocked and ready for
/// `SetClipboardData`.
fn global_from_bytes(bytes: &[u8]) -> Result<HANDLE, WireStatus> {
    // SAFETY: allocation of `bytes.len()` movable bytes.
    let mem = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) };
    if mem.is_null() {
        return Err(WireStatus::ClipboardError);
    }
    // SAFETY: fresh allocation; the returned pointer is valid until unlock.
    let ptr = unsafe { GlobalLock(mem) };
    if ptr.is_null() {
        // SAFETY: unowned allocation with zero lock count.
        unsafe {
            GlobalFree(mem);
        }
        return Err(WireStatus::ClipboardError);
    }
    // SAFETY: `ptr` is exclusive and sized `bytes.len()`.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
        GlobalUnlock(mem);
    }
    Ok(mem)
}

struct Publication {
    format: u32,
    mem: HANDLE,
    len: usize,
    secret: bool,
}

fn free_publications(blocks: &mut [Publication]) {
    for block in blocks {
        if !block.mem.is_null() {
            if block.secret && block.len > 0 {
                // SAFETY: the block is still locally owned and `len` is its
                // allocated byte length; erase before releasing the heap.
                unsafe {
                    let ptr = GlobalLock(block.mem);
                    if !ptr.is_null() {
                        let bytes = std::slice::from_raw_parts_mut(ptr.cast::<u8>(), block.len);
                        libhydrogen_sys::memzero(bytes);
                        GlobalUnlock(block.mem);
                    }
                    GlobalFree(block.mem);
                }
            } else {
                // SAFETY: ownership was not transferred to the clipboard.
                unsafe {
                    GlobalFree(block.mem);
                }
            }
            block.mem = std::ptr::null_mut();
        }
    }
}

fn allocate_publication(
    blocks: &mut Vec<Publication>,
    format: u32,
    bytes: &[u8],
    secret: bool,
) -> Result<(), WireStatus> {
    match global_from_bytes(bytes) {
        Ok(mem) => {
            blocks.push(Publication {
                format,
                mem,
                len: bytes.len(),
                secret,
            });
            Ok(())
        }
        Err(error) => {
            free_publications(blocks);
            Err(error)
        }
    }
}

/// Allocates and encodes UTF-16 directly into the publication block, avoiding
/// an ordinary plaintext `Vec<u16>` staging copy.
fn allocate_text_publication(blocks: &mut Vec<Publication>, text: &str) -> Result<(), WireStatus> {
    let units = text.encode_utf16().count();
    // SAFETY: allocate movable storage for `units` plus the trailing NUL.
    let mem = unsafe { GlobalAlloc(GMEM_MOVEABLE, (units + 1) * 2) };
    if mem.is_null() {
        free_publications(blocks);
        return Err(WireStatus::ClipboardError);
    }
    // SAFETY: fresh allocation; the returned pointer is valid until unlock.
    let ptr = unsafe { GlobalLock(mem) };
    if ptr.is_null() {
        // SAFETY: unowned allocation with zero lock count.
        unsafe {
            GlobalFree(mem);
        }
        free_publications(blocks);
        return Err(WireStatus::ClipboardError);
    }
    // SAFETY: `ptr` is exclusive and sized for `units + 1` UTF-16 units.
    unsafe {
        let out = ptr.cast::<u16>();
        for (index, unit) in text.encode_utf16().enumerate() {
            out.add(index).write(unit);
        }
        out.add(units).write(0);
        GlobalUnlock(mem);
    }
    blocks.push(Publication {
        format: CF_UNICODETEXT as u32,
        mem,
        len: (units + 1) * 2,
        secret: true,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_clipboard_value_is_not_cleared_for_old_expiry() {
        let inner = Inner {
            owned: Mutex::new(Some(OwnedClip {
                sequence: 42,
                value_hash: value_hash(b"replacement"),
                expires: Instant::now() + Duration::from_secs(30),
            })),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
        };
        clear_if_owned_expected(&inner, Some(41));
        let guard = inner.owned.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.as_ref().map(|owned| owned.sequence), Some(42));
    }

    #[test]
    fn binary_and_nul_values_are_refused() {
        let clip = SecureClipboard::new();
        // Invalid UTF-8.
        assert_eq!(
            clip.publish(&[0xFF, 0xFE], Duration::from_secs(5)),
            Err(WireStatus::ValueNotText)
        );
        // Interior NUL.
        assert_eq!(
            clip.publish(b"ab\0c", Duration::from_secs(5)),
            Err(WireStatus::ValueNotText)
        );
    }
}
