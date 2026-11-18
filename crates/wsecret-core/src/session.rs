//! Session and key lifetimes: unlock/lock, the `pass` derivation chain, and
//! the key-at-rest encryption layer (plan §3.4 `Session`/`SecretBytes`,
//! §5.3 secret memory + key-at-rest encryption).
//!
//! Key-at-rest invariant (plan §5.3): the session key is stored **only** as
//! `CryptProtectMemory(CRYPTPROTECTMEMORY_SAME_PROCESS)` ciphertext for the
//! whole session lifetime. Every operation that needs the key decrypts a
//! copy into a transient [`SecretBytes`] buffer (`VirtualAlloc` +
//! `VirtualLock`, WER-excluded), uses it, and re-zeroizes it on drop — the
//! at-rest copy is never decrypted in place. DPAPI encrypt/decrypt failure
//! fails closed with [`Error::MemoryProtection`]: no plaintext key is ever
//! left behind on a failure path.
//!
//! This module owns Win32 memory/DPAPI/WER calls directly (the assignment
//! places `SecretBytes` in this file); the rest of the crate uses only the
//! safe wrappers below.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard};

use windows_sys::Win32::Security::Cryptography::{
    CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
    CryptUnprotectMemory,
};
use windows_sys::Win32::System::ErrorReporting::{
    WerRegisterExcludedMemoryBlock, WerUnregisterExcludedMemoryBlock,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualLock,
    VirtualUnlock,
};

use crate::error::Error;
use crate::format::{Header, check_name};
use crate::windows::security::{self, ResidencyLease};

/// What the unlock scan observed (plan §3.4 confirmation gate; recorded by
/// the store scan, consulted by the CLI before creating a new partition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockEvidence {
    /// At least one record decrypted with this session key.
    MatchingRecords,
    /// No record decrypted; creation/derive/agent-launch require
    /// `confirm_new_partition`.
    NoMatchingRecords,
    /// The user re-entered the passphrase to confirm a new partition.
    UserConfirmedNewPartition,
    /// The 32-byte key was adopted from a trusted agent capability
    /// (plan §5.2 acquisition, upstream `pass_ok = match` in `s_ask_agent`):
    /// header equality alone authorizes creation/derive without the
    /// no-records retype confirmation. The launching environment and the
    /// inherited capability are TRUSTED INPUTS (audit P13 — see
    /// `windows::agent_bridge` module docs).
    AgentAuthorized,
}

/// An owned, zeroizing, native secret allocation (plan §5.3).
///
/// Backed by `VirtualAlloc` (never `Vec`/`String`), page-locked with
/// `VirtualLock` (failure fails closed), best-effort excluded from WER
/// dumps, and zeroized via `hydro_memzero` before the pages are unlocked
/// and freed on [`SecretBytes::clear`] / drop (non-panicking).
///
/// Not `Clone`/`Copy`; `Debug` is redacted. `Send` (ownership moves with
/// the value) but deliberately **not** `Sync` (the raw pointer makes it
/// `!Sync` automatically).
///
/// Buffer ownership: this is THE owner of decrypted secret bytes in the
/// crate — record values returned by `store::Store::find` and transient
/// renders in the CLI layer. Secret plaintext must never escape as an
/// ordinary `Vec`/`String`; borrow with [`SecretBytes::as_slice`], mutate
/// with [`SecretBytes::as_mut_slice`], and let drop (or `clear`) erase it.
pub struct SecretBytes {
    ptr: *mut u8,
    len: usize,
    /// `WerRegisterExcludedMemoryBlock` succeeded for this allocation.
    wer: bool,
    /// Present only on a transient key-use allocation. Field drop order keeps
    /// the operation counted until after `SecretBytes::drop` has erased it.
    operation: Option<security::OperationGuard>,
}

// SAFETY: the allocation is owned exclusively by the value; moving the owner
// to another thread transfers that ownership. `VirtualUnlock`/`VirtualFree`/
// `hydro_memzero` are process-global operations valid from any thread.
unsafe impl Send for SecretBytes {}

impl SecretBytes {
    /// Allocates `len` zero-filled secret bytes. The OS zeroes fresh
    /// committed pages; the buffer is page-locked before it can hold
    /// secret material.
    ///
    /// [`Error::NoMemory`] if the allocation fails, [`Error::MemoryProtection`]
    /// if the pages cannot be locked (fail closed: the allocation is freed).
    pub fn new(len: usize) -> Result<Self, Error> {
        if len == 0 {
            return Ok(Self {
                ptr: ptr::null_mut(),
                len: 0,
                wer: false,
                operation: None,
            });
        }
        // SAFETY: requesting a fresh private allocation of `len` bytes;
        // null return is checked before any use.
        let raw =
            unsafe { VirtualAlloc(ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if raw.is_null() {
            return Err(Error::NoMemory);
        }
        let mut buf = SecretBytes {
            ptr: raw.cast::<u8>(),
            len,
            wer: false,
            operation: None,
        };
        // SAFETY: `raw` is a live allocation of `len` bytes.
        if unsafe { VirtualLock(raw, len) } == 0 {
            // Fail closed (plan §5.3): never hand out an unlocked buffer.
            buf.release();
            return Err(Error::MemoryProtection);
        }
        // WER exclusion is best-effort (plan §5.3): proceed on failure.
        if len <= u32::MAX as usize {
            // SAFETY: `raw` is a live allocation of `len` bytes.
            let hr = unsafe { WerRegisterExcludedMemoryBlock(raw, len as u32) };
            buf.wer = hr >= 0;
        }
        Ok(buf)
    }

    /// Copies `src` into a fresh secret allocation (used for the at-rest
    /// key buffer before it is encrypted in place).
    pub fn from_slice(src: &[u8]) -> Result<Self, Error> {
        let mut buf = Self::new(src.len())?;
        buf.as_mut_slice().copy_from_slice(src);
        Ok(buf)
    }

    /// Number of owned bytes (0 after [`SecretBytes::clear`]).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty (also true after `clear`).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The buffer contents. Empty slice after `clear`.
    pub fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: `ptr`/`len` describe the live allocation owned by `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Mutable view of the buffer contents.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.ptr.is_null() {
            return &mut [];
        }
        // SAFETY: `ptr`/`len` describe the live allocation owned by `self`;
        // `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Zeroizes the contents in place (observable step of `clear`, kept
    /// separate so tests can verify the zeroization).
    fn zeroize_contents(&mut self) {
        if !self.ptr.is_null() {
            libhydrogen_sys::memzero(self.as_mut_slice());
        }
    }

    /// Zeroizes the contents, then unregisters/unlocks/frees the pages and
    /// marks the buffer empty. Non-panicking; idempotent.
    pub fn clear(&mut self) {
        self.zeroize_contents();
        self.release();
        self.len = 0;
    }

    /// Releases the OS resources (WER unregister → `VirtualUnlock` →
    /// `VirtualFree`, plan §5.3 drop order) and invalidates the pointer.
    fn release(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        if self.wer {
            // SAFETY: registered for this address at allocation time.
            unsafe { WerUnregisterExcludedMemoryBlock(self.ptr.cast()) };
            self.wer = false;
        }
        // SAFETY: `ptr`/`len` describe the live locked allocation.
        unsafe {
            VirtualUnlock(self.ptr.cast(), self.len);
            VirtualFree(self.ptr.cast(), 0, MEM_RELEASE);
        }
        self.ptr = ptr::null_mut();
    }
}

impl Drop for SecretBytes {
    /// Non-panicking destructor: zeroize → unregister → unlock → free.
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for SecretBytes {
    /// Redacted: never expose secret bytes (or their length) in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// Encrypts `buf` in place with `CryptProtectMemory(SAME_PROCESS)`.
///
/// The buffer length must be a nonzero multiple of
/// `CRYPTPROTECTMEMORY_BLOCK_SIZE` (16); violations fail closed.
/// Failure → [`Error::MemoryProtection`].
fn protect_in_place(buf: &mut [u8]) -> Result<(), Error> {
    let block = CRYPTPROTECTMEMORY_BLOCK_SIZE as usize;
    if buf.is_empty() || buf.len() % block != 0 || buf.len() > u32::MAX as usize {
        return Err(Error::MemoryProtection);
    }
    // SAFETY: `buf` is valid writable memory of `buf.len()` bytes, which the
    // block-size check guarantees is acceptable to the API.
    let ok = unsafe {
        CryptProtectMemory(
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            CRYPTPROTECTMEMORY_SAME_PROCESS,
        )
    };
    if ok == 0 {
        return Err(Error::MemoryProtection);
    }
    Ok(())
}

/// Decrypts `buf` in place (the inverse of [`protect_in_place`]).
/// Failure → [`Error::MemoryProtection`].
fn unprotect_in_place(buf: &mut [u8]) -> Result<(), Error> {
    let block = CRYPTPROTECTMEMORY_BLOCK_SIZE as usize;
    if buf.is_empty() || buf.len() % block != 0 || buf.len() > u32::MAX as usize {
        return Err(Error::MemoryProtection);
    }
    // SAFETY: as `protect_in_place`; `buf` holds ciphertext of this size.
    let ok = unsafe {
        CryptUnprotectMemory(
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            CRYPTPROTECTMEMORY_SAME_PROCESS,
        )
    };
    if ok == 0 {
        return Err(Error::MemoryProtection);
    }
    Ok(())
}

/// Views a 32-byte [`SecretBytes`] as a fixed key array.
fn key_array(buf: &mut SecretBytes) -> Result<&mut [u8; 32], Error> {
    <&mut [u8; 32]>::try_from(buf.as_mut_slice()).map_err(|_| Error::MemoryProtection)
}

/// Zeroizes the passphrase buffer on drop: erasure on **all** return paths,
/// including errors and unwinds (plan §3.4 contract).
///
/// Holds the `&mut [u8]` for its whole lifetime, so the passphrase can be
/// read through the guard (`as_slice`) while the guard is armed and cannot
/// be aliased outside it; `zeroize` may be run early (upstream `s_unlock`
/// erases right after the derivation) and again at drop.
struct EraseOnDrop<'a> {
    buf: &'a mut [u8],
}

impl<'a> EraseOnDrop<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        EraseOnDrop { buf }
    }

    /// The passphrase bytes (borrowed only while the guard is alive).
    fn as_slice(&self) -> &[u8] {
        self.buf
    }

    /// Erases the buffer now; drop erases again (idempotent).
    fn zeroize(&mut self) {
        libhydrogen_sys::memzero(self.buf);
    }
}

impl Drop for EraseOnDrop<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Shared only with the residency watchdog, which holds a Weak reference.
/// Callers still access the key through the non-`Sync` `Session`; the mutex
/// lets the watchdog erase after every in-flight operation has drained.
#[cfg(feature = "fault-injection")]
static LAST_TRANSIENT_ADDRESS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Last transient allocation address for the external transient-window probe.
#[cfg(feature = "fault-injection")]
pub fn transient_key_address_for_test() -> usize {
    LAST_TRANSIENT_ADDRESS.load(std::sync::atomic::Ordering::Acquire)
}

pub(crate) struct SessionKey {
    inner: Mutex<SecretBytes>,
}

impl SessionKey {
    fn new(key: SecretBytes) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(key),
        })
    }

    fn lock(&self) -> MutexGuard<'_, SecretBytes> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn clear_for_watchdog(&self) {
        self.lock().clear();
    }
}

/// An unlocked session: the store header plus the MASTER-derived session key
/// held **at rest as DPAPI ciphertext** (plan §5.3).
///
/// `Send` but not `Sync` (plan §3.4: exclusive access; `Cell` marker preserves
/// that API even though the watchdog can synchronize on the key slot). Drops
/// erase via the non-panicking [`SecretBytes`] destructor.
pub struct Session {
    header: Header,
    /// At-rest ciphertext of the 32-byte session key. Empty (len 0) when the
    /// session is locked, including after watchdog-initiated erasure.
    key: Arc<SessionKey>,
    residency: Option<ResidencyLease>,
    evidence: UnlockEvidence,
    _not_sync: PhantomData<Cell<()>>,
}

impl Session {
    /// Derives the session key from `pass` and the store header exactly as
    /// upstream `s_unlock` does (`hydro_pwhash_deterministic` under `MASTER`,
    /// memlimit 0, threads 1), stores it at rest as
    /// `CryptProtectMemory(SAME_PROCESS)` ciphertext, and zeroizes the
    /// passphrase buffer on every return path (including errors).
    ///
    /// The KDF itself cannot fail for these fixed valid parameters
    /// (plan §1.4); the `Result` reports the fail-closed secret-memory and
    /// DPAPI steps (`Error::MemoryProtection`/`Error::NoMemory`) — on any
    /// error no session is created and every buffer is already erased.
    pub fn unlock(header: &Header, pass: &mut [u8]) -> Result<Session, Error> {
        // Monitoring/admission starts BEFORE the KDF. The guard also covers
        // publication, so a poisoned in-flight unlock never creates a session.
        let _acquisition = security::begin_secret_acquisition()?;
        // The guard owns `pass` for the whole function: zeroized on every
        // return path, including errors and unwinds.
        let mut pass = EraseOnDrop::new(pass);
        // Transient secure buffer for the plaintext key (plan §5.3: the
        // plaintext exists only inside per-operation windows).
        let mut transient = SecretBytes::new(32)?;
        libhydrogen_sys::pwhash_deterministic(
            key_array(&mut transient)?,
            pass.as_slice(),
            &libhydrogen_sys::CTX_MASTER,
            &header.master,
            header.ops_limit,
        );
        // Upstream `s_unlock` erases the passphrase immediately after the
        // derivation; the guard covers the remaining (fallible) steps too.
        pass.zeroize();

        // At-rest copy: fresh secure allocation, then encrypted IN PLACE —
        // the plaintext copy in `transient` is zeroized when it drops.
        let mut key = SecretBytes::new(32)?;
        key.as_mut_slice().copy_from_slice(transient.as_slice());
        protect_in_place(key.as_mut_slice())?;
        transient.clear();

        let key = SessionKey::new(key);
        let residency = security::publish_session(&key)?;
        Ok(Session {
            header: header.clone(),
            key,
            residency: Some(residency),
            evidence: UnlockEvidence::NoMatchingRecords,
            _not_sync: PhantomData,
        })
    }

    /// Builds a session from an already-derived key (internal: the agent
    /// bridge's `adopt_from_pipe` path, which adopts the 73-byte
    /// header + key blob). The key is wrapped in the at-rest protection
    /// immediately; failure leaves no key material behind.
    // Cross-slice contract surface: the agent-bridge slice (plan §5.2/§5.8)
    // is this function's only caller and is not implemented yet.
    #[allow(dead_code)]
    pub(crate) fn from_parts(header: Header, key: [u8; 32]) -> Result<Session, Error> {
        let _acquisition = security::begin_secret_acquisition()?;
        let mut rest = SecretBytes::from_slice(&key)?;
        protect_in_place(rest.as_mut_slice())?;
        let key = SessionKey::new(rest);
        let residency = security::publish_session(&key)?;
        Ok(Session {
            header,
            key,
            residency: Some(residency),
            evidence: UnlockEvidence::NoMatchingRecords,
            _not_sync: PhantomData,
        })
    }

    /// The store header this session was unlocked against.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Header `ops_limit` (upstream `load64_le(s.x.hdr.ops_limit)`); every
    /// derivation uses it.
    pub fn ops_limit(&self) -> u64 {
        self.header.ops_limit
    }

    /// What the unlock scan observed (plan §3.4 confirmation gate).
    pub fn evidence(&self) -> UnlockEvidence {
        self.evidence
    }

    /// Records scan evidence for the confirmation gate (used by the store
    /// scan after enumerating records).
    // Cross-slice contract surface: the session/CLI confirmation-gate wiring
    // (plan §3.4 `confirm_new_partition`) is not implemented yet.
    #[allow(dead_code)]
    pub(crate) fn set_evidence(&mut self, evidence: UnlockEvidence) {
        self.evidence = evidence;
    }

    /// Whether the session is locked (key zeroized and released).
    pub fn is_locked(&self) -> bool {
        self.key.lock().is_empty()
    }

    /// Zeroizes the key and marks the session locked (upstream `s_lock`).
    /// Non-panicking; idempotent. A locked session rejects every operation
    /// that needs the key with [`Error::Locked`].
    pub fn lock(&mut self) {
        self.key.lock().clear();
        self.residency.take();
        self.evidence = UnlockEvidence::NoMatchingRecords;
    }

    /// Decrypts the at-rest key into a transient secure buffer. The caller
    /// must drop the returned buffer as soon as the operation completes
    /// (dropping zeroizes it); the at-rest copy stays ciphertext.
    fn open_transient(&self) -> Result<SecretBytes, Error> {
        // Increment the in-flight count before checking the key. The watchdog
        // can poison concurrently, but then waits for this guard to drain.
        let operation = security::begin_key_operation()?;
        let mut transient = SecretBytes::new(32)?;
        transient.operation = Some(operation);
        {
            let key = self.key.lock();
            if key.is_empty() {
                return Err(Error::Locked);
            }
            transient.as_mut_slice().copy_from_slice(key.as_slice());
        }
        unprotect_in_place(transient.as_mut_slice())?;
        #[cfg(feature = "fault-injection")]
        LAST_TRANSIENT_ADDRESS.store(
            transient.as_slice().as_ptr() as usize,
            std::sync::atomic::Ordering::Release,
        );
        Ok(transient)
    }

    /// Runs `f` with the transiently decrypted session key. The plaintext
    /// key exists only for the duration of the closure; the transient buffer
    /// is zeroized on drop, including on unwind. `f` must not retain the
    /// reference (plan §5.3 per-operation decrypt window).
    ///
    /// [`Error::Locked`] if the session is locked; [`Error::MemoryProtection`]
    /// / [`Error::NoMemory`] from the fail-closed secure path.
    pub(crate) fn with_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Error> {
        let mut transient = self.open_transient()?;
        let out = f(key_array(&mut transient)?);
        Ok(out)
    }

    /// Drives a deliberate, bounded plaintext window for the external P4j
    /// probe. Production code uses the crate-private `with_key` path directly.
    #[cfg(feature = "fault-injection")]
    pub fn with_key_for_test<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Error> {
        self.with_key(f)
    }

    /// Test-only address of the at-rest ciphertext, used by the external
    /// ReadProcessMemory acceptance probe. Never compiled into production.
    #[cfg(feature = "fault-injection")]
    pub fn key_address_for_test(&self) -> usize {
        self.key.lock().as_slice().as_ptr() as usize
    }

    /// The `pass` command derivation chain (plan §1.5, upstream `s_pass`):
    /// `k_0` = the session key; `k_i = hydro_pwhash_deterministic(32,
    /// subkey_i, PASSWD, k_{i-1}, opslimit, 0, 1)`. Returns the raw 32-byte
    /// `k_last` (output normalization is the caller's concern).
    ///
    /// With an empty `subkeys` slice the chain degenerates to `k_0` itself.
    /// Every subkey is validated with upstream `s_keylen` semantics before
    /// any derivation happens; chain temporaries live in transient secure
    /// buffers and are zeroized on every return path (including errors and
    /// unwinds).
    pub fn derive_chain(&self, subkeys: &[&[u8]]) -> Result<[u8; 32], Error> {
        // Validate first so the error path holds no key material
        // (fixes upstream `s_pass`'s derive-then-fatal gap).
        for sub in subkeys {
            check_name(sub).map_err(Error::Name)?;
        }
        // k_0: transient decrypt of the at-rest key.
        let mut prev = self.open_transient()?;
        let mut cur = SecretBytes::new(32)?;
        for sub in subkeys {
            libhydrogen_sys::pwhash_deterministic(
                key_array(&mut cur)?,
                sub,
                &libhydrogen_sys::CTX_PASSWD,
                key_array(&mut prev)?,
                self.header.ops_limit,
            );
            std::mem::swap(&mut prev, &mut cur);
        }
        let out = *key_array(&mut prev)?;
        // `prev`/`cur` drop here: zeroized on every path.
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NameError;

    fn test_header() -> Header {
        Header {
            version: 0,
            master: [0x2a; 32],
            ops_limit: 10_000,
        }
    }

    /// Independent reference derivation of the session key, mirroring
    /// upstream `s_unlock` through the pinned KDF.
    fn reference_session_key(header: &Header, pass: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        libhydrogen_sys::pwhash_deterministic(
            &mut key,
            pass,
            &libhydrogen_sys::CTX_MASTER,
            &header.master,
            header.ops_limit,
        );
        key
    }

    #[test]
    fn unlock_derives_expected_session_key() {
        let header = test_header();
        let mut pass = b"correct horse battery staple".to_vec();
        let expected = reference_session_key(&header, &pass);
        let s = Session::unlock(&header, &mut pass).expect("unlock");
        assert_eq!(s.ops_limit(), 10_000);
        assert_eq!(s.header(), &header);
        assert!(!s.is_locked());
        s.with_key(|k| assert_eq!(k, &expected))
            .expect("transient key check");
    }

    #[test]
    fn unlock_zeroizes_the_passphrase_buffer() {
        let header = test_header();
        let mut pass = b"correct horse battery staple".to_vec();
        let _s = Session::unlock(&header, &mut pass).expect("unlock");
        assert!(
            pass.iter().all(|&b| b == 0),
            "passphrase buffer must be zeroized"
        );
    }

    #[test]
    fn lock_zeroizes_key_and_blocks_key_access() {
        let header = test_header();
        let mut pass = b"pw".to_vec();
        let mut s = Session::unlock(&header, &mut pass).expect("unlock");
        assert!(s.with_key(|_| ()).is_ok());
        s.lock();
        assert!(s.is_locked());
        // The at-rest buffer is emptied (zeroized and released).
        assert!(s.key.lock().is_empty());
        // Every key-dependent operation is refused.
        assert!(matches!(s.with_key(|_| ()), Err(Error::Locked)));
        assert!(matches!(s.derive_chain(&[b"a"]), Err(Error::Locked)));
        // Idempotent.
        s.lock();
        assert!(s.is_locked());
    }

    #[test]
    fn derive_chain_matches_second_independent_derivation() {
        let header = test_header();
        let mut pass = b"pass".to_vec();
        let s = Session::unlock(&header, &mut pass).expect("unlock");
        let subkeys: &[&[u8]] = &[b"alice", b"bob", b"carol"];

        let got = s.derive_chain(subkeys).expect("derive_chain");

        // Second, fully independent derivation: hand-rolled chain through
        // the pinned KDF, mirroring upstream `s_pass`'s loop.
        let mut k = reference_session_key(&header, b"pass");
        for sub in subkeys {
            let mut next = [0u8; 32];
            libhydrogen_sys::pwhash_deterministic(
                &mut next,
                sub,
                &libhydrogen_sys::CTX_PASSWD,
                &k,
                header.ops_limit,
            );
            k = next;
        }
        assert_eq!(got, k);

        // Determinism per fixed tuple: a second independent session agrees.
        let mut pass2 = b"pass".to_vec();
        let s2 = Session::unlock(&header, &mut pass2).expect("unlock 2");
        assert_eq!(s2.derive_chain(subkeys).expect("second chain"), got);
    }

    #[test]
    fn derive_chain_with_no_subkeys_returns_session_key() {
        let header = test_header();
        let mut pass = b"pass".to_vec();
        let s = Session::unlock(&header, &mut pass).expect("unlock");
        let got = s.derive_chain(&[]).expect("empty chain");
        assert_eq!(got, reference_session_key(&header, b"pass"));
    }

    #[test]
    fn derive_chain_rejects_invalid_subkeys_without_touching_the_key() {
        let header = test_header();
        let mut pass = b"pass".to_vec();
        let s = Session::unlock(&header, &mut pass).expect("unlock");
        assert!(matches!(
            s.derive_chain(&[b""]),
            Err(Error::Name(NameError::Empty))
        ));
        assert!(matches!(
            s.derive_chain(&[b"has space"]),
            Err(Error::Name(NameError::SpecialChar))
        ));
        assert!(matches!(
            s.derive_chain(&[b"has\ttab"]),
            Err(Error::Name(NameError::SpecialChar))
        ));
        assert!(matches!(
            s.derive_chain(&[&[b'k'; 256]]),
            Err(Error::Name(NameError::TooLong))
        ));
        // The error path left the session usable (key intact).
        let expected = reference_session_key(&header, b"pass");
        s.with_key(|k| assert_eq!(k, &expected))
            .expect("key intact after error");
    }

    #[test]
    fn at_rest_key_is_ciphertext_while_idle() {
        let header = test_header();
        let mut pass = b"pass".to_vec();
        let s = Session::unlock(&header, &mut pass).expect("unlock");
        let expected = reference_session_key(&header, b"pass");

        // While idle, the at-rest buffer is NOT the plaintext key...
        let at_rest = s.key.lock().as_slice().to_vec();
        assert_ne!(at_rest, &expected[..], "at rest must be ciphertext");
        // ...but it IS the key's ciphertext: decrypting a copy recovers it.
        let mut copy = at_rest.clone();
        unprotect_in_place(&mut copy).expect("ciphertext must decrypt");
        assert_eq!(copy, expected);

        // A transient operation leaves the at-rest copy untouched.
        s.with_key(|k| assert_eq!(k, &expected))
            .expect("transient use");
        assert_eq!(
            s.key.lock().as_slice(),
            at_rest,
            "at rest must stay ciphertext"
        );
    }

    #[test]
    fn from_parts_wraps_the_key_at_rest() {
        let header = test_header();
        let key = [0x5au8; 32];
        let s = Session::from_parts(header.clone(), key).expect("from_parts");
        assert_ne!(
            s.key.lock().as_slice(),
            &key[..],
            "at rest must be ciphertext"
        );
        s.with_key(|k| assert_eq!(k, &key)).expect("transient use");
    }

    #[test]
    fn secret_bytes_zeroizes_contents_on_clear() {
        let mut buf = SecretBytes::from_slice(&[7u8; 32]).expect("alloc");
        assert_eq!(buf.as_slice(), &[7u8; 32]);
        buf.zeroize_contents();
        assert_eq!(buf.as_slice(), &[0u8; 32], "contents must be zeroized");
        buf.clear();
        assert!(buf.is_empty());
        // Idempotent.
        buf.clear();
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let buf = SecretBytes::from_slice(b"super-secret").expect("alloc");
        let dbg = format!("{buf:?}");
        assert!(
            dbg.contains("redacted"),
            "Debug must render redacted: {dbg}"
        );
        assert!(
            !dbg.contains("super-secret"),
            "secret bytes must not appear in Debug: {dbg}"
        );
    }

    #[test]
    fn erase_guard_zeroizes_on_scope_exit() {
        let mut buf = vec![0xabu8; 8];
        {
            let _guard = EraseOnDrop::new(&mut buf);
        }
        assert!(buf.iter().all(|&b| b == 0), "guard must zeroize on drop");
    }

    #[test]
    fn dpapi_protect_round_trip_masks_plaintext() {
        let mut buf = *b"0123456789abcdef0123456789abcdef";
        let plain = buf;
        protect_in_place(&mut buf).expect("protect");
        assert_ne!(buf, plain, "protect must mask the buffer");
        unprotect_in_place(&mut buf).expect("unprotect");
        assert_eq!(buf, plain, "round trip must recover the plaintext");
    }

    #[test]
    fn dpapi_rejects_invalid_block_sizes_failing_closed() {
        let mut empty: [u8; 0] = [];
        assert!(matches!(
            protect_in_place(&mut empty),
            Err(Error::MemoryProtection)
        ));
        assert!(matches!(
            protect_in_place(&mut [0u8; 3]),
            Err(Error::MemoryProtection)
        ));
        assert!(matches!(
            unprotect_in_place(&mut [0u8; 17]),
            Err(Error::MemoryProtection)
        ));
    }

    #[test]
    fn evidence_tracks_scan_and_resets_on_lock() {
        let header = test_header();
        let mut pass = b"pass".to_vec();
        let mut s = Session::unlock(&header, &mut pass).expect("unlock");
        assert_eq!(s.evidence(), UnlockEvidence::NoMatchingRecords);
        s.set_evidence(UnlockEvidence::MatchingRecords);
        assert_eq!(s.evidence(), UnlockEvidence::MatchingRecords);
        s.lock();
        assert_eq!(
            s.evidence(),
            UnlockEvidence::NoMatchingRecords,
            "lock() resets the confirmation gate"
        );
    }

    #[test]
    fn session_and_secret_bytes_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Session>();
        assert_send::<SecretBytes>();
    }
}
