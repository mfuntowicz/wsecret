//! Native Windows Hello unlock via WebAuthn PRF (hmac-secret) — "Hello via
//! native WebAuthn PRF/hmac-secret with required UV, not sign-only or
//! consent+DPAPI".
//!
//! # What is sealed (explicit residency disclosure)
//!
//! The Hello binding wraps a broker-PRIVATE unlock capability: the master
//! passphrase (passphrase-equivalent material) that the broker retained in
//! locked memory for the current unlocked epoch (see `main.rs`'s broker
//! state docs). It does NOT wrap or persist the raw partition/session key:
//! no core `Session` API exposes key bytes, none is added, and the on-disk
//! sidecar contains no plaintext key material — only the hydro_secretbox
//! seal under the WebAuthn PRF output. A party holding the sidecar AND able
//! to satisfy the authenticator's user verification (biometric/PIN of the
//! enrolled Windows user) can recover the passphrase; that is exactly the
//! guarantee Windows Hello sells, and the store itself remains
//! passphrase-encrypted and portable.
//!
//! # Ceremony shape (microsoft/webauthn `webauthn.h`; Windows SDK 26100
//! bindings `windows_sys::Win32::Networking::WindowsWebServices`)
//!
//! - Enrollment: `WebAuthNAuthenticatorMakeCredential` (platform
//!   authenticator, resident credential, `bEnablePrf`, UV REQUIRED,
//!   attestation NONE) → credential id, then a PROBE
//!   `WebAuthNAuthenticatorGetAssertion` with a fresh 32-byte salt MUST
//!   return `pHmacSecret.cbFirst == 32` with the UV flag set in the
//!   authenticator data (registration-time `bPrfEnabled` is NOT trusted —
//!   Windows Hello has been observed reporting it false while PRF works,
//!   and true while it does not).
//! - Unlock: `WebAuthNAuthenticatorGetAssertion` over the stored credential
//!   id with the SAME salt (default WebAuthn-PRF hash mode, `dwFlags = 0`),
//!   UV REQUIRED again; the UV (0x04) and UP (0x01) bits of the returned
//!   authenticator-data flags are verified before the 32-byte output is
//!   used. CTAP 2.2 keeps distinct `CredRandomWithUV`/`CredRandomWithoutUV`
//!   values, so a UV=0 output derives a DIFFERENT key — the flag check is
//!   load-bearing, not ceremony.
//!
//! # Fail-disabled
//!
//! If `webauthn.dll` predates the PRF options version, no user-verifying
//! platform authenticator exists, the OS predates Hello hmac-secret support
//! (KB5077181 floor), or the enrollment probe returns no PRF output, Hello
//! is [`HelloState::Unsupported`] and Hello unlock answers
//! [`WireStatus::HelloUnavailable`]. There is NO fallback to a weaker
//! mechanism: passphrase unlock keeps working everywhere.
//!
//! # Sidecar record (`<store>.hello`)
//!
//! Versioned binary written through the same hardened creation path as the
//! store (`winfile::create_store`: exclusive create, non-inheritable;
//! reparse points are rejected on read):
//!
//! ```text
//! 0   4    magic "WSHB"
//! 4   1    version = 1
//! 5   1    flags = 0
//! 6   2    reserved = 0
//! 8   32   store_master (header master field: store identity binding)
//! 40  32   user_sid_hash (hydro_hash of the user SID: account binding)
//! 72  2    cred_id_len (u16 LE, 1..=1024)
//! 74  N    cred_id (WebAuthn credential id: device binding)
//! 74+N  32 prf_salt (PRF input, default WebAuthn-PRF hash mode)
//! 106+N 24 nonce (hydro_secretbox)
//! 130+N 2  sealed_len (u16 LE = 512)
//! 132+N 512 sealed (hydro_secretbox of the 476-byte capability envelope)
//! ```
//!
//! Capability envelope plaintext (476 bytes, ctx `WSHELLO1`):
//! `u8 version = 1 | u8 pass_len | passphrase bytes | zero padding`.
//! The WebAuthn user handle is `hydro_hash(store_master | user_sid_hash)`
//! under ctx `WSHLOUSR` (32 bytes, distinct per store — enrolling a second
//! store never overwrites the first credential on the same authenticator).
//!
//! Recovery/unbind: deleting the sidecar (or `HelloForget`) removes the
//! binding; the store stays passphrase-unlockable forever. Users can also
//! delete the passkey in Windows Settings — that destroys the wrap key and
//! Hello unlock reports [`WireStatus::HelloFailed`] until re-enrollment.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNCancelCurrentOperation,
    WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber,
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_sys::core::GUID;
use windows_sys::w;

use libhydrogen_sys::{self, ENTRY_BYTES, ENTRY_PAYLOAD};
use wsecret_core::windows::{file as winfile, security};

use crate::protocol::{HelloState, WireStatus};

/// Stable RP ID for the Hello credential. CHANGING THIS ORPHANS EVERY
/// ENROLLED CREDENTIAL (the wrap key becomes unrecoverable) — it is part of
/// the compatibility contract forever. (`w!` yields `PCWSTR`.)
const RP_ID: *const u16 = w!("wsecret.local");
/// RP display name.
const RP_NAME: *const u16 = w!("WSecret");
/// User entity name.
const USER_NAME: *const u16 = w!("wsecret");
/// User entity display label.
const USER_DISPLAY: *const u16 = w!("WSecret");
/// hydro_secretbox context for the capability envelope (distinct from the
/// store's MASTER/SECRET/PASSWD contexts).
const CTX_HELLO: &[u8; 8] = b"WSHELLO1";
/// hydro_hash context for the user-SID binding.
const CTX_SID: &[u8; 8] = b"WSHLOSID";
/// hydro_hash context for the WebAuthn user handle.
const CTX_USER: &[u8; 8] = b"WSHLOUSR";
/// Sidecar magic.
const MAGIC: &[u8; 4] = b"WSHB";
/// Sidecar format version.
const RECORD_VERSION: u8 = 1;
/// Maximum credential id bytes.
const MAX_CRED_ID: usize = 1024;
/// Maximum accepted sidecar size (fixed fields + max cred id + sealed).
const MAX_RECORD: u64 = (132 + MAX_CRED_ID + ENTRY_BYTES) as u64;
/// WebAuthn options `dwVersion` for the PRF flow (v6: bEnablePrf /
/// pHmacSecretSaltValues).
const OPTIONS_VERSION: u32 = 6;
/// Entity/client-data struct version (`WEBAUTHN_*_CURRENT_VERSION` = 1).
const STRUCT_VERSION: u32 = 1;
/// Authenticator-data flag bits we require (UP | UV).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
/// Upstream passphrase cap (`s_ask_pass`): 127 content bytes.
const MAX_PASS: usize = 127;

/// Parsed sidecar record (all binding fields included).
pub struct Record {
    /// Store identity binding (header master field).
    pub store_master: [u8; 32],
    /// Account binding (`hydro_hash` of the user SID).
    pub user_sid_hash: [u8; 32],
    /// Credential id (device binding).
    pub cred_id: Vec<u8>,
    /// PRF input salt (32 bytes, default WebAuthn-PRF hash mode).
    pub prf_salt: [u8; 32],
    /// hydro_secretbox nonce (24 bytes).
    pub nonce: [u8; 24],
    /// The 512-byte hydro_secretbox seal.
    pub sealed: [u8; ENTRY_BYTES],
}

/// The sidecar path for a store: `<store>.hello`.
pub fn sidecar_path(store: &Path) -> PathBuf {
    let mut name = store.as_os_str().to_owned();
    name.push(".hello");
    PathBuf::from(name)
}

/// Cheap availability: webauthn.dll speaks the PRF options version AND a
/// user-verifying platform authenticator exists. Advisory only — the
/// enrollment PRF probe is the binding capability check.
pub fn availability() -> HelloState {
    // SAFETY: query-only calls; no borrowed pointers.
    unsafe {
        if WebAuthNGetApiVersionNumber() < OPTIONS_VERSION {
            return HelloState::Unsupported;
        }
        let mut available: i32 = 0;
        if WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&mut available) < 0
            || available == 0
        {
            return HelloState::Unsupported;
        }
    }
    HelloState::Available
}

/// Binding state for `store`: [`HelloState::Enrolled`] only when a record
/// exists AND its store/SID bindings match this machine and account.
pub fn state(store: &Path, store_master: &[u8; 32]) -> HelloState {
    if availability() == HelloState::Unsupported {
        return HelloState::Unsupported;
    }
    match load_record(store) {
        Ok(Some(record)) if bindings_match(&record, store_master) => HelloState::Enrolled,
        _ => HelloState::Available,
    }
}

/// Enrolls Hello for `store`: creates the platform PRF credential, proves
/// PRF output with required UV, seals `pass` under the PRF output and writes
/// the sidecar. Fail-disabled: any failure leaves NO sidecar and maps to
/// [`WireStatus::HelloUnavailable`] / [`WireStatus::HelloFailed`].
pub fn enroll(
    store: &Path,
    store_master: &[u8; 32],
    pass: &[u8],
    deadline: Instant,
) -> Result<HelloState, WireStatus> {
    if availability() == HelloState::Unsupported {
        return Err(WireStatus::HelloUnavailable);
    }
    if pass.is_empty() || pass.len() > MAX_PASS {
        return Err(WireStatus::InputInvalid);
    }
    let mut prf_salt = [0u8; 32];
    libhydrogen_sys::random_buf(&mut prf_salt);

    let cred_id = make_credential(store_master, deadline)?;
    // The probe IS the capability check (registration flags are untrusted).
    let wrap_key =
        prf_assertion(&cred_id, &prf_salt, deadline).map_err(|_| WireStatus::HelloUnavailable)?;

    let mut nonce = [0u8; 24];
    libhydrogen_sys::random_buf(&mut nonce);
    let mut envelope = [0u8; ENTRY_PAYLOAD];
    envelope[0] = 1;
    envelope[1] = pass.len() as u8;
    envelope[2..2 + pass.len()].copy_from_slice(pass);
    let mut sealed = [0u8; ENTRY_BYTES];
    libhydrogen_sys::secretbox_encrypt(&mut sealed, &envelope, CTX_HELLO, &wrap_key);
    libhydrogen_sys::memzero(&mut envelope);

    let record = Record {
        store_master: *store_master,
        user_sid_hash: sid_binding()?,
        cred_id,
        prf_salt,
        nonce,
        sealed,
    };
    write_record(store, &record)?;
    Ok(HelloState::Enrolled)
}

/// Hello unlock: asserts PRF with required UV over the stored credential,
/// unseals the capability envelope and RETURNS the passphrase for
/// [`wsecret_core::session::Session::unlock`] (upstream unlock semantics
/// preserved). The caller wipes the returned buffer.
pub fn unlock(
    store: &Path,
    store_master: &[u8; 32],
    deadline: Instant,
) -> Result<Vec<u8>, WireStatus> {
    if availability() == HelloState::Unsupported {
        return Err(WireStatus::HelloUnavailable);
    }
    let record = load_record(store)?.ok_or(WireStatus::HelloNotEnrolled)?;
    if !bindings_match(&record, store_master) {
        // A record for another store/account is "no binding for this store".
        return Err(WireStatus::HelloNotEnrolled);
    }
    let wrap_key =
        prf_assertion(&record.cred_id, &record.prf_salt, deadline).map_err(|_| WireStatus::HelloFailed)?;
    let mut envelope = [0u8; ENTRY_PAYLOAD];
    if !libhydrogen_sys::secretbox_decrypt(&mut envelope, &record.sealed, CTX_HELLO, &wrap_key) {
        libhydrogen_sys::memzero(&mut envelope);
        return Err(WireStatus::HelloFailed);
    }
    let pass_len = envelope[1] as usize;
    let pass = if envelope[0] == 1 && (1..=MAX_PASS).contains(&pass_len) {
        Ok(envelope[2..2 + pass_len].to_vec())
    } else {
        Err(WireStatus::HelloFailed)
    };
    libhydrogen_sys::memzero(&mut envelope);
    pass
}

/// Deletes the binding record (idempotent).
pub fn forget(store: &Path) -> Result<(), WireStatus> {
    match std::fs::remove_file(sidecar_path(store)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WireStatus::Io),
    }
}

/// Store + account binding check (constant-time compares via `hydro_equal`).
fn bindings_match(record: &Record, store_master: &[u8; 32]) -> bool {
    let sid_ok = match sid_binding() {
        Ok(sid) => libhydrogen_sys::equal(&record.user_sid_hash, &sid),
        Err(_) => false,
    };
    sid_ok && libhydrogen_sys::equal(&record.store_master, store_master)
}

// ---- WebAuthn ceremonies -------------------------------------------------

/// `WebAuthNAuthenticatorMakeCredential` with PRF enabled; returns the
/// credential id. Fail-closed on any API failure.
fn make_credential(store_master: &[u8; 32], deadline: Instant) -> Result<Vec<u8>, WireStatus> {
    let user_id = user_handle(store_master)?;
    let client = ClientData::new("webauthn.create")?;
    let client_data = client.view();

    let mut rp = zeroed::<WEBAUTHN_RP_ENTITY_INFORMATION>();
    rp.dwVersion = STRUCT_VERSION;
    rp.pwszId = RP_ID;
    rp.pwszName = RP_NAME;

    let mut user = zeroed::<WEBAUTHN_USER_ENTITY_INFORMATION>();
    user.dwVersion = STRUCT_VERSION;
    user.cbId = user_id.len() as u32;
    user.pbId = user_id.as_ptr() as *mut u8;
    user.pwszName = USER_NAME;
    user.pwszDisplayName = USER_DISPLAY;

    let mut param = zeroed::<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>();
    param.dwVersion = STRUCT_VERSION;
    param.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    param.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    let mut params = zeroed::<WEBAUTHN_COSE_CREDENTIAL_PARAMETERS>();
    params.cCredentialParameters = 1;
    params.pCredentialParameters = &mut param;

    let mut cancellation = zeroed::<GUID>();
    // SAFETY: GUID is a plain 16-byte C value; random bytes are sufficient
    // for a cancellation identifier and avoid a COM dependency.
    unsafe {
        libhydrogen_sys::random_buf(std::slice::from_raw_parts_mut(
            &mut cancellation as *mut GUID as *mut u8,
            std::mem::size_of::<GUID>(),
        ));
    }

    let mut opts = zeroed::<WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS>();
    opts.dwVersion = OPTIONS_VERSION;
    opts.dwTimeoutMilliseconds = remaining_ms(deadline);
    opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    opts.bRequireResidentKey = 0;
    opts.bPreferResidentKey = 1;
    opts.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    opts.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    opts.pCancellationId = &mut cancellation;
    opts.bEnablePrf = 1;

    let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
    // SAFETY: every struct above is fully initialized for the versions set;
    // `attestation` receives a DLL-owned block freed below.
    let hr = with_cancellation(&cancellation, deadline, || unsafe {
        WebAuthNAuthenticatorMakeCredential(
            GetForegroundWindow(),
            &rp,
            &user,
            &params,
            &client_data,
            &opts,
            &mut attestation,
        )
    })?;
    if hr < 0 || attestation.is_null() {
        return Err(WireStatus::HelloFailed);
    }
    // SAFETY: DLL-owned block, read-only borrow, freed exactly once below.
    let cred_id = unsafe {
        let att = &*attestation;
        if att.cbCredentialId == 0 || att.cbCredentialId as usize > MAX_CRED_ID {
            None
        } else {
            Some(
                std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize).to_vec(),
            )
        }
    };
    // SAFETY: matches the allocation above.
    unsafe { WebAuthNFreeCredentialAttestation(attestation) };
    cred_id.ok_or(WireStatus::HelloFailed)
}

/// `WebAuthNAuthenticatorGetAssertion` with the PRF salt (default
/// WebAuthn-PRF hash mode) and REQUIRED user verification. Verifies the
/// returned UP/UV flags and returns the 32-byte PRF output.
fn prf_assertion(
    cred_id: &[u8],
    prf_salt: &[u8; 32],
    deadline: Instant,
) -> Result<[u8; 32], WireStatus> {
    let client = ClientData::new("webauthn.get")?;
    let client_data = client.view();

    let mut cred = zeroed::<WEBAUTHN_CREDENTIAL_EX>();
    cred.dwVersion = STRUCT_VERSION;
    cred.cbId = cred_id.len() as u32;
    cred.pbId = cred_id.as_ptr() as *mut u8;
    cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    let mut cred_ptr: *mut WEBAUTHN_CREDENTIAL_EX = &mut cred;
    let mut allow = zeroed::<WEBAUTHN_CREDENTIAL_LIST>();
    allow.cCredentials = 1;
    allow.ppCredentials = &mut cred_ptr;

    let mut salt = zeroed::<WEBAUTHN_HMAC_SECRET_SALT>();
    salt.cbFirst = 32;
    salt.pbFirst = prf_salt.as_ptr() as *mut u8;
    let mut salt_values = zeroed::<WEBAUTHN_HMAC_SECRET_SALT_VALUES>();
    salt_values.pGlobalHmacSalt = &mut salt;

    let mut cancellation = zeroed::<GUID>();
    // SAFETY: GUID is a plain 16-byte C value filled with random bytes.
    unsafe {
        libhydrogen_sys::random_buf(std::slice::from_raw_parts_mut(
            &mut cancellation as *mut GUID as *mut u8,
            std::mem::size_of::<GUID>(),
        ));
    }

    let mut opts = zeroed::<WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS>();
    opts.dwVersion = OPTIONS_VERSION;
    opts.dwTimeoutMilliseconds = remaining_ms(deadline);
    opts.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    opts.pAllowCredentialList = &mut allow;
    opts.pHmacSecretSaltValues = &mut salt_values;
    opts.pCancellationId = &mut cancellation;
    // dwFlags stays 0: default WebAuthn-PRF salt hashing (interop mode).

    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: all structs initialized; `assertion` receives a DLL-owned
    // block freed below.
    let hr = with_cancellation(&cancellation, deadline, || unsafe {
        WebAuthNAuthenticatorGetAssertion(
            GetForegroundWindow(),
            RP_ID,
            &client_data,
            &opts,
            &mut assertion,
        )
    })?;
    if hr < 0 || assertion.is_null() {
        return Err(WireStatus::HelloFailed);
    }
    // SAFETY: DLL-owned block; read-only; freed exactly once below. Hot
    // fields are gated on the returned dwVersion (older DLLs allocate less).
    let out = unsafe {
        let a = &*assertion;
        let mut ok = a.dwVersion >= 3 && !a.pHmacSecret.is_null();
        let mut key = [0u8; 32];
        if ok {
            let hs = &*a.pHmacSecret;
            ok = hs.cbFirst == 32 && !hs.pbFirst.is_null();
            if ok {
                key.copy_from_slice(std::slice::from_raw_parts(hs.pbFirst, 32));
            }
        }
        // UV assurance: authenticator data = 32-byte RP ID hash | flags |
        // counter...; require UP and UV (CTAP CredRandomWithUV binding).
        if ok {
            ok = a.cbAuthenticatorData >= 33 && !a.pbAuthenticatorData.is_null();
            if ok {
                let flags = *a.pbAuthenticatorData.add(32);
                ok = flags & FLAG_UP != 0 && flags & FLAG_UV != 0;
            }
        }
        Some(key).filter(|_| ok)
    };
    // SAFETY: matches the allocation above.
    unsafe { WebAuthNFreeAssertion(assertion) };
    out.ok_or(WireStatus::HelloFailed)
}

/// Owned client-data JSON for one ceremony.
struct ClientData {
    json: Vec<u8>,
}

impl ClientData {
    /// Builds `{"type":…,"challenge":<base64url 32 random>,"origin":…}`.
    fn new(ceremony: &str) -> Result<ClientData, WireStatus> {
        let mut challenge = [0u8; 32];
        libhydrogen_sys::random_buf(&mut challenge);
        let encoded = base64url(&challenge);
        let json = format!(
            "{{\"type\":\"{ceremony}\",\"challenge\":\"{encoded}\",\"origin\":\"https://wsecret.local\"}}"
        )
        .into_bytes();
        Ok(ClientData { json })
    }

    /// The `WEBAUTHN_CLIENT_DATA` view (valid while `self` is borrowed).
    fn view(&self) -> WEBAUTHN_CLIENT_DATA {
        let mut data = zeroed::<WEBAUTHN_CLIENT_DATA>();
        data.dwVersion = STRUCT_VERSION;
        data.cbClientDataJSON = self.json.len() as u32;
        data.pbClientDataJSON = self.json.as_ptr() as *mut u8;
        data.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
        data
    }
}

/// WebAuthn user handle: `hydro_hash(store_master | user_sid_hash)` — 32
/// bytes, distinct per store, within `WEBAUTHN_MAX_USER_ID_LENGTH`.
fn user_handle(store_master: &[u8; 32]) -> Result<Vec<u8>, WireStatus> {
    let sid_hash = sid_binding()?;
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(store_master);
    input.extend_from_slice(&sid_hash);
    let mut out = [0u8; 32];
    libhydrogen_sys::hash(&mut out, &input, CTX_USER);
    libhydrogen_sys::memzero(&mut input);
    Ok(out.to_vec())
}

/// Account binding: `hydro_hash(current user SID)`.
fn sid_binding() -> Result<[u8; 32], WireStatus> {
    let sid = winfile::current_user_sid().map_err(|_| WireStatus::Io)?;
    let mut out = [0u8; 32];
    libhydrogen_sys::hash(&mut out, &sid, CTX_SID);
    Ok(out)
}

// ---- sidecar record I/O --------------------------------------------------

/// Reads and validates the sidecar; `Ok(None)` = absent.
fn load_record(store: &Path) -> Result<Option<Record>, WireStatus> {
    let path = sidecar_path(store);
    let file = match winfile::open_store_read(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WireStatus::Io),
    };
    let len = winfile::file_len(&file).map_err(|_| WireStatus::Io)?;
    if len > MAX_RECORD {
        return Err(WireStatus::HelloFailed);
    }
    let mut buf = vec![0u8; len as usize];
    let got_all = winfile::read_at(&file, 0, &mut buf).map_err(|_| WireStatus::Io)?;
    if !got_all {
        return Err(WireStatus::HelloFailed);
    }
    parse_record(&buf).map(Some)
}

/// Parses the versioned record with exact-length checks (any deviation is
/// [`WireStatus::HelloFailed`]; a corrupt binding is never used).
fn parse_record(buf: &[u8]) -> Result<Record, WireStatus> {
    let bad = WireStatus::HelloFailed;
    if buf.len() < 74 || &buf[0..4] != MAGIC || buf[4] != RECORD_VERSION {
        return Err(bad);
    }
    let cred_len = u16::from_le_bytes([buf[72], buf[73]]) as usize;
    if cred_len == 0 || cred_len > MAX_CRED_ID {
        return Err(bad);
    }
    let need = 74 + cred_len + 32 + 24 + 2 + ENTRY_BYTES;
    if buf.len() != need {
        return Err(bad);
    }
    let mut store_master = [0u8; 32];
    store_master.copy_from_slice(&buf[8..40]);
    let mut user_sid_hash = [0u8; 32];
    user_sid_hash.copy_from_slice(&buf[40..72]);
    let mut at = 74 + cred_len;
    let mut prf_salt = [0u8; 32];
    prf_salt.copy_from_slice(&buf[at..at + 32]);
    at += 32;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&buf[at..at + 24]);
    at += 24;
    let sealed_len = u16::from_le_bytes([buf[at], buf[at + 1]]) as usize;
    at += 2;
    if sealed_len != ENTRY_BYTES {
        return Err(bad);
    }
    let mut sealed = [0u8; ENTRY_BYTES];
    sealed.copy_from_slice(&buf[at..at + ENTRY_BYTES]);
    Ok(Record {
        store_master,
        user_sid_hash,
        cred_id: buf[74..74 + cred_len].to_vec(),
        prf_salt,
        nonce,
        sealed,
    })
}

/// Serializes the record.
fn encode_record(record: &Record) -> Vec<u8> {
    let mut out = Vec::with_capacity(132 + record.cred_id.len() + ENTRY_BYTES);
    out.extend_from_slice(MAGIC);
    out.push(RECORD_VERSION);
    out.push(0); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&record.store_master);
    out.extend_from_slice(&record.user_sid_hash);
    out.extend_from_slice(&(record.cred_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&record.cred_id);
    out.extend_from_slice(&record.prf_salt);
    out.extend_from_slice(&record.nonce);
    out.extend_from_slice(&(ENTRY_BYTES as u16).to_le_bytes());
    out.extend_from_slice(&record.sealed);
    out
}

/// Writes the sidecar with the store's hardened creation path
/// (`winfile::create_store`: exclusive create, non-inheritable). An existing
/// record is removed first so re-enrollment replaces it; a failed write
/// removes the partial file.
fn write_record(store: &Path, record: &Record) -> Result<(), WireStatus> {
    let path = sidecar_path(store);
    let bytes = encode_record(record);
    let _ = std::fs::remove_file(&path); // replace semantics
    let file = winfile::create_store(&path).map_err(|_| WireStatus::Io)?;
    let written = winfile::write_at(&file, 0, &bytes).map_err(|_| WireStatus::Io)?;
    if written != bytes.len() || !winfile::flush(&file) {
        let _ = std::fs::remove_file(&path);
        return Err(WireStatus::Io);
    }
    Ok(())
}

// ---- helpers -------------------------------------------------------------

fn zeroed<T: Copy>() -> T {
    // SAFETY: all WebAuthn structs here are PODs (scalars, pointers and
    // nested PODs); zero-initialization is the documented init pattern.
    unsafe { std::mem::zeroed() }
}

fn remaining_ms(deadline: Instant) -> u32 {
    let left = deadline.saturating_duration_since(Instant::now());
    left.clamp(Duration::from_secs(1), Duration::from_secs(300))
        .as_millis() as u32
}

/// Runs one modal WebAuthn call with a hardened deadline watcher. The native
/// timeout alone is not sufficient on every desktop state (notably the lock
/// screen); cancellation uses the ceremony's unique GUID and no secret data.
fn with_cancellation<T>(
    cancellation: &GUID,
    deadline: Instant,
    operation: impl FnOnce() -> T,
) -> Result<T, WireStatus> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let cancellation = *cancellation;
    let watcher = security::spawn_hardened_thread(move || {
        let wait = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(wait).is_err() {
            // SAFETY: the GUID is copied into this thread and remains valid
            // for the call; cancellation carries no secret material.
            unsafe { WebAuthNCancelCurrentOperation(&cancellation) };
        }
    })
    .map_err(|_| WireStatus::MemoryProtection)?;
    let result = operation();
    let _ = done_tx.send(());
    watcher.join().map_err(|_| WireStatus::MemoryProtection)?;
    Ok(result)
}

/// Minimal base64url (no padding) for the client-data challenge.
fn base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_exactly() {
        let record = Record {
            store_master: [7u8; 32],
            user_sid_hash: [9u8; 32],
            cred_id: vec![1, 2, 3],
            prf_salt: [3u8; 32],
            nonce: [5u8; 24],
            sealed: [11u8; ENTRY_BYTES],
        };
        let bytes = encode_record(&record);
        let parsed = parse_record(&bytes).unwrap();
        assert_eq!(parsed.store_master, record.store_master);
        assert_eq!(parsed.user_sid_hash, record.user_sid_hash);
        assert_eq!(parsed.cred_id, record.cred_id);
        assert_eq!(parsed.prf_salt, record.prf_salt);
        assert_eq!(parsed.nonce, record.nonce);
        assert_eq!(parsed.sealed, record.sealed);

        // Any truncation or tail is rejected.
        assert!(matches!(
            parse_record(&bytes[..bytes.len() - 1]),
            Err(WireStatus::HelloFailed)
        ));
        let mut with_tail = bytes.clone();
        with_tail.push(0);
        assert!(matches!(parse_record(&with_tail), Err(WireStatus::HelloFailed)));
    }

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
    }
}
