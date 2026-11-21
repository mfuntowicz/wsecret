//! WSB1 — the private broker wire contract (normative).
//!
//! This module is the single authority for the Quick Access broker protocol.
//! Everything is packed sequential **little-endian** with **no implicit
//! alignment or padding**; explicit pad bytes appear only where the layouts
//! below say so. A consumer MUST verify each payload is consumed exactly:
//! a short payload or trailing bytes is a STRUCTURAL violation
//! ([`ParseError::Fatal`]: [`WireStatus::InvalidArgument`] once, then the
//! connection terminates). LEGAL frames carrying illegal VALUES (name-rule
//! violations, bad mode bytes, …) are [`ParseError::Reject`]: the error
//! response carries the precise status and the connection CONTINUES — a UI
//! typo never tears the session down.
//!
//! # Transport and launch
//!
//! The client (WinUI shell, CLI, tests) is the PARENT. It creates two
//! anonymous pipes and spawns `wsecret-broker.exe` with
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` limited to exactly the two broker
//! ends — the command channel (parent writes, broker reads) and the response
//! channel (broker writes, parent reads) — with `STARTF_USESTDHANDLES` set to
//! all-NULL standard handles. There is NO named endpoint anywhere.
//!
//! ```text
//! wsecret-broker.exe --rd-handle <dec> --wr-handle <dec> [--store <PATH>]
//! ```
//!
//! Handle values are decimal integers; the broker rejects anything that is
//! not a distinct non-null `FILE_TYPE_PIPE` handle pair. The store path
//! resolves as `--store`, else `%SECRET_STORE%`, else `%HOME%/.secret`, else
//! `%USERPROFILE%\.secret` (upstream `s_set_path` order).
//!
//! The first frame MUST be [`Opcode::Hello`] with `version` = [`VERSION`].
//! On version mismatch the broker responds [`WireStatus::VersionMismatch`]
//! (`aux` = its [`MAX_SUPPORTED_VERSION`]) and exits. Client death / EOF on
//! the command channel tears the broker down: lock, wipe, clear the
//! broker-owned clipboard if still owned, exit 0.
//!
//! # Frames
//!
//! 24-byte header, then `payload_len` body bytes (bounded by
//! [`MAX_PAYLOAD`]):
//!
//! ```text
//! offset size field
//! 0      4    magic         = 0x3142_5357 ("WSB1" as LE bytes 'W','S','B','1')
//! 4      2    version       = 1 (wire protocol version)
//! 6      2    opcode
//! 8      4    flags         = 0 (nonzero => protocol violation)
//! 12     4    request_id    client-chosen, nonzero, echoed in the response
//! 16     4    generation    session epoch targeted by the request (0 = none)
//! 20     4    payload_len   <= 65536
//! ```
//!
//! There are NO broker-initiated push frames in v1: every request gets
//! exactly one response, matched by `request_id`. Responses may complete out
//! of order (a `Cancel` is processed while an operation runs); the client
//! MUST reject a response whose `request_id` it did not issue and MUST drop
//! responses whose `generation` is stale for it (stale-response rejection).
//!
//! # Security policy (binding)
//!
//! Secret record VALUES never cross the channel in either direction. The
//! client sees metadata only: raw name bytes, slots, counts, kinds, TTLs,
//! countdowns, statuses. Secret material enters the broker only through its
//! own masked console input ([`crate::native_input`]) and leaves only as a
//! broker-owned secure-clipboard write ([`crate::clipboard`]) or a Hello PRF
//! operation ([`crate::hello`]). TOTP digits are derived display secrets and
//! obey the same rule: [`Opcode::Code`] copies them to the clipboard and
//! returns only the countdown.
//!
//! Name bytes are the record identity: EXACT raw store bytes, up to
//! [`MAX_NAME`] bytes, compared byte-for-byte, never normalized or
//! re-encoded.
//!
//! # Lifecycle and generation
//!
//! ```text
//! Locked --Unlock--> Unlocking --done--> Unlocked --Lock--> Locking --done--> Locked
//! ```
//!
//! The session `generation` counter starts at 0 and increments by 1 when an
//! unlock attempt finishes (success OR failure) and when a lock finishes.
//! Session-scoped requests ([`Opcode::is_session_scoped`]) are legal only in
//! [`Lifecycle::Unlocked`] and MUST carry the current generation; anything
//! else is [`WireStatus::StaleGeneration`] or [`WireStatus::WrongState`].
//! While [`Lifecycle::Unlocking`]/[`Lifecycle::Locking`] only `Hello`,
//! `Ping`, `Cancel`, `Shutdown` and `HelloForget` are answered; everything
//! else is [`WireStatus::Busy`].
//!
//! # Timeouts
//!
//! - handshake (first frame): [`HANDSHAKE_TIMEOUT_MS`]
//! - inter-byte while assembling a frame: [`FRAME_TIMEOUT_MS`]
//! - whole-request deadline (covers prompts and WebAuthn): [`REQUEST_DEADLINE_MS`]
//!
//! Expiry yields [`WireStatus::Timeout`] (or teardown when the channel
//! itself stalled). `Cancel` is honored at operation checkpoints; a request
//! cancelled this way answers [`WireStatus::Cancelled`].
//!
//! # Clipboard TTL policy (user brief)
//!
//! Password/value copies live 30 s ([`CLIPBOARD_TTL_MS`]); OTP copies live
//! the earlier of that and the code window expiry. The broker clears the
//! clipboard at TTL only while it still owns it (clipboard sequence number
//! unchanged).
//!
//! # Codes routing and code targets
//!
//! A name is CODE-CAPABLE iff it contains the case-sensitive substring
//! `totp` (the historical upstream `s_show` rule) OR has an exact `topt`
//! `/`-separated path component (the alias namespace). That single
//! predicate routes `Meta`'s kind byte, `Copy`'s auto mode and
//! [`Opcode::CodeTargets`]' self case, and it is mirrored EXACTLY by the
//! UI's `NameCodec.IsCodeName` auto-copy label heuristic (`totp-notes` and
//! `mytotp32` are historical-substring codes; `topt` is an exact-alias
//! code; `Topt`/`TOTP` spellings are NOT code names). Codes-view
//! auto-index membership is the NARROWER component-exact rule
//! (`NameCodec.IsAutoIndexedCodeName` = `quick::discover_code`).
//!
//! Decoding: the one core adapter owns it whenever a code component exists
//! (component `totp32` → base32; `totp` and the `topt` alias → raw; the
//! alias is raw by default — Base32 only through explicit import metadata,
//! which v0 stores never carry). Substring-only historical names keep the
//! CLI convention verbatim (`totp_for`, kind selection included).
//!
//! A code-routed copy NEVER falls back to publishing the record value (the
//! seed): an invalid seed or a misrouted request answers
//! [`WireStatus::InvalidTotp`] and nothing is published. [`Opcode::Copy`]
//! and [`Opcode::Code`] are name-addressed and therefore refuse with
//! [`WireStatus::Conflict`] when the exact name occurs on more than one
//! record of the session — upstream first-match shadowing is never guessed.
//! Both accept an OPTIONAL trailing `u64 expect_slot` identity guard (legacy
//! frames without it stay valid): when present it must be a valid record
//! slot and the unique record carrying the name must still live at that
//! slot — deleted ([`WireStatus::NotFound`]) or moved/ambiguous
//! ([`WireStatus::Conflict`]) records refuse, while a changed VALUE at the
//! same slot + name is current and is what gets copied (upstream
//! semantics). The palette always sends the guard (the slot it displayed),
//! closing the rename/delete + recreate race that name-only addressing
//! cannot see.
//!
//! [`Opcode::CodeTargets`] is the Ctrl+Enter "Copy code" input (metadata
//! only): the source is addressed by slot + exact name bytes and must still
//! match (stale selection → [`WireStatus::Conflict`]); a code-capable
//! source yields exactly itself ("self"), otherwise the result is
//! `wsecret_core::quick::codes_for_account` over this partition — only
//! records whose link resolves uniquely to the source, never a descendant
//! guess, never cross-vault. It fails closed with [`WireStatus::Conflict`]
//! on ambiguous (duplicate) names and with [`WireStatus::ResourceLimit`]
//! on a partial index (`wsecret_core::quick::NavIndex` truncation) or a
//! result above [`MAX_CODE_TARGETS`]; an empty result is the legitimate
//! "no linked code" answer.

use wsecret_core::error::{CommitState, Error, NameError};
use wsecret_core::format::BLOCK;

/// Wire magic: the bytes `'W' 'S' 'B' '1'` little-endian.
pub const MAGIC: u32 = 0x3142_5357;
/// Wire protocol version carried in every frame.
pub const VERSION: u16 = 1;
/// Highest wire version this broker speaks (Hello `aux` on mismatch).
pub const MAX_SUPPORTED_VERSION: u16 = VERSION;
/// Header size in bytes.
pub const HEADER_LEN: usize = 24;
/// Hard bound on `payload_len`, checked BEFORE any body allocation.
pub const MAX_PAYLOAD: u32 = 65536;
/// Maximum raw name bytes (upstream `Keys are limited to 255 bytes`).
pub const MAX_NAME: usize = 255;
/// Maximum entries returned by one [`Opcode::List`] page.
pub const MAX_LIST_COUNT: u16 = 240;
/// Maximum deterministic subkeys in [`Opcode::New`] (`gen = 1`).
pub const MAX_SUBKEYS: u16 = 16;
/// Maximum deterministic subkey bytes.
pub const MAX_SUBKEY_LEN: usize = 255;
/// Maximum rows returned by one [`Opcode::CodeTargets`] response. The
/// result is fail-closed above this bound (never silently truncated).
pub const MAX_CODE_TARGETS: u16 = 64;
/// Handshake deadline: the first frame must arrive within this many ms.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 15_000;
/// Inter-byte deadline while a frame is being assembled.
pub const FRAME_TIMEOUT_MS: u64 = 10_000;
/// Whole-request deadline (prompts and WebAuthn assertions included).
pub const REQUEST_DEADLINE_MS: u64 = 120_000;
/// Secure-clipboard residency for value copies (user brief: 30 s).
pub const CLIPBOARD_TTL_MS: u32 = 30_000;

/// Broker lifecycle state (wire values in `Hello`/`Ping` responses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Lifecycle {
    /// No session; no secret material resident.
    Locked = 0,
    /// An unlock attempt is running (prompt / Hello assertion / derive).
    Unlocking = 1,
    /// Session live; session-scoped requests are legal.
    Unlocked = 2,
    /// A lock is running (wipe in progress).
    Locking = 3,
}

impl Lifecycle {
    /// Wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Whether `op` may be dispatched in this state. `Cancel`, `Hello`,
    /// `Ping`, `Shutdown` and `HelloForget` are legal in every state.
    pub fn permits(self, op: Opcode) -> bool {
        match op {
            Opcode::Hello
            | Opcode::Ping
            | Opcode::Cancel
            | Opcode::Shutdown
            | Opcode::HelloForget => true,
            Opcode::Unlock => matches!(self, Lifecycle::Locked),
            // Lock is idempotent in Locked (an answered no-op).
            Opcode::Lock => matches!(self, Lifecycle::Locked | Lifecycle::Unlocked),
            Opcode::List
            | Opcode::Meta
            | Opcode::Copy
            | Opcode::Code
            | Opcode::CodeTargets
            | Opcode::New
            | Opcode::Set
            | Opcode::Update
            | Opcode::HelloEnroll => matches!(self, Lifecycle::Unlocked),
        }
    }
}

/// Hello binding state (wire values in `Hello`/`Ping`/`HelloEnroll`
/// responses). [`HelloState::Unsupported`] is the fail-disabled posture: no
/// usable WebAuthn PRF with required user verification means Hello unlock
/// is unavailable and NOTHING weaker is ever substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HelloState {
    /// WebAuthn PRF with required UV is unavailable: feature disabled.
    Unsupported = 0,
    /// Available, no binding record for this store.
    Available = 1,
    /// Available and bound (Hello unlock possible).
    Enrolled = 2,
}

impl HelloState {
    /// Wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Capability bits in the `Hello` response.
pub mod caps {
    /// Value/code copy via the broker secure clipboard.
    pub const COPY: u32 = 1 << 0;
    /// TOTP Codes actions (copy + countdown).
    pub const CODES: u32 = 1 << 1;
    /// Write operations (`New`/`Set`/`Update`).
    pub const WRITES: u32 = 1 << 2;
    /// Hello (WebAuthn PRF) enrollment/unlock.
    pub const HELLO: u32 = 1 << 3;
}

/// Request opcodes (wire `opcode` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// Handshake / state / capabilities. MUST be the first frame.
    Hello = 0x0001,
    /// Liveness + state + generation.
    Ping = 0x0002,
    /// Cancel the in-flight request identified by its `request_id`.
    Cancel = 0x0003,
    /// Teardown and exit 0.
    Shutdown = 0x0004,
    /// Unlock the store (broker-native masked prompt, or Hello PRF).
    Unlock = 0x0010,
    /// Wipe the session; optionally clear the owned clipboard.
    Lock = 0x0011,
    /// Paged name listing (metadata only).
    List = 0x0020,
    /// Entry metadata (slot, kind, value length, countdown).
    Meta = 0x0021,
    /// Copy a value/code into the broker secure clipboard.
    Copy = 0x0022,
    /// Codes action: copy the current TOTP code into the secure clipboard.
    Code = 0x0023,
    /// Code targets for one picked record (metadata only; the Ctrl+Enter
    /// "Copy code" chooser input).
    CodeTargets = 0x0024,
    /// Generate and store a fresh secret (value goes to the clipboard).
    New = 0x0030,
    /// Create/replace a secret with broker-native masked value entry.
    Set = 0x0031,
    /// Rename and/or replace/regenerate an existing secret.
    Update = 0x0032,
    /// Enroll Hello: bind the epoch secret under WebAuthn PRF + UV.
    HelloEnroll = 0x0040,
    /// Delete the Hello binding record (idempotent, any state).
    HelloForget = 0x0041,
}

impl Opcode {
    /// Parses a wire opcode byte; `None` = unknown.
    pub fn from_wire(code: u16) -> Option<Opcode> {
        Some(match code {
            0x0001 => Opcode::Hello,
            0x0002 => Opcode::Ping,
            0x0003 => Opcode::Cancel,
            0x0004 => Opcode::Shutdown,
            0x0010 => Opcode::Unlock,
            0x0011 => Opcode::Lock,
            0x0020 => Opcode::List,
            0x0021 => Opcode::Meta,
            0x0022 => Opcode::Copy,
            0x0023 => Opcode::Code,
            0x0024 => Opcode::CodeTargets,
            0x0030 => Opcode::New,
            0x0031 => Opcode::Set,
            0x0032 => Opcode::Update,
            0x0040 => Opcode::HelloEnroll,
            0x0041 => Opcode::HelloForget,
            _ => return None,
        })
    }

    /// Whether the request is scoped to a live session: such requests are
    /// legal only in [`Lifecycle::Unlocked`] and must carry the current
    /// generation.
    pub fn is_session_scoped(self) -> bool {
        matches!(
            self,
            Opcode::List
                | Opcode::Meta
                | Opcode::Copy
                | Opcode::Code
                | Opcode::CodeTargets
                | Opcode::New
                | Opcode::Set
                | Opcode::Update
                | Opcode::HelloEnroll
        )
    }
}

/// Wire status domain (first `u16` of every response payload).
///
/// Numbering rule: `0..=25` are the `wsecret_core::error::Status` codes
/// VERBATIM (one catalog with the C ABI; several are never produced on the
/// wire and stay reserved). `0x100..` are protocol-only codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum WireStatus {
    /// Success (core 0).
    Ok = 0,
    /// Malformed frame/payload/flags — protocol violation (core 1).
    InvalidArgument = 1,
    /// Name violates the store name rules (core 2).
    InvalidName = 2,
    /// Name + value + 1 exceed one entry record (core 3).
    EntryTooBig = 3,
    /// The store file does not exist (core 4).
    StoreNotFound = 4,
    /// The store file already exists (core 5; reserved — use `AlreadyExists`).
    StoreExists = 5,
    /// STORE format version unsupported (core 6; not the wire version).
    UnsupportedVersion = 6,
    /// Store structure violates the format contract (core 7).
    MalformedStore = 7,
    /// Configured resource limit exceeded (core 8; KDF caps included).
    ResourceLimit = 8,
    /// Record not found (core 9).
    NotFound = 9,
    /// Record already exists (core 10).
    AlreadyExists = 10,
    /// User confirmation required (core 11; reserved — broker confirms internally).
    ConfirmationRequired = 11,
    /// Retyped passphrase did not match (core 12).
    PassphraseMismatch = 12,
    /// Store region/file locked by another holder (core 13).
    Locked = 13,
    /// Writer mutex busy (core 14; reserved on the wire — see `Busy`).
    MutexBusy = 14,
    /// Identity/state changed underneath the operation; CAS failures land
    /// here (core 15).
    Conflict = 15,
    /// Cancelled: `Cancel` request or empty/EOF at a broker prompt (core 16).
    Cancelled = 16,
    /// I/O failure (core 17).
    Io = 17,
    /// Cryptographic failure (core 18).
    Crypto = 18,
    /// Memory allocation failure (core 19).
    NoMemory = 19,
    /// Secret-memory protection failed (core 20).
    MemoryProtection = 20,
    /// Filesystem lacks required semantics (core 21; reserved).
    UnsupportedFilesystem = 21,
    /// SSH-agent access unavailable (core 22; reserved — no agents here).
    AgentUnavailable = 22,
    /// Contained panic (core 23).
    Panic = 23,
    /// Commit outcome uncertain; reconcile (core 24).
    CommitUncertain = 24,
    /// TOTP value invalid (core 25).
    InvalidTotp = 25,

    /// Wire protocol version unsupported; `aux` = broker max version.
    VersionMismatch = 0x100,
    /// Request illegal for the current lifecycle state.
    WrongState = 0x101,
    /// Request targeted a stale session generation.
    StaleGeneration = 0x102,
    /// Lifecycle transition or another request is in flight.
    Busy = 0x103,
    /// Frame/prompt/assertion deadline expired.
    Timeout = 0x104,
    /// Hello unavailable (fail-disabled: no WebAuthn PRF with required UV).
    HelloUnavailable = 0x105,
    /// No Hello binding record for this store.
    HelloNotEnrolled = 0x106,
    /// Hello assertion refused / UV failed / unseal failed.
    HelloFailed = 0x107,
    /// Secure clipboard could not be acquired or written.
    ClipboardError = 0x108,
    /// Value is not UTF-8 text without interior NUL; text copy refused.
    ValueNotText = 0x109,
    /// Broker-owned masked input impossible (no console could be opened).
    NoConsole = 0x10A,
    /// Broker prompt input rejected: too long, control bytes, or invalid
    /// UTF-16 (upstream `Input too long!` / `Invalid input!`).
    InputInvalid = 0x10B,
}

impl WireStatus {
    /// Wire code.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Maps a core error to the wire domain. Lossy by design: the wire
    /// reports the classification, never internal detail.
    pub fn from_error(error: &Error) -> WireStatus {
        match error {
            Error::Io(_) => WireStatus::Io,
            Error::Format(_) => WireStatus::MalformedStore,
            Error::Name(name) => match name {
                NameError::Exists => WireStatus::AlreadyExists,
                NameError::NotFound => WireStatus::NotFound,
                NameError::EntryTooBig => WireStatus::EntryTooBig,
                _ => WireStatus::InvalidName,
            },
            Error::Cancelled => WireStatus::Cancelled,
            Error::Agent(_) => WireStatus::AgentUnavailable,
            Error::ResourceLimit(_) => WireStatus::ResourceLimit,
            Error::MemoryProtection => WireStatus::MemoryProtection,
            Error::ConfirmationRequired => WireStatus::ConfirmationRequired,
            Error::PassphraseMismatch => WireStatus::PassphraseMismatch,
            Error::Locked => WireStatus::Locked,
            Error::Busy => WireStatus::MutexBusy,
            Error::Conflict => WireStatus::Conflict,
            Error::CommitUncertain => WireStatus::CommitUncertain,
            Error::InvalidTotp => WireStatus::InvalidTotp,
            Error::Panic => WireStatus::Panic,
            Error::Crypto => WireStatus::Crypto,
            Error::NoMemory => WireStatus::NoMemory,
            _ => WireStatus::Io,
        }
    }
}

/// Decoded 24-byte frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Wire version (must equal [`VERSION`] after the handshake).
    pub version: u16,
    /// Request opcode.
    pub opcode: u16,
    /// Must be 0 in v1.
    pub flags: u32,
    /// Client-chosen correlation id (nonzero).
    pub request_id: u32,
    /// Session generation targeted by the request.
    pub generation: u32,
    /// Body length; bounded by [`MAX_PAYLOAD`].
    pub payload_len: u32,
}

/// Frame-level decode failure. ALL of these are protocol violations: the
/// broker answers [`WireStatus::InvalidArgument`] (or `VersionMismatch`)
/// once and tears the connection down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Bad magic or nonzero flags or zero `request_id`.
    Corrupt,
    /// `payload_len` exceeds [`MAX_PAYLOAD`] (rejected before allocation).
    Oversize,
    /// Version field is not [`VERSION`].
    Version(u16),
}

impl FrameHeader {
    /// Encodes the header (magic + fields) into exactly [`HEADER_LEN`] bytes.
    pub fn encode(self, out: &mut [u8; HEADER_LEN]) {
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.opcode.to_le_bytes());
        out[8..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.generation.to_le_bytes());
        out[20..24].copy_from_slice(&self.payload_len.to_le_bytes());
    }

    /// Decodes and validates one header: magic, flags = 0, nonzero
    /// `request_id`, `payload_len` within [`MAX_PAYLOAD`], version =
    /// [`VERSION`].
    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<FrameHeader, FrameError> {
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(FrameError::Corrupt);
        }
        let header = FrameHeader {
            version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            opcode: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            request_id: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            generation: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            payload_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        };
        if header.flags != 0 || header.request_id == 0 {
            return Err(FrameError::Corrupt);
        }
        if header.payload_len > MAX_PAYLOAD {
            return Err(FrameError::Oversize);
        }
        if header.version != VERSION {
            return Err(FrameError::Version(header.version));
        }
        Ok(header)
    }
}

/// Decode cursor over one request body: sequential little-endian, no
/// padding; every accessor fails on a short buffer and the caller checks
/// [`BodyReader::finish`] so trailing bytes are a protocol violation.
pub struct BodyReader<'a> {
    body: &'a [u8],
    at: usize,
}

impl<'a> BodyReader<'a> {
    /// Wraps a body.
    pub fn new(body: &'a [u8]) -> BodyReader<'a> {
        BodyReader { body, at: 0 }
    }

    /// Cursor position (for diagnostics).
    pub fn position(&self) -> usize {
        self.at
    }

    /// Bytes left after the cursor.
    pub fn remaining(&self) -> usize {
        self.body.len() - self.at
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.body.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    /// One `u8`.
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    /// One `u16`.
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    /// One `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// One `u64`.
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    /// `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }

    /// Fails unless the body is consumed exactly.
    pub fn finish(self) -> Option<()> {
        (self.at == self.body.len()).then_some(())
    }
}

/// Appends to a response body.
pub struct BodyWriter {
    out: Vec<u8>,
}

impl BodyWriter {
    /// Starts a response body with `status` and `aux`.
    pub fn new(status: WireStatus, aux: u16) -> BodyWriter {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&status.code().to_le_bytes());
        out.extend_from_slice(&aux.to_le_bytes());
        BodyWriter { out }
    }

    /// Appends one `u8`.
    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    /// Appends one `u16`.
    pub fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Appends one `u32`.
    pub fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Appends one `u64`.
    pub fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Appends raw bytes (the caller length-prefixes separately when needed).
    pub fn bytes(&mut self, v: &[u8]) {
        self.out.extend_from_slice(v);
    }

    /// Appends a `u16`-length-prefixed blob.
    pub fn blob(&mut self, v: &[u8]) {
        debug_assert!(v.len() <= u16::MAX as usize);
        self.u16(v.len() as u16);
        self.bytes(v);
    }

    /// Finishes the body.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}

/// A decoded request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Handshake.
    Hello,
    /// Liveness probe.
    Ping,
    /// Cancel `target` (a `request_id`).
    Cancel {
        /// The request to cancel.
        target: u32,
    },
    /// Teardown.
    Shutdown,
    /// Unlock attempt.
    Unlock {
        /// 0 = broker-native masked prompt, 1 = Hello PRF.
        mode: u8,
    },
    /// Lock the session.
    Lock {
        /// 1 = also clear the broker-owned clipboard.
        clear_clipboard: u8,
    },
    /// Paged listing.
    List {
        /// First entry index in physical order.
        offset: u32,
        /// Page size (1..=[`MAX_LIST_COUNT`]).
        count: u16,
        /// Upstream substring needle (empty = all).
        needle: Vec<u8>,
    },
    /// Entry metadata.
    Meta {
        /// Raw name bytes.
        name: Vec<u8>,
    },
    /// Copy to the secure clipboard.
    Copy {
        /// Raw name bytes.
        name: Vec<u8>,
        /// 0 auto (code-capable name -> code, else value), 1 raw value,
        /// 2 code. A code-routed copy never falls back to the raw value.
        mode: u8,
        /// Optional identity guard (EXACTLY one trailing `u64`, or none;
        /// anything in between is a structural violation). When present it
        /// must be a valid record slot (nonzero, block-aligned) and the
        /// unique record carrying `name` must live at that slot: deleted,
        /// moved or ambiguous (duplicate-name) records refuse with
        /// [`WireStatus::NotFound`] / [`WireStatus::Conflict`]. A changed
        /// VALUE at the same slot + name is current and is what gets copied
        /// (upstream semantics). When absent, only the legacy unique-name
        /// check applies.
        expect_slot: u64,
    },
    /// Codes action.
    Code {
        /// Raw name bytes.
        name: Vec<u8>,
        /// Optional identity guard: same trailing-`u64` contract as
        /// [`Request::Copy`].
        expect_slot: u64,
    },
    /// Code targets for one picked record (metadata only).
    CodeTargets {
        /// Source record slot (record block offset); must still hold `name`.
        slot: u64,
        /// Source raw name bytes.
        name: Vec<u8>,
    },
    /// Generate + store (fresh value goes to the secure clipboard).
    New {
        /// Raw name bytes.
        name: Vec<u8>,
        /// 0 = random (upstream `new`), 1 = deterministic (upstream `pass`).
        /// (`gen` alone is a reserved keyword in edition 2024.)
        gen_kind: u8,
        /// Deterministic subkeys (`gen_kind = 1` only).
        subkeys: Vec<Vec<u8>>,
    },
    /// Broker-native value entry + store.
    Set {
        /// Raw name bytes.
        name: Vec<u8>,
    },
    /// Rename and/or replace/regenerate.
    Update {
        /// CAS guard: expected slot (0 = no check).
        expect_slot: u64,
        /// Existing raw name bytes.
        name: Vec<u8>,
        /// New raw name bytes (empty = keep).
        new_name: Vec<u8>,
        /// 0 prompt new value, 1 rename-only keep value, 2 regenerate.
        mode: u8,
    },
    /// Enroll Hello.
    HelloEnroll,
    /// Forget the Hello binding.
    HelloForget,
}

/// Validates raw name bytes against the upstream name rules (non-empty,
/// <= [`MAX_NAME`] bytes, no byte `<= 0x20`).
pub fn validate_name(name: &[u8]) -> Result<(), WireStatus> {
    if name.is_empty() || name.len() > MAX_NAME || name.iter().any(|&b| b <= b' ') {
        return Err(WireStatus::InvalidName);
    }
    Ok(())
}

/// Decode failure classification. Structural failures are protocol
/// violations (one error response, then the broker terminates);
/// semantic rejections answer their status and the connection CONTINUES
/// (a UI typo must never tear the session down).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Protocol violation: malformed/short/trailing payload or framing.
    Fatal(WireStatus),
    /// Legal frame, illegal request value (name rules, mode bytes, …).
    Reject(WireStatus),
}

/// Reads a `u16`-length-prefixed blob: an over-long prefix is a semantic
/// rejection, a truncated body is a structural violation.
fn read_blob<'a>(r: &mut BodyReader<'a>, max: usize) -> Result<&'a [u8], ParseError> {
    let len = r.u16().ok_or(ParseError::Fatal(WireStatus::InvalidArgument))? as usize;
    if len > max {
        return Err(ParseError::Reject(WireStatus::InvalidArgument));
    }
    r.bytes(len)
        .ok_or(ParseError::Fatal(WireStatus::InvalidArgument))
}

/// Parses one request body. Structural decode failures are
/// [`ParseError::Fatal`]; value-domain failures are [`ParseError::Reject`].
pub fn parse_request(opcode: Opcode, body: &[u8]) -> Result<Request, ParseError> {
    use ParseError::{Fatal, Reject};
    let fatal = || Fatal(WireStatus::InvalidArgument);
    let mut r = BodyReader::new(body);
    let request = match opcode {
        Opcode::Hello => Request::Hello,
        Opcode::Ping => Request::Ping,
        Opcode::Cancel => {
            let target = r.u32().ok_or_else(fatal)?;
            if target == 0 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::Cancel { target }
        }
        Opcode::Shutdown => Request::Shutdown,
        Opcode::Unlock => {
            let mode = r.u8().ok_or_else(fatal)?;
            let _pad = r.bytes(3).ok_or_else(fatal)?;
            if mode > 1 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::Unlock { mode }
        }
        Opcode::Lock => Request::Lock {
            clear_clipboard: r.u8().ok_or_else(fatal)?,
        },
        Opcode::List => {
            let offset = r.u32().ok_or_else(fatal)?;
            let count = r.u16().ok_or_else(fatal)?;
            let needle = read_blob(&mut r, MAX_NAME)?;
            if count == 0 || count > MAX_LIST_COUNT {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::List {
                offset,
                count,
                needle: needle.to_vec(),
            }
        }
        Opcode::Meta => Request::Meta {
            name: read_name(&mut r)?,
        },
        Opcode::Copy => {
            let name = read_name(&mut r)?;
            let mode = r.u8().ok_or_else(fatal)?;
            let _pad = r.bytes(3).ok_or_else(fatal)?;
            if mode > 2 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::Copy {
                name,
                mode,
                expect_slot: read_expect_slot(&mut r)?,
            }
        }
        Opcode::Code => {
            let name = read_name(&mut r)?;
            Request::Code {
                name,
                expect_slot: read_expect_slot(&mut r)?,
            }
        }
        Opcode::CodeTargets => {
            let slot = r.u64().ok_or_else(fatal)?;
            // Slots are record block offsets (>= one block, aligned):
            // anything else is an illegal VALUE (non-fatal rejection).
            if slot == 0 || slot % BLOCK as u64 != 0 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::CodeTargets {
                slot,
                name: read_name(&mut r)?,
            }
        }
        Opcode::New => {
            let name = read_name(&mut r)?;
            let gen_kind = r.u8().ok_or_else(fatal)?;
            let _pad = r.bytes(1).ok_or_else(fatal)?;
            if gen_kind > 1 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            let n = r.u16().ok_or_else(fatal)?;
            if n > MAX_SUBKEYS {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            let mut subkeys = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let sub = read_blob(&mut r, MAX_SUBKEY_LEN)?;
                // Upstream `s_keylen` semantics (shared with name rules).
                validate_name(sub).map_err(Reject)?;
                subkeys.push(sub.to_vec());
            }
            // gen_kind = 1 (deterministic) requires subkeys; 0 forbids them.
            if (gen_kind == 0) != subkeys.is_empty() {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            Request::New {
                name,
                gen_kind,
                subkeys,
            }
        }
        Opcode::Set => Request::Set {
            name: read_name(&mut r)?,
        },
        Opcode::Update => {
            let expect_slot = r.u64().ok_or_else(fatal)?;
            let name = read_name(&mut r)?;
            let new_name = read_blob(&mut r, MAX_NAME)?;
            let mode = r.u8().ok_or_else(fatal)?;
            if mode > 2 {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            // Rename-only updates must carry the new name.
            if mode == 1 && new_name.is_empty() {
                return Err(Reject(WireStatus::InvalidArgument));
            }
            if !new_name.is_empty() {
                validate_name(new_name).map_err(Reject)?;
            }
            Request::Update {
                expect_slot,
                name,
                new_name: new_name.to_vec(),
                mode,
            }
        }
        Opcode::HelloEnroll => Request::HelloEnroll,
        Opcode::HelloForget => Request::HelloForget,
    };
    r.finish().ok_or_else(fatal)?;
    Ok(request)
}

fn read_name(r: &mut BodyReader<'_>) -> Result<Vec<u8>, ParseError> {
    let name = read_blob(r, MAX_NAME)?;
    validate_name(name).map_err(ParseError::Reject)?;
    Ok(name.to_vec())
}

/// Reads the OPTIONAL trailing `u64` identity guard of [`Opcode::Copy`] /
/// [`Opcode::Code`]: no trailing bytes = `0` (legacy unique-name check
/// only); EXACTLY 8 trailing bytes = a valid record slot (nonzero,
/// [`BLOCK`]-aligned) the unique record must live at exactly. Any other
/// trailing LENGTH is a structural violation regardless of content; a bad
/// slot VALUE is a non-fatal rejection. There is no way to express "guard
/// at slot 0": an absent guard is the only unchecked form.
fn read_expect_slot(r: &mut BodyReader<'_>) -> Result<u64, ParseError> {
    match r.remaining() {
        0 => Ok(0),
        8 => {
            let slot = r
                .u64()
                .ok_or(ParseError::Fatal(WireStatus::InvalidArgument))?;
            if slot == 0 || slot % BLOCK as u64 != 0 {
                return Err(ParseError::Reject(WireStatus::InvalidArgument));
            }
            Ok(slot)
        }
        _ => Err(ParseError::Fatal(WireStatus::InvalidArgument)),
    }
}

/// Builds a full response frame. The response header repeats the request's
/// `opcode` (correlation aid; matching is by `request_id`), carries the
/// current `generation`, and the body begins `u16 status | u16 aux`.
pub fn response_frame(request_id: u32, generation: u32, opcode: u16, payload: &[u8]) -> Vec<u8> {
    let header = FrameHeader {
        version: VERSION,
        opcode,
        flags: 0,
        request_id,
        generation,
        payload_len: payload.len() as u32,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    let mut head = [0u8; HEADER_LEN];
    header.encode(&mut head);
    out.extend_from_slice(&head);
    out.extend_from_slice(payload);
    out
}

/// Convenience: an error response body (`status`, `aux`, no payload).
pub fn error_body(status: WireStatus, aux: u16) -> Vec<u8> {
    BodyWriter::new(status, aux).into_bytes()
}

/// Maps a core [`CommitState`] to its wire `aux` value on write responses.
pub fn commit_state_aux(state: CommitState) -> u16 {
    match state {
        CommitState::NotCommitted => 1,
        CommitState::Committed => 2,
        CommitState::Unknown => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_and_rejects_violations() {
        let header = FrameHeader {
            version: VERSION,
            opcode: Opcode::Ping as u16,
            flags: 0,
            request_id: 7,
            generation: 3,
            payload_len: 0,
        };
        let mut bytes = [0u8; HEADER_LEN];
        header.encode(&mut bytes);
        assert_eq!(FrameHeader::decode(&bytes).unwrap(), header);

        // Bad magic.
        let mut bad = bytes;
        bad[0] = 0;
        assert_eq!(FrameHeader::decode(&bad), Err(FrameError::Corrupt));
        // Nonzero flags.
        let mut bad = bytes;
        bad[8] = 1;
        assert_eq!(FrameHeader::decode(&bad), Err(FrameError::Corrupt));
        // Zero request id.
        let mut bad = bytes;
        bad[12] = 0;
        assert_eq!(FrameHeader::decode(&bad), Err(FrameError::Corrupt));
        // Oversize body rejected before allocation.
        let mut bad = bytes;
        bad[20..24].copy_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        assert_eq!(FrameHeader::decode(&bad), Err(FrameError::Oversize));
        // Version mismatch reported distinctly.
        let mut bad = bytes;
        bad[4] = 2;
        assert_eq!(FrameHeader::decode(&bad), Err(FrameError::Version(2)));
    }

    #[test]
    fn requests_consume_exactly() {
        // Update with CAS guard parses.
        let mut body = Vec::new();
        body.extend_from_slice(&9u64.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(b"ab");
        body.extend_from_slice(&0u16.to_le_bytes());
        body.push(0);
        let req = parse_request(Opcode::Update, &body).unwrap();
        assert_eq!(
            req,
            Request::Update {
                expect_slot: 9,
                name: b"ab".to_vec(),
                new_name: Vec::new(),
                mode: 0,
            }
        );

        // Trailing byte = structural protocol violation.
        let mut with_tail = body.clone();
        with_tail.push(0);
        assert_eq!(
            parse_request(Opcode::Update, &with_tail),
            Err(ParseError::Fatal(WireStatus::InvalidArgument))
        );

        // Name rules enforced at decode as a NON-fatal rejection.
        let mut bad_name = Vec::new();
        bad_name.extend_from_slice(&2u16.to_le_bytes());
        bad_name.push(b'a');
        bad_name.push(b' '); // <= 0x20
        assert_eq!(
            parse_request(Opcode::Meta, &bad_name),
            Err(ParseError::Reject(WireStatus::InvalidName))
        );
    }

    #[test]
    fn copy_and_code_accept_an_optional_exact_expect_slot() {
        // Copy legacy form (no trailing bytes): expect_slot disabled.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&2u16.to_le_bytes());
        legacy.extend_from_slice(b"ab");
        legacy.push(2u8); // mode = code
        legacy.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            parse_request(Opcode::Copy, &legacy).unwrap(),
            Request::Copy {
                name: b"ab".to_vec(),
                mode: 2,
                expect_slot: 0,
            }
        );

        // Copy with EXACTLY one trailing u64 identity guard.
        let mut checked = legacy.clone();
        checked.extend_from_slice(&1024u64.to_le_bytes());
        assert_eq!(
            parse_request(Opcode::Copy, &checked).unwrap(),
            Request::Copy {
                name: b"ab".to_vec(),
                mode: 2,
                expect_slot: 1024,
            }
        );

        // 1..=7 or >8 trailing bytes stay structural violations.
        for extra in [1usize, 4, 7, 9, 16] {
            let mut bad = legacy.clone();
            bad.resize(legacy.len() + extra, 0);
            assert_eq!(
                parse_request(Opcode::Copy, &bad),
                Err(ParseError::Fatal(WireStatus::InvalidArgument))
            );
        }

        // A present guard must be a valid record slot: 0 (the "no check"
        // form is the ABSENT guard) and unaligned values are rejected as
        // illegal values, non-fatal.
        for bad_slot in [0u64, 1, 513, u64::MAX] {
            let mut bad = legacy.clone();
            bad.extend_from_slice(&bad_slot.to_le_bytes());
            assert_eq!(
                parse_request(Opcode::Copy, &bad),
                Err(ParseError::Reject(WireStatus::InvalidArgument))
            );
        }

        // Code: legacy and checked forms, same structural rule.
        let mut code = Vec::new();
        code.extend_from_slice(&2u16.to_le_bytes());
        code.extend_from_slice(b"ab");
        assert_eq!(
            parse_request(Opcode::Code, &code).unwrap(),
            Request::Code {
                name: b"ab".to_vec(),
                expect_slot: 0,
            }
        );
        let mut code_checked = code.clone();
        code_checked.extend_from_slice(&1024u64.to_le_bytes());
        assert_eq!(
            parse_request(Opcode::Code, &code_checked).unwrap(),
            Request::Code {
                name: b"ab".to_vec(),
                expect_slot: 1024,
            }
        );
        let mut code_bad = code.clone();
        code_bad.extend_from_slice(&[0u8; 3]);
        assert_eq!(
            parse_request(Opcode::Code, &code_bad),
            Err(ParseError::Fatal(WireStatus::InvalidArgument))
        );
    }

    #[test]
    fn code_targets_requests_consume_exactly() {
        // slot + name parses.
        let mut body = Vec::new();
        body.extend_from_slice(&1024u64.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(b"ab");
        let req = parse_request(Opcode::CodeTargets, &body).unwrap();
        assert_eq!(
            req,
            Request::CodeTargets {
                slot: 1024,
                name: b"ab".to_vec(),
            }
        );

        // Trailing byte = structural protocol violation.
        let mut with_tail = body.clone();
        with_tail.push(0);
        assert_eq!(
            parse_request(Opcode::CodeTargets, &with_tail),
            Err(ParseError::Fatal(WireStatus::InvalidArgument))
        );

        // Slot must be a record block offset: illegal VALUE, non-fatal.
        for bad in [0u64, 1, 513, 1023, u64::MAX] {
            let mut b = Vec::new();
            b.extend_from_slice(&bad.to_le_bytes());
            b.extend_from_slice(&1u16.to_le_bytes());
            b.push(b'a');
            assert_eq!(
                parse_request(Opcode::CodeTargets, &b),
                Err(ParseError::Reject(WireStatus::InvalidArgument))
            );
        }

        // Name rules enforced at decode as a NON-fatal rejection.
        let mut bad_name = Vec::new();
        bad_name.extend_from_slice(&1024u64.to_le_bytes());
        bad_name.extend_from_slice(&2u16.to_le_bytes());
        bad_name.extend_from_slice(b"a ");
        assert_eq!(
            parse_request(Opcode::CodeTargets, &bad_name),
            Err(ParseError::Reject(WireStatus::InvalidName))
        );

        // Short body (slot only) is structural.
        assert_eq!(
            parse_request(Opcode::CodeTargets, &1024u64.to_le_bytes()),
            Err(ParseError::Fatal(WireStatus::InvalidArgument))
        );
    }

    #[test]
    fn lifecycle_legality_matches_the_contract() {
        use Lifecycle::*;
        assert!(Locked.permits(Opcode::Unlock));
        assert!(!Unlocked.permits(Opcode::Unlock));
        assert!(Locked.permits(Opcode::Lock)); // idempotent no-op
        assert!(Unlocked.permits(Opcode::List));
        assert!(!Unlocking.permits(Opcode::List));
        assert!(Unlocking.permits(Opcode::Cancel));
        assert!(Locking.permits(Opcode::Shutdown));
        assert!(!Locked.permits(Opcode::Copy));
        // CodeTargets is session-scoped metadata: Unlocked + current
        // generation only, registered at 0x0024.
        assert!(Unlocked.permits(Opcode::CodeTargets));
        assert!(!Locked.permits(Opcode::CodeTargets));
        assert!(!Unlocking.permits(Opcode::CodeTargets));
        assert!(Opcode::CodeTargets.is_session_scoped());
        assert_eq!(Opcode::from_wire(0x0024), Some(Opcode::CodeTargets));
        // Old opcodes keep their wire values.
        assert_eq!(Opcode::from_wire(0x0022), Some(Opcode::Copy));
        assert_eq!(Opcode::from_wire(0x0023), Some(Opcode::Code));
    }
}
