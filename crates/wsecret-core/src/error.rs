//! Error taxonomy shared by the Rust API and the future C ABI (plan §3.4).
//!
//! [`Status`] holds the 26 stable status codes (0–25) from the ABI contract
//! (Sol §3.7, `OK`…`INVALID_TOTP`). Codes are never repurposed. The Win32
//! `os_error` side-channel travels alongside the status (mirroring
//! `WsErrorV1` in the future ABI) and is captured at the point of failure;
//! it is zero when no OS error applies. No diagnostic string produced here
//! contains plaintext, passphrases, names, or derived keys — the error types
//! structurally cannot carry name/value bytes. The library never prints; the
//! CLI maps [`Error`] to the exact upstream string catalog (plan §4).
//!
//! Mapping from the Rust [`Error`] categories to the stable codes:
//!
//! | `Error` | `Status` |
//! |---|---|
//! | `Io(_)` | `IO` (17), `os_error` from the inner `std::io::Error` |
//! | `Format(UnsupportedVersion(_))` | `UNSUPPORTED_VERSION` (6) |
//! | `Format(OpsLimitTooLow(_))` | `MALFORMED_STORE` (7) |
//! | `Format(EntryTooBig)` | `ENTRY_TOO_BIG` (3) |
//! | `Format(MalformedRecord \| StoreLayout)` | `MALFORMED_STORE` (7) |
//! | `Format(Name(n))` | `n.status()` (see below) |
//! | `Name(Empty \| SpecialChar \| TooLong)` | `INVALID_NAME` (2) |
//! | `Name(NotFound)` | `NOT_FOUND` (9) |
//! | `Name(Exists)` | `ALREADY_EXISTS` (10) |
//! | `Name(EntryTooBig)` | `ENTRY_TOO_BIG` (3) |
//! | `Cancelled` | `CANCELLED` (16) |
//! | `Agent(_)` | `AGENT_UNAVAILABLE` (22) |
//! | `ResourceLimit(_)` | `RESOURCE_LIMIT` (8) |
//! | `MemoryProtection` | `MEMORY_PROTECTION` (20) |
//! | `ConfirmationRequired` | `CONFIRMATION_REQUIRED` (11) |
//! | `PassphraseMismatch` | `PASSPHRASE_MISMATCH` (12) |
//! | `Locked` | `LOCKED` (13) |
//! | `Busy` | `BUSY` (14) |
//! | `Conflict` | `CONFLICT` (15) |
//! | `CommitUncertain` | `COMMIT_UNCERTAIN` (24) |
//! | `InvalidTotp` | `INVALID_TOTP` (25) |
//! | `Panic` | `PANIC` (23) |
//! | `Crypto` | `CRYPTO` (18) |
//! | `NoMemory` | `NO_MEMORY` (19) |
//! | `UnsupportedFilesystem` | `UNSUPPORTED_FILESYSTEM` (21) |
//! | `StoreNotFound` | `STORE_NOT_FOUND` (4) |
//! | `StoreExists` | `STORE_EXISTS` (5) |
//!
//! `INVALID_ARGUMENT` (1) has no [`Error`] variant on purpose: it is produced
//! by the C ABI's argument-validation layer (plan §6), which rejects
//! malformed pointers/lengths before Rust values are constructed.
//!
//! Mutation outcomes are `(status, CommitState)` pairs (plan §5.6 point 5):
//! mutation entry points return [`CommitOutcome`], carrying [`CommitFailure`]
//! (`error` + [`CommitState`]) on failure and [`CommitReceipt`] on success.

use std::fmt;

/// The 26 stable status codes (0–25) of the ABI contract (Sol §3.7).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Success (0).
    Ok = 0,
    /// ABI-level argument validation failure (1); not produced by [`Error`].
    InvalidArgument = 1,
    /// Name violates the store's name rules (2).
    InvalidName = 2,
    /// Name + value do not fit one entry record (3).
    EntryTooBig = 3,
    /// The store file does not exist (4).
    StoreNotFound = 4,
    /// The store file already exists (5).
    StoreExists = 5,
    /// Header carries an unsupported format version (6).
    UnsupportedVersion = 6,
    /// Store structure violates the format contract (7).
    MalformedStore = 7,
    /// A configured resource limit was exceeded (8).
    ResourceLimit = 8,
    /// Requested record not found (9).
    NotFound = 9,
    /// Record already exists (10).
    AlreadyExists = 10,
    /// User confirmation required before proceeding (11).
    ConfirmationRequired = 11,
    /// Retyped passphrase does not match (12).
    PassphraseMismatch = 12,
    /// Target region/file is locked by another holder (13).
    Locked = 13,
    /// Serialization mutex or resource is busy (14).
    Busy = 14,
    /// Store identity/state changed underneath the operation (15).
    Conflict = 15,
    /// Operation cancelled (16).
    Cancelled = 16,
    /// I/O failure (17).
    Io = 17,
    /// Cryptographic failure (18).
    Crypto = 18,
    /// Memory allocation failure (19).
    NoMemory = 19,
    /// Secret-memory protection failed (locking/zeroization) (20).
    MemoryProtection = 20,
    /// Filesystem cannot support the required semantics (21).
    UnsupportedFilesystem = 21,
    /// SSH-agent access unavailable (22).
    AgentUnavailable = 22,
    /// Contained Rust panic (23).
    Panic = 23,
    /// Commit outcome is uncertain; reconcile, do not blindly retry (24).
    CommitUncertain = 24,
    /// TOTP value invalid (25).
    InvalidTotp = 25,
}

impl Status {
    /// The stable numeric code (0–25) used by the C ABI.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// Stable status plus the Win32 `os_error` side-channel, mirroring the future
/// ABI's `WsErrorV1 { os_error, commit_state }` carrier (plan §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusReport {
    pub status: Status,
    /// Relevant Win32 error captured at the failure point; 0 otherwise.
    pub os_error: u32,
}

/// Name-rule and name-lookup failures (plan §3.4: `Name` → `INVALID_NAME` /
/// `NOT_FOUND` / `ALREADY_EXISTS` / `ENTRY_TOO_BIG`).
///
/// Variants carry no name bytes: diagnostics can never leak names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// Name is empty (upstream: "Empty keys are not allowed").
    Empty,
    /// Name contains a byte `<= 0x20` (upstream: "Special characaters are not
    /// allowed in keys" — upstream typo preserved in the CLI string catalog).
    SpecialChar,
    /// Name longer than 255 bytes (upstream: "Keys are limited to 255 bytes").
    TooLong,
    /// A record with this name already exists (upstream: "Secret %s exists!").
    Exists,
    /// No record with this name (upstream: "Secret %s not found").
    NotFound,
    /// Name + value + 1 exceed one entry's data area (upstream: "Entry too big!").
    EntryTooBig,
}

impl NameError {
    /// Stable status code for this name failure.
    pub const fn status(self) -> Status {
        match self {
            NameError::Empty | NameError::SpecialChar | NameError::TooLong => Status::InvalidName,
            NameError::NotFound => Status::NotFound,
            NameError::Exists => Status::AlreadyExists,
            NameError::EntryTooBig => Status::EntryTooBig,
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            NameError::Empty => "empty name",
            NameError::SpecialChar => "name contains a special character",
            NameError::TooLong => "name is too long",
            NameError::Exists => "record already exists",
            NameError::NotFound => "record not found",
            NameError::EntryTooBig => "entry is too big",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for NameError {}

/// Store-format failures (plan §3.4: `Format` → `UNSUPPORTED_VERSION` /
/// `MALFORMED_STORE`, with `ENTRY_TOO_BIG` and name-rule passthrough).
///
/// Variants carry no record content: malformed records are rejected without
/// exposing partial names or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// `version != 0` in the header (upstream `s_header` case 1).
    UnsupportedVersion(u8),
    /// `ops_limit < 10000` in the header (upstream `s_header` case 2).
    OpsLimitTooLow(u64),
    /// Name-rule failure (see [`NameError`]).
    Name(NameError),
    /// `name_len + value_len + 1 > 474` (upstream: "Entry too big!").
    EntryTooBig,
    /// Authenticated record fails structural validation: no NUL inside the
    /// bounded name area, or `slen` exceeds the data area.
    MalformedRecord,
    /// Store-level structural violation (plan §3.5): length not a multiple
    /// of 512, target slot outside the record area, header block too short.
    StoreLayout,
}

impl FormatError {
    /// Stable status code for this format failure.
    pub const fn status(self) -> Status {
        match self {
            FormatError::UnsupportedVersion(_) => Status::UnsupportedVersion,
            // No dedicated code exists for a below-floor opslimit among the 26;
            // plan §3.4 maps `Format` to UNSUPPORTED_VERSION/MALFORMED_STORE,
            // and this is a malformed store invariant, not a version issue.
            FormatError::OpsLimitTooLow(_) => Status::MalformedStore,
            FormatError::EntryTooBig => Status::EntryTooBig,
            FormatError::MalformedRecord | FormatError::StoreLayout => Status::MalformedStore,
            FormatError::Name(name) => name.status(),
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::UnsupportedVersion(v) => {
                write!(f, "unsupported store version {v}")
            }
            FormatError::OpsLimitTooLow(n) => {
                write!(f, "store opslimit {n} is below the minimum")
            }
            FormatError::Name(name) => write!(f, "invalid name: {name}"),
            FormatError::EntryTooBig => f.write_str("entry is too big"),
            FormatError::MalformedRecord => f.write_str("malformed store record"),
            FormatError::StoreLayout => f.write_str("malformed store layout"),
        }
    }
}

impl std::error::Error for FormatError {}

/// SSH-agent failures (`Agent` → `AGENT_UNAVAILABLE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    /// The requested `SSH_AUTH_SOCK` endpoint is not the one supported local
    /// endpoint.
    EnvParse,
    /// The ssh-agent wire exchange failed or the response does not match the
    /// request framing (length/header mismatch).
    ProtocolMismatch,
    /// No ssh-agent reachable at the expected endpoint.
    Unavailable,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            AgentError::EnvParse => "invalid agent environment",
            AgentError::ProtocolMismatch => "agent protocol mismatch",
            AgentError::Unavailable => "agent unavailable",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AgentError {}

/// Which configured bound a [`LimitExceeded`] diagnoses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// The store header's KDF `ops_limit` (work factor) is above the
    /// caller's ceiling ([`crate::store::Limits::max_opslimit`]).
    OpsLimit,
    /// The store file size is above the caller's ceiling
    /// ([`crate::store::Limits::max_store_bytes`]).
    StoreBytes,
}

/// The explicit remedy for an exceeded limit (WS-06: a cap rejection must
/// tell the user that a limit was exceeded, the numerical bound, and exactly
/// what to do about it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitRemedy {
    /// Re-run with the global `--allow-expensive-kdf` option, in the leading
    /// position before the command word. It lifts only the `ops_limit`
    /// ceiling: the [`crate::format::OPS_LIMIT_MIN`] floor still applies.
    AllowExpensiveKdf,
    /// No user override exists: the calling application configured the bound.
    CallerConfigured,
}

/// Diagnosis carried by [`Error::ResourceLimit`]: which limit was exceeded,
/// the offending value, the numerical bound, and the explicit remedy. The
/// [`fmt::Display`] is the complete user-facing message body (the CLI adds
/// its `Fatal: ` prefix; the library never prints).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitExceeded {
    /// Which bound was exceeded.
    pub kind: LimitKind,
    /// The offending value found (header `ops_limit`, store size in bytes).
    pub actual: u64,
    /// The configured numerical bound.
    pub limit: u64,
    /// What the user can do about it.
    pub remedy: LimitRemedy,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            LimitKind::OpsLimit => write!(
                f,
                "Store opslimit {} exceeds the limit of {}",
                self.actual, self.limit
            )?,
            LimitKind::StoreBytes => write!(
                f,
                "Store size {} exceeds the limit of {} bytes",
                self.actual, self.limit
            )?,
        }
        match self.remedy {
            LimitRemedy::AllowExpensiveKdf => f.write_str(
                "; re-run with --allow-expensive-kdf before the command to allow expensive key derivation",
            ),
            LimitRemedy::CallerConfigured => {
                f.write_str("; the limit is configured by the calling application")
            }
        }
    }
}

impl std::error::Error for LimitExceeded {}

/// The one error enum shared by the Rust API and the future C ABI (plan §3.4).
#[derive(Debug)]
pub enum Error {
    /// I/O failure on the store file or console/ssh-agent transport.
    Io(std::io::Error),
    /// Store-format failure (see [`FormatError`]).
    Format(FormatError),
    /// Name-rule or name-lookup failure (see [`NameError`]).
    Name(NameError),
    /// Operation cancelled before completion (or after commit — see
    /// [`CommitReceipt::warnings`]).
    Cancelled,
    /// SSH-agent failure (see [`AgentError`]).
    Agent(AgentError),
    /// A configured resource limit was exceeded ([`LimitExceeded`] carries
    /// the diagnosis: which limit, the offending value, the numerical bound
    /// and the explicit remedy).
    ResourceLimit(LimitExceeded),
    /// Secret-memory protection (locking/zeroization) failed.
    MemoryProtection,
    /// The operation requires user confirmation before proceeding.
    ConfirmationRequired,
    /// Retyped passphrase does not match the first entry.
    PassphraseMismatch,
    /// Store region or session is locked. On `LOCKED` the CLI renders the
    /// upstream catalog string `Fatal: Unable to lock <path>` with the path
    /// it opened (upstream `s_set_secret` builds `Unable to lock %s` from
    /// `s.path`); the library never prints, so the path is supplied by the
    /// CLI layer (plan §3.4: the CLI maps errors to the exact catalog).
    Locked,
    /// Writer-serialization mutex is busy.
    Busy,
    /// Store identity or state changed underneath the operation.
    Conflict,
    /// Commit outcome uncertain; the caller must reopen/reconcile.
    CommitUncertain,
    /// TOTP value invalid (upstream: "Invalid secret").
    InvalidTotp,
    /// Contained Rust panic at an ABI boundary.
    Panic,
    /// Cryptographic failure reported by the pinned libhydrogen.
    Crypto,
    /// Memory allocation failure.
    NoMemory,
    /// Filesystem lacks required semantics (hard links, named streams, ...).
    UnsupportedFilesystem,
    /// The store file does not exist.
    StoreNotFound,
    /// The store file already exists.
    StoreExists,
}

impl Error {
    /// The stable status code for this error.
    pub const fn status(&self) -> Status {
        match self {
            Error::Io(_) => Status::Io,
            Error::Format(format) => format.status(),
            Error::Name(name) => name.status(),
            Error::Cancelled => Status::Cancelled,
            Error::Agent(_) => Status::AgentUnavailable,
            Error::ResourceLimit(_) => Status::ResourceLimit,
            Error::MemoryProtection => Status::MemoryProtection,
            Error::ConfirmationRequired => Status::ConfirmationRequired,
            Error::PassphraseMismatch => Status::PassphraseMismatch,
            Error::Locked => Status::Locked,
            Error::Busy => Status::Busy,
            Error::Conflict => Status::Conflict,
            Error::CommitUncertain => Status::CommitUncertain,
            Error::InvalidTotp => Status::InvalidTotp,
            Error::Panic => Status::Panic,
            Error::Crypto => Status::Crypto,
            Error::NoMemory => Status::NoMemory,
            Error::UnsupportedFilesystem => Status::UnsupportedFilesystem,
            Error::StoreNotFound => Status::StoreNotFound,
            Error::StoreExists => Status::StoreExists,
        }
    }

    /// The Win32 `os_error` side-channel: the raw OS error of the inner
    /// `std::io::Error` for [`Error::Io`], zero otherwise.
    pub fn os_error(&self) -> u32 {
        match self {
            Error::Io(io) => match io.raw_os_error() {
                Some(code) => code as u32,
                None => 0,
            },
            _ => 0,
        }
    }

    /// Status plus `os_error`, as carried across the future C ABI.
    pub fn report(&self) -> StatusReport {
        StatusReport {
            status: self.status(),
            os_error: self.os_error(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(io) => write!(f, "i/o error: {io}"),
            Error::Format(format) => write!(f, "store format error: {format}"),
            Error::Name(name) => write!(f, "name error: {name}"),
            Error::Cancelled => f.write_str("operation cancelled"),
            Error::Agent(agent) => write!(f, "agent error: {agent}"),
            // The diagnosis IS the message: which limit, the offending
            // value, the numerical bound and the explicit remedy.
            Error::ResourceLimit(limit) => write!(f, "{limit}"),
            Error::MemoryProtection => f.write_str("memory protection failure"),
            Error::ConfirmationRequired => f.write_str("confirmation required"),
            Error::PassphraseMismatch => f.write_str("passphrases don't match"),
            Error::Locked => f.write_str("store region is locked"),
            Error::Busy => f.write_str("store writer is busy"),
            Error::Conflict => f.write_str("store changed underneath the operation"),
            Error::CommitUncertain => f.write_str("commit outcome uncertain"),
            Error::InvalidTotp => f.write_str("invalid secret"),
            Error::Panic => f.write_str("contained panic"),
            Error::Crypto => f.write_str("cryptographic failure"),
            Error::NoMemory => f.write_str("out of memory"),
            Error::UnsupportedFilesystem => f.write_str("unsupported filesystem"),
            Error::StoreNotFound => f.write_str("secret store doesn't exist"),
            Error::StoreExists => f.write_str("secret store already exists"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(io) => Some(io),
            Error::Format(format) => Some(format),
            Error::Name(name) => Some(name),
            Error::Agent(agent) => Some(agent),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(io: std::io::Error) -> Self {
        Error::Io(io)
    }
}

impl From<FormatError> for Error {
    fn from(format: FormatError) -> Self {
        match format {
            // Surface name-rule failures through the `Name` category so the
            // taxonomy's `Name` → name-status mapping stays direct.
            FormatError::Name(name) => Error::Name(name),
            other => Error::Format(other),
        }
    }
}

impl From<NameError> for Error {
    fn from(name: NameError) -> Self {
        Error::Name(name)
    }
}

impl From<AgentError> for Error {
    fn from(agent: AgentError) -> Self {
        Error::Agent(agent)
    }
}

impl From<FormatError> for CommitFailure {
    /// Format rejections happen before write initiation (plan §5.6 point 5):
    /// the store is unchanged.
    fn from(format: FormatError) -> Self {
        CommitFailure::before_write(Error::from(format))
    }
}

impl From<NameError> for CommitFailure {
    /// Name rejections happen before write initiation (plan §5.6 point 5).
    fn from(name: NameError) -> Self {
        CommitFailure::before_write(Error::Name(name))
    }
}

/// Commit outcome of a mutation (plan §5.6 point 5 trichotomy).
///
/// `#[repr(u32)]` values match the future ABI's `commit_state` codes 1–3;
/// the ABI's code 0 (`NOT_APPLICABLE`) is written by the ABI layer for
/// non-mutating calls and has no Rust counterpart.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitState {
    /// Failure before write initiation: the store is unchanged.
    NotCommitted = 1,
    /// All checkpoints (write initiation, completed write, successful flush)
    /// passed.
    Committed = 2,
    /// Bytes may have been written but completion/durability is unknown;
    /// the caller must reopen/reconcile, not blindly retry.
    Unknown = 3,
}

/// Post-commit warning bit: a panic was contained after the commit
/// checkpoint (plan §5.6 point 5's warning channel).
pub const WARN_POST_COMMIT_PANIC: u32 = 1 << 0;
/// Post-commit warning bit: cancellation arrived after the commit checkpoint
/// (plan §5.6 point 5's warning channel).
pub const WARN_POST_COMMIT_CANCELLED: u32 = 1 << 1;
/// Warning bit: the writer mutex was acquired after a previous owner died
/// holding it (`WAIT_ABANDONED`) — the mutation proceeds but no store
/// integrity is claimed (plan §5.6 point 1).
pub const WARN_ABANDONED_MUTEX: u32 = 1 << 2;

/// The mutation outcome reported alongside success (plan §3.4/§5.6 point 5):
/// the commit state plus the post-commit warning bitmask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub state: CommitState,
    pub warnings: u32,
}

impl CommitReceipt {
    /// A receipt for a mutation with no post-commit anomalies.
    pub const fn new(state: CommitState) -> Self {
        CommitReceipt { state, warnings: 0 }
    }

    /// Records a post-commit warning bit.
    pub const fn with_warning(self, warning: u32) -> Self {
        CommitReceipt {
            state: self.state,
            warnings: self.warnings | warning,
        }
    }
}

impl Default for CommitReceipt {
    fn default() -> Self {
        CommitReceipt::new(CommitState::NotCommitted)
    }
}

/// A mutation failure: the `(status, CommitState)` pair the Rust layer
/// reports for mutations (plan §5.6 point 5). Mutation entry points return
/// [`CommitOutcome`]; non-mutating operations return plain [`Error`].
///
/// This is deliberately not convertible `Into<Error>`: dropping the commit
/// state would destroy the distinction the ABI's `WsErrorV1.commit_state`
/// must preserve.
#[derive(Debug)]
pub struct CommitFailure {
    /// The failure itself.
    pub error: Error,
    /// How far the mutation got (plan §5.6 point 5 trichotomy).
    pub state: CommitState,
}

impl CommitFailure {
    /// Builds a `(error, state)` pair.
    pub fn new(error: Error, state: CommitState) -> Self {
        CommitFailure { error, state }
    }

    /// Failure before write initiation: the store is unchanged.
    pub fn before_write(error: Error) -> Self {
        CommitFailure {
            error,
            state: CommitState::NotCommitted,
        }
    }

    /// Failure after write initiation: partial effects possible (plan
    /// §5.6 point 5: everything between checkpoints (i) and (ii) — including
    /// a failed/short write — and between (ii) and (iii) — including a failed
    /// flush — is `Unknown`).
    pub fn unknown(error: Error) -> Self {
        CommitFailure {
            error,
            state: CommitState::Unknown,
        }
    }

    /// The stable status code of the wrapped error.
    pub fn status(&self) -> Status {
        self.error.status()
    }
}

/// Mutation result: [`CommitReceipt`] on success (always `Committed`),
/// [`CommitFailure`] on failure.
pub type CommitOutcome<T> = Result<T, CommitFailure>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_are_stable() {
        assert_eq!(Status::Ok.code(), 0);
        assert_eq!(Status::InvalidArgument.code(), 1);
        assert_eq!(Status::InvalidName.code(), 2);
        assert_eq!(Status::EntryTooBig.code(), 3);
        assert_eq!(Status::StoreNotFound.code(), 4);
        assert_eq!(Status::StoreExists.code(), 5);
        assert_eq!(Status::UnsupportedVersion.code(), 6);
        assert_eq!(Status::MalformedStore.code(), 7);
        assert_eq!(Status::ResourceLimit.code(), 8);
        assert_eq!(Status::NotFound.code(), 9);
        assert_eq!(Status::AlreadyExists.code(), 10);
        assert_eq!(Status::ConfirmationRequired.code(), 11);
        assert_eq!(Status::PassphraseMismatch.code(), 12);
        assert_eq!(Status::Locked.code(), 13);
        assert_eq!(Status::Busy.code(), 14);
        assert_eq!(Status::Conflict.code(), 15);
        assert_eq!(Status::Cancelled.code(), 16);
        assert_eq!(Status::Io.code(), 17);
        assert_eq!(Status::Crypto.code(), 18);
        assert_eq!(Status::NoMemory.code(), 19);
        assert_eq!(Status::MemoryProtection.code(), 20);
        assert_eq!(Status::UnsupportedFilesystem.code(), 21);
        assert_eq!(Status::AgentUnavailable.code(), 22);
        assert_eq!(Status::Panic.code(), 23);
        assert_eq!(Status::CommitUncertain.code(), 24);
        assert_eq!(Status::InvalidTotp.code(), 25);
    }

    #[test]
    fn commit_state_codes_match_abi() {
        assert_eq!(CommitState::NotCommitted as u32, 1);
        assert_eq!(CommitState::Committed as u32, 2);
        assert_eq!(CommitState::Unknown as u32, 3);
    }

    #[test]
    fn error_mapping_table() {
        assert_eq!(Error::Cancelled.status(), Status::Cancelled);
        assert_eq!(Error::Locked.status(), Status::Locked);
        assert_eq!(
            Error::Format(FormatError::UnsupportedVersion(1)).status(),
            Status::UnsupportedVersion
        );
        assert_eq!(
            Error::Format(FormatError::OpsLimitTooLow(1)).status(),
            Status::MalformedStore
        );
        assert_eq!(
            Error::Format(FormatError::MalformedRecord).status(),
            Status::MalformedStore
        );
        assert_eq!(
            Error::Format(FormatError::StoreLayout).status(),
            Status::MalformedStore
        );
        assert_eq!(
            Error::Format(FormatError::Name(NameError::NotFound)).status(),
            Status::NotFound
        );
        assert_eq!(Error::Name(NameError::NotFound).status(), Status::NotFound);
        assert_eq!(Error::StoreExists.status(), Status::StoreExists);
    }

    #[test]
    fn format_error_name_flows_into_name_category() {
        let err: Error = FormatError::Name(NameError::TooLong).into();
        assert!(matches!(err, Error::Name(NameError::TooLong)));
        let err: Error = FormatError::EntryTooBig.into();
        assert!(matches!(err, Error::Format(FormatError::EntryTooBig)));
    }

    #[test]
    fn io_error_carries_os_error_side_channel() {
        let io = std::io::Error::from_raw_os_error(5);
        let err = Error::Io(io);
        assert_eq!(err.status(), Status::Io);
        assert_eq!(err.os_error(), 5);
        let plain = Error::Cancelled;
        assert_eq!(plain.os_error(), 0);
    }

    #[test]
    fn resource_limit_diagnosis_names_limit_bound_and_remedy() {
        let ops = Error::ResourceLimit(LimitExceeded {
            kind: LimitKind::OpsLimit,
            actual: 1_000_001,
            limit: 1_000_000,
            remedy: LimitRemedy::AllowExpensiveKdf,
        });
        assert_eq!(ops.status(), Status::ResourceLimit);
        assert_eq!(
            ops.to_string(),
            "Store opslimit 1000001 exceeds the limit of 1000000; re-run with \
             --allow-expensive-kdf before the command to allow expensive key derivation"
        );
        // The remedy is part of the diagnosis: the message must name the
        // explicit override.
        assert!(ops.to_string().contains("--allow-expensive-kdf"));

        let bytes = Error::ResourceLimit(LimitExceeded {
            kind: LimitKind::StoreBytes,
            actual: 4096,
            limit: 512,
            remedy: LimitRemedy::CallerConfigured,
        });
        assert_eq!(bytes.status(), Status::ResourceLimit);
        assert_eq!(
            bytes.to_string(),
            "Store size 4096 exceeds the limit of 512 bytes; the limit is \
             configured by the calling application"
        );
    }

    #[test]
    fn commit_receipt_warning_bits() {
        let receipt = CommitReceipt::new(CommitState::Committed)
            .with_warning(WARN_POST_COMMIT_PANIC)
            .with_warning(WARN_POST_COMMIT_CANCELLED);
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(
            receipt.warnings,
            WARN_POST_COMMIT_PANIC | WARN_POST_COMMIT_CANCELLED
        );
    }

    #[test]
    fn commit_failure_pairs_preserve_state() {
        let f = CommitFailure::before_write(Error::Busy);
        assert_eq!(f.state, CommitState::NotCommitted);
        assert_eq!(f.status(), Status::Busy);
        let f = CommitFailure::unknown(Error::Cancelled);
        assert_eq!(f.state, CommitState::Unknown);
        assert_eq!(f.status(), Status::Cancelled);
        let outcome: CommitOutcome<()> =
            Err(CommitFailure::new(Error::Locked, CommitState::Unknown));
        assert!(outcome.is_err());
    }
}
