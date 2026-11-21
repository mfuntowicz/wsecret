//! Block I/O, scanning, slots and in-place writes (spec §3.5, §5.6).
//!
//! Layout (spec §1.1): a flat sequence of 512-byte blocks; block 0 is the
//! header, blocks 1..N are encrypted entries. Reads tolerate a trailing
//! partial block (upstream-exact); mutations reject stores whose length is
//! not a multiple of 512.
//!
//! Mutation protocol (spec §5.6, ONE protocol): the `Global\wsecret-store-*`
//! writer mutex is held across the read-scan-modify-write critical section
//! (acquire it with [`Store::lock_writers`] to span `find` + write); each
//! record write takes an exclusive non-blocking `LockFileEx` lock on the
//! target 512-byte region, writes EXACTLY 512 bytes in place, then
//! `FlushFileBuffers`. Commit states follow spec §5.6 point 5.

use std::cell::Cell;
use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(feature = "fault-injection")]
use crate::error::WARN_POST_COMMIT_CANCELLED;
use crate::error::{
    Error, FormatError, LimitExceeded, LimitKind, LimitRemedy, NameError, WARN_ABANDONED_MUTEX,
    WARN_POST_COMMIT_PANIC,
};
use crate::format::{
    BLOCK, ENTRY_DATA_LEN, ENTRY_PLAIN_LEN, Entry, HEADER_LEN, Header, OPS_LIMIT_MIN,
    build_entry_payload, check_name,
};
use crate::session::{SecretBytes, Session};
use crate::windows::file as winfile;
use crate::windows::security::{MutexOutcome, WriterMutex};

// Commit outcomes, receipts and warning bits live in `crate::error` (the one
// taxonomy shared with the future ABI); re-exported here for store clients.
pub use crate::error::{CommitFailure, CommitOutcome, CommitReceipt, CommitState};

/// Result of [`Store::find`].
///
/// Deliberately not `Clone`/`PartialEq`: the record value is secret
/// material and must not be duplicated or compared through this handle.
/// `Debug` is safe to log — [`SecretBytes`] renders `<redacted>`.
#[derive(Debug)]
pub enum ScanOutcome {
    /// First exact match (case-sensitive, full-length including the NUL
    /// terminator, upstream `hydro_equal(data, key, len + 1)`).
    Found {
        /// Byte offset of the record block (a multiple of 512, >= 512).
        slot: u64,
        /// The record name (metadata).
        name: Vec<u8>,
        /// The record value: zeroizing owner, erased on drop (plan §5.3).
        /// Borrow with [`SecretBytes::as_slice`]; the plaintext never
        /// escapes as an ordinary `Vec`.
        value: SecretBytes,
    },
    /// No match.
    NotFound {
        /// First decryptable `DELETED:`-prefixed record (tracked only when
        /// `create` is true); the reusable slot.
        tombstone: Option<u64>,
        /// At least one record decrypted with this session key (upstream
        /// `pass_ok` — feeds the confirmation gate).
        decrypted_any: bool,
    },
}

/// Result of [`Store::find_meta`]: metadata only — the record value never
/// leaves the scan buffer, so existence probes and slot-only rewrites carry
/// no secret bytes at all. `Debug` is safe to log (names are CLI-visible
/// metadata; values are absent by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanMeta {
    /// First exact match (same matching rules as [`ScanOutcome::Found`]).
    Found {
        /// Byte offset of the record block (a multiple of 512, >= 512).
        slot: u64,
        /// The record name (metadata).
        name: Vec<u8>,
    },
    /// No match.
    NotFound {
        /// First decryptable `DELETED:`-prefixed record (tracked only when
        /// `create` is true); the reusable slot.
        tombstone: Option<u64>,
        /// At least one record decrypted with this session key (upstream
        /// `pass_ok` — feeds the confirmation gate).
        decrypted_any: bool,
    },
}

/// Metadata of the record occupying one slot (spec §3.5 block address; the
/// Quick Access identity is `slot` + exact `name` bytes). No value material
/// is carried: `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMeta {
    /// Byte offset of the record block (a multiple of 512, >= 512).
    pub slot: u64,
    /// The record name (metadata), exact bytes as stored.
    pub name: Vec<u8>,
    /// The record name carries the raw `DELETED:` tombstone prefix (lookup
    /// parity).
    pub tombstone: bool,
}

/// A slot-addressed record read ([`Store::read_at`]): metadata plus the
/// record value in a zeroizing [`SecretBytes`] owner (erased on drop).
#[derive(Debug)]
pub struct SlotRecord {
    /// The slot metadata.
    pub meta: SlotMeta,
    /// The record value: zeroizing owner. Borrow with
    /// [`SecretBytes::as_slice`]; the plaintext never escapes as a `Vec`.
    pub value: SecretBytes,
}

/// What a failed compare-and-set found instead of the expected record
/// (pre-write report: the store is byte-unchanged on every mismatch).
#[derive(Debug)]
pub struct CasMismatch {
    /// The record occupying the slot at compare time. `None` = no record of
    /// this session is there (beyond EOF, a trailing partial block, or an
    /// opaque other-partition block).
    pub found: Option<SlotMeta>,
    /// The name matched but the value differed (value-level CAS only).
    pub value_changed: bool,
}

/// A failed [`Store::cas_slot`]: a content mismatch (always before write
/// initiation, store byte-unchanged) or the write protocol's own failure
/// (the §5.6 point 5 [`CommitFailure`] trichotomy is preserved unchanged).
#[derive(Debug)]
pub enum CasFailure {
    /// The slot's content did not match the expectation; nothing written.
    Mismatch(CasMismatch),
    /// The write protocol reported a failure: pre-write rejections carry
    /// [`CommitState::NotCommitted`], write-path failures their checkpoint
    /// state.
    Write(CommitFailure),
}

/// The `DELETED:` tombstone prefix check (lookup parity).
fn is_tombstone(name: &[u8]) -> bool {
    name.starts_with(b"DELETED:")
}

/// Internal result of [`Store::lookup`]: the caller's projection of a
/// matched record, or the fixed not-found report.
enum Lookup<T> {
    Found(T),
    NotFound {
        tombstone: Option<u64>,
        decrypted_any: bool,
    },
}

/// Resource caps applied when opening a store (plan §3.4 limits policy; WS-06
/// open policy). `None` for a field is "no ceiling" on that dimension.
///
/// The DEFAULT policy ([`Limits::default`], used by [`Store::open`],
/// [`Store::open_read`] and every ordinary CLI/agent/SSH/future-import open)
/// caps the header `ops_limit` at [`OPS_LIMIT_MAX`] (1_000_000) and the store
/// size at [`STORE_BYTES_MAX`] (64 MiB). Both are deliberate, documented
/// divergences from upstream: the pinned KDF loop cannot be interrupted, so a
/// crafted header with `ops_limit = 2^64 - 1` pins a core ~forever (upstream
/// hangs identically), and a crafted store length forces store-sized
/// allocations before anything else can run. Stores created upstream with
/// `ops_limit > 1_000_000` still open — through the explicit
/// [`Limits::allow_expensive_kdf`] override (CLI: `--allow-expensive-kdf` in
/// the leading position before the command word, never inherited from the
/// environment or from `agent`/`ssh agent` child arguments). Stores
/// legitimately larger than [`STORE_BYTES_MAX`] open only through the
/// explicit, per-open [`Limits::trusted_file`] override (one file, one open —
/// never implicit, never inherited). The [`OPS_LIMIT_MIN`] format floor
/// always applies and is never lifted.
///
/// The caps are checked after the header/size inspection but before any KDF
/// execution or store-sized allocation — i.e. before the open returns its
/// handle — so no caller reaches an unbounded derivation or an expensive
/// prompt by accident (plan §3.4 enforcement order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum accepted header `ops_limit` (`None` = unlimited).
    pub max_opslimit: Option<u64>,
    /// Maximum accepted store size in bytes (`None` = unlimited).
    pub max_store_bytes: Option<u64>,
}

/// Ordinary-open ceiling for the header `ops_limit` (WS-06): the largest
/// work factor an unmodified invocation derives without the explicit
/// `--allow-expensive-kdf` override. Independent of the format constants —
/// [`crate::format::OPS_LIMIT_MIN`] (10000) is the floor, upstream
/// `init`'s default is 100000 — and enforced by [`Limits::default`].
pub const OPS_LIMIT_MAX: u64 = 1_000_000;

/// Ordinary-open ceiling for the store size: 64 MiB (131072 record blocks
/// plus the header — far beyond any legitimate store). Enforced by
/// [`Limits::default`] before any store-sized allocation; raised only
/// through the explicit per-open [`Limits::trusted_file`] override.
pub const STORE_BYTES_MAX: u64 = 64 * 1024 * 1024;

impl Limits {
    /// The explicit expensive-KDF override (CLI `--allow-expensive-kdf`):
    /// the `ops_limit` ceiling is lifted, every other cap keeps its ordinary
    /// value. The [`OPS_LIMIT_MIN`] floor still applies. Never implicit —
    /// callers must receive it from an explicit user action per invocation.
    pub fn allow_expensive_kdf() -> Limits {
        Limits {
            max_opslimit: None,
            ..Limits::default()
        }
    }

    /// The explicit, per-open trusted-file override: raises (or lifts with
    /// `None`) the store-size ceiling for ONE open of a file the user has
    /// explicitly trusted to be that large. Every other cap keeps its
    /// ordinary value. Never implicit and never inherited from the
    /// environment: the caller must receive it from an explicit user action
    /// for this file (plan §3.4 limits policy).
    pub fn trusted_file(max_store_bytes: Option<u64>) -> Limits {
        Limits {
            max_store_bytes,
            ..Limits::default()
        }
    }

    /// The `ops_limit` ceiling check shared by the open gate and the CLI
    /// `init` bound. Enforces the [`Limits::max_opslimit`] ceiling only; the
    /// [`OPS_LIMIT_MIN`] floor is a format invariant enforced at header
    /// parse/create and is not lifted by any policy. A rejection carries the
    /// full diagnosis (limit exceeded, numerical bound, explicit remedy).
    pub fn check_opslimit(&self, ops_limit: u64) -> Result<(), Error> {
        if let Some(limit) = self.max_opslimit {
            if ops_limit > limit {
                return Err(Error::ResourceLimit(LimitExceeded {
                    kind: LimitKind::OpsLimit,
                    actual: ops_limit,
                    limit,
                    remedy: LimitRemedy::AllowExpensiveKdf,
                }));
            }
        }
        Ok(())
    }
}

impl Default for Limits {
    /// The ordinary-open policy: [`OPS_LIMIT_MAX`] ceiling on `ops_limit`,
    /// [`STORE_BYTES_MAX`] ceiling on the store size.
    fn default() -> Self {
        Limits {
            max_opslimit: Some(OPS_LIMIT_MAX),
            max_store_bytes: Some(STORE_BYTES_MAX),
        }
    }
}

/// An open store file (spec §3.5). Fields are private; the store is driven
/// through the methods below.
pub struct Store {
    file: File,
    header: Header,
    /// The wsecret-writer mutex while it is held (spec §5.6 points 1-2).
    mutex: Option<WriterMutex>,
    /// Path the store was opened through (spec §5.6 6b secure-reopen).
    path: PathBuf,
    /// `(volume_serial, file_index, links)` captured at open/create
    /// (spec §5.6 6b).
    identity: winfile::FileIdentity,
    /// The 41-byte header binding captured at open/create (spec §5.6 6b(a)).
    header_binding: [u8; HEADER_LEN],
    /// Set when 6b revalidation failed: every further mutation fails with
    /// [`Error::Conflict`] until the store is reopened.
    invalidated: bool,
}

/// RAII holder for the cross-process writer mutex. Dereferences to the locked
/// store so `find` and the subsequent write can share one critical section;
/// every return/unwind releases the mutex on the owning thread.
pub struct WriterGuard<'a>(&'a mut Store);

impl std::ops::Deref for WriterGuard<'_> {
    type Target = Store;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for WriterGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        self.0.unlock_writers();
    }
}

impl Store {
    /// Binds the 6b revalidation state (identity + header bytes + path) to a
    /// freshly opened store file, given its already-read header block.
    fn bind(file: File, header: Header, path: &Path, block: &[u8; BLOCK]) -> Result<Store, Error> {
        let identity = winfile::identity(&file).map_err(io_err)?;
        let mut header_binding = [0u8; HEADER_LEN];
        header_binding.copy_from_slice(&block[..HEADER_LEN]);
        Ok(Store {
            file,
            header,
            mutex: None,
            path: path.to_path_buf(),
            identity,
            header_binding,
            invalidated: false,
        })
    }

    /// Spec §5.6 6b pre-mutation revalidation: (a) the header block read
    /// through this handle must still equal the binding captured at open;
    /// (b) a FRESH handle opened at the recorded path must name the SAME
    /// file (deletion+recreation / rename-swap → [`Error::Conflict`], the
    /// store is invalidated); (c) on success the fresh handle replaces the
    /// long-lived one for the upcoming write.
    fn revalidate(&mut self) -> Result<(), CommitFailure> {
        if self.invalidated {
            return Err(CommitFailure::before_write(Error::Conflict));
        }
        // (a) same-file header rewrite detection through our own handle.
        let mut block = [0u8; BLOCK];
        let same = winfile::read_at(&self.file, 0, &mut block)
            .map_err(|e| CommitFailure::before_write(Error::Io(e)))?;
        if !same || block[..HEADER_LEN] != self.header_binding {
            self.invalidated = true;
            return Err(CommitFailure::before_write(Error::Conflict));
        }
        // (b) secure reopen: the pathname must still name the recorded file.
        let fresh = winfile::open_store(&self.path)
            .map_err(|e| CommitFailure::before_write(Error::Io(e)))?;
        let fresh_id =
            winfile::identity(&fresh).map_err(|e| CommitFailure::before_write(Error::Io(e)))?;
        if fresh_id != self.identity {
            self.invalidated = true;
            return Err(CommitFailure::before_write(Error::Conflict));
        }
        // (c) re-anchor the long-lived handle to the fresh one.
        self.file = fresh;
        Ok(())
    }
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e)
}

/// Failed write after initiation: partial effects possible (plan §5.6
/// point 5 — a `write_at` failure cannot prove nothing landed, and its
/// internal seek is strictly pre-initiation; the conservative `Unknown`
/// class is used for both, see `windows::file::write_at`).
fn write_failed(e: std::io::Error) -> CommitFailure {
    CommitFailure::unknown(Error::Io(e))
}

/// Short write: checkpoint (ii) failed after bytes changed.
fn short_write(n: usize) -> CommitFailure {
    CommitFailure::unknown(Error::Io(std::io::Error::other(format!(
        "short write: {n} of {BLOCK} bytes"
    ))))
}

/// Flush failure: write completed (checkpoint (ii)), durability unknown.
fn flush_failed() -> CommitFailure {
    CommitFailure::unknown(Error::Io(std::io::Error::other("FlushFileBuffers failed")))
}

/// `From` lets `?` carry pre-write rejections (name/format checks, file-len
/// failures before initiation) into `CommitOutcome` with `NotCommitted`.
impl From<std::io::Error> for CommitFailure {
    fn from(e: std::io::Error) -> Self {
        CommitFailure::before_write(Error::Io(e))
    }
}

// ---------------------------------------------------------------------------
// §5.6 point 5 fault seams (compiled only with the `fault-injection` feature;
// production builds reduce these to the plain write path)
// ---------------------------------------------------------------------------

/// Injected-fault error text (identical at every seam).
#[cfg(feature = "fault-injection")]
fn injected_io() -> std::io::Error {
    std::io::Error::other("injected I/O fault at mutation checkpoint")
}

/// Before checkpoint (i) seam (plan §5.6 point 5 row 1: failure before write
/// initiation → the wrapped status with `NotCommitted`, store unchanged).
fn seam_before_write() -> Result<(), CommitFailure> {
    #[cfg(feature = "fault-injection")]
    {
        use crate::fault::{Fault, Point, take};
        match take(Point::BeforeWrite) {
            Some(Fault::Io) => return Err(CommitFailure::before_write(Error::Io(injected_io()))),
            Some(Fault::Cancel) => return Err(CommitFailure::before_write(Error::Cancelled)),
            Some(Fault::Panic) => panic!("injected panic at mutation checkpoint"),
            Some(Fault::Kill) => crate::fault::kill_now(),
            // `arm` rejects ShortWrite outside MidWrite; drop defensively.
            Some(Fault::ShortWrite) | None => {}
        }
    }
    Ok(())
}

/// Checkpoints (i)→(ii): the real positioned write (looping like upstream
/// `s_write`) behind the MidWrite seam. Returns the byte count accepted by
/// the OS — the caller's count check turns a short count into the §5.6
/// point 5 short-write failure.
fn seam_write(file: &File, offset: u64, block: &[u8; BLOCK]) -> CommitOutcome<usize> {
    #[cfg(feature = "fault-injection")]
    {
        use crate::fault::{Fault, Point, take};
        match take(Point::MidWrite) {
            Some(Fault::Io) => return Err(CommitFailure::unknown(Error::Io(injected_io()))),
            Some(Fault::Cancel) => {
                return Err(CommitFailure::new(Error::Cancelled, CommitState::Unknown));
            }
            Some(Fault::Panic) => panic!("injected panic at mutation checkpoint"),
            Some(Fault::ShortWrite) => {
                // Land exactly half the block and report the short count.
                return winfile::write_at(file, offset, &block[..BLOCK / 2]).map_err(write_failed);
            }
            Some(Fault::Kill) => {
                // Kill mid-write (E5): a 256-byte prefix lands, then death —
                // no flush, no unlock, no destructors.
                let _ = winfile::write_at(file, offset, &block[..BLOCK / 2]);
                crate::fault::kill_now();
            }
            None => {}
        }
    }
    winfile::write_at(file, offset, block).map_err(write_failed)
}

/// Checkpoints (ii)→(iii) seam (plan §5.6 point 5 row 3, "INCLUDING flush
/// returning zero"): the 512 bytes are in the page cache, durability unknown.
fn seam_after_write() -> Result<(), CommitFailure> {
    #[cfg(feature = "fault-injection")]
    {
        use crate::fault::{Fault, Point, take};
        match take(Point::AfterWrite) {
            Some(Fault::Io) => return Err(flush_failed()),
            Some(Fault::Cancel) => {
                return Err(CommitFailure::new(Error::Cancelled, CommitState::Unknown));
            }
            Some(Fault::Panic) => panic!("injected panic at mutation checkpoint"),
            Some(Fault::Kill) => crate::fault::kill_now(), // written, unflushed
            Some(Fault::ShortWrite) | None => {}
        }
    }
    Ok(())
}

/// Post-checkpoint-(iii) seam (plan §5.6 point 5 final reconciliation):
/// returns the warning bits to OR into the receipt; an injected panic here is
/// contained by the mutation boundary and reported as warning bit 0.
fn seam_post_commit() -> u32 {
    #[cfg(feature = "fault-injection")]
    {
        use crate::fault::{Fault, Point, take};
        match take(Point::AfterFlush) {
            Some(Fault::Cancel) => return WARN_POST_COMMIT_CANCELLED,
            Some(Fault::Panic) => panic!("injected panic at mutation checkpoint"),
            Some(Fault::Kill) => crate::fault::kill_now(),
            _ => {}
        }
    }
    0
}

/// Releases the §5.6 point 3 byte-range lock on every exit path — including
/// a contained-panic unwind through the mutation's `catch_unwind` boundary.
struct RangeLock<'a> {
    file: &'a File,
    offset: u64,
}

impl Drop for RangeLock<'_> {
    fn drop(&mut self) {
        let _ = winfile::unlock_range(self.file, self.offset, BLOCK as u64);
    }
}

impl Store {
    /// Creates a new store exclusively (upstream `s_init`): a single 512-byte
    /// header block with a random master key and `ops_limit` (upstream
    /// default 100000, minimum 10000 — pass
    /// [`crate::format::OPS_LIMIT_DEFAULT`] for the default).
    ///
    /// Creation itself derives nothing (no KDF runs here) and enforces only
    /// the [`OPS_LIMIT_MIN`] floor. Callers that want the ordinary open
    /// policy (WS-06: `ops_limit` <= [`OPS_LIMIT_MAX`]) bound the value with
    /// [`Limits::check_opslimit`] before creating — as the CLI `init` does —
    /// otherwise the resulting store needs [`Limits::allow_expensive_kdf`]
    /// to reopen.
    ///
    /// A creation is a mutation (plan §5.6 point 4 "Initialization"): it
    /// reports [`CommitOutcome`] like every other write path.
    pub fn create(path: &Path, ops_limit: u64) -> CommitOutcome<(Store, Header, CommitReceipt)> {
        if ops_limit < OPS_LIMIT_MIN {
            return Err(CommitFailure::before_write(Error::Format(
                FormatError::OpsLimitTooLow(ops_limit),
            )));
        }
        let mut master = [0u8; 32];
        libhydrogen_sys::random_buf(&mut master);
        let header = Header {
            version: crate::format::VERSION.0,
            master,
            ops_limit,
        };
        let block = Header::encode_init(master, ops_limit);
        let file = winfile::create_store(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CommitFailure::before_write(Error::StoreExists)
            } else {
                CommitFailure::before_write(Error::Io(e))
            }
        })?;
        // 6b binding captured pre-write (the file exists from creation on).
        let identity =
            winfile::identity(&file).map_err(|e| CommitFailure::before_write(Error::Io(e)))?;
        let mut header_binding = [0u8; HEADER_LEN];
        header_binding.copy_from_slice(&block[..HEADER_LEN]);
        // Init write (spec §5.6 point 4 "Initialization"): same write + flush
        // trichotomy, no range lock (exclusive creation is the serialization),
        // inside the §5.6 point 5 panic boundary (C16b: a contained
        // post-commit panic reports OK/Committed + warning bit 0).
        let phase = Cell::new(CommitState::NotCommitted);
        let warnings = Cell::new(0u32);
        let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            seam_before_write()?;
            phase.set(CommitState::Unknown); // checkpoint (i)
            let n = seam_write(&file, 0, &block)?; // checkpoints (i)→(ii)
            if n != BLOCK {
                return Err(short_write(n));
            }
            seam_after_write()?; // checkpoints (ii)→(iii)
            if !winfile::flush(&file) {
                return Err(flush_failed());
            }
            phase.set(CommitState::Committed); // checkpoint (iii)
            warnings.set(warnings.get() | seam_post_commit());
            Ok(())
        }));
        match written {
            Ok(Ok(())) => {}
            Ok(Err(failure)) => return Err(failure),
            Err(_) if phase.get() == CommitState::Committed => {
                warnings.set(warnings.get() | WARN_POST_COMMIT_PANIC);
            }
            Err(_) => return Err(CommitFailure::new(Error::Panic, phase.get())),
        }
        let receipt = CommitReceipt::new(CommitState::Committed).with_warning(warnings.get());
        let store = Store {
            file,
            header: header.clone(),
            mutex: None,
            path: path.to_path_buf(),
            identity,
            header_binding,
            invalidated: false,
        };
        Ok((store, header, receipt))
    }

    /// Opens an existing store read/write: reads the 512-byte header block
    /// and validates it as upstream `s_header` does (version 0, `ops_limit`
    /// >= 10000). Ordinary policy ([`Limits::default`]): `ops_limit` capped
    /// at [`OPS_LIMIT_MAX`] before any KDF or prompt (see [`Limits`]).
    pub fn open(path: &Path) -> Result<(Store, Header), Error> {
        Self::open_with_limits(path, Limits::default())
    }

    /// Opens an existing store read-only (read paths such as `list`/`show`
    /// work on stores the user cannot write, as upstream `O_RDONLY` does).
    /// Ordinary policy ([`Limits::default`]): `ops_limit` capped at
    /// [`OPS_LIMIT_MAX`] before any KDF or prompt (see [`Limits`]).
    pub fn open_read(path: &Path) -> Result<(Store, Header), Error> {
        Self::open_read_with_limits(path, Limits::default())
    }

    /// [`Store::open`] under `limits` (see [`Limits`]): the header/size
    /// inspection plus the caps, all checked before any KDF execution or
    /// store-sized allocation.
    pub fn open_with_limits(path: &Path, limits: Limits) -> Result<(Store, Header), Error> {
        let file = winfile::open_store(path).map_err(map_open_err)?;
        Self::open_file_with_limits(file, path, limits)
    }

    /// [`Store::open_read`] under `limits` (see [`Limits`]).
    pub fn open_read_with_limits(path: &Path, limits: Limits) -> Result<(Store, Header), Error> {
        let file = winfile::open_store_read(path).map_err(map_open_err)?;
        Self::open_file_with_limits(file, path, limits)
    }

    fn open_file_with_limits(
        file: File,
        path: &Path,
        limits: Limits,
    ) -> Result<(Store, Header), Error> {
        // Inspection first (a short/unversioned store is a format error even
        // when a cap is also exceeded), then the caps — all before any KDF
        // execution or store-sized allocation (plan §3.4 enforcement order).
        let (header, block) = Self::read_header(&file)?;
        limits.check_opslimit(header.ops_limit)?;
        if let Some(max) = limits.max_store_bytes {
            let len = winfile::file_len(&file).map_err(io_err)?;
            if len > max {
                return Err(Error::ResourceLimit(LimitExceeded {
                    kind: LimitKind::StoreBytes,
                    actual: len,
                    limit: max,
                    remedy: LimitRemedy::TrustedFileOverride,
                }));
            }
        }
        let store = Self::bind(file, header.clone(), path, &block)?;
        Ok((store, header))
    }

    fn read_header(file: &File) -> Result<(Header, [u8; BLOCK]), Error> {
        let mut block = [0u8; BLOCK];
        // Upstream requires a full 512-byte header block ("Unable to read").
        if !winfile::read_at(file, 0, &mut block).map_err(io_err)? {
            return Err(Error::Format(FormatError::StoreLayout));
        }
        let header = Header::parse(&block).map_err(Error::Format)?;
        Ok((header, block))
    }

    /// The validated header captured at open/create.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Acquires and holds the wsecret-writer mutex for the upcoming
    /// read-scan-modify-write critical section (spec §5.6 points 1-2); call
    /// [`Store::unlock_writers`] on the same thread when the section ends.
    /// Idempotent while already held. Mutations acquire it automatically
    /// when it is not held (then release at the end of their own write).
    ///
    /// Error contract (WS-03): [`Error::Busy`] only on contention (another
    /// wsecret writer currently holds the mutex); mutex creation/wait
    /// failures preserve their OS error in [`Error::Io`].
    pub fn lock_writers(&mut self) -> Result<MutexOutcome, Error> {
        if self.mutex.is_none() {
            let canonical = winfile::final_path(&self.file).map_err(io_err)?;
            self.mutex = Some(WriterMutex::acquire(&canonical)?);
        }
        Ok(self.mutex.as_ref().map(WriterMutex::outcome).unwrap())
    }

    /// Scoped form of [`Store::lock_writers`]: the returned guard releases the
    /// mutex on drop, including early returns and unwinds.
    pub fn lock_writers_scoped(&mut self) -> Result<WriterGuard<'_>, Error> {
        self.lock_writers()?;
        Ok(WriterGuard(self))
    }

    /// Releases the writer mutex held since [`Store::lock_writers`].
    pub fn unlock_writers(&mut self) {
        self.mutex = None;
    }

    /// Streaming enumeration (upstream `s_print_keys`): decrypts each 512-byte
    /// entry with the session key, skips records that fail authentication
    /// silently, and calls `on_name` once per surviving record name. `needle`
    /// filters by ASCII case-insensitive substring. The callback borrows the
    /// name bytes only for the duration of the call.
    pub fn scan_each(
        &mut self,
        s: &Session,
        needle: Option<&[u8]>,
        on_name: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.scan_each_at(s, needle, &mut |_, name, _| {
            on_name(name)?;
            Ok(true)
        })?;
        Ok(())
    }

    /// Slot-addressed streaming enumeration with early stop: like
    /// [`Store::scan_each`], but `on_record` receives the record's slot
    /// (byte offset) and tombstone flag and returns `Ok(false)` to stop the
    /// scan early. The outer result is `Ok(true)` when the scan stopped
    /// early (the caller's cap was hit) and `Ok(false)` when it ran to the
    /// end — the bounded metadata scan behind the Quick Access index.
    ///
    /// Same visibility rules as [`Store::scan_each`]: blocks that do not
    /// authenticate under the session are skipped silently (other
    /// passphrase partitions stay invisible); a decryptable record that
    /// fails structural validation aborts the scan with
    /// [`FormatError::MalformedRecord`] (upstream `s_keylen` fatal parity).
    pub fn scan_each_at(
        &mut self,
        s: &Session,
        needle: Option<&[u8]>,
        on_record: &mut dyn FnMut(u64, &[u8], bool) -> Result<bool, Error>,
    ) -> Result<bool, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self.scan_each_at_inner(s, needle, on_record, &mut payload);
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    fn scan_each_at_inner(
        &mut self,
        s: &Session,
        needle: Option<&[u8]>,
        on_record: &mut dyn FnMut(u64, &[u8], bool) -> Result<bool, Error>,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<bool, Error> {
        let mut block = [0u8; BLOCK];
        let mut offset = BLOCK as u64;
        // Fixed 512-byte read buffer; a short read is the tolerated trailing
        // partial block (spec §1.1) and ends the scan.
        while winfile::read_at(&self.file, offset, &mut block).map_err(io_err)? {
            if self.decrypt(s, &block, payload)? {
                // `Entry::decode` runs the full structural validation
                // (bounded NUL, `check_name`, slen bounds) — upstream
                // `s_keylen` fatals on poison names; we abort the scan the
                // same way (errors carry no record bytes).
                let entry = Entry::decode(payload).map_err(Error::from)?;
                if needle.is_none_or(|n| ascii_contains(entry.name, n)) {
                    if !on_record(offset, entry.name, is_tombstone(entry.name))? {
                        return Ok(true);
                    }
                }
            }
            offset += BLOCK as u64;
        }
        Ok(false)
    }

    /// Materialized enumeration: the names of every record decryptable with
    /// the session key, filtered by `needle` (ASCII case-insensitive
    /// substring when given). Tombstone names are listed like any other
    /// (upstream-visible quirk).
    pub fn scan(&mut self, s: &Session, needle: Option<&[u8]>) -> Result<Vec<Vec<u8>>, Error> {
        let mut names = Vec::new();
        self.scan_each(s, needle, &mut |name| {
            names.push(name.to_vec());
            Ok(())
        })?;
        Ok(names)
    }

    /// Slot-addressed metadata read (spec §3.5): decrypts ONLY the block at
    /// `slot` (a multiple of 512, >= 512) and projects its metadata. The
    /// record value never leaves the (zeroized) read buffer.
    ///
    /// - `Ok(Some(_))` — a record of this session occupies the slot;
    /// - `Ok(None)` — no record of this session is there: beyond EOF, a
    ///   trailing partial block, or a block that does not authenticate under
    ///   this key (a record of ANOTHER passphrase partition stays opaque and
    ///   unrevealed, exactly as in scans);
    /// - [`FormatError::StoreLayout`] — `slot` is not a record block offset;
    /// - [`FormatError::MalformedRecord`] — the block authenticated but
    ///   fails structural validation (upstream `s_keylen` fatal parity).
    ///
    /// The identity callers must key on is `slot` + exact `name` bytes:
    /// name-only lookup cannot distinguish duplicate names (upstream
    /// first-match shadowing), which is why slot-addressed reads exist.
    pub fn read_meta_at(&mut self, s: &Session, slot: u64) -> Result<Option<SlotMeta>, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self.read_slot(s, slot, &mut payload, |entry| {
            Ok(SlotMeta {
                slot,
                name: entry.name.to_vec(),
                tombstone: is_tombstone(entry.name),
            })
        });
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    /// Slot-addressed value read: [`Store::read_meta_at`] plus the record
    /// value materialized exactly once into a zeroizing [`SecretBytes`]
    /// owner. Same visibility rules — a foreign-partition slot yields
    /// `Ok(None)` and never reveals another partition's bytes. Broker/CLI
    /// code only: the value must never be relayed to an untrusted client.
    pub fn read_at(&mut self, s: &Session, slot: u64) -> Result<Option<SlotRecord>, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self.read_slot(s, slot, &mut payload, |entry| {
            Ok(SlotRecord {
                meta: SlotMeta {
                    slot,
                    name: entry.name.to_vec(),
                    tombstone: is_tombstone(entry.name),
                },
                value: SecretBytes::from_slice(entry.value)?,
            })
        });
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    /// Shared slot read behind [`Store::read_meta_at`] / [`Store::read_at`]:
    /// `on_found` projects the decrypted record while the read buffer is
    /// alive.
    fn read_slot<T>(
        &mut self,
        s: &Session,
        slot: u64,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        on_found: impl FnOnce(&Entry<'_>) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        if slot % BLOCK as u64 != 0 || slot < BLOCK as u64 {
            return Err(Error::Format(FormatError::StoreLayout));
        }
        let mut block = [0u8; BLOCK];
        // A short read is the tolerated trailing partial block (spec §1.1):
        // no complete record lives at this offset.
        if !winfile::read_at(&self.file, slot, &mut block).map_err(io_err)? {
            return Ok(None);
        }
        if !self.decrypt(s, &block, payload)? {
            // Not our partition (or a damaged block): opaque, never revealed.
            return Ok(None);
        }
        let entry = Entry::decode(payload).map_err(Error::from)?;
        Ok(Some(on_found(&entry)?))
    }

    /// First-match lookup (upstream `s_get_secret`): exact case-sensitive
    /// full-length match including the NUL terminator. With `create` true
    /// the scan also records the first decryptable `DELETED:`-prefixed record
    /// as the reusable tombstone slot, and an existing record with this name
    /// is an error (`Secret %s exists!`). `NotFound::decrypted_any` carries
    /// upstream `pass_ok` for the confirmation gate.
    ///
    /// The matched record's value is materialized exactly once, into a
    /// zeroizing [`SecretBytes`] owner. When only existence or the slot is
    /// needed, use [`Store::find_meta`] — there the value never leaves the
    /// scan buffer.
    pub fn find(&mut self, s: &Session, name: &[u8], create: bool) -> Result<ScanOutcome, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self
            .lookup(s, name, create, &mut payload, |slot, entry| {
                Ok(ScanOutcome::Found {
                    slot,
                    name: entry.name.to_vec(),
                    value: SecretBytes::from_slice(entry.value)?,
                })
            })
            .map(|hit| match hit {
                Lookup::Found(outcome) => outcome,
                Lookup::NotFound {
                    tombstone,
                    decrypted_any,
                } => ScanOutcome::NotFound {
                    tombstone,
                    decrypted_any,
                },
            });
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    /// Metadata-only first-match lookup: the same scan, matching and error
    /// semantics as [`Store::find`], but the record value is never copied
    /// out of the (zeroized) scan buffer. The right call for existence
    /// probes (`create` checks) and slot-only rewrites (renew).
    pub fn find_meta(&mut self, s: &Session, name: &[u8], create: bool) -> Result<ScanMeta, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self
            .lookup(s, name, create, &mut payload, |slot, entry| {
                Ok(ScanMeta::Found {
                    slot,
                    name: entry.name.to_vec(),
                })
            })
            .map(|hit| match hit {
                Lookup::Found(meta) => meta,
                Lookup::NotFound {
                    tombstone,
                    decrypted_any,
                } => ScanMeta::NotFound {
                    tombstone,
                    decrypted_any,
                },
            });
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    /// Shared first-match scan (upstream `s_get_secret`) behind
    /// [`Store::find`] and [`Store::find_meta`]: `on_found` projects the
    /// matched record while the decrypted payload is alive, so each caller
    /// copies out exactly what it needs and nothing else.
    fn lookup<T>(
        &mut self,
        s: &Session,
        name: &[u8],
        create: bool,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        on_found: impl FnOnce(u64, &Entry<'_>) -> Result<T, Error>,
    ) -> Result<Lookup<T>, Error> {
        check_name(name)?;
        let len = name.len();
        let mut block = [0u8; BLOCK];
        let mut tombstone: Option<u64> = None;
        let mut decrypted_any = false;
        let mut offset = BLOCK as u64;
        while winfile::read_at(&self.file, offset, &mut block).map_err(io_err)? {
            if self.decrypt(s, &block, payload)? {
                // Upstream-exact matching over the raw record (plan §1.8):
                // the tombstone capture is a raw 8-byte prefix compare and
                // the match compares `name NUL` including the terminator
                // (upstream `hydro_equal(data, key, len + 1)`), so a record
                // that fails structural validation is neither a match nor a
                // scan abort here (upstream `s_get_secret` scans past it;
                // only the exact-match arm fatals "Invalid secret" and runs
                // `s_keylen`). `Entry::decode` reproduces both checks below
                // without exposing partial record bytes.
                let data: &[u8] = &payload[2..2 + ENTRY_DATA_LEN];
                if create && tombstone.is_none() && data.starts_with(b"DELETED:") {
                    tombstone = Some(offset);
                }
                let matched = data.len() >= len + 1 && &data[..len] == name && data[len] == 0;
                if matched {
                    if create {
                        return Err(Error::Name(NameError::Exists));
                    }
                    let entry = Entry::decode(payload).map_err(Error::from)?;
                    return Ok(Lookup::Found(on_found(offset, &entry)?));
                }
                decrypted_any = true;
            }
            offset += BLOCK as u64;
        }
        Ok(Lookup::NotFound {
            tombstone: if create { tombstone } else { None },
            decrypted_any,
        })
    }

    /// In-place 512-byte slot write (spec §5.6 point 3): replaces the record
    /// block at `slot` (byte offset, multiple of 512, >= 512) under the writer
    /// mutex and a `LockFileEx` exclusive non-blocking lock, then flushes.
    pub fn write_slot(
        &mut self,
        slot: u64,
        s: &Session,
        name: &[u8],
        value: &[u8],
    ) -> CommitOutcome<CommitReceipt> {
        self.mutate(slot, s, name, value)
    }

    /// Writes the record at the first tombstone `slot` when given, otherwise
    /// appends at EOF. Same write protocol as [`Store::write_slot`].
    pub fn append_or_reuse(
        &mut self,
        slot: Option<u64>,
        s: &Session,
        name: &[u8],
        value: &[u8],
    ) -> CommitOutcome<CommitReceipt> {
        let offset = match slot {
            Some(slot) => slot,
            None => winfile::file_len(&self.file)?,
        };
        self.mutate(offset, s, name, value)
    }

    /// Content compare-and-set write at `slot` (spec §5.6 write protocol
    /// with a CAS gate): under the writer mutex and after §5.6 6b
    /// revalidation, the record currently occupying `slot` must be exactly
    /// `expect_name` and — when `expect_value` is given — its value must
    /// match (constant-time). Only then are `new_name`/`new_value` written
    /// in place: EXACTLY 512 bytes, one block, so other records and other
    /// passphrase partitions are never read or rewritten. Every mismatch is
    /// reported before write initiation with the store byte-unchanged
    /// ([`CasFailure::Mismatch`]); the write path keeps the §5.6 point 5
    /// [`CommitState`] trichotomy unchanged ([`CasFailure::Write`]).
    ///
    /// Mutations take the writer mutex automatically when the caller has
    /// not already held it via [`Store::lock_writers`] — hold it across the
    /// projection read + [`Store::cas_slot`] to span one critical section.
    pub fn cas_slot(
        &mut self,
        slot: u64,
        s: &Session,
        expect_name: &[u8],
        expect_value: Option<&[u8]>,
        new_name: &[u8],
        new_value: &[u8],
    ) -> Result<CommitReceipt, CasFailure> {
        let mut payload = build_entry_payload(new_name, new_value)
            .map_err(|e| CasFailure::Write(CommitFailure::from(e)))?;
        // §5.6 point 5 / §6 panic boundary (as `mutate`): a contained panic
        // is reported as `(Error::Panic, phase)` — or, past checkpoint (iii),
        // as the committed receipt plus warning bit 0.
        let phase = Cell::new(CommitState::NotCommitted);
        let warnings = Cell::new(0u32);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cas_inner(
                slot,
                s,
                expect_name,
                expect_value,
                &mut payload,
                &phase,
                &warnings,
            )
        }));
        libhydrogen_sys::memzero(&mut payload);
        match result {
            Ok(outcome) => outcome,
            Err(_) if phase.get() == CommitState::Committed => {
                Ok(CommitReceipt::new(CommitState::Committed)
                    .with_warning(warnings.get() | WARN_POST_COMMIT_PANIC))
            }
            Err(_) => Err(CasFailure::Write(CommitFailure::new(
                Error::Panic,
                phase.get(),
            ))),
        }
    }

    fn cas_inner(
        &mut self,
        slot: u64,
        s: &Session,
        expect_name: &[u8],
        expect_value: Option<&[u8]>,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        phase: &Cell<CommitState>,
        warnings: &Cell<u32>,
    ) -> Result<CommitReceipt, CasFailure> {
        // wsecret-writer serialization (spec §5.6 points 1-2): held across
        // the compare AND the write (the mutex ACL/effective-permission
        // validation runs inside `WriterMutex::acquire`, before any write).
        let acquired_here = self.mutex.is_none();
        if acquired_here {
            let canonical = winfile::final_path(&self.file)
                .map_err(|e| CasFailure::Write(CommitFailure::from(e)))?;
            self.mutex = Some(
                WriterMutex::acquire(&canonical)
                    .map_err(|e| CasFailure::Write(CommitFailure::before_write(e)))?,
            );
        }
        if self.mutex.as_ref().is_some_and(|m| m.abandoned) {
            warnings.set(warnings.get() | WARN_ABANDONED_MUTEX);
        }
        let result =
            self.cas_locked(slot, s, expect_name, expect_value, payload, phase, warnings);
        self.release_if(acquired_here);
        result
    }

    /// The CAS critical section with the writer mutex held: §5.6 6b
    /// revalidation, in-place shape checks, content compare, encrypt, write.
    fn cas_locked(
        &mut self,
        slot: u64,
        s: &Session,
        expect_name: &[u8],
        expect_value: Option<&[u8]>,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        phase: &Cell<CommitState>,
        warnings: &Cell<u32>,
    ) -> Result<CommitReceipt, CasFailure> {
        self.revalidate().map_err(CasFailure::Write)?;

        // In-place shape rules (spec §3.5): the store length must be a
        // multiple of 512 (stricter rejection of I/O-damaged input) and the
        // target must be a complete record slot in [512, len] — a
        // compare-and-set never appends. All rejections are pre-write.
        let len = winfile::file_len(&self.file)
            .map_err(|e| CasFailure::Write(CommitFailure::from(e)))?;
        if len % BLOCK as u64 != 0
            || len < BLOCK as u64
            || slot % BLOCK as u64 != 0
            || slot < BLOCK as u64
            || slot + BLOCK as u64 > len
        {
            return Err(CasFailure::Write(CommitFailure::before_write(
                Error::Format(FormatError::StoreLayout),
            )));
        }

        // Content CAS under the mutex (the read gap closes here).
        let mut current = [0u8; ENTRY_PLAIN_LEN];
        let compare = self.cas_compare(s, slot, expect_name, expect_value, &mut current);
        libhydrogen_sys::memzero(&mut current);
        compare?;

        let mut block = [0u8; BLOCK];
        s.with_key(|key| {
            libhydrogen_sys::secretbox_encrypt(
                &mut block,
                payload,
                &libhydrogen_sys::CTX_SECRET,
                key,
            );
        })
        .map_err(|e| CasFailure::Write(CommitFailure::before_write(e)))?;

        self.write_block(slot, &block, phase, warnings)
            .map_err(CasFailure::Write)
    }

    /// The content-compare half of the CAS: reads and decrypts ONLY the
    /// target block (the caller zeroizes `current`) and checks the name
    /// (exact bytes) and the optional value (constant-time). A block that no
    /// longer holds a record of this session reports `found: None`.
    fn cas_compare(
        &self,
        s: &Session,
        slot: u64,
        expect_name: &[u8],
        expect_value: Option<&[u8]>,
        current: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<(), CasFailure> {
        let mut block = [0u8; BLOCK];
        let occupied = if winfile::read_at(&self.file, slot, &mut block)
            .map_err(|e| CasFailure::Write(CommitFailure::from(e)))?
            && self
                .decrypt(s, &block, current)
                .map_err(|e| CasFailure::Write(CommitFailure::before_write(e)))?
        {
            let entry = Entry::decode(current)
                .map_err(|f| CasFailure::Write(CommitFailure::before_write(Error::from(f))))?;
            let meta = SlotMeta {
                slot,
                name: entry.name.to_vec(),
                tombstone: is_tombstone(entry.name),
            };
            if entry.name != expect_name {
                return Err(CasFailure::Mismatch(CasMismatch {
                    found: Some(meta),
                    value_changed: false,
                }));
            }
            if let Some(expected) = expect_value {
                if !libhydrogen_sys::equal(entry.value, expected) {
                    return Err(CasFailure::Mismatch(CasMismatch {
                        found: Some(meta),
                        value_changed: true,
                    }));
                }
            }
            true
        } else {
            false
        };
        if !occupied {
            return Err(CasFailure::Mismatch(CasMismatch {
                found: None,
                value_changed: false,
            }));
        }
        Ok(())
    }

    fn mutate(
        &mut self,
        offset: u64,
        s: &Session,
        name: &[u8],
        value: &[u8],
    ) -> CommitOutcome<CommitReceipt> {
        let mut payload = build_entry_payload(name, value)?;
        // §5.6 point 5 / §6 panic boundary: a contained panic is reported as
        // `(Error::Panic, phase)` — or, past checkpoint (iii), as the
        // committed receipt plus warning bit 0 (the mutation is durable;
        // reporting `PANIC` for it would misdirect a retry).
        let phase = Cell::new(CommitState::NotCommitted);
        let warnings = Cell::new(0u32);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.mutate_inner(offset, s, &mut payload, &phase, &warnings)
        }));
        libhydrogen_sys::memzero(&mut payload);
        match result {
            Ok(outcome) => outcome,
            Err(_) if phase.get() == CommitState::Committed => {
                Ok(CommitReceipt::new(CommitState::Committed)
                    .with_warning(warnings.get() | WARN_POST_COMMIT_PANIC))
            }
            Err(_) => Err(CommitFailure::new(Error::Panic, phase.get())),
        }
    }

    fn mutate_inner(
        &mut self,
        offset: u64,
        s: &Session,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        phase: &Cell<CommitState>,
        warnings: &Cell<u32>,
    ) -> CommitOutcome<CommitReceipt> {
        // wsecret-writer serialization (spec §5.6 points 1-2): held across
        // the whole read-scan-modify-write critical section; acquired here
        // only when the caller has not already held it via `lock_writers`.
        let acquired_here = self.mutex.is_none();
        if acquired_here {
            let canonical = winfile::final_path(&self.file).map_err(CommitFailure::from)?;
            self.mutex =
                Some(WriterMutex::acquire(&canonical).map_err(CommitFailure::before_write)?);
        }
        if self.mutex.as_ref().is_some_and(|m| m.abandoned) {
            warnings.set(warnings.get() | WARN_ABANDONED_MUTEX);
        }
        let result = self.mutate_locked(offset, s, payload, phase, warnings);
        self.release_if(acquired_here);
        result
    }

    /// The modify phase with the writer mutex held: §5.6 6b revalidation,
    /// shape checks, encrypt, write.
    fn mutate_locked(
        &mut self,
        offset: u64,
        s: &Session,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
        phase: &Cell<CommitState>,
        warnings: &Cell<u32>,
    ) -> CommitOutcome<CommitReceipt> {
        // §5.6 6b revalidation FIRST: a store whose pathname was rebound
        // (deletion+recreation, rename-swap) or whose header was rewritten
        // fails with `Conflict` and is invalidated — before any shape check
        // or write trusts the file.
        self.revalidate()?;

        // Mutation shape rules (spec §3.5): the store length must be a
        // multiple of 512 (stricter rejection of I/O-damaged input); the
        // target must be a complete record slot in [512, len], or exactly
        // len for an append. All rejections are pre-write: the store is
        // unchanged (plan §5.6 point 5).
        let len = winfile::file_len(&self.file)?;
        if len % BLOCK as u64 != 0 || len < BLOCK as u64 {
            return Err(CommitFailure::before_write(Error::Format(
                FormatError::StoreLayout,
            )));
        }
        let append = offset == len;
        if !append
            && (offset % BLOCK as u64 != 0 || offset < BLOCK as u64 || offset + BLOCK as u64 > len)
        {
            return Err(CommitFailure::before_write(Error::Format(
                FormatError::StoreLayout,
            )));
        }

        let mut block = [0u8; BLOCK];
        s.with_key(|key| {
            libhydrogen_sys::secretbox_encrypt(
                &mut block,
                payload,
                &libhydrogen_sys::CTX_SECRET,
                key,
            );
        })
        .map_err(CommitFailure::before_write)?;

        self.write_block(offset, &block, phase, warnings)
    }

    /// The §5.6 point 3-5 write protocol over one prepared 512-byte block:
    /// range lock → exactly 512 bytes in place → flush, with the checkpoint
    /// trichotomy of point 5.
    fn write_block(
        &mut self,
        offset: u64,
        block: &[u8; BLOCK],
        phase: &Cell<CommitState>,
        warnings: &Cell<u32>,
    ) -> CommitOutcome<CommitReceipt> {
        // Lock the target 512-byte region (upstream F_SETLK over one record).
        // A lock failure is always before checkpoint (i) — the store is
        // unchanged; `Error::Locked` pairs with `NotCommitted` (plan §5.6
        // point 5). The upstream catalog string `Unable to lock <path>` is
        // rendered by the CLI layer (see `Error::Locked`).
        if let Err(e) = winfile::lock_range(&self.file, offset, BLOCK as u64) {
            return Err(if winfile::is_lock_violation(&e) {
                CommitFailure::before_write(Error::Locked)
            } else {
                CommitFailure::before_write(Error::Io(e))
            });
        }
        // Released on every exit path, including a contained-panic unwind.
        let _range = RangeLock {
            file: &self.file,
            offset,
        };

        (|| {
            // Checkpoint (i) write initiation: everything from here to the
            // flush is the `Unknown` band of plan §5.6 point 5.
            seam_before_write()?;
            phase.set(CommitState::Unknown);
            // Checkpoints (i)→(ii): exactly 512 bytes in place. A failed or
            // short write after initiation may have left partial effects —
            // `Unknown` (plan §5.6 point 5).
            let n = seam_write(&self.file, offset, block)?;
            if n != BLOCK {
                return Err(short_write(n));
            }
            // Checkpoints (ii)→(iii): flush failure (including a zero
            // return from `FlushFileBuffers`) is `Unknown`.
            seam_after_write()?;
            if !winfile::flush(&self.file) {
                return Err(flush_failed());
            }
            // Checkpoint (iii) passed: the mutation IS committed.
            phase.set(CommitState::Committed);
            warnings.set(warnings.get() | seam_post_commit());
            Ok(CommitReceipt::new(CommitState::Committed).with_warning(warnings.get()))
        })()
    }

    fn release_if(&mut self, acquired_here: bool) {
        if acquired_here {
            self.mutex = None;
        }
    }

    fn decrypt(
        &self,
        s: &Session,
        block: &[u8; BLOCK],
        payload: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<bool, Error> {
        // The transient key exists only inside the closure (key-at-rest).
        s.with_key(|key| {
            libhydrogen_sys::secretbox_decrypt(payload, block, &libhydrogen_sys::CTX_SECRET, key)
        })
    }
}

fn map_open_err(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        Error::StoreNotFound
    } else {
        io_err(e)
    }
}

/// ASCII case-insensitive substring test (spec §4: wsecret folds case with
/// ASCII rules, unlike upstream's locale-dependent `strcasestr`).
fn ascii_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NameError;
    use crate::format::{OPS_LIMIT_DEFAULT, VERSION};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wsecret-store-test-{}-{}-{tag}.secret",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    const KEY: [u8; 32] = [7u8; 32];
    const FOREIGN_KEY: [u8; 32] = [9u8; 32];

    fn test_header() -> Header {
        Header {
            version: VERSION.0,
            master: [0x2a; 32],
            ops_limit: OPS_LIMIT_DEFAULT,
        }
    }

    fn session() -> Session {
        Session::from_parts(test_header(), KEY).unwrap()
    }

    fn entry_block(name: &[u8], value: &[u8]) -> [u8; BLOCK] {
        entry_block_with(&KEY, name, value)
    }

    fn entry_block_with(key: &[u8; 32], name: &[u8], value: &[u8]) -> [u8; BLOCK] {
        let payload = build_entry_payload(name, value).unwrap();
        let mut block = [0u8; BLOCK];
        libhydrogen_sys::secretbox_encrypt(&mut block, &payload, &libhydrogen_sys::CTX_SECRET, key);
        block
    }

    /// Builds a store file the way an upstream writer would have left it.
    fn fixture(path: &Path, entries: &[[u8; BLOCK]], tail: &[u8]) {
        let header = Header {
            version: VERSION.0,
            master: [0x2a; 32],
            ops_limit: OPS_LIMIT_DEFAULT,
        };
        let mut bytes = Header::encode_init(header.master, header.ops_limit).to_vec();
        for e in entries {
            bytes.extend_from_slice(e);
        }
        bytes.extend_from_slice(tail);
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn create_open_round_trip() {
        let path = temp_path("roundtrip");
        let (store, header, receipt) = Store::create(&path, OPS_LIMIT_DEFAULT).unwrap();
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.warnings, 0);
        assert_eq!(header.version, VERSION.0);
        assert_eq!(header.ops_limit, OPS_LIMIT_DEFAULT);
        assert_eq!(store.header(), &header);
        drop(store);

        let (store2, header2) = Store::open(&path).unwrap();
        assert_eq!(header2, header);
        drop(store2);

        // Exclusive creation: a second create while the file exists fails
        // with StoreExists.
        let err = match Store::create(&path, OPS_LIMIT_DEFAULT) {
            Err(e) => e,
            Ok(_) => panic!("second create must fail"),
        };
        assert!(matches!(
            err,
            CommitFailure {
                error: Error::StoreExists,
                state: CommitState::NotCommitted
            }
        ));
        std::fs::remove_file(&path).unwrap();

        // Missing store and out-of-floor opslimit.
        let missing = temp_path("missing");
        assert!(matches!(Store::open(&missing), Err(Error::StoreNotFound)));
        assert!(matches!(
            Store::create(&temp_path("floor"), OPS_LIMIT_MIN - 1),
            Err(CommitFailure {
                error: Error::Format(FormatError::OpsLimitTooLow(_)),
                state: CommitState::NotCommitted
            })
        ));
    }

    #[test]
    fn open_validates_header() {
        // Too short for a header block.
        let path = temp_path("short");
        std::fs::write(&path, [0u8; 100]).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(Error::Format(FormatError::StoreLayout))
        ));
        std::fs::remove_file(&path).unwrap();

        // Bad version byte (upstream "Unkown version 1").
        let path = temp_path("version");
        let mut block = [0u8; BLOCK];
        block[0] = 1;
        std::fs::write(&path, block).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(Error::Format(FormatError::UnsupportedVersion(1)))
        ));
        std::fs::remove_file(&path).unwrap();

        // opslimit below the 10000 floor.
        let path = temp_path("ops");
        let mut block = [0u8; BLOCK];
        block[33] = 0xff; // LE 255 < 10000
        std::fs::write(&path, block).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(Error::Format(FormatError::OpsLimitTooLow(255)))
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn scan_and_find_fixture_entries() {
        let path = temp_path("scanfind");
        fixture(
            &path,
            &[
                entry_block(b"alpha", b"one"),
                // Decryptable only with FOREIGN_KEY: skipped silently.
                entry_block_with(&FOREIGN_KEY, b"foreign", b"secret"),
                entry_block(b"beta", b"two"),
            ],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        // Undecryptable records are skipped silently.
        assert_eq!(
            store.scan(&s, None).unwrap(),
            vec![b"alpha".to_vec(), b"beta".to_vec()]
        );
        // ASCII case-insensitive substring filter.
        assert_eq!(
            store.scan(&s, Some(b"ALP")).unwrap(),
            vec![b"alpha".to_vec()]
        );
        assert_eq!(store.scan(&s, Some(b"TA")).unwrap(), vec![b"beta".to_vec()]);
        assert!(store.scan(&s, Some(b"foreign")).unwrap().is_empty());

        // Exact case-sensitive full-length match (including the NUL).
        match store.find(&s, b"beta", false).unwrap() {
            ScanOutcome::Found { slot, name, value } => {
                assert_eq!(slot, 3 * BLOCK as u64);
                assert_eq!(name, b"beta");
                assert_eq!(value.as_slice(), b"two");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        // Prefixes and case variants do not match.
        assert!(matches!(
            store.find(&s, b"bet", false),
            Ok(ScanOutcome::NotFound { .. })
        ));
        assert!(matches!(
            store.find(&s, b"BETA", false),
            Ok(ScanOutcome::NotFound { .. })
        ));
        // Missing name: pass_ok (decrypted_any) is set, no tombstone.
        assert!(matches!(
            store.find(&s, b"missing", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: true,
            }
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn find_reports_empty_partition_and_tombstone() {
        let path = temp_path("passok");
        fixture(&path, &[], &[]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();
        // Nothing decryptable: confirmation gate sees decrypted_any == false.
        assert!(matches!(
            store.find(&s, b"x", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: false,
            }
        ));
        std::fs::remove_file(&path).unwrap();

        // create=true tracks the FIRST tombstone only; create=false ignores
        // tombstones entirely.
        let path = temp_path("tomb");
        fixture(
            &path,
            &[
                entry_block(b"DELETED:one", b"x"),
                entry_block(b"keep", b"k"),
                entry_block(b"DELETED:two", b"y"),
            ],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        assert!(matches!(
            store.find(&s, b"fresh", true).unwrap(),
            ScanOutcome::NotFound {
                tombstone: Some(offset),
                decrypted_any: true,
            } if offset == BLOCK as u64
        ));
        assert!(matches!(
            store.find(&s, b"fresh", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: true,
            }
        ));
        // create=true with the name already present: upstream "Secret %s
        // exists!".
        assert!(matches!(
            store.find(&s, b"keep", true),
            Err(Error::Name(NameError::Exists))
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn tombstone_reuse_writes_in_place() {
        let path = temp_path("reuse");
        fixture(
            &path,
            &[
                entry_block(b"DELETED:old", b"x"),
                entry_block(b"keep", b"k"),
            ],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();
        let before = std::fs::read(&path).unwrap();

        let tombstone = match store.find(&s, b"fresh", true).unwrap() {
            ScanOutcome::NotFound { tombstone, .. } => tombstone.unwrap(),
            other => panic!("expected NotFound, got {other:?}"),
        };
        assert_eq!(tombstone, BLOCK as u64);
        let receipt = store
            .append_or_reuse(Some(tombstone), &s, b"fresh", b"v")
            .unwrap();
        assert_eq!(
            receipt,
            CommitReceipt {
                state: CommitState::Committed,
                warnings: 0
            }
        );

        // File length unchanged; the reused slot holds the new record; the
        // neighbouring record is byte-identical.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(
            &after[2 * BLOCK..],
            &before[2 * BLOCK..],
            "non-selected blocks must be preserved byte-for-byte"
        );
        match store.find(&s, b"fresh", false).unwrap() {
            ScanOutcome::Found { slot, value, .. } => {
                assert_eq!(slot, tombstone);
                assert_eq!(value.as_slice(), b"v");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        assert!(matches!(
            store.find(&s, b"DELETED:old", false),
            Ok(ScanOutcome::NotFound { .. })
        ));
        match store.find(&s, b"keep", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value.as_slice(), b"k"),
            other => panic!("expected Found, got {other:?}"),
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_slot_overwrites_in_place() {
        let path = temp_path("overwrite");
        fixture(
            &path,
            &[entry_block(b"alpha", b"one"), entry_block(b"beta", b"two")],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();
        let before = std::fs::read(&path).unwrap();

        let receipt = store
            .write_slot(BLOCK as u64, &s, b"alpha", b"changed")
            .unwrap();
        assert_eq!(receipt.state, CommitState::Committed);

        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.len(),
            before.len(),
            "overwrite must not grow the file"
        );
        assert_eq!(
            &after[2 * BLOCK..],
            &before[2 * BLOCK..],
            "the untouched slot must be byte-identical"
        );
        match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value.as_slice(), b"changed"),
            other => panic!("expected Found, got {other:?}"),
        }
        match store.find(&s, b"beta", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value.as_slice(), b"two"),
            other => panic!("expected Found, got {other:?}"),
        }

        // Slot rules: the header block, misaligned slots and slots past EOF
        // are all rejected before any write.
        for bad in [0u64, 1, BLOCK as u64 + 1, 10 * BLOCK as u64] {
            assert!(
                matches!(
                    store.write_slot(bad, &s, b"alpha", b"z"),
                    Err(CommitFailure {
                        error: Error::Format(FormatError::StoreLayout),
                        state: CommitState::NotCommitted
                    })
                ),
                "slot {bad} must be rejected"
            );
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn append_at_eof() {
        let path = temp_path("append");
        fixture(&path, &[entry_block(b"alpha", b"one")], &[]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        let receipt = store.append_or_reuse(None, &s, b"new", b"val").unwrap();
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(std::fs::read(&path).unwrap().len(), 3 * BLOCK);

        match store.find(&s, b"new", false).unwrap() {
            ScanOutcome::Found { slot, value, .. } => {
                assert_eq!(slot, 2 * BLOCK as u64);
                assert_eq!(value.as_slice(), b"val");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value.as_slice(), b"one"),
            other => panic!("expected Found, got {other:?}"),
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn trailing_partial_block_tolerated_on_read() {
        let path = temp_path("partial");
        // Upstream can leave a short suffix; readers ignore it (spec §1.1).
        fixture(&path, &[entry_block(b"alpha", b"one")], &[0xbb; 100]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        assert_eq!(store.scan(&s, None).unwrap(), vec![b"alpha".to_vec()]);
        assert!(matches!(
            store.find(&s, b"alpha", false),
            Ok(ScanOutcome::Found { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn mutation_rejects_unaligned_store_length() {
        let path = temp_path("damaged");
        fixture(&path, &[entry_block(b"alpha", b"one")], &[0xcc; 3]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        // Reads still work (tolerated trailing partial block)...
        assert_eq!(store.scan(&s, None).unwrap(), vec![b"alpha".to_vec()]);
        // ...but every mutation rejects the non-512-multiple length
        // (spec §3.5, strict rejection of I/O-damaged input).
        assert!(matches!(
            store.write_slot(BLOCK as u64, &s, b"alpha", b"x"),
            Err(CommitFailure {
                error: Error::Format(FormatError::StoreLayout),
                state: CommitState::NotCommitted
            })
        ));
        assert!(matches!(
            store.append_or_reuse(None, &s, b"new", b"x"),
            Err(CommitFailure {
                error: Error::Format(FormatError::StoreLayout),
                state: CommitState::NotCommitted
            })
        ));
        assert!(matches!(
            store.append_or_reuse(Some(BLOCK as u64), &s, b"new", b"x"),
            Err(CommitFailure {
                error: Error::Format(FormatError::StoreLayout),
                state: CommitState::NotCommitted
            })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_with_limits_enforces_the_caps() {
        let path = temp_path("limits");
        fixture(&path, &[entry_block(b"alpha", b"one")], &[]);

        // The fixture header runs at OPS_LIMIT_DEFAULT (100000), well under
        // the default policy ceiling: ordinary opens accept it.
        assert!(Store::open_with_limits(&path, Limits::default()).is_ok());
        assert!(Store::open_read_with_limits(&path, Limits::default()).is_ok());

        // Explicit caps: just below rejects with the full diagnosis, exactly
        // at the cap passes.
        let under = Limits {
            max_opslimit: Some(OPS_LIMIT_DEFAULT - 1),
            max_store_bytes: None,
        };
        let err = match Store::open_with_limits(&path, under) {
            Err(err) => err,
            Ok(_) => panic!("under the cap must reject"),
        };
        let diagnosis = match err {
            Error::ResourceLimit(diagnosis) => diagnosis,
            other => panic!("want ResourceLimit, got {other:?}"),
        };
        assert_eq!(
            diagnosis,
            LimitExceeded {
                kind: LimitKind::OpsLimit,
                actual: OPS_LIMIT_DEFAULT,
                limit: OPS_LIMIT_DEFAULT - 1,
                remedy: LimitRemedy::AllowExpensiveKdf,
            }
        );
        let exact = Limits {
            max_opslimit: Some(OPS_LIMIT_DEFAULT),
            max_store_bytes: None,
        };
        assert!(Store::open_with_limits(&path, exact).is_ok());

        // Store-size cap, same boundary semantics (read-only open too).
        let len = std::fs::metadata(&path).unwrap().len();
        let over = Limits {
            max_opslimit: None,
            max_store_bytes: Some(len - 1),
        };
        let err = match Store::open_read_with_limits(&path, over) {
            Err(err) => err,
            Ok(_) => panic!("over the size cap must reject"),
        };
        let diagnosis = match err {
            Error::ResourceLimit(diagnosis) => diagnosis,
            other => panic!("want ResourceLimit, got {other:?}"),
        };
        assert_eq!(
            diagnosis,
            LimitExceeded {
                kind: LimitKind::StoreBytes,
                actual: len,
                limit: len - 1,
                remedy: LimitRemedy::TrustedFileOverride,
            }
        );
        let fit = Limits {
            max_opslimit: None,
            max_store_bytes: Some(len),
        };
        assert!(Store::open_read_with_limits(&path, fit).is_ok());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn default_policy_caps_opslimit_at_one_million() {
        // Boundary: the ceiling itself is accepted by an ordinary open.
        let at = temp_path("limits-max-at");
        std::fs::write(&at, Header::encode_init([0x2a; 32], OPS_LIMIT_MAX)).unwrap();
        assert!(Store::open(&at).is_ok());
        assert!(Store::open_read(&at).is_ok());

        // One step above the ceiling rejects before any KDF execution (the
        // open never derives) with the full diagnosis.
        let over = temp_path("limits-max-over");
        std::fs::write(&over, Header::encode_init([0x2a; 32], OPS_LIMIT_MAX + 1)).unwrap();
        for result in [Store::open(&over), Store::open_read(&over)] {
            let err = match result {
                Err(err) => err,
                Ok(_) => panic!("above the default ceiling must reject"),
            };
            let diagnosis = match err {
                Error::ResourceLimit(diagnosis) => diagnosis,
                other => panic!("want ResourceLimit, got {other:?}"),
            };
            assert_eq!(
                diagnosis,
                LimitExceeded {
                    kind: LimitKind::OpsLimit,
                    actual: OPS_LIMIT_MAX + 1,
                    limit: OPS_LIMIT_MAX,
                    remedy: LimitRemedy::AllowExpensiveKdf,
                }
            );
        }

        // The explicit override opens the same store; nothing is derived at
        // open time, so acceptance here is proof the override is honored
        // without expensive computation.
        let (store, header) = Store::open_with_limits(&over, Limits::allow_expensive_kdf())
            .expect("explicit override opens the above-ceiling store");
        assert_eq!(header.ops_limit, OPS_LIMIT_MAX + 1);
        assert_eq!(store.header(), &header);

        // "normal minimum still applies": the override lifts only the
        // ceiling — the format floor is still enforced at open.
        let floor = temp_path("limits-floor");
        std::fs::write(&floor, Header::encode_init([0x2a; 32], OPS_LIMIT_MIN - 1)).unwrap();
        assert!(matches!(
            Store::open_with_limits(&floor, Limits::allow_expensive_kdf()),
            Err(Error::Format(FormatError::OpsLimitTooLow(9999)))
        ));
        std::fs::remove_file(&at).unwrap();
        std::fs::remove_file(&over).unwrap();
        std::fs::remove_file(&floor).unwrap();
    }

    #[test]
    fn check_opslimit_is_the_shared_ceiling_gate() {
        // Default policy: the ceiling is exactly OPS_LIMIT_MAX.
        assert!(Limits::default().check_opslimit(OPS_LIMIT_MAX).is_ok());
        let err = Limits::default()
            .check_opslimit(OPS_LIMIT_MAX + 1)
            .expect_err("above the ceiling");
        // Full diagnosis: limit exceeded, numerical bound, explicit remedy.
        let diagnosis = match err {
            Error::ResourceLimit(diagnosis) => diagnosis,
            other => panic!("want ResourceLimit, got {other:?}"),
        };
        assert_eq!(diagnosis.kind, LimitKind::OpsLimit);
        assert_eq!(diagnosis.actual, OPS_LIMIT_MAX + 1);
        assert_eq!(diagnosis.limit, OPS_LIMIT_MAX);
        assert_eq!(diagnosis.remedy, LimitRemedy::AllowExpensiveKdf);

        // The override constructor lifts the ceiling only.
        let override_policy = Limits::allow_expensive_kdf();
        assert_eq!(override_policy.max_opslimit, None);
        assert_eq!(
            override_policy.max_store_bytes,
            Limits::default().max_store_bytes
        );
        assert!(override_policy.check_opslimit(u64::MAX).is_ok());
    }

    #[test]
    fn open_with_limits_reports_format_errors_before_the_caps() {
        // Inspection first (plan §3.4 enforcement order): a short store is a
        // format error even when every cap is exceeded.
        let path = temp_path("limits-order");
        std::fs::write(&path, [0u8; 100]).unwrap();
        let caps = Limits {
            max_opslimit: Some(0),
            max_store_bytes: Some(0),
        };
        assert!(matches!(
            Store::open_with_limits(&path, caps),
            Err(Error::Format(FormatError::StoreLayout))
        ));
        std::fs::remove_file(&path).unwrap();

        // A bad version byte wins over an exceeded ops cap.
        let path = temp_path("limits-order2");
        let mut block = [0u8; BLOCK];
        block[0] = 1;
        block[33..41].copy_from_slice(&OPS_LIMIT_DEFAULT.to_le_bytes());
        std::fs::write(&path, block).unwrap();
        assert!(matches!(
            Store::open_with_limits(&path, caps),
            Err(Error::Format(FormatError::UnsupportedVersion(1)))
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn second_writer_gets_busy() {
        let path = temp_path("busy");
        let (mut holder, _, _) = Store::create(&path, OPS_LIMIT_DEFAULT).unwrap();

        // Main thread holds the writer mutex across the critical section.
        let outcome = holder.lock_writers().unwrap();
        assert_eq!(outcome, MutexOutcome::Acquired);

        // Another thread's mutation must fail immediately with Busy. The
        // competing store is opened INSIDE the thread (Store/WriterMutex are
        // thread-ownership-bound: Windows mutexes release on the owner
        // thread only).
        let path2 = path.clone();
        let result = std::thread::spawn(move || {
            let (mut writer, _) = Store::open(&path2).unwrap();
            let s = Session::from_parts(test_header(), KEY).unwrap();
            writer.append_or_reuse(None, &s, b"k", b"v")
        })
        .join()
        .unwrap();
        assert!(matches!(
            result,
            Err(CommitFailure {
                error: Error::Busy,
                state: CommitState::NotCommitted
            })
        ));

        // After release the same mutation succeeds.
        holder.unlock_writers();
        let path2 = path.clone();
        let result = std::thread::spawn(move || {
            let (mut writer, _) = Store::open(&path2).unwrap();
            let s = Session::from_parts(test_header(), KEY).unwrap();
            writer.append_or_reuse(None, &s, b"k", b"v")
        })
        .join()
        .unwrap();
        assert!(matches!(
            result,
            Ok(CommitReceipt {
                state: CommitState::Committed,
                ..
            })
        ));
        drop(holder);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn names_and_values_are_validated_like_upstream() {
        let path = temp_path("valid");
        let (mut store, _, _) = Store::create(&path, OPS_LIMIT_DEFAULT).unwrap();
        let s = session();

        assert!(matches!(
            store.append_or_reuse(None, &s, b"", b"v"),
            Err(CommitFailure {
                error: Error::Name(NameError::Empty),
                state: CommitState::NotCommitted
            })
        ));
        assert!(matches!(
            store.append_or_reuse(None, &s, b"has space", b"v"),
            Err(CommitFailure {
                error: Error::Name(NameError::SpecialChar),
                state: CommitState::NotCommitted
            })
        ));
        // 255-byte name + value 218 fits; 219 does not (upstream
        // "Entry too big!").
        let name = [b'n'; 255];
        assert!(matches!(
            store.append_or_reuse(None, &s, &name, &[0u8; 219]),
            Err(CommitFailure {
                error: Error::Format(FormatError::EntryTooBig),
                state: CommitState::NotCommitted
            })
        ));
        let receipt = store.append_or_reuse(None, &s, &name, &[0u8; 218]).unwrap();
        assert_eq!(receipt.state, CommitState::Committed);
        drop(store);
        std::fs::remove_file(&path).unwrap();
    }

    /// A record block whose raw bytes match `name` but which fails
    /// structural validation (upstream `s_get_secret` matches it raw and
    /// then fatals "Invalid secret"; our exact-match arm aborts with the
    /// decode error).
    fn poison_block(name: &[u8]) -> [u8; BLOCK] {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let data = &mut payload[2..2 + ENTRY_DATA_LEN];
        data[..name.len()].copy_from_slice(name);
        data[name.len()] = 0;
        // `slen` past the data area: `Entry::decode` rejects the record.
        payload[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
        let mut block = [0u8; BLOCK];
        libhydrogen_sys::secretbox_encrypt(
            &mut block,
            &payload,
            &libhydrogen_sys::CTX_SECRET,
            &KEY,
        );
        block
    }

    #[test]
    fn find_meta_matches_find_without_materializing_the_value() {
        let path = temp_path("meta");
        fixture(
            &path,
            &[
                entry_block(b"alpha", b"one"),
                entry_block(b"DELETED:old", b"x"),
            ],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        // Found: identical slot and name; `ScanMeta` has no value arm at
        // all, so the record value can never leave the scan buffer through
        // the metadata path.
        let (slot, name, mut value) = match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { slot, name, value } => (slot, name, value),
            other => panic!("expected Found, got {other:?}"),
        };
        assert_eq!(value.as_slice(), b"one");
        assert_eq!(
            store.find_meta(&s, b"alpha", false).unwrap(),
            ScanMeta::Found {
                slot,
                name: name.clone(),
            }
        );

        // NotFound parity in both create modes (tombstone + pass_ok).
        assert_eq!(
            store.find_meta(&s, b"fresh", true).unwrap(),
            ScanMeta::NotFound {
                tombstone: Some(2 * BLOCK as u64),
                decrypted_any: true,
            }
        );
        assert!(matches!(
            store.find(&s, b"fresh", true).unwrap(),
            ScanOutcome::NotFound {
                tombstone: Some(t),
                decrypted_any: true,
            } if t == 2 * BLOCK as u64
        ));
        assert_eq!(
            store.find_meta(&s, b"fresh", false).unwrap(),
            ScanMeta::NotFound {
                tombstone: None,
                decrypted_any: true,
            }
        );

        // create=true with the name present: upstream "Secret %s exists!".
        assert!(matches!(
            store.find_meta(&s, b"alpha", true),
            Err(Error::Name(NameError::Exists))
        ));
        value.clear();
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn find_value_owner_lifecycle_is_zeroizing() {
        let path = temp_path("lifecycle");
        fixture(&path, &[entry_block(b"alpha", b"synthetic-secret")], &[]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        // Owned and readable through the zeroizing owner; `clear` erases
        // in place and the buffer reports empty. The owner's lifecycle is
        // independent of the record: a later lookup sees the same bytes.
        let mut first = match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { value, .. } => value,
            other => panic!("expected Found, got {other:?}"),
        };
        assert_eq!(first.as_slice(), b"synthetic-secret");
        first.clear();
        assert!(first.is_empty());
        assert_eq!(first.as_slice(), b"");

        let second = match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { value, .. } => value,
            other => panic!("expected Found, got {other:?}"),
        };
        assert_eq!(second.as_slice(), b"synthetic-secret");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn lookup_debug_redacts_record_values() {
        let path = temp_path("redacted");
        fixture(&path, &[entry_block(b"alpha", b"super-secret")], &[]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        let outcome = store.find(&s, b"alpha", false).unwrap();
        let dbg = format!("{outcome:?}");
        assert!(
            dbg.contains("redacted"),
            "value must render redacted: {dbg}"
        );
        assert!(
            !dbg.contains("super-secret"),
            "record value must not appear in Debug: {dbg}"
        );
        // Metadata is safe to log: the meta result shows name and slot
        // (the name renders as its Debug byte list, e.g. `alpha` →
        // `[97, 108, 112, 104, 97]`).
        let meta = store.find_meta(&s, b"alpha", false).unwrap();
        let meta_dbg = format!("{meta:?}");
        assert!(
            meta_dbg.contains("97, 108, 112, 104, 97"),
            "metadata stays visible: {meta_dbg}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn lookup_rejects_invalid_names_before_the_scan() {
        // The fixture holds a poison record whose raw bytes match the
        // invalid name `bad name`, plus a poison record with a VALID name as
        // the control: a scan that reached the match would report
        // Exists/MalformedRecord, never a name-rule error.
        let path = temp_path("early");
        fixture(
            &path,
            &[poison_block(b"bad name"), poison_block(b"good")],
            &[],
        );
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();

        for create in [false, true] {
            for probe in [
                store.find(&s, b"", create),
                store.find(&s, b"has space", create),
                store.find(&s, &[b'n'; 256], create),
            ] {
                let err = probe.expect_err("invalid names must be rejected");
                assert!(
                    matches!(
                        err,
                        Error::Name(NameError::Empty | NameError::SpecialChar | NameError::TooLong)
                    ),
                    "expected a name-rule error, got {err:?}"
                );
            }
            for probe in [
                store.find_meta(&s, b"", create),
                store.find_meta(&s, b"has space", create),
                store.find_meta(&s, &[b'n'; 256], create),
            ] {
                let err = probe.expect_err("invalid names must be rejected");
                assert!(
                    matches!(
                        err,
                        Error::Name(NameError::Empty | NameError::SpecialChar | NameError::TooLong)
                    ),
                    "expected a name-rule error, got {err:?}"
                );
            }
        }
        // The name rule wins even where a raw match would have produced
        // upstream's `Secret %s exists!` (create=true against the poison
        // `bad name` record).
        assert!(matches!(
            store.find(&s, b"bad name", true),
            Err(Error::Name(NameError::SpecialChar))
        ));
        assert!(matches!(
            store.find_meta(&s, b"bad name", true),
            Err(Error::Name(NameError::SpecialChar))
        ));

        // Control: the scan is live — the poison record under a VALID name
        // aborts at the exact-match arm with the structural error.
        assert!(matches!(
            store.find(&s, b"good", false),
            Err(Error::Format(FormatError::MalformedRecord))
        ));
        assert!(matches!(
            store.find_meta(&s, b"good", false),
            Err(Error::Format(FormatError::MalformedRecord))
        ));
        std::fs::remove_file(&path).unwrap();
    }
}
