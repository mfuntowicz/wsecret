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
use crate::error::{Error, FormatError, NameError, WARN_ABANDONED_MUTEX, WARN_POST_COMMIT_PANIC};
use crate::format::{
    BLOCK, ENTRY_DATA_LEN, ENTRY_PLAIN_LEN, Entry, HEADER_LEN, Header, OPS_LIMIT_MIN,
    build_entry_payload, check_name,
};
use crate::session::Session;
use crate::windows::file as winfile;
use crate::windows::security::{MutexOutcome, WriterMutex};

// Commit outcomes, receipts and warning bits live in `crate::error` (the one
// taxonomy shared with the future ABI); re-exported here for store clients.
pub use crate::error::{CommitFailure, CommitOutcome, CommitReceipt, CommitState};

/// Result of [`Store::find`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// First exact match (case-sensitive, full-length including the NUL
    /// terminator, upstream `hydro_equal(data, key, len + 1)`).
    Found {
        /// Byte offset of the record block (a multiple of 512, >= 512).
        slot: u64,
        /// The record name.
        name: Vec<u8>,
        /// The record value.
        value: Vec<u8>,
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

/// Opt-in resource caps applied when opening a store (plan §3.4 limits
/// policy; §9 blocker 9). `None` is unlimited — the DEFAULT, matching
/// upstream acceptance of any `ops_limit >= 10000` (Hy4 P-3: a default bound
/// would reject stores upstream accepts). `max_list_bytes` governs decrypted
/// enumeration and is deliberately not part of this open-time gate.
///
/// `max_opslimit` exists because the pinned KDF loop cannot be interrupted:
/// a crafted header with `ops_limit = 2^64 - 1` pins a core ~forever
/// (upstream hangs identically). The cap is checked after the header/size
/// inspection but before any KDF execution or store-sized allocation — i.e.
/// before the open returns its handle — so an opted-in caller can never
/// reach the unbounded derivation (plan §3.4 enforcement order).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Maximum accepted header `ops_limit` (`None` = unlimited).
    pub max_opslimit: Option<u64>,
    /// Maximum accepted store size in bytes (`None` = unlimited).
    pub max_store_bytes: Option<u64>,
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
    /// >= 10000). No resource caps (see [`Limits`]).
    pub fn open(path: &Path) -> Result<(Store, Header), Error> {
        Self::open_with_limits(path, Limits::default())
    }

    /// Opens an existing store read-only (read paths such as `list`/`show`
    /// work on stores the user cannot write, as upstream `O_RDONLY` does).
    /// No resource caps (see [`Limits`]).
    pub fn open_read(path: &Path) -> Result<(Store, Header), Error> {
        Self::open_read_with_limits(path, Limits::default())
    }

    /// [`Store::open`] under `limits` (see [`Limits`]): the header/size
    /// inspection plus the opt-in caps, all checked before any KDF execution
    /// or store-sized allocation.
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
        if limits
            .max_opslimit
            .is_some_and(|max| header.ops_limit > max)
        {
            return Err(Error::ResourceLimit);
        }
        if let Some(max) = limits.max_store_bytes {
            let len = winfile::file_len(&file).map_err(io_err)?;
            if len > max {
                return Err(Error::ResourceLimit);
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
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self.scan_each_inner(s, needle, on_name, &mut payload);
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    fn scan_each_inner(
        &mut self,
        s: &Session,
        needle: Option<&[u8]>,
        on_name: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<(), Error> {
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
                    on_name(entry.name)?;
                }
            }
            offset += BLOCK as u64;
        }
        Ok(())
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

    /// First-match lookup (upstream `s_get_secret`): exact case-sensitive
    /// full-length match including the NUL terminator. With `create` true
    /// the scan also records the first decryptable `DELETED:`-prefixed record
    /// as the reusable tombstone slot, and an existing record with this name
    /// is an error (`Secret %s exists!`). `NotFound::decrypted_any` carries
    /// upstream `pass_ok` for the confirmation gate.
    pub fn find(&mut self, s: &Session, name: &[u8], create: bool) -> Result<ScanOutcome, Error> {
        let mut payload = [0u8; ENTRY_PLAIN_LEN];
        let result = self.find_inner(s, name, create, &mut payload);
        libhydrogen_sys::memzero(&mut payload);
        result
    }

    fn find_inner(
        &mut self,
        s: &Session,
        name: &[u8],
        create: bool,
        payload: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<ScanOutcome, Error> {
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
                    return Ok(ScanOutcome::Found {
                        slot: offset,
                        name: entry.name.to_vec(),
                        value: entry.value.to_vec(),
                    });
                }
                decrypted_any = true;
            }
            offset += BLOCK as u64;
        }
        Ok(ScanOutcome::NotFound {
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
                assert_eq!(value, b"two");
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
        assert_eq!(
            store.find(&s, b"missing", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: true,
            }
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn find_reports_empty_partition_and_tombstone() {
        let path = temp_path("passok");
        fixture(&path, &[], &[]);
        let (mut store, _) = Store::open(&path).unwrap();
        let s = session();
        // Nothing decryptable: confirmation gate sees decrypted_any == false.
        assert_eq!(
            store.find(&s, b"x", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: false,
            }
        );
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
        assert_eq!(
            store.find(&s, b"fresh", true).unwrap(),
            ScanOutcome::NotFound {
                tombstone: Some(BLOCK as u64),
                decrypted_any: true,
            }
        );
        assert_eq!(
            store.find(&s, b"fresh", false).unwrap(),
            ScanOutcome::NotFound {
                tombstone: None,
                decrypted_any: true,
            }
        );
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
                assert_eq!(value, b"v");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        assert!(matches!(
            store.find(&s, b"DELETED:old", false),
            Ok(ScanOutcome::NotFound { .. })
        ));
        match store.find(&s, b"keep", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"k"),
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
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"changed"),
            other => panic!("expected Found, got {other:?}"),
        }
        match store.find(&s, b"beta", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"two"),
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
                assert_eq!(value, b"val");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        match store.find(&s, b"alpha", false).unwrap() {
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"one"),
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
    fn open_with_limits_enforces_the_opt_in_caps() {
        let path = temp_path("limits");
        fixture(&path, &[entry_block(b"alpha", b"one")], &[]);

        // Default (unlimited) opens fine — the caps are opt-in (Hy4 P-3).
        assert!(Store::open_with_limits(&path, Limits::default()).is_ok());
        assert!(Store::open_read_with_limits(&path, Limits::default()).is_ok());

        // The fixture header runs at OPS_LIMIT_DEFAULT: just below rejects,
        // exactly at the cap passes.
        let under = Limits {
            max_opslimit: Some(OPS_LIMIT_DEFAULT - 1),
            max_store_bytes: None,
        };
        assert!(matches!(
            Store::open_with_limits(&path, under),
            Err(Error::ResourceLimit)
        ));
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
        assert!(matches!(
            Store::open_read_with_limits(&path, over),
            Err(Error::ResourceLimit)
        ));
        let fit = Limits {
            max_opslimit: None,
            max_store_bytes: Some(len),
        };
        assert!(Store::open_read_with_limits(&path, fit).is_ok());
        std::fs::remove_file(&path).unwrap();
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
}
