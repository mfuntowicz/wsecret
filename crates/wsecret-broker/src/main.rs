//! `wsecret-broker`: the Quick Access secret broker.
//!
//! A SEPARATE process that owns all vault secrets and sessions. The WinUI
//! shell is metadata-only: it spawns this broker with exactly two inherited
//! anonymous-pipe handles (private channel, no named endpoint), receives raw
//! name bytes / slots / countdowns / statuses, and NEVER a secret value or a
//! TOTP code. Secret input arrives only from a broker-launched native masked
//! prompt process ([`native_input`]) and leaves only through the broker's
//! secure clipboard ([`clipboard`]) or native WebAuthn PRF (Hello,
//! [`hello`]).
//!
//! Startup order (binding):
//!
//! 1. FIRST ACTION: `security::init_process_protection` (process and
//!    every-thread DACLs) — before any argument, channel or store work, and
//!    fail-closed (exit 3);
//! 2. argv (`--rd-handle <dec> --wr-handle <dec> [--store <PATH>]`) and
//!    channel-handle validation (`FILE_TYPE_PIPE`, distinct, non-null;
//!    exit 4 on refusal);
//!    `--native-prompt` dispatches to the private input helper at this point,
//!    without opening the vault channel, store, clipboard, or a session;
//! 3. hardened reader thread + handshake deadline (the first frame MUST be
//!    `Hello`, version 1; exit 5 on handshake failure);
//! 4. serve until `Shutdown`, disconnect (client death) or teardown.
//!
//! Lifecycle: `Locked -> Unlocking -> Unlocked -> Locking -> Locked`, with
//! the session generation +1 at every unlock-attempt completion and lock
//! completion ([`protocol`] carries the legality table). Teardown always
//! wipes the session and the Hello epoch material and clears the
//! broker-owned clipboard while it is still owned.
//!
//! # Secret residency (explicit)
//!
//! While unlocked, the broker holds in locked memory: the derived session
//! key (inside `wsecret_core::Session`, the library's own locked/zeroizing
//! owner) and — the Hello enrollment capability — the master PASSPHRASE
//! (`SecretBytes`, wiped on lock/teardown/drop). This passphrase-equivalent
//! material is broker-owned and never crosses the channel, the console
//! output, or the clipboard except through the documented channels; this is
//! the design Main ruled acceptable in place of any raw partition-key
//! export. See [`hello`] for what the sidecar seals and why.

mod clipboard;
mod hello;
mod ipc;
mod native_input;
mod protocol;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libhydrogen_sys::memzero;
use wsecret_core::error::{CommitFailure, CommitReceipt, CommitState, Error, NameError};
use wsecret_core::pass::{deterministic_pass, normalize_password};
use wsecret_core::quick::{self, CodeKind, CodeTarget, NavRef, NavRow};
use wsecret_core::session::{initialize_native_memory, sessions_same_key, SecretBytes, Session};
use wsecret_core::store::{Limits, ScanMeta, ScanOutcome, Store};
use wsecret_core::totp::{totp, totp32, totp_for, TotpCode};
use wsecret_core::windows::security;

use crate::clipboard::SecureClipboard;
use crate::ipc::{
    spawn_reader, ChannelEnds, ChannelReader, ChannelWriter, ReaderEvent, ReaderSignals,
    RecvOutcome,
};
use crate::native_input::{BrokerConsole, PROMPT_CONFIRM, PROMPT_PASSPHRASE, PROMPT_SECRET};
use crate::protocol::{
    commit_state_aux, BodyWriter, HelloState, Lifecycle, Opcode, ParseError, Request, WireStatus,
    REQUEST_DEADLINE_MS, caps,
};

/// Upstream `S_ENV_STORE`.
const ENV_STORE: &str = "SECRET_STORE";
/// Upstream `s_set_path`'s `HOME` fallback.
const ENV_HOME: &str = "HOME";
/// Windows `%USERPROFILE%` fallback (plan §4 divergence, same as the CLI).
const ENV_USERPROFILE: &str = "USERPROFILE";
/// Upstream path bounds (`s_set_path`: 2..1023 bytes).
const PATH_MIN_BYTES: usize = 2;
const PATH_MAX_BYTES: usize = 1023;

/// Exit codes (the launch contract): 0 normal teardown/Shutdown/disconnect;
/// 2 usage; 3 protection init failed; 4 invalid channel handles; 5
/// handshake failure.
const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_PROTECTION: i32 = 3;
const EXIT_CHANNEL: i32 = 4;
const EXIT_HANDSHAKE: i32 = 5;

/// Operation error: `(wire status, response aux, teardown?)`.
type OpError = (WireStatus, u16, bool);

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // 1. FIRST ACTION: core process protection, before anything else.
    if security::init_process_protection().is_err() {
        return EXIT_PROTECTION;
    }
    // 2. argv + channel handles.
    let args = match Args::parse() {
        Ok(args) => args,
        Err(()) => return EXIT_USAGE,
    };
    if args.native_prompt {
        return match native_input::run_helper(args.rd, args.wr) {
            Ok(()) => EXIT_OK,
            Err(_) => EXIT_CHANNEL,
        };
    }
    let ends = match ChannelEnds::from_raw(args.rd, args.wr) {
        Ok(ends) => ends,
        Err(_) => return EXIT_CHANNEL,
    };
    let (reader, writer, signals) = match spawn_reader(ends, true) {
        Ok(parts) => parts,
        Err(_) => return EXIT_CHANNEL,
    };
    let store_path = args.store.unwrap_or_else(resolve_store_path);

    let mut broker = Broker {
        reader,
        writer,
        signals,
        clipboard: SecureClipboard::new(),
        console: None,
        store_path,
        lifecycle: Lifecycle::Locked,
        generation: 0,
        unlocked: None,
        handshaken: false,
    };
    // Clipboard TTL is mandatory: without the hardened expiry worker no
    // broker is allowed to publish secrets with a claimed expiry.
    let _expiry = match broker.clipboard.spawn_expiry_thread() {
        Ok(thread) => thread,
        Err(_) => {
            broker.teardown();
            return EXIT_PROTECTION;
        }
    };

    // Initialize crypto/memory/WebAuthn/clipboard while locked, then explicitly
    // harden any threads they created before the first secret acquisition.
    libhydrogen_sys::init();
    if initialize_native_memory().is_err() {
        broker.teardown();
        return EXIT_PROTECTION;
    }
    let _ = hello::availability();
    let _ = broker.clipboard.initialize();
    if security::register_discovered_threads().is_err() {
        broker.teardown();
        return EXIT_PROTECTION;
    }

    let code = broker.serve();
    broker.teardown();
    code
}

/// Parsed command line.
struct Args {
    /// Command-channel read handle value.
    rd: usize,
    /// Response-channel write handle value.
    wr: usize,
    /// The isolated native-input process, never a vault broker.
    native_prompt: bool,
    /// Optional explicit store path.
    store: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Args, ()> {
        let mut rd: Option<usize> = None;
        let mut wr: Option<usize> = None;
        let mut store: Option<PathBuf> = None;
        let mut native_prompt = false;
        let mut items = std::env::args_os().skip(1);
        while let Some(flag) = items.next() {
            match flag.to_str() {
                Some("--native-prompt") if !native_prompt => native_prompt = true,
                Some("--rd-handle") => {
                    let value = items.next().ok_or(())?;
                    rd = Some(parse_handle(&value)?);
                }
                Some("--wr-handle") => {
                    let value = items.next().ok_or(())?;
                    wr = Some(parse_handle(&value)?);
                }
                Some("--store") => {
                    let path = items.next().ok_or(())?;
                    if path.is_empty() {
                        return Err(());
                    }
                    store = Some(PathBuf::from(path));
                }
                _ => return Err(()),
            }
        }
        if native_prompt && store.is_some() {
            return Err(());
        }
        Ok(Args {
            rd: rd.ok_or(())?,
            wr: wr.ok_or(())?,
            native_prompt,
            store,
        })
    }
}

fn parse_handle(value: &std::ffi::OsStr) -> Result<usize, ()> {
    value
        .to_str()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n != 0)
        .ok_or(())
}

/// Upstream `s_set_path` order (same as `wsecret-cli`): nonempty
/// `$SECRET_STORE`, else `$HOME/.secret`, else `%USERPROFILE%\.secret`, else
/// the upstream empty-home literal; the resolved path must be 2..1023 bytes.
fn resolve_store_path() -> PathBuf {
    let nonempty = |name: &str| -> Option<std::ffi::OsString> {
        std::env::var_os(name).filter(|v| !v.is_empty())
    };
    let path = if let Some(store) = nonempty(ENV_STORE) {
        PathBuf::from(store)
    } else if let Some(home) = nonempty(ENV_HOME) {
        PathBuf::from(home).join(".secret")
    } else if let Some(profile) = nonempty(ENV_USERPROFILE) {
        PathBuf::from(profile).join(".secret")
    } else {
        PathBuf::from("/.secret")
    };
    let len = path.as_os_str().as_encoded_bytes().len();
    if !(PATH_MIN_BYTES..=PATH_MAX_BYTES).contains(&len) {
        // Mirror upstream `s_fatal("Invalid path... Check $HOME or $SECRET_STORE")`:
        // nowhere safe to operate, so refuse at startup.
        std::process::exit(EXIT_USAGE);
    }
    path
}

/// The live session epoch (only while [`Lifecycle::Unlocked`]).
struct Unlocked {
    /// The open store (mutations take the writer mutex first).
    store: Store,
    /// The derived-key session (core-owned locked memory).
    session: Session,
    /// Hello enrollment capability: the master passphrase retained
    /// broker-owned for THIS epoch only (see module docs). Wiped on lock,
    /// teardown and drop.
    hello_material: SecretBytes,
    /// Store identity (header master field) for Hello bindings.
    store_master: [u8; 32],
}

impl Unlocked {
    /// Metadata-only slot lookup for one name (no value materialized).
    fn slot_of(&mut self, name: &[u8]) -> Result<u64, OpError> {
        match self
            .store
            .find_meta(&self.session, name, false)
            .map_err(core_err)?
        {
            ScanMeta::Found { slot, .. } => Ok(slot),
            // The store changed underneath the scan: honest conflict.
            ScanMeta::NotFound { .. } => Err((WireStatus::Conflict, 0, false)),
        }
    }
}

/// The broker state machine.
struct Broker {
    reader: ChannelReader,
    writer: ChannelWriter,
    signals: Arc<ReaderSignals>,
    clipboard: SecureClipboard,
    console: Option<BrokerConsole>,
    store_path: PathBuf,
    lifecycle: Lifecycle,
    generation: u32,
    unlocked: Option<Unlocked>,
    handshaken: bool,
}

impl Broker {
    /// The serve loop: bounded waits, one response per request, teardown on
    /// disconnect.
    fn serve(&mut self) -> i32 {
        let mut exit_code = EXIT_OK;
        loop {
            // Between requests there is no key-use operation in flight. Harden
            // native threads Windows created since the last admission instead
            // of letting an idle clipboard/OLE thread become a disconnect.
            // Any failure remains fail-closed at the next key operation.
            let _ = security::register_discovered_threads_for_session();
            // Residency poison is permanent for this process. Teardown (in run)
            // wipes owned state; pipe EOF tells the palette to discard its index.
            if security::process_is_poisoned() {
                return EXIT_PROTECTION;
            }
            match self.reader.recv(Duration::from_millis(200)) {
                RecvOutcome::Closed => break,
                RecvOutcome::Timeout => continue,
                RecvOutcome::Event(event) => match event {
                    ReaderEvent::VersionMismatch {
                        request_id,
                        version: _,
                    } => {
                        // Contract: aux = the broker's MAX supported version.
                        let _ = self.writer.respond_error(
                            request_id,
                            self.generation,
                            0,
                            WireStatus::VersionMismatch,
                            protocol::MAX_SUPPORTED_VERSION,
                        );
                        exit_code = EXIT_HANDSHAKE;
                        break;
                    }
                    ReaderEvent::CancelAck { request_id, .. } => {
                        let _ = self.writer.respond_error(
                            request_id,
                            self.generation,
                            Opcode::Cancel as u16,
                            WireStatus::Ok,
                            0,
                        );
                    }
                    ReaderEvent::Request(header, body) => {
                        if self.handle_request(
                            header.opcode,
                            header.request_id,
                            header.generation,
                            &body,
                        ) {
                            break;
                        }
                    }
                },
            }
        }
        exit_code
    }

    /// Handles one request frame. Returns true when the broker must tear
    /// down (Shutdown or protocol violation).
    fn handle_request(
        &mut self,
        opcode_wire: u16,
        request_id: u32,
        request_generation: u32,
        body: &[u8],
    ) -> bool {
        let deadline = Instant::now() + Duration::from_millis(REQUEST_DEADLINE_MS);
        let Some(opcode) = Opcode::from_wire(opcode_wire) else {
            self.respond_error(request_id, WireStatus::InvalidArgument, 0);
            return true;
        };
        // 1. Body decode — structural failures are fatal protocol
        //    violations; semantic rejections answer and the connection
        //    continues.
        let request = match protocol::parse_request(opcode, body) {
            Ok(request) => request,
            Err(ParseError::Fatal(status)) => {
                self.respond_error(request_id, status, 0);
                return true;
            }
            Err(ParseError::Reject(status)) => {
                self.respond_error(request_id, status, 0);
                return false;
            }
        };
        // 2. The first frame MUST be the Hello handshake.
        if !self.handshaken {
            if opcode != Opcode::Hello {
                self.respond_error(request_id, WireStatus::InvalidArgument, 0);
                return true;
            }
            self.handshaken = true;
        }
        // 3. Lifecycle legality.
        if !self.lifecycle.permits(opcode) {
            let status = if matches!(self.lifecycle, Lifecycle::Unlocking | Lifecycle::Locking) {
                WireStatus::Busy
            } else {
                WireStatus::WrongState
            };
            self.respond_error(request_id, status, 0);
            return false;
        }
        // 4. Session generation: requests pinned to a stale epoch never run.
        if opcode.is_session_scoped() && request_generation != self.generation {
            self.respond_error(request_id, WireStatus::StaleGeneration, 0);
            return false;
        }

        // 5. Admit the whole request once. Per-record key operations reuse
        // this admission instead of enumerating process threads per record.
        let _batch = if opcode.is_session_scoped() {
            match security::begin_operation_batch() {
                Ok(batch) => Some(batch),
                Err(_) => {
                    self.respond_error(request_id, WireStatus::MemoryProtection, 0);
                    return false;
                }
            }
        } else {
            None
        };
        // 6. Execute, then close admission BEFORE reporting success. A thread
        // created during a short request is caught at drain, not excused later.
        let mut outcome = self.dispatch(request_id, request, deadline);
        drop(_batch);
        if security::process_is_poisoned() {
            outcome = Err((WireStatus::MemoryProtection, 0, false));
        }
        let (payload, teardown) = match outcome {
            Ok(payload) => (payload, false),
            Err((status, aux, teardown)) => (protocol::error_body(status, aux), teardown),
        };
        let _ = self
            .writer
            .respond(request_id, self.generation, opcode_wire, &payload);
        self.signals.clear_cancel(request_id);
        if opcode == Opcode::Shutdown {
            return true;
        }
        teardown
    }

    /// Executes one request; `Ok` is the response payload (status/aux
    /// included), `Err` is [`OpError`].
    fn dispatch(
        &mut self,
        request_id: u32,
        request: Request,
        deadline: Instant,
    ) -> Result<Vec<u8>, OpError> {
        match request {
            Request::Hello => Ok(self.state_body(true)),
            Request::Ping => Ok(self.state_body(false)),
            // Already applied by the reader; the response is owed here.
            Request::Cancel { .. } | Request::Shutdown => {
                Ok(BodyWriter::new(WireStatus::Ok, 0).into_bytes())
            }
            Request::Unlock { mode } => self.op_unlock(mode, request_id, deadline),
            Request::Lock { clear_clipboard } => self.op_lock(clear_clipboard != 0),
            Request::List {
                offset,
                count,
                needle,
            } => self.op_list(offset, count, &needle),
            Request::Meta { name } => self.op_meta(&name),
            Request::Copy {
                name,
                mode,
                expect_slot,
            } => self.op_copy(&name, mode, false, expect_slot),
            Request::Code { name, expect_slot } => self.op_copy(&name, 2, true, expect_slot),
            Request::CodeTargets { slot, name } => self.op_code_targets(slot, &name),
            Request::New {
                name,
                gen_kind,
                subkeys,
            } => self.op_new(&name, gen_kind, &subkeys),
            Request::Set { name } => self.op_set(&name, request_id, deadline),
            Request::Update {
                expect_slot,
                name,
                new_name,
                mode,
            } => self.op_update(expect_slot, &name, &new_name, mode, request_id, deadline),
            Request::HelloEnroll => self.op_hello_enroll(deadline),
            Request::HelloForget => {
                let _ = hello::forget(&self.store_path);
                Ok(hello_state_body(
                    WireStatus::Ok,
                    self.hello_state_now(),
                ))
            }
        }
    }

    // ---- lifecycle ops ---------------------------------------------------

    /// `Hello` (full = true) / `Ping` (full = false) response body.
    fn state_body(&self, full: bool) -> Vec<u8> {
        let hello_state = self.hello_state_now();
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        w.u8(self.lifecycle.code());
        w.u8(hello_state.code());
        if full {
            w.u16(protocol::MAX_SUPPORTED_VERSION);
            w.u32(self.generation);
            w.u32(
                caps::COPY
                    | caps::CODES
                    | caps::WRITES
                    | if hello_state != HelloState::Unsupported {
                        caps::HELLO
                    } else {
                        0
                    },
            );
        } else {
            w.u16(0);
            w.u32(self.generation);
        }
        w.into_bytes()
    }

    /// Current Hello binding state (needs the store identity; before the
    /// first unlock it is read from the store header directly).
    fn hello_state_now(&self) -> HelloState {
        match &self.unlocked {
            Some(u) => hello::state(&self.store_path, &u.store_master),
            None => match Store::open_read(&self.store_path) {
                Ok((_store, header)) => hello::state(&self.store_path, &header.master),
                Err(_) => HelloState::Available,
            },
        }
    }

    /// `Unlock` (mode 0: broker-native masked prompt; mode 1: Hello PRF).
    fn op_unlock(
        &mut self,
        mode: u8,
        request_id: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, OpError> {
        self.lifecycle = Lifecycle::Unlocking;
        let outcome = self.do_unlock(mode, request_id, deadline);
        // Every unlock ATTEMPT bumps the generation (success or failure), so
        // requests pinned to an older epoch can never land on a new one.
        self.generation += 1;
        match outcome {
            Ok(()) => {
                self.lifecycle = Lifecycle::Unlocked;
                let mut w = BodyWriter::new(WireStatus::Ok, 0);
                w.u32(self.generation);
                Ok(w.into_bytes())
            }
            Err((status, aux, _)) => {
                self.lifecycle = Lifecycle::Locked;
                Err((status, aux, false))
            }
        }
    }

    fn do_unlock(
        &mut self,
        mode: u8,
        request_id: u32,
        deadline: Instant,
    ) -> Result<(), OpError> {
        // Open BEFORE prompting (fail on a missing/corrupt store with no
        // prompt and no derived secret — the agent_bridge hardening rule).
        let (mut store, header) = Store::open_with_limits(&self.store_path, Limits::default())
            .map_err(|e| {
                let status = match &e {
                    Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                        WireStatus::StoreNotFound
                    }
                    _ => WireStatus::from_error(&e),
                };
                (status, 0, false)
            })?;
        let store_master = header.master;
        // Establish the private prompt channel while locked, including for
        // Hello unlocks whose first typed input may be a later Set/Update.
        self.ensure_console()?;
        let mut pass = match mode {
            0 => self.prompt(PROMPT_PASSPHRASE, deadline, request_id, true)?,
            1 => {
                security::register_discovered_threads()
                    .map_err(|_| (WireStatus::MemoryProtection, 0, false))?;
                hello::unlock(&self.store_path, &store_master, deadline)
                    .map_err(|s| (s, 0, false))?
            }
            _ => return Err((WireStatus::InvalidArgument, 0, false)),
        };
        // WebAuthn may create broker-process worker threads during the PRF
        // ceremony. Register and harden them before admitting the recovered
        // passphrase or derived session key to protected memory.
        if security::register_discovered_threads().is_err() {
            memzero(&mut pass);
            return Err((WireStatus::MemoryProtection, 0, false));
        }
        if pass.is_empty() {
            return Err((WireStatus::Cancelled, 0, false));
        }
        // Hello enrollment capability: retained broker-owned for this epoch.
        let hello_material =
            SecretBytes::from_slice(&pass).map_err(|e| (WireStatus::from_error(&e), 0, false))?;
        let session =
            Session::unlock(&header, &mut pass).map_err(|e| (WireStatus::from_error(&e), 0, false))?;
        memzero(&mut pass);

        // Upstream `pass_ok`: any decryptable record avoids the new-partition
        // retype. Stop at the first match; no value is materialized.
        let mut decryptable = false;
        store
            .scan_each_at(&session, None, &mut |_, _, _| {
                decryptable = true;
                Ok(false)
            })
            .map_err(core_err)?;

        // Upstream `s_get_secret` empty-partition confirmation (the CLI runs
        // it per command; the broker runs it once per unlock — the epoch
        // analog). Hello unlocks skip it: UV already confirmed the human.
        if mode == 0 && !decryptable {
            let mut again = self.prompt(PROMPT_CONFIRM, deadline, request_id, true)?;
            if again.is_empty() {
                return Err((WireStatus::Cancelled, 0, false));
            }
            let check = Session::unlock(&header, &mut again)
                .map_err(|e| (WireStatus::from_error(&e), 0, false))?;
            memzero(&mut again);
            let same = sessions_same_key(&session, &check)
                .map_err(|e| (WireStatus::from_error(&e), 0, false))?;
            if !same {
                return Err((WireStatus::PassphraseMismatch, 0, false));
            }
        }
        self.unlocked = Some(Unlocked {
            store,
            session,
            hello_material,
            store_master,
        });
        Ok(())
    }

    /// `Lock`: wipe the session (and the epoch capability), optionally clear
    /// the owned clipboard.
    fn op_lock(&mut self, clear_clipboard: bool) -> Result<Vec<u8>, OpError> {
        self.lifecycle = Lifecycle::Locking;
        if let Some(unlocked) = self.unlocked.take() {
            // SecretBytes/Session wipe on drop.
            drop(unlocked);
        }
        if clear_clipboard {
            self.clipboard.clear_if_owned();
        }
        self.generation += 1;
        self.lifecycle = Lifecycle::Locked;
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        w.u32(self.generation);
        Ok(w.into_bytes())
    }

    // ---- read ops --------------------------------------------------------

    /// `List`: names in physical order (exact raw bytes), paged; each row
    /// carries the record's ACTUAL slot (never a first-match slot —
    /// duplicate names stay distinct rows). One streaming pass per request
    /// with the upstream case-insensitive substring `needle` semantics:
    /// only the requested window is retained (bounded by `count`), while
    /// `total` counts every match. No value is ever materialized.
    fn op_list(
        &mut self,
        offset: u32,
        count: u16,
        needle: &[u8],
    ) -> Result<Vec<u8>, OpError> {
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let needle = if needle.is_empty() {
            None
        } else {
            Some(needle)
        };
        let start = offset as u64;
        let end = start + count as u64;
        let mut total: u64 = 0;
        let mut returned = 0u16;
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        // status | aux | total | returned | pad; fill counts after streaming the page.
        w.u32(0);
        w.u16(0);
        w.u16(0);
        unlocked
            .store
            .scan_each_at(&unlocked.session, needle, &mut |slot, name, tombstone| {
                if tombstone {
                    return Ok(true);
                }
                if total >= start && total < end {
                    w.u64(slot);
                    w.blob(name);
                    returned += 1;
                }
                total += 1;
                Ok(true)
            })
            .map_err(core_err)?;

        let mut body = w.into_bytes();
        body[4..8].copy_from_slice(&(total.min(u32::MAX as u64) as u32).to_le_bytes());
        body[8..10].copy_from_slice(&returned.to_le_bytes());
        Ok(body)
    }

    /// `Meta`: slot, kind, value length, code countdown (metadata only).
    /// `kind = 1` when [`derive_code`] yields a code for this record right
    /// now (the value-valid half of the code-name rule; the name-only half
    /// is the UI's `NameCodec.IsCodeName`).
    fn op_meta(&mut self, name: &[u8]) -> Result<Vec<u8>, OpError> {
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let slot = unlocked.slot_of(name)?;
        let value = match unlocked
            .store
            .find(&unlocked.session, name, false)
            .map_err(core_err)?
        {
            ScanOutcome::Found { value, .. } => value,
            ScanOutcome::NotFound { .. } => return Err((WireStatus::NotFound, 0, false)),
        };
        let now = unix_now();
        let code = derive_code(name, value.as_slice(), now);
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        w.u64(slot);
        w.u8(if code.is_some() { 1 } else { 0 });
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u32(value.len() as u32);
        w.u32(if code.is_some() { code_remaining(now) } else { 0 });
        w.blob(name);
        Ok(w.into_bytes())
    }

    /// `Copy` (mode 0 auto, 1 raw value, 2 code) and `Code`: bytes go ONLY to
    /// the secure clipboard; the response carries TTL/countdown metadata.
    /// `code_layout` selects the `Code` response field order
    /// (`code_remaining_s | clipboard_ttl_ms` instead of
    /// `clipboard_ttl_ms | code_remaining_s`).
    ///
    /// Identity before secrecy: the exact name must occur on exactly ONE
    /// record of this partition (upstream first-match shadowing is never
    /// guessed — two or more occurrences refuse with [`WireStatus::Conflict`],
    /// the core `StaleKind::AmbiguousName` convention), and a
    /// nonzero `expect_slot` must be that record's slot (deleted →
    /// [`WireStatus::NotFound`]; renamed/moved/recreated elsewhere →
    /// [`WireStatus::Conflict`]). A changed VALUE at the same slot + name is
    /// current and is what gets copied (upstream semantics).
    ///
    /// A code-routed request NEVER falls back to publishing the record value
    /// (the seed): an invalid seed, an alias record or a misclassification
    /// refuses with [`WireStatus::InvalidTotp`] and nothing is published.
    fn op_copy(
        &mut self,
        name: &[u8],
        mode: u8,
        code_layout: bool,
        expect_slot: u64,
    ) -> Result<Vec<u8>, OpError> {
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        // One exact-name pass, early-stopped at the second occurrence, and
        // NO value materialized: an exact match always contains the name as
        // a substring, so the needle never excludes a candidate.
        let mut slot: u64 = 0;
        let mut occurrences: u32 = 0;
        unlocked
            .store
            .scan_each_at(
                &unlocked.session,
                Some(name),
                &mut |at, found, _tombstone| {
                    if found == name {
                        occurrences += 1;
                        slot = at;
                        return Ok(occurrences < 2);
                    }
                    Ok(true)
                },
            )
            .map_err(core_err)?;
        match occurrences {
            0 => return Err((WireStatus::NotFound, 0, false)),
            1 => {}
            _ => return Err((WireStatus::Conflict, 0, false)),
        }
        if expect_slot != 0 && slot != expect_slot {
            // The displayed record was renamed, deleted or replaced: the
            // name now belongs to a different record (or none was shown).
            return Err((WireStatus::Conflict, 0, false));
        }
        let record = unlocked
            .store
            .read_at(&unlocked.session, slot)
            .map_err(core_err)?
            // The record moved between the scan and the read: honest conflict.
            .ok_or((WireStatus::Conflict, 0, false))?;
        if record.meta.name.as_slice() != name {
            return Err((WireStatus::Conflict, 0, false));
        }
        let value = record.value;
        let now = unix_now();
        let want_code = mode == 2 || (mode == 0 && code_candidate(name));
        let mut bytes: Vec<u8>;
        let (remaining, digits, ttl_ms) = if want_code {
            // Code-routed: never fall back to the raw value/seed.
            let code = derive_code(name, value.as_slice(), now)
                .ok_or((WireStatus::InvalidTotp, 0, false))?;
            let remaining = code_remaining(now);
            // User brief: OTP copies expire at the EARLIER of the 30 s
            // timeout and the code window.
            bytes = code.to_vec();
            (remaining, code.len() as u8, remaining * 1000)
        } else {
            bytes = value.as_slice().to_vec();
            (0, 0u8, protocol::CLIPBOARD_TTL_MS)
        };
        let publish = self
            .clipboard
            .publish(&bytes, Duration::from_millis(ttl_ms as u64));
        memzero(&mut bytes);
        publish.map_err(|s| (s, 0, false))?;
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        if code_layout {
            w.u32(remaining);
            w.u32(ttl_ms);
        } else {
            w.u32(ttl_ms);
            w.u32(remaining);
        }
        w.u8(digits);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        Ok(w.into_bytes())
    }

    /// `CodeTargets`: the Ctrl+Enter "Copy code" input — the exact safe code
    /// records for one picked item, metadata only. Contract (the wire
    /// reference is the `protocol` module's "Codes routing and code
    /// targets"):
    ///
    /// - the source is addressed by slot + exact name bytes and must still
    ///   match ([`WireStatus::Conflict`] on a stale/moved selection);
    /// - when the source itself is code-capable ([`code_candidate`]) the
    ///   result is exactly the source ("self");
    /// - otherwise the result is `quick::codes_for_account` over THIS
    ///   partition: only records whose link resolves uniquely to the source
    ///   — never a descendant guess, never cross-vault;
    /// - fail closed with [`WireStatus::Conflict`] on ambiguous identity:
    ///   the source name or any returned name occurs on more than one
    ///   indexed record (the chooser must never see indistinguishable rows
    ///   and the follow-up name-addressed `Code` must not shadow);
    /// - fail closed with [`WireStatus::ResourceLimit`] on a partial index
    ///   (bounded-index truncation) or more than
    ///   [`protocol::MAX_CODE_TARGETS`] qualifying rows;
    /// - an EMPTY result is the legitimate "no linked code" answer.
    fn op_code_targets(&mut self, slot: u64, name: &[u8]) -> Result<Vec<u8>, OpError> {
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let index = unlocked
            .store
            .navigate(&unlocked.session, quick::NavOptions::default())
            .map_err(core_err)?;
        if index.truncated() {
            return Err((WireStatus::ResourceLimit, 0, false));
        }
        let source = NavRef {
            slot,
            name: name.to_vec(),
        };
        let Some(source_row) = index.get(&source) else {
            // The picked record was deleted, renamed or replaced.
            return Err((WireStatus::Conflict, 0, false));
        };
        if source_row.ambiguous {
            // Duplicate exact names: the link rule cannot say "this record".
            return Err((WireStatus::Conflict, 0, false));
        }
        let rows: Vec<&NavRow> = if code_candidate(name) {
            vec![source_row]
        } else {
            quick::codes_for_account(&index, &source)
        };
        if rows.len() > protocol::MAX_CODE_TARGETS as usize {
            return Err((WireStatus::ResourceLimit, 0, false));
        }
        // Fail closed on indistinguishable targets: the chooser displays
        // names and the follow-up `Code` is name-addressed.
        for (i, row) in rows.iter().enumerate() {
            if rows[..i].iter().any(|prev| prev.r.name == row.r.name) {
                return Err((WireStatus::Conflict, 0, false));
            }
        }
        let mut w = BodyWriter::new(WireStatus::Ok, 0);
        w.u16(rows.len() as u16);
        w.u16(0);
        for row in &rows {
            w.u64(row.r.slot);
            w.blob(&row.r.name);
        }
        Ok(w.into_bytes())
    }

    // ---- write ops -------------------------------------------------------

    /// `New`: absence required; generate (random upstream-`new` style, or
    /// deterministic upstream-`pass` style over the subkeys), store, and
    /// copy the fresh secret to the secure clipboard (the analog of
    /// upstream printing it).
    fn op_new(
        &mut self,
        name: &[u8],
        gen_kind: u8,
        subkeys: &[Vec<u8>],
    ) -> Result<Vec<u8>, OpError> {
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let mut guard = unlocked.store.lock_writers_scoped().map_err(core_err)?;
        let tombstone = match guard
            .find_meta(&unlocked.session, name, true)
            .map_err(|e| (map_exists(&e), 0, false))?
        {
            ScanMeta::Found { .. } => return Err((WireStatus::AlreadyExists, 0, false)),
            ScanMeta::NotFound { tombstone, .. } => tombstone,
        };
        let mut candidate = if gen_kind == 0 {
            let mut raw = [0u8; 512];
            libhydrogen_sys::random_buf(&mut raw);
            let normalized = normalize_password(&raw);
            memzero(&mut raw);
            normalized
        } else {
            let refs: Vec<&[u8]> = subkeys.iter().map(|s| s.as_slice()).collect();
            deterministic_pass(&unlocked.session, &refs).map_err(core_err)?
        };
        let (warn_bits, aux) = commit_result(
            guard.append_or_reuse(tombstone, &unlocked.session, name, &candidate),
        )?;
        drop(guard);
        let publish = self.clipboard.publish(
            &candidate,
            Duration::from_millis(protocol::CLIPBOARD_TTL_MS as u64),
        );
        memzero(&mut candidate);
        publish.map_err(|s| (s, commit_state_aux(CommitState::Committed), false))?;
        let slot = unlocked.slot_of(name)?;
        write_body(slot, warn_bits, aux, protocol::CLIPBOARD_TTL_MS)
    }

    /// `Set`: absence required; value entered at the broker's own masked
    /// prompt. Empty input is upstream's silent no-write outcome.
    fn op_set(
        &mut self,
        name: &[u8],
        request_id: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, OpError> {
        self.ensure_console()?;
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let mut guard = unlocked.store.lock_writers_scoped().map_err(core_err)?;
        match guard
            .find_meta(&unlocked.session, name, true)
            .map_err(|e| (map_exists(&e), 0, false))?
        {
            ScanMeta::Found { .. } => return Err((WireStatus::AlreadyExists, 0, false)),
            ScanMeta::NotFound { tombstone, .. } => {
                // The writer mutex stays held across the prompt (the CLI
                // holds it the same way), so the tombstone cannot move.
                let raw = prompt_line(
                    self.console.as_ref().expect("ensured"),
                    &self.signals,
                    PROMPT_SECRET,
                    deadline,
                    request_id,
                    false,
                )?;
                if raw.is_empty() {
                    // Upstream `s_do`: empty input with nothing to keep.
                    return write_body(0, 0, commit_state_aux(CommitState::NotCommitted), 0);
                }
                let mut raw = raw;
                let outcome = guard.append_or_reuse(tombstone, &unlocked.session, name, &raw);
                let (warn_bits, aux) = commit_result(outcome)?;
                memzero(&mut raw);
                drop(guard);
                let slot = unlocked.slot_of(name)?;
                write_body(slot, warn_bits, aux, 0)
            }
        }
    }

    /// `Update`: CAS-guarded rename and/or value replacement/regeneration
    /// (upstream `update`/`renew` semantics, including the rename-keeps-value
    /// and bare-empty-input no-write rules).
    fn op_update(
        &mut self,
        expect_slot: u64,
        name: &[u8],
        new_name: &[u8],
        mode: u8,
        request_id: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, OpError> {
        self.ensure_console()?;
        let renaming = !new_name.is_empty();
        let target: &[u8] = if renaming { new_name } else { name };
        // The rename form with empty input keeps the old value, so only that
        // form (and mode 1) materializes it.
        let needs_old = mode == 1 || (mode == 0 && renaming);
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or((WireStatus::WrongState, 0, false))?;
        let mut guard = unlocked.store.lock_writers_scoped().map_err(core_err)?;
        let (slot, old_value) = if needs_old {
            match guard
                .find(&unlocked.session, name, false)
                .map_err(core_err)?
            {
                ScanOutcome::Found { slot, value, .. } => (slot, Some(value)),
                ScanOutcome::NotFound { .. } => return Err((WireStatus::NotFound, 0, false)),
            }
        } else {
            match guard
                .find_meta(&unlocked.session, name, false)
                .map_err(core_err)?
            {
                ScanMeta::Found { slot, .. } => (slot, None),
                ScanMeta::NotFound { .. } => return Err((WireStatus::NotFound, 0, false)),
            }
        };
        // CAS guard: the record must still live where the client saw it.
        if expect_slot != 0 && slot != expect_slot {
            return Err((WireStatus::Conflict, 0, false));
        }

        // Fresh generated value (mode 2) goes to the clipboard afterwards.
        let mut generated: Option<Vec<u8>> = None;
        let mut owned: Option<Vec<u8>> = None;
        let mut ttl_ms = 0u32;
        let mut no_write = false;
        match mode {
            0 => {
                let raw = prompt_line(
                    self.console.as_ref().expect("ensured"),
                    &self.signals,
                    PROMPT_SECRET,
                    deadline,
                    request_id,
                    false,
                )?;
                if raw.is_empty() {
                    match (renaming, old_value) {
                        // `update KEY NEWKEY` + empty input: rename, keep
                        // the old value bytes (borrowed, no copy).
                        (true, Some(old)) => {
                            let (warn_bits, aux) = commit_result(guard.write_slot(
                                slot,
                                &unlocked.session,
                                target,
                                old.as_slice(),
                            ))?;
                            drop(guard);
                            let slot = unlocked.slot_of(target)?;
                            return write_body(slot, warn_bits, aux, 0);
                        }
                        // Bare `update KEY` + empty input: no write at all.
                        _ => no_write = true,
                    }
                } else {
                    owned = Some(raw);
                }
            }
            1 => {
                // Rename-only: write the old value back under the new name.
                let old = old_value.ok_or((WireStatus::NotFound, 0, false))?;
                owned = Some(old.as_slice().to_vec());
            }
            _ => {
                // Renew: fresh generated secret (upstream `renew`), copied
                // to the clipboard like upstream printing it.
                let mut raw = [0u8; 512];
                libhydrogen_sys::random_buf(&mut raw);
                let normalized = normalize_password(&raw);
                memzero(&mut raw);
                generated = Some(normalized.clone());
                owned = Some(normalized);
                ttl_ms = protocol::CLIPBOARD_TTL_MS;
            }
        }
        if no_write {
            return write_body(slot, 0, commit_state_aux(CommitState::NotCommitted), 0);
        }
        let mut value = owned.ok_or((WireStatus::NotFound, 0, false))?;
        let (warn_bits, aux) = commit_result(guard.write_slot(
            slot,
            &unlocked.session,
            target,
            &value,
        ))?;
        memzero(&mut value);
        drop(guard);
        if let Some(mut fresh) = generated {
            let publish = self.clipboard.publish(
                &fresh,
                Duration::from_millis(protocol::CLIPBOARD_TTL_MS as u64),
            );
            memzero(&mut fresh);
            publish.map_err(|s| (s, commit_state_aux(CommitState::Committed), false))?;
        }
        let slot = unlocked.slot_of(target)?;
        write_body(slot, warn_bits, aux, ttl_ms)
    }

    /// `HelloEnroll`: bind the epoch capability under WebAuthn PRF + UV.
    fn op_hello_enroll(&mut self, deadline: Instant) -> Result<Vec<u8>, OpError> {
        let (path, master, mut material) = {
            let unlocked = self
                .unlocked
                .as_ref()
                .ok_or((WireStatus::WrongState, 0, false))?;
            (
                self.store_path.clone(),
                unlocked.store_master,
                unlocked.hello_material.as_slice().to_vec(),
            )
        };
        let result = hello::enroll(&path, &master, &material, deadline);
        memzero(&mut material);
        let state = result.map_err(|s| (s, 0, false))?;
        Ok(hello_state_body(WireStatus::Ok, state))
    }

    // ---- helpers ---------------------------------------------------------

    /// Launches the native prompt helper once, before admitting a session.
    fn ensure_console(&mut self) -> Result<(), OpError> {
        if self.console.is_none() {
            let console = BrokerConsole::open().map_err(|e| (e.status, e.aux, false))?;
            security::register_discovered_threads()
                .map_err(|_| (WireStatus::MemoryProtection, 0, false))?;
            self.console = Some(console);
        }
        Ok(())
    }

    /// Broker-native masked prompt with the request deadline and channel
    /// cancellation. `passphrase = true` applies upstream `s_ask_pass`
    /// empty-input abort; `false` passes an empty line through for the
    /// upstream `s_do` policy.
    fn prompt(
        &mut self,
        prompt: &str,
        deadline: Instant,
        request_id: u32,
        passphrase: bool,
    ) -> Result<Vec<u8>, OpError> {
        self.ensure_console()?;
        prompt_line(
            self.console.as_ref().expect("opened above"),
            &self.signals,
            prompt,
            deadline,
            request_id,
            passphrase,
        )
    }

    fn respond_error(&mut self, request_id: u32, status: WireStatus, aux: u16) {
        let _ = self
            .writer
            .respond_error(request_id, self.generation, 0, status, aux);
    }

    /// Lock, wipe and clear on `Shutdown`, disconnect or startup failure.
    fn teardown(&mut self) {
        if let Some(unlocked) = self.unlocked.take() {
            drop(unlocked); // wipes session + epoch capability
        }
        self.lifecycle = Lifecycle::Locked;
        // The client is gone or asked to stop: clear the clipboard if we
        // still own it, then stop the expiry thread.
        self.clipboard.clear_if_owned();
        self.clipboard.shutdown();
    }
}

// ---- free helpers ---------------------------------------------------------

/// One broker-native masked prompt (free function so write ops can prompt
/// while the writer guard borrows `self.unlocked`). `passphrase = true`
/// applies upstream `s_ask_pass` empty-input abort; `false` passes an empty
/// line through for the upstream `s_do` policy.
fn prompt_line(
    con: &BrokerConsole,
    signals: &Arc<ReaderSignals>,
    prompt: &str,
    deadline: Instant,
    request_id: u32,
    passphrase: bool,
) -> Result<Vec<u8>, OpError> {
    let cancel = || signals.canceled(request_id);
    let result = if passphrase {
        con.read_passphrase(prompt, deadline, &cancel)
    } else {
        con.read_secret(prompt, deadline, &cancel)
    };
    result.map_err(|e| (e.status, e.aux, false))
}

/// `HelloEnroll`/`HelloForget` response body.
fn hello_state_body(status: WireStatus, state: HelloState) -> Vec<u8> {
    let mut w = BodyWriter::new(status, 0);
    w.u8(state.code());
    w.into_bytes()
}

/// Write-response body (`slot | warn_bits | clipboard_ttl_ms`).
fn write_body(
    slot: u64,
    warn_bits: u32,
    aux: u16,
    ttl_ms: u32,
) -> Result<Vec<u8>, OpError> {
    let mut w = BodyWriter::new(WireStatus::Ok, aux);
    w.u64(slot);
    w.u32(warn_bits);
    w.u32(ttl_ms);
    Ok(w.into_bytes())
}

/// Maps a core error to [`OpError`].
fn core_err(error: Error) -> OpError {
    (WireStatus::from_error(&error), 0, false)
}

/// Maps a commit outcome: `(warn_bits, aux)` on success,
/// `(status, commit-state, no-teardown)` on failure.
fn commit_result(
    outcome: Result<CommitReceipt, CommitFailure>,
) -> Result<(u32, u16), OpError> {
    match outcome {
        Ok(receipt) => Ok((receipt.warnings, commit_state_aux(receipt.state))),
        Err(failure) => Err((
            WireStatus::from_error(&failure.error),
            commit_state_aux(failure.state),
            false,
        )),
    }
}

/// Maps `find_meta(create = true)`'s `NameError::Exists` error form.
fn map_exists(error: &Error) -> WireStatus {
    match error {
        Error::Name(NameError::Exists) => WireStatus::AlreadyExists,
        other => WireStatus::from_error(other),
    }
}

/// Upstream `contains(name, "totp")`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Exact `/`-separated path component match (ASCII slash only, no
/// normalization — `wsecret_core::quick::discover_code`'s component rule).
fn has_component(name: &[u8], component: &[u8]) -> bool {
    name.split(|&b| b == b'/').any(|seg| seg == component)
}

/// The ONE code-name routing rule behind `Meta`'s kind byte, `Copy`'s
/// auto/code routing and `CodeTargets`' self case. It must agree EXACTLY
/// with the UI's `NameCodec.IsCodeName` candidate heuristic:
///
/// - the historical upstream substring rule: case-sensitive `totp`
///   anywhere in the name (`s_show` / [`wsecret_core::totp::totp_for`]);
/// - the exact `topt` alias path component (the alias display namespace).
///
/// `Topt`/`TOTP` spellings and near-misses like `topt-notes` are NOT code
/// names; `mytotp32` and `totp-notes` ARE (historical substring).
fn code_candidate(name: &[u8]) -> bool {
    contains(name, b"totp") || has_component(name, b"topt")
}

/// Derives the current code for a code-candidate name. The ONE core adapter
/// (`quick::discover_code`'s kind) owns decoding for every record that
/// carries a code component (`totp32` → base32, `totp`/`topt` → raw; the
/// alias is raw by default — Base32 only through explicit import metadata,
/// which v0 stores never carry). A substring-only historical name keeps the
/// CLI convention verbatim ([`wsecret_core::totp::totp_for`], kind
/// selection included). `None` = no code: callers MUST refuse and never
/// fall back to publishing the record value (the seed).
fn derive_code(name: &[u8], value: &[u8], now: u64) -> Option<TotpCode> {
    let counter = now / 30;
    match quick::discover_code(name) {
        Some(CodeTarget::Supported {
            kind: CodeKind::Base32,
            ..
        }) => totp32(value, counter),
        Some(CodeTarget::Supported {
            kind: CodeKind::Raw, ..
        }) => totp(value, counter),
        // Only reachable through explicit import metadata (none in v0).
        Some(CodeTarget::UnsupportedImport) => None,
        // Historical substring names (no code component): the CLI rule.
        None if contains(name, b"totp") => totp_for(name, value, now),
        None => None,
    }
}

/// Unix seconds (upstream samples `time(NULL)` inside `s_show`).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seconds left in the current 30 s TOTP window.
fn code_remaining(now: u64) -> u32 {
    (30 - (now % 30)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsecret_core::totp::{totp, totp32};

    #[test]
    fn code_candidate_agrees_with_the_documented_rule() {
        // Historical upstream substring (case-sensitive).
        for name in [
            &b"totp"[..],
            &b"mytotp32"[..],
            &b"totp-notes"[..],
            &b"Work/GitHub/totp32"[..],
        ] {
            assert!(code_candidate(name), "{name:?}");
        }
        // Exact `topt` alias component (and nothing fuzzier).
        for name in [&b"topt"[..], &b"Work/GitHub/topt"[..], &b"x/topt/y"[..]] {
            assert!(code_candidate(name), "{name:?}");
        }
        // NOT code names: case variants and near-miss components.
        for name in [
            &b"Work/TOTP"[..],
            &b"Topt"[..],
            &b"x/topt-notes"[..],
            &b"x/topt32"[..],
            &b"password"[..],
            &b"x/OTP"[..],
        ] {
            assert!(!code_candidate(name), "{name:?}");
        }
    }

    #[test]
    fn derive_code_refuses_instead_of_falling_back_to_the_value() {
        let now = 1_700_000_000;
        let counter = now / 30;
        let raw = b"0123456789abcdef"; // valid raw HMAC key
        let b32 = b"JBSWY3DPEHPK3PXP"; // valid base32

        // Historical substring-only names keep the CLI rule verbatim
        // (kind selection included).
        assert_eq!(derive_code(b"mytotp32", b32, now), totp32(b32, counter));
        // Invalid seed under a `totp32` name: no code, and the raw value is
        // never a fallback (upstream "Invalid secret").
        assert_eq!(derive_code(b"mytotp32", raw, now), None);
        // The one core adapter owns decoding whenever a code component
        // exists: component kind beats the historical substring kind.
        assert_eq!(derive_code(b"x/totp", raw, now), totp(raw, counter));
        assert_eq!(derive_code(b"GitHub/totp32", b32, now), totp32(b32, counter));
        assert_eq!(derive_code(b"mytotp32/totp", raw, now), totp(raw, counter));
        // Exact alias derives RAW TOTP even for base32-looking text (the
        // core alias rule: Base32 only via explicit import metadata).
        assert_eq!(derive_code(b"x/topt", raw, now), totp(raw, counter));
        assert_eq!(derive_code(b"x/topt", b32, now), totp(b32, counter));
        // Invalid seeds refuse (empty, and past the 64-byte key bound).
        assert_eq!(derive_code(b"x/topt", b"", now), None);
        assert_eq!(derive_code(b"x/topt", &[0u8; 65], now), None);
        // Misclassification: a value record named like a code, and a code
        // spelling the rule does not accept, derive NOTHING — the caller
        // refuses instead of publishing the record value.
        assert_eq!(derive_code(b"password", raw, now), None);
        assert_eq!(derive_code(b"x/TOTP", raw, now), None);
        assert_eq!(derive_code(b"x/topt-notes", raw, now), None);
    }
}
