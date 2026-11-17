//! `wsecret` command-line interface (bin target `wsecret`).
//!
//! Command dispatch for the eleven upstream commands (`secret.c`, pinned
//! `angt/secret` revision), wired onto `wsecret-core` store operations and
//! the sibling modules of this crate:
//!
//! - `args` (library target): the argz-exact parser, the command table, the
//!   parser-level `help`/usage branches and the `Option %s …` messages.
//! - [`console`]: `CONIN$`/`CONOUT$` prompting with echo suppression.
//! - [`output`]: `show`/`dump` rendering (TOTP dispatch, `s_printable`,
//!   Base64) and byte-exact stdout/stderr writes.
//! - [`agent`]: trusted-agent acquisition and launch.
//!
//! This file owns:
//!
//! 1. **Command dispatch** ([`Ctx::run`]) for `init`, `list`, `show`, `dump`,
//!    `new`, `set`, `renew`, `update`, `pass`, `agent` and `version`,
//!    including upstream's empty-input exit-0 policy, the no-records
//!    confirmation gate (`s_get_secret` `pass_ok` semantics) and the staged
//!    generate/print/commit flow for `new`/`renew` (the secret is printed
//!    BEFORE the write — plan audit P9).
//! 2. **The fatal string catalog** ([`msg_*`]): the literal upstream strings
//!    with their typos preserved (`Unkown version`, `Special characaters`).
//!    Every fatal is rendered as `Fatal: <body>\n` through
//!    [`args::fatal_line`] (upstream's 256-byte truncation) on stderr.
//! 3. **The help/completion matrix** (plan §4, audit P8): `… help` with a
//!    console stdout prints the usage line and exits 255; with a redirected
//!    stdout an authorized session lists names and exits 255 while an
//!    unauthorized (no agent capability) invocation exits 0 silently without
//!    opening `CONIN$`; `new`/`set help` produce NO usage and NO names.
//!
//! Exit codes (plan §4): 0 success / silent empty-input exit, 1 `Fatal: …`,
//! 255 usage, 254 parser help ([`args::run`] produces 255/254 itself).

mod agent;
mod console;
mod output;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use wsecret_cli::args::{self, Command, Dispatch, EXIT_FATAL, EXIT_OK, EXIT_USAGE};
use wsecret_core::error::{CommitFailure, Error, FormatError, NameError};
use wsecret_core::format::{Header, NAME_MAX, VERSION};
use wsecret_core::pass::{self, deterministic_pass};
use wsecret_core::session::{SecretBytes, Session};
use wsecret_core::store::{ScanOutcome, Store};
use wsecret_core::windows::agent_bridge::sessions_same_key;

use crate::agent::AgentLaunchError;
use crate::console::ConsoleError;

/// Upstream `s_ask_pass("Passphrase: ")`.
const PROMPT_PASSPHRASE: &str = agent::PROMPT_PASSPHRASE;
/// Upstream `s_get_secret`'s no-records retype prompt.
const PROMPT_CONFIRM: &str = agent::PROMPT_CONFIRM_NEW_PARTITION;
/// Upstream `s_input(secret, sizeof(secret), "Secret: ")`.
const PROMPT_SECRET: &str = "Secret: ";
/// Upstream `S_ENV_STORE`.
const ENV_STORE: &str = "SECRET_STORE";
/// Upstream `s_set_path`'s `HOME` fallback, then the Windows `%USERPROFILE%`
/// fallback (plan §4 divergence).
const ENV_HOME: &str = "HOME";
const ENV_USERPROFILE: &str = "USERPROFILE";

// -----------------------------------------------------------------------
// Fatal string catalog (plan §4; upstream strings verbatim, typos literal).
// Every function returns the message BODY only; `args::fatal_line` adds the
// `Fatal: ` prefix and the trailing newline with upstream's truncation.
// -----------------------------------------------------------------------

/// `s_fatal("Secret store %s doesn't exist", s.path)`.
fn msg_store_missing(path: &[u8]) -> Vec<u8> {
    let mut m = b"Secret store ".to_vec();
    m.extend_from_slice(path);
    m.extend_from_slice(b" doesn't exist");
    m
}

/// `s_fatal("Secret store %s already exists", s.path)`.
fn msg_store_exists(path: &[u8]) -> Vec<u8> {
    let mut m = b"Secret store ".to_vec();
    m.extend_from_slice(path);
    m.extend_from_slice(b" already exists");
    m
}

/// `s_fatal("Unable to read %s", s.path)`.
fn msg_unable_to_read(path: &[u8]) -> Vec<u8> {
    let mut m = b"Unable to read ".to_vec();
    m.extend_from_slice(path);
    m
}

/// `s_fatal("Unkown version %" PRIu8, s.x.hdr.version)` — upstream typo.
fn msg_unknown_version(version: u8) -> Vec<u8> {
    format!("Unkown version {version}").into_bytes()
}

/// `s_fatal("Store opslimit is below the minimum of %u", S_OPS_LIMIT)`.
fn msg_opslimit_too_low() -> Vec<u8> {
    format!(
        "Store opslimit is below the minimum of {}",
        wsecret_core::format::OPS_LIMIT_MIN
    )
    .into_bytes()
}

/// `s_fatal("s_ask_pass() failed")`.
fn msg_ask_pass_failed() -> Vec<u8> {
    b"s_ask_pass() failed".to_vec()
}

/// `s_fatal("Input too long!")`.
fn msg_input_too_long() -> Vec<u8> {
    b"Input too long!".to_vec()
}

/// `s_fatal("Invalid input!")`.
fn msg_invalid_input() -> Vec<u8> {
    b"Invalid input!".to_vec()
}

/// `s_fatal("Empty keys are not allowed")`.
fn msg_empty_keys() -> Vec<u8> {
    b"Empty keys are not allowed".to_vec()
}

/// `s_fatal("Special characaters are not allowed in keys")` — upstream typo.
fn msg_special_chars() -> Vec<u8> {
    b"Special characaters are not allowed in keys".to_vec()
}

/// `s_fatal("Keys are limited to %u bytes", S_KEYLENMAX)`.
fn msg_keys_limited() -> Vec<u8> {
    format!("Keys are limited to {NAME_MAX} bytes").into_bytes()
}

/// `s_fatal("Invalid secret")`.
fn msg_invalid_secret() -> Vec<u8> {
    b"Invalid secret".to_vec()
}

/// `s_fatal("Secret %s exists!", key)`.
fn msg_secret_exists(key: &[u8]) -> Vec<u8> {
    let mut m = b"Secret ".to_vec();
    m.extend_from_slice(key);
    m.extend_from_slice(b" exists!");
    m
}

/// `s_fatal("Secret %s not found", key)`.
fn msg_secret_not_found(key: &[u8]) -> Vec<u8> {
    let mut m = b"Secret ".to_vec();
    m.extend_from_slice(key);
    m.extend_from_slice(b" not found");
    m
}

/// `s_fatal("Entry too big!")`.
fn msg_entry_too_big() -> Vec<u8> {
    b"Entry too big!".to_vec()
}

/// `s_fatal("Unable to lock %s", s.path)`.
fn msg_unable_to_lock(path: &[u8]) -> Vec<u8> {
    let mut m = b"Unable to lock ".to_vec();
    m.extend_from_slice(path);
    m
}

/// `s_fatal("Passphrases don't match!")`.
fn msg_passphrases_dont_match() -> Vec<u8> {
    b"Passphrases don't match!".to_vec()
}

/// `s_init`: `if (getenv(S_ENV_AGENT)) s_fatal("Agent is running...")`.
fn msg_agent_running() -> Vec<u8> {
    b"Agent is running...".to_vec()
}

/// `s_agent`: `if (getenv(S_ENV_AGENT)) s_fatal("Already running...")`.
///
/// (Body rendered at the `AgentLaunchError` site; kept here as catalog
/// documentation and asserted by the tests.)
#[allow(dead_code)]
fn msg_already_running() -> Vec<u8> {
    b"Already running...".to_vec()
}

/// `s_fatal("Missing env SHELL, nothing to exec!")`.
#[allow(dead_code)]
fn msg_missing_shell() -> Vec<u8> {
    b"Missing env SHELL, nothing to exec!".to_vec()
}

/// `s_fatal("Unable to queue the key")`.
#[allow(dead_code)]
fn msg_unable_to_queue() -> Vec<u8> {
    b"Unable to queue the key".to_vec()
}

/// `s_set_path`: `s_fatal("Invalid path... Check $HOME or $" S_ENV_STORE)`.
fn msg_invalid_path() -> Vec<u8> {
    b"Invalid path... Check $HOME or $SECRET_STORE".to_vec()
}

/// `s_fatal("%s: %s", subject, strerror(errno))` — the strerror-wrapper
/// shape used for open/seek/exec/console failures.
fn msg_strerror(subject: &[u8], detail: &[u8]) -> Vec<u8> {
    let mut m = subject.to_vec();
    m.extend_from_slice(b": ");
    m.extend_from_slice(detail);
    m
}

fn io_detail(e: &io::Error) -> Vec<u8> {
    e.to_string().into_bytes()
}

/// The name-rule messages (`s_keylen`). `Exists`/`NotFound` carry no name
/// bytes in the library error, so their `%s` forms are built at the call
/// sites that still hold the key ([`msg_secret_exists`],
/// [`msg_secret_not_found`]).
fn name_message(name: &NameError) -> Vec<u8> {
    match name {
        NameError::Empty => msg_empty_keys(),
        NameError::SpecialChar => msg_special_chars(),
        NameError::TooLong => msg_keys_limited(),
        NameError::EntryTooBig => msg_entry_too_big(),
        // Unreachable through dispatch: both are rendered with the key at
        // their call sites; kept complete so the mapping is total.
        NameError::Exists => msg_secret_exists(b""),
        NameError::NotFound => msg_secret_not_found(b""),
    }
}

/// The store-format messages (`s_header` + the record-structure checks).
fn format_message(format: &FormatError, path: &[u8]) -> Vec<u8> {
    match format {
        FormatError::UnsupportedVersion(version) => msg_unknown_version(*version),
        FormatError::OpsLimitTooLow(_) => msg_opslimit_too_low(),
        FormatError::Name(name) => name_message(name),
        FormatError::EntryTooBig => msg_entry_too_big(),
        // Upstream's exact-match arm fatals `Invalid secret` on an
        // out-of-bounds `slen` (`s_get_secret`); the no-bounded-NUL case
        // would fatal `Keys are limited to 255 bytes` through `s_keylen`.
        // Core collapses both into `MalformedRecord`; the closer literal
        // `Invalid secret` is used and the collapse is a documented
        // message-only divergence.
        FormatError::MalformedRecord => msg_invalid_secret(),
        FormatError::StoreLayout => msg_unable_to_read(path),
    }
}

/// What a command ends with: a process exit code, upstream's silent
/// `s_exit(0)`, or a `Fatal: …` body (rendered by [`Ctx::finish`]).
enum Outcome {
    /// Exit with this code without further output.
    Code(u32),
    /// Upstream `s_exit(0)`: prompt EOF/empty input, wrong-passphrase
    /// `list`, unauthorized non-interactive completion.
    Silent,
    /// `Fatal: <body>\n` on stderr, exit 1.
    Fatal(Vec<u8>),
}

impl Outcome {
    fn fatal(body: Vec<u8>) -> Self {
        Outcome::Fatal(body)
    }
}

/// Maps a library error onto the catalog (plan §4: the CLI, never the
/// library, renders upstream strings). `path` is the store path for the
/// `"%s"`-shaped messages.
fn error_outcome(error: &Error, path: &[u8]) -> Outcome {
    match error {
        Error::StoreNotFound => Outcome::fatal(msg_store_missing(path)),
        Error::StoreExists => Outcome::fatal(msg_store_exists(path)),
        Error::Name(name) => Outcome::fatal(name_message(name)),
        Error::Format(format) => Outcome::fatal(format_message(format, path)),
        // Region lock / writer-mutex contention share upstream's one lock
        // message (`Unable to lock %s`).
        Error::Locked | Error::Busy => Outcome::fatal(msg_unable_to_lock(path)),
        Error::PassphraseMismatch => Outcome::fatal(msg_passphrases_dont_match()),
        Error::InvalidTotp => Outcome::fatal(msg_invalid_secret()),
        // Upstream exits 0 on empty prompt input (`s_exit(0)`).
        Error::Cancelled => Outcome::Silent,
        Error::Io(io) => Outcome::fatal(msg_strerror(path, &io_detail(io))),
        // Unreachable in dispatch (the confirmation gate runs here); mapped
        // to upstream's one ask-flow failure string so the mapping is total.
        Error::ConfirmationRequired => Outcome::fatal(msg_ask_pass_failed()),
        // No upstream string exists for these internal failures; the
        // library's diagnostic is the honest fallback.
        other => Outcome::fatal(other.to_string().into_bytes()),
    }
}

/// The console catalog bodies (`s_input`/`s_fatal` on the tty path).
fn console_message(error: &ConsoleError) -> Vec<u8> {
    match error {
        ConsoleError::InputTooLong => msg_input_too_long(),
        ConsoleError::InvalidInput => msg_invalid_input(),
        ConsoleError::ConsoleIn(e) => msg_strerror(b"CONIN$", &io_detail(e)),
        ConsoleError::ConsoleOut(e) => msg_strerror(b"CONOUT$", &io_detail(e)),
    }
}

/// Everything the dispatch touches outside `wsecret-core`: console
/// prompting, raw stdio, and the trusted-agent transport. Production wires
/// [`RealPlatform`]; tests substitute a scripted one, which is what makes
/// the dispatch logic unit-testable without a console or a child process.
trait Platform {
    /// Upstream `isatty(1)`: gates usage text and terminal rendering.
    fn stdout_is_console(&self) -> bool;
    /// Echo-suppressed passphrase entry (or its `--pass-hex` form). An
    /// empty line is the upstream `s_exit(0)` case; the real console exits
    /// itself, so dispatch defensively treats an empty return the same way.
    fn read_passphrase(&mut self, prompt: &str, pass_hex: bool) -> Result<Vec<u8>, ConsoleError>;
    /// Secret value entry (tty prompt or redirected stdin, upstream `s_do`).
    fn read_secret(&mut self, prompt: &str) -> Result<Vec<u8>, ConsoleError>;
    /// Byte-exact stdout write (no CRT text mode, no CRLF/BOM).
    fn write_stdout(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Byte-exact stderr write for `Fatal: …` lines.
    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Trusted-agent key adoption (`s_ask_agent`): `None` falls back to the
    /// passphrase path.
    fn agent_acquire(&mut self, header: &Header) -> Option<Session>;
    /// Trusted-agent launch (`s_agent`), returning the child's exit code.
    fn agent_launch(
        &mut self,
        store_path: &Path,
        cmd: &[&OsStr],
        pass_hex: bool,
    ) -> Result<i32, AgentLaunchError>;
    /// Upstream `getenv(S_ENV_AGENT)` presence test used by `init`.
    fn agent_env_set(&self) -> bool;
}

/// Production platform: the real console/output/agent modules.
struct RealPlatform;

impl Platform for RealPlatform {
    fn stdout_is_console(&self) -> bool {
        console::is_console()
    }

    fn read_passphrase(&mut self, prompt: &str, pass_hex: bool) -> Result<Vec<u8>, ConsoleError> {
        if pass_hex {
            console::read_passphrase_hex(prompt)
        } else {
            console::read_passphrase(prompt)
        }
    }

    fn read_secret(&mut self, prompt: &str) -> Result<Vec<u8>, ConsoleError> {
        console::read_secret(prompt)
    }

    fn write_stdout(&mut self, bytes: &[u8]) -> io::Result<()> {
        output::write_stdout(bytes)
    }

    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()> {
        output::write_stderr(bytes)
    }

    fn agent_acquire(&mut self, header: &Header) -> Option<Session> {
        agent::acquire(header)
    }

    fn agent_launch(
        &mut self,
        store_path: &Path,
        cmd: &[&OsStr],
        pass_hex: bool,
    ) -> Result<i32, AgentLaunchError> {
        let mut prompt = |p: &str| -> io::Result<Vec<u8>> {
            self.read_passphrase(p, pass_hex)
                .map_err(|e| io::Error::other(e.to_string()))
        };
        agent::launch(store_path, cmd, &mut prompt)
    }

    fn agent_env_set(&self) -> bool {
        std::env::var_os(wsecret_core::windows::agent_bridge::ENV_AGENT).is_some()
    }
}

/// One unlocked store: the open file plus the session key needed to use it
/// (upstream's open `fd` + derived `s.x.key` pair).
struct Unlocked {
    store: Store,
    session: Session,
}

/// The command context: store path, platform, and the plan-§4 global modes.
struct Ctx<P> {
    store_path: PathBuf,
    platform: P,
    /// `--pass-hex`: raw-byte passphrase entry (plan §5.4, audit P5).
    pass_hex: bool,
    /// `agent` command words as original `OsString`s (byte-exact argv for
    /// `CreateProcessW`; never round-tripped through UTF-8).
    agent_cmd: Vec<OsString>,
}

impl<P: Platform> Ctx<P> {
    fn path_bytes(&self) -> Vec<u8> {
        self.store_path.as_os_str().as_encoded_bytes().to_vec()
    }

    /// Renders the final fatal line and returns the process exit code.
    fn finish(&mut self, outcome: Outcome) -> u32 {
        match outcome {
            Outcome::Code(code) => code,
            Outcome::Silent => EXIT_OK,
            Outcome::Fatal(body) => {
                let _ = self.platform.write_stderr(&args::fatal_line(&body));
                EXIT_FATAL
            }
        }
    }

    fn write_stdout(&mut self, bytes: &[u8]) -> Result<(), Outcome> {
        self.platform
            .write_stdout(bytes)
            .map_err(|e| Outcome::fatal(msg_strerror(b"stdout", &io_detail(&e))))
    }

    fn error(&self, error: &Error) -> Outcome {
        error_outcome(error, &self.path_bytes())
    }

    fn commit_error(&self, failure: &CommitFailure) -> Outcome {
        // Plan §5.6 point 5: `CommitState::Unknown` means the write may have
        // landed — upstream would have silently truncated here. The stricter
        // wsecret behavior reports the underlying error and exits 1; the
        // commit state itself is a library/ABI concern.
        self.error(&failure.error)
    }

    /// Upstream `s_open_secret`: open, validate the header, adopt the agent
    /// key when offered, otherwise prompt on the console. `use_tty == false`
    /// is the non-interactive completion path: no agent capability means the
    /// upstream silent `s_exit(0)` ([`Outcome::Silent`]).
    fn open_session(&mut self, use_tty: bool, writable: bool) -> Result<Unlocked, Outcome> {
        let opened = if writable {
            Store::open(&self.store_path)
        } else {
            Store::open_read(&self.store_path)
        };
        let (store, header) = match opened {
            Ok(opened) => opened,
            Err(e) => return Err(self.error(&e)),
        };
        // Cover agent adoption and console passphrase acquisition, not just
        // the nested KDF guard inside Session::unlock/from_parts.
        let _acquisition = match wsecret_core::windows::security::begin_secret_acquisition() {
            Ok(guard) => guard,
            Err(error) => return Err(self.error(&error)),
        };
        if let Some(session) = self.platform.agent_acquire(&header) {
            return Ok(Unlocked { store, session });
        }
        if !use_tty {
            return Err(Outcome::Silent);
        }
        let mut pass = match self
            .platform
            .read_passphrase(PROMPT_PASSPHRASE, self.pass_hex)
        {
            Ok(pass) => pass,
            Err(e) => return Err(Outcome::fatal(console_message(&e))),
        };
        if pass.is_empty() {
            return Err(Outcome::Silent);
        }
        match Session::unlock(&header, &mut pass) {
            Ok(session) => Ok(Unlocked { store, session }),
            // Upstream: `if (s_unlock(pass, len)) s_fatal("s_ask_pass() failed")`.
            Err(_) => Err(Outcome::fatal(msg_ask_pass_failed())),
        }
    }

    /// Upstream `s_get_secret`'s no-records gate: when nothing decrypted,
    /// retype the passphrase and compare the derived keys in constant time
    /// (`Passphrases don't match!` on mismatch). Ok(()) may proceed.
    fn confirm_partition(&mut self, session: &Session) -> Result<(), Outcome> {
        let _acquisition = match wsecret_core::windows::security::begin_secret_acquisition() {
            Ok(guard) => guard,
            Err(error) => return Err(self.error(&error)),
        };
        let mut again = match self.platform.read_passphrase(PROMPT_CONFIRM, self.pass_hex) {
            Ok(pass) => pass,
            Err(e) => return Err(Outcome::fatal(console_message(&e))),
        };
        if again.is_empty() {
            return Err(Outcome::Silent);
        }
        let check = match Session::unlock(session.header(), &mut again) {
            Ok(session) => session,
            Err(_) => return Err(Outcome::fatal(msg_ask_pass_failed())),
        };
        match sessions_same_key(session, &check) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Outcome::fatal(msg_passphrases_dont_match())),
            Err(e) => Err(self.error(&e)),
        }
    }

    /// Secret value entry with the upstream `s_do` empty-input policy left to
    /// the caller (`None` = empty input; the buffer is wiped either way).
    fn read_secret(&mut self) -> Result<Option<SecretBytes>, Outcome> {
        let mut raw = match self.platform.read_secret(PROMPT_SECRET) {
            Ok(raw) => raw,
            Err(e) => return Err(Outcome::fatal(console_message(&e))),
        };
        if raw.is_empty() {
            return Ok(None);
        }
        let secret = SecretBytes::from_slice(&raw).map_err(|e| self.error(&e));
        libhydrogen_sys::memzero(&mut raw);
        Ok(Some(secret?))
    }

    /// Upstream `s_normalize_and_show` generation half: 512 random bytes
    /// normalized to a printable secret of at most `S_PWDGENLEN` characters
    /// (plan §4: `new`/`renew` print ≤25 chars from 512 candidates).
    fn generate_candidate(&self) -> Result<SecretBytes, Outcome> {
        let mut raw = [0u8; 512];
        libhydrogen_sys::random_buf(&mut raw);
        let normalized = pass::normalize_password(&raw);
        libhydrogen_sys::memzero(&mut raw);
        let mut normalized = normalized;
        let secret = SecretBytes::from_slice(&normalized).map_err(|e| self.error(&e));
        libhydrogen_sys::memzero(&mut normalized);
        secret
    }

    /// Writes the generated secret to stdout exactly as upstream
    /// `s_normalize_and_show` does (raw characters, console newline), then
    /// returns the buffer for the commit step — the print happens BEFORE the
    /// write (plan audit P9 write-failure window, parity preserved).
    fn print_generated(&mut self, secret: &SecretBytes) -> Result<(), Outcome> {
        let mut shown = secret.as_slice().to_vec();
        if self.platform.stdout_is_console() {
            shown.push(b'\n');
        }
        let result = self.write_stdout(&shown);
        libhydrogen_sys::memzero(&mut shown);
        result
    }

    /// Shared `s_print_keys` body: one `name\n` per matching record, in
    /// physical order (upstream always emits the newline, even piped).
    fn list_names(&mut self, mut unlocked: Unlocked, needle: Option<&[u8]>) -> Result<(), Outcome> {
        let mut out = Vec::new();
        {
            let Unlocked { store, session } = &mut unlocked;
            let mut sink = |name: &[u8]| -> Result<(), Error> {
                out.extend_from_slice(name);
                out.push(b'\n');
                Ok(())
            };
            if let Err(e) = store.scan_each(session, needle, &mut sink) {
                return Err(self.error(&e));
            }
        }
        self.write_stdout(&out)
    }

    /// Non-interactive name completion (`s_print_keys(NULL, 0)`): names and
    /// exit 255 when authorized, silent exit 0 otherwise (audit P8).
    fn run_complete_names(&mut self) -> Outcome {
        let unlocked = match self.open_session(false, false) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        match self.list_names(unlocked, None) {
            Ok(()) => Outcome::Code(EXIT_USAGE),
            Err(outcome) => outcome,
        }
    }

    fn run_list(&mut self, needle: Option<&[u8]>) -> Outcome {
        let unlocked = match self.open_session(true, false) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        match self.list_names(unlocked, needle) {
            Ok(()) => Outcome::Code(EXIT_OK),
            Err(outcome) => outcome,
        }
    }

    /// `show` (dump = false) and `dump` (dump = true): the first record with
    /// this exact name; `dump` bypasses TOTP ONLY (plan §1.11).
    fn run_show(&mut self, key: &[u8], dump: bool) -> Outcome {
        let mut unlocked = match self.open_session(true, false) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let found = {
            let Unlocked { store, session } = &mut unlocked;
            match store.find(session, key, false) {
                Err(e) => return self.error(&e),
                Ok(ScanOutcome::NotFound { .. }) => {
                    return Outcome::fatal(msg_secret_not_found(key));
                }
                Ok(ScanOutcome::Found { name, value, .. }) => (name, value),
            }
        };
        let (name, value) = found;
        let totp_name = !dump && contains(&name, b"totp");
        let rendered = output::render_value(&value, dump, &name, self.platform.stdout_is_console());
        if totp_name && rendered.is_empty() {
            // Upstream `s_show`: an empty TOTP struct is `Fatal: Invalid
            // secret`, printed before any stdout byte.
            return Outcome::fatal(msg_invalid_secret());
        }
        match self.write_stdout(&rendered) {
            Ok(()) => Outcome::Code(EXIT_OK),
            Err(outcome) => outcome,
        }
    }

    /// `new KEY`: requires absence, generates and prints the secret, then
    /// commits it into the first `DELETED:` tombstone slot or at EOF.
    fn run_new(&mut self, key: &[u8]) -> Outcome {
        let mut unlocked = match self.open_session(true, true) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let Unlocked { store, session } = &mut unlocked;
        let mut store = match store.lock_writers_scoped() {
            Ok(store) => store,
            Err(error) => return self.error(&error),
        };
        let (tombstone, decrypted_any) = match store.find(session, key, true) {
            Err(Error::Name(NameError::Exists)) => {
                return Outcome::fatal(msg_secret_exists(key));
            }
            Err(e) => return self.error(&e),
            Ok(ScanOutcome::Found { .. }) => {
                return Outcome::fatal(msg_secret_exists(key));
            }
            Ok(ScanOutcome::NotFound {
                tombstone,
                decrypted_any,
            }) => (tombstone, decrypted_any),
        };
        if !decrypted_any {
            if let Err(outcome) = self.confirm_partition(session) {
                return outcome;
            }
        }
        let candidate = match self.generate_candidate() {
            Ok(candidate) => candidate,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = self.print_generated(&candidate) {
            return outcome;
        }
        match store.append_or_reuse(tombstone, session, key, candidate.as_slice()) {
            Ok(_) => Outcome::Code(EXIT_OK),
            Err(failure) => self.commit_error(&failure),
        }
    }

    /// `set KEY`: requires absence, stores the entered value.
    fn run_set(&mut self, key: &[u8]) -> Outcome {
        let mut unlocked = match self.open_session(true, true) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let Unlocked { store, session } = &mut unlocked;
        let mut store = match store.lock_writers_scoped() {
            Ok(store) => store,
            Err(error) => return self.error(&error),
        };
        let (tombstone, decrypted_any) = match store.find(session, key, true) {
            Err(Error::Name(NameError::Exists)) => {
                return Outcome::fatal(msg_secret_exists(key));
            }
            Err(e) => return self.error(&e),
            Ok(ScanOutcome::Found { .. }) => {
                return Outcome::fatal(msg_secret_exists(key));
            }
            Ok(ScanOutcome::NotFound {
                tombstone,
                decrypted_any,
            }) => (tombstone, decrypted_any),
        };
        if !decrypted_any {
            if let Err(outcome) = self.confirm_partition(session) {
                return outcome;
            }
        }
        let secret = match self.read_secret() {
            Ok(secret) => secret,
            Err(outcome) => return outcome,
        };
        let Some(secret) = secret else {
            // Upstream `s_do`: empty input and nothing to keep → `s_exit(0)`.
            return Outcome::Silent;
        };
        match store.append_or_reuse(tombstone, session, key, secret.as_slice()) {
            Ok(_) => Outcome::Code(EXIT_OK),
            Err(failure) => self.commit_error(&failure),
        }
    }

    /// `renew KEY`: requires an existing record, replaces its value with a
    /// fresh generated secret in place (name kept).
    fn run_renew(&mut self, key: &[u8]) -> Outcome {
        let mut unlocked = match self.open_session(true, true) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let Unlocked { store, session } = &mut unlocked;
        let mut store = match store.lock_writers_scoped() {
            Ok(store) => store,
            Err(error) => return self.error(&error),
        };
        let slot = match store.find(session, key, false) {
            Err(e) => return self.error(&e),
            Ok(ScanOutcome::NotFound { .. }) => {
                return Outcome::fatal(msg_secret_not_found(key));
            }
            Ok(ScanOutcome::Found { slot, .. }) => slot,
        };
        let candidate = match self.generate_candidate() {
            Ok(candidate) => candidate,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = self.print_generated(&candidate) {
            return outcome;
        }
        match store.write_slot(slot, session, key, candidate.as_slice()) {
            Ok(_) => Outcome::Code(EXIT_OK),
            Err(failure) => self.commit_error(&failure),
        }
    }

    /// `update KEY [NEWKEY]`: requires an existing record; replaces the
    /// value, optionally renaming. `update KEY NEWKEY` with empty input keeps
    /// the old value (upstream rename-keeps-value rule, `secret.c` s_do);
    /// bare `update KEY` with empty input exits 0 without a write.
    fn run_update(&mut self, key: &[u8], new_key: Option<&[u8]>) -> Outcome {
        let mut unlocked = match self.open_session(true, true) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let Unlocked { store, session } = &mut unlocked;
        let mut store = match store.lock_writers_scoped() {
            Ok(store) => store,
            Err(error) => return self.error(&error),
        };
        let (slot, mut old_value) = match store.find(session, key, false) {
            Err(e) => return self.error(&e),
            Ok(ScanOutcome::NotFound { .. }) => {
                return Outcome::fatal(msg_secret_not_found(key));
            }
            Ok(ScanOutcome::Found { slot, value, .. }) => (slot, value),
        };
        let name = new_key.unwrap_or(key);
        let mut value = match self.read_secret() {
            Err(outcome) => {
                libhydrogen_sys::memzero(&mut old_value);
                return outcome;
            }
            Ok(Some(secret)) => secret.as_slice().to_vec(),
            Ok(None) => match new_key {
                // Rename form with empty input: keep the old value bytes.
                Some(_) => std::mem::take(&mut old_value),
                None => {
                    libhydrogen_sys::memzero(&mut old_value);
                    return Outcome::Silent;
                }
            },
        };
        libhydrogen_sys::memzero(&mut old_value);
        let outcome = match store.write_slot(slot, session, name, &value) {
            Ok(_) => Outcome::Code(EXIT_OK),
            Err(failure) => self.commit_error(&failure),
        };
        libhydrogen_sys::memzero(&mut value);
        outcome
    }

    /// `pass KEY [SUBKEY...]`: unstored deterministic derivation over every
    /// word (upstream chains `argv[1..]`); an empty partition requires the
    /// confirmation retype.
    fn run_pass(&mut self, keys: &[&[u8]]) -> Outcome {
        let mut unlocked = match self.open_session(true, false) {
            Ok(unlocked) => unlocked,
            Err(outcome) => return outcome,
        };
        let mut decrypted_any = false;
        {
            let Unlocked { store, session } = &mut unlocked;
            let mut sink = |_: &[u8]| -> Result<(), Error> {
                decrypted_any = true;
                Ok(())
            };
            if let Err(e) = store.scan_each(session, None, &mut sink) {
                return self.error(&e);
            }
        }
        if !decrypted_any {
            if let Err(outcome) = self.confirm_partition(&unlocked.session) {
                return outcome;
            }
        }
        let mut derived = match deterministic_pass(&unlocked.session, keys) {
            Ok(derived) => derived,
            Err(e) => return self.error(&e),
        };
        if self.platform.stdout_is_console() {
            derived.push(b'\n');
        }
        let outcome = self.write_stdout(&derived);
        libhydrogen_sys::memzero(&mut derived);
        match outcome {
            Ok(()) => Outcome::Code(EXIT_OK),
            Err(outcome) => outcome,
        }
    }

    /// `agent [CMD [ARG...]]`: launch the trusted zone and propagate the
    /// child's exit code (upstream `execvp` semantics).
    fn run_agent(&mut self) -> Outcome {
        let cmd: Vec<&OsStr> = self.agent_cmd.iter().map(OsString::as_os_str).collect();
        match self
            .platform
            .agent_launch(&self.store_path, &cmd, self.pass_hex)
        {
            Ok(code) => Outcome::Code(code as u32),
            Err(AgentLaunchError::Cancelled) => Outcome::Silent,
            Err(AgentLaunchError::Core(e)) => self.error(&e),
            Err(e) => match e.message() {
                Some(body) => Outcome::fatal(body.into_bytes()),
                None => Outcome::Silent,
            },
        }
    }

    /// `version`: exactly `0.21\n` (byte parity; plan §4).
    fn run_version(&mut self) -> Outcome {
        let text = format!("{}.{}\n", VERSION.0, VERSION.1);
        match self.write_stdout(text.as_bytes()) {
            Ok(()) => Outcome::Code(EXIT_OK),
            Err(outcome) => outcome,
        }
    }

    /// `init [opslimit N]`: exclusive creation of the 512-byte header block.
    fn run_init(&mut self, ops_limit: u64) -> Outcome {
        if self.platform.agent_env_set() {
            return Outcome::fatal(msg_agent_running());
        }
        match Store::create(&self.store_path, ops_limit) {
            Ok(_) => Outcome::Code(EXIT_OK),
            Err(failure) => self.commit_error(&failure),
        }
    }

    /// Command dispatch table (upstream `main`'s `struct argz z[]` bodies).
    fn run(&mut self, command: Command<'_>) -> Outcome {
        match command {
            Command::Init { ops_limit } => self.run_init(ops_limit),
            Command::List { needle } => self.run_list(needle),
            Command::Show { key } => self.run_show(key, false),
            Command::Dump { key } => self.run_show(key, true),
            Command::New { key } => self.run_new(key),
            Command::Set { key } => self.run_set(key),
            Command::Renew { key } => self.run_renew(key),
            Command::Update { key, new_key } => self.run_update(key, new_key),
            Command::Pass { keys } => self.run_pass(keys),
            Command::Agent { .. } => self.run_agent(),
            Command::Version => self.run_version(),
        }
    }
}

/// Substring test with upstream `strstr` semantics (`s_show`'s TOTP gate).
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= hay.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// Bridges [`args::Dispatch`] to [`Ctx`]: executes parsed commands and owns
/// the fatal rendering/exit-code mapping.
struct Dispatcher<P> {
    ctx: Ctx<P>,
}

impl<P: Platform> Dispatch for Dispatcher<P> {
    fn execute(&mut self, command: Command<'_>) -> u32 {
        let outcome = self.ctx.run(command);
        self.ctx.finish(outcome)
    }

    fn complete_names(&mut self) -> u32 {
        let outcome = self.ctx.run_complete_names();
        self.ctx.finish(outcome)
    }
}

// -----------------------------------------------------------------------
// argv preparation: the plan-§4 global modes and the store path.
// -----------------------------------------------------------------------

/// `--keys-hex`/`--pass-hex` are wsecret additions (plan §4) and are stripped
/// from argv before the argz-exact walk sees it.
struct Flags {
    keys_hex: bool,
    pass_hex: bool,
}

fn strip_flags(mut raw: Vec<OsString>) -> (Vec<OsString>, Flags) {
    let mut flags = Flags {
        keys_hex: false,
        pass_hex: false,
    };
    let mut kept = Vec::with_capacity(raw.len());
    for (index, word) in raw.drain(..).enumerate() {
        if index > 0 && word == "--keys-hex" {
            flags.keys_hex = true;
        } else if index > 0 && word == "--pass-hex" {
            flags.pass_hex = true;
        } else {
            kept.push(word);
        }
    }
    (kept, flags)
}

/// Commands whose positional words are record keys / needle / subkeys
/// (`--keys-hex` decodes them; `help` is kept literal so the help matrix
/// still works under the mode).
const KEY_COMMANDS: &[&[u8]] = &[
    b"list", b"show", b"dump", b"new", b"set", b"renew", b"update", b"pass",
];

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Strict hex decoding for `--keys-hex` operands: `[0-9a-fA-F]` pairs only.
fn decode_hex(word: &[u8]) -> Option<Vec<u8>> {
    if word.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(word.len() / 2);
    for pair in word.chunks(2) {
        out.push(hex_value(pair[0])? << 4 | hex_value(pair[1])?);
    }
    Some(out)
}

/// Encodes the stripped argv for [`args::parse`]: raw bytes by default,
/// hex-decoded operands under `--keys-hex`. Errors carry the catalog body
/// (`Invalid input!`).
fn encode_argv(words: &[OsString], keys_hex: bool) -> Result<Vec<Vec<u8>>, Vec<u8>> {
    let mut out = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let raw = word.as_encoded_bytes();
        let decode = keys_hex
            && index >= 2
            && raw != b"help"
            && words.get(1).is_some_and(|cmd| {
                let cmd = cmd.as_encoded_bytes();
                KEY_COMMANDS.contains(&cmd)
            });
        if decode {
            out.push(decode_hex(raw).ok_or_else(msg_invalid_input)?);
        } else {
            out.push(raw.to_vec());
        }
    }
    Ok(out)
}

/// Upstream `s_set_path`: nonempty `$SECRET_STORE`, else `$HOME/.secret`,
/// else `%USERPROFILE%\.secret` (plan §4 divergence), else the upstream
/// empty-home literal; the resolved path must be 2..1023 bytes.
fn resolve_store_path(
    store: Option<OsString>,
    home: Option<OsString>,
    userprofile: Option<OsString>,
) -> Result<PathBuf, Vec<u8>> {
    let nonempty = |value: &Option<OsString>| match value {
        Some(value) if !value.is_empty() => Some(value.clone()),
        _ => None,
    };
    let path = if let Some(store) = nonempty(&store) {
        PathBuf::from(store)
    } else if let Some(home) = nonempty(&home) {
        PathBuf::from(home).join(".secret")
    } else if let Some(userprofile) = nonempty(&userprofile) {
        PathBuf::from(userprofile).join(".secret")
    } else {
        PathBuf::from("/.secret")
    };
    let len = path.as_os_str().as_encoded_bytes().len();
    if len <= 1 || len >= 1024 {
        return Err(msg_invalid_path());
    }
    Ok(path)
}

/// `std::io::Write` adapter over [`output::write_stdout`] so [`args::Cli`]
/// gets byte-exact writes (never the CRT text mode).
struct StdoutSink;

impl Write for StdoutSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        output::write_stdout(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Same for stderr ([`output::write_stderr`]).
struct StderrSink;

impl Write for StderrSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        output::write_stderr(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wires argv, the store path and the platform into [`args::run`] and
/// returns the process exit code.
fn run_main(raw: Vec<OsString>, mut platform: impl Platform) -> u32 {
    let (words, flags) = strip_flags(raw);
    let store_path = match resolve_store_path(
        std::env::var_os(ENV_STORE),
        std::env::var_os(ENV_HOME),
        std::env::var_os(ENV_USERPROFILE),
    ) {
        Ok(path) => path,
        Err(body) => {
            let _ = platform.write_stderr(&args::fatal_line(&body));
            return EXIT_FATAL;
        }
    };
    let owned = match encode_argv(&words, flags.keys_hex) {
        Ok(owned) => owned,
        Err(body) => {
            let _ = platform.write_stderr(&args::fatal_line(&body));
            return EXIT_FATAL;
        }
    };
    let argv: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    // `agent` takes its command words as original `OsString`s (byte-exact
    // for `CreateProcessW`); everything else runs on the encoded bytes.
    let agent_cmd = if words
        .get(1)
        .is_some_and(|cmd| cmd.as_encoded_bytes() == b"agent")
    {
        words[2..].to_vec()
    } else {
        Vec::new()
    };
    let stdout_is_tty = platform.stdout_is_console();
    let mut dispatcher = Dispatcher {
        ctx: Ctx {
            store_path,
            platform,
            pass_hex: flags.pass_hex,
            agent_cmd,
        },
    };
    let (mut out, mut err) = (StdoutSink, StderrSink);
    let mut cli = args::Cli {
        stdout_is_tty,
        stdout: &mut out,
        stderr: &mut err,
    };
    args::run(&argv, &mut cli, &mut dispatcher)
}

fn main() {
    libhydrogen_sys::init();
    // §5.8: harden the process and every existing thread before argument
    // dispatch, store access, agent adoption, prompting, or KDF execution.
    if let Err(error) = wsecret_core::windows::security::init_process_protection() {
        let _ = output::write_stderr(&args::fatal_line(error.to_string().as_bytes()));
        std::process::exit(EXIT_FATAL as i32);
    }
    // Upstream installs its no-op signal handlers before any work (plan §4
    // console-ctrl parity); setup failure is ignored like upstream's.
    let _ = console::install_console_ctrl_handler();
    let code = run_main(std::env::args_os().collect(), RealPlatform);
    std::process::exit(code as i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wsecret_core::format::OPS_LIMIT_MIN;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wsecret-cli-test-{}-{}-{tag}.secret",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    const PW: &[u8] = b"correct horse";

    fn unlock_pw(header: &Header) -> Session {
        Session::unlock(header, &mut PW.to_vec()).expect("unlock fixture")
    }

    /// Fixture store mirroring the `wsecret-core` store tests: header block
    /// (fast opslimit) plus whole records appended upstream-style.
    struct Fixture {
        path: PathBuf,
        header: Header,
    }

    impl Fixture {
        fn new(tag: &str, entries: &[(&[u8], &[u8])]) -> Fixture {
            let path = temp_path(tag);
            let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
            let session = unlock_pw(&header);
            for (name, value) in entries {
                store
                    .append_or_reuse(None, &session, name, value)
                    .expect("append record");
            }
            Fixture { path, header }
        }

        fn empty(tag: &str) -> Fixture {
            Fixture::new(tag, &[])
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Scripted [`Platform`]: fixed passphrases, queued secret values, a
    /// switchable agent capability and captured stdio. This is what makes
    /// every dispatch path testable without a console or a child process.
    struct FakePlatform {
        passphrase: Vec<u8>,
        confirm: Option<Vec<u8>>,
        secrets: VecDeque<Vec<u8>>,
        /// Optional prompt gate for the concurrent-writer regression: ready
        /// is signaled after the scan, before the write can proceed.
        secret_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        agent_session: bool,
        agent_env: bool,
        launch: LaunchScript,
        stdout_tty: bool,
        out: Vec<u8>,
        err: Vec<u8>,
        prompts: Vec<String>,
    }

    #[derive(Clone, Debug)]
    enum LaunchScript {
        Code(i32),
        AlreadyRunning,
        MissingShell,
        QueueKey,
        Exec(&'static str, &'static str),
        Cancelled,
        Mismatch,
        StoreMissing,
    }

    impl FakePlatform {
        fn new() -> FakePlatform {
            FakePlatform {
                passphrase: PW.to_vec(),
                confirm: None,
                secrets: VecDeque::new(),
                secret_gate: None,
                agent_session: false,
                agent_env: false,
                launch: LaunchScript::Code(0),
                stdout_tty: false,
                out: Vec::new(),
                err: Vec::new(),
                prompts: Vec::new(),
            }
        }

        fn tty() -> FakePlatform {
            FakePlatform {
                stdout_tty: true,
                ..FakePlatform::new()
            }
        }

        /// Authorized completion: an agent capability with the fixture key.
        fn authorized() -> FakePlatform {
            FakePlatform {
                agent_session: true,
                ..FakePlatform::new()
            }
        }

        fn with_secret(mut self, value: &[u8]) -> FakePlatform {
            self.secrets.push_back(value.to_vec());
            self
        }
    }

    impl Platform for FakePlatform {
        fn stdout_is_console(&self) -> bool {
            self.stdout_tty
        }

        fn read_passphrase(
            &mut self,
            prompt: &str,
            _pass_hex: bool,
        ) -> Result<Vec<u8>, ConsoleError> {
            self.prompts.push(prompt.to_owned());
            if prompt == PROMPT_CONFIRM {
                Ok(self
                    .confirm
                    .clone()
                    .unwrap_or_else(|| self.passphrase.clone()))
            } else {
                Ok(self.passphrase.clone())
            }
        }

        fn read_secret(&mut self, prompt: &str) -> Result<Vec<u8>, ConsoleError> {
            self.prompts.push(prompt.to_owned());
            if let Some((ready, release)) = &self.secret_gate {
                ready.send(()).expect("prompt gate ready");
                release.recv().expect("prompt gate release");
            }
            Ok(self.secrets.pop_front().unwrap_or_default())
        }

        fn write_stdout(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.out.extend_from_slice(bytes);
            Ok(())
        }

        fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.err.extend_from_slice(bytes);
            Ok(())
        }

        fn agent_acquire(&mut self, header: &Header) -> Option<Session> {
            if self.agent_session {
                Session::unlock(header, &mut PW.to_vec()).ok()
            } else {
                None
            }
        }

        fn agent_launch(
            &mut self,
            _store_path: &Path,
            _cmd: &[&OsStr],
            _pass_hex: bool,
        ) -> Result<i32, AgentLaunchError> {
            match self.launch.clone() {
                LaunchScript::Code(code) => Ok(code),
                LaunchScript::AlreadyRunning => Err(AgentLaunchError::AlreadyRunning),
                LaunchScript::MissingShell => Err(AgentLaunchError::MissingShell),
                LaunchScript::QueueKey => Err(AgentLaunchError::QueueKey),
                LaunchScript::Exec(name, error) => Err(AgentLaunchError::Exec {
                    name: name.to_owned(),
                    error: io::Error::other(error),
                }),
                LaunchScript::Cancelled => Err(AgentLaunchError::Cancelled),
                LaunchScript::Mismatch => Err(AgentLaunchError::PassphraseMismatch),
                LaunchScript::StoreMissing => Err(AgentLaunchError::Core(Error::StoreNotFound)),
            }
        }

        fn agent_env_set(&self) -> bool {
            self.agent_env
        }
    }

    /// One dispatch run: parse + execute through the real [`args::run`].
    struct Run {
        code: u32,
        /// Command output ([`Platform::write_stdout`]).
        out: Vec<u8>,
        /// Fatal lines ([`Platform::write_stderr`]).
        err: Vec<u8>,
        /// Parser-level output (table, usage lines, `Option …` values).
        parser_out: Vec<u8>,
        /// Parser-level errors (the `Option …` messages).
        parser_err: Vec<u8>,
        prompts: Vec<String>,
    }

    fn dispatch(path: &Path, platform: FakePlatform, words: &[&[u8]]) -> Run {
        let mut argv_owned: Vec<Vec<u8>> = vec![b"wsecret".to_vec()];
        argv_owned.extend(words.iter().map(|w| w.to_vec()));
        let argv: Vec<&[u8]> = argv_owned.iter().map(Vec::as_slice).collect();
        let agent_cmd = if words.first() == Some(&b"agent".as_slice()) {
            words[1..]
                .iter()
                .map(|w| OsString::from(String::from_utf8_lossy(w).into_owned()))
                .collect()
        } else {
            Vec::new()
        };
        let mut parser_out = Vec::new();
        let mut parser_err = Vec::new();
        let mut dispatcher = Dispatcher {
            ctx: Ctx {
                store_path: path.to_path_buf(),
                platform,
                pass_hex: false,
                agent_cmd,
            },
        };
        let code = {
            let mut cli = args::Cli {
                stdout_is_tty: dispatcher.ctx.platform.stdout_tty,
                stdout: &mut parser_out,
                stderr: &mut parser_err,
            };
            args::run(&argv, &mut cli, &mut dispatcher)
        };
        let platform = dispatcher.ctx.platform;
        Run {
            code,
            out: platform.out,
            err: platform.err,
            parser_out,
            parser_err,
            prompts: platform.prompts,
        }
    }

    fn fatal(body: &[u8]) -> Vec<u8> {
        args::fatal_line(body)
    }

    /// §5.6 points 1-2 at the REAL CLI dispatch layer: `set` holds the named
    /// writer mutex from its absence scan through the secret prompt and final
    /// append. A second writer therefore gets BUSY (`Unable to lock`), never a
    /// mandatory-range-lock scan failure or a lost update.
    #[test]
    fn cli_set_holds_writer_mutex_across_prompt_and_write() {
        let fx = Fixture::new("cli-writer-critical-section", &[(b"alpha", b"one")]);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut first_platform = FakePlatform::new().with_secret(b"first");
        first_platform.secret_gate = Some((ready_tx, release_rx));
        let first_path = fx.path.clone();
        let first =
            std::thread::spawn(move || dispatch(&first_path, first_platform, &[b"set", b"beta"]));
        ready_rx.recv().expect("first writer reached its prompt");

        let second = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(b"second"),
            &[b"set", b"gamma"],
        );
        assert_eq!(second.code, EXIT_FATAL);
        assert_eq!(
            second.err,
            fatal(&msg_unable_to_lock(fx.path.as_os_str().as_encoded_bytes())),
            "second writer must fail at the named writer mutex"
        );

        release_tx.send(()).expect("release first writer");
        let first = first.join().expect("first writer thread");
        assert_eq!(
            first.code,
            EXIT_OK,
            "first writer stderr: {:?}",
            String::from_utf8_lossy(&first.err)
        );

        let (mut store, header) = Store::open(&fx.path).expect("reopen store");
        let session = unlock_pw(&header);
        match store.find(&session, b"beta", false).expect("find beta") {
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"first"),
            other => panic!("beta missing: {other:?}"),
        }
        assert!(
            matches!(
                store.find(&session, b"gamma", false).expect("find gamma"),
                ScanOutcome::NotFound { .. }
            ),
            "BUSY loser must not have written gamma"
        );
    }

    // ---- error string catalog ----------------------------------------

    #[test]
    fn catalog_strings_are_literal_upstream() {
        assert_eq!(
            msg_store_missing(b"/x/.secret"),
            b"Secret store /x/.secret doesn't exist"
        );
        assert_eq!(
            msg_store_exists(b"/x/.secret"),
            b"Secret store /x/.secret already exists"
        );
        assert_eq!(
            msg_unable_to_read(b"/x/.secret"),
            b"Unable to read /x/.secret"
        );
        assert_eq!(msg_unknown_version(3), b"Unkown version 3");
        assert_eq!(
            msg_opslimit_too_low(),
            b"Store opslimit is below the minimum of 10000"
        );
        assert_eq!(msg_ask_pass_failed(), b"s_ask_pass() failed");
        assert_eq!(msg_input_too_long(), b"Input too long!");
        assert_eq!(msg_invalid_input(), b"Invalid input!");
        assert_eq!(msg_empty_keys(), b"Empty keys are not allowed");
        // Typos are literal.
        assert_eq!(
            msg_special_chars(),
            b"Special characaters are not allowed in keys"
        );
        assert_eq!(msg_keys_limited(), b"Keys are limited to 255 bytes");
        assert_eq!(msg_invalid_secret(), b"Invalid secret");
        assert_eq!(msg_secret_exists(b"k"), b"Secret k exists!");
        assert_eq!(msg_secret_not_found(b"k"), b"Secret k not found");
        assert_eq!(msg_entry_too_big(), b"Entry too big!");
        assert_eq!(
            msg_unable_to_lock(b"/x/.secret"),
            b"Unable to lock /x/.secret"
        );
        assert_eq!(msg_passphrases_dont_match(), b"Passphrases don't match!");
        assert_eq!(msg_agent_running(), b"Agent is running...");
        assert_eq!(msg_already_running(), b"Already running...");
        assert_eq!(msg_missing_shell(), b"Missing env SHELL, nothing to exec!");
        assert_eq!(msg_unable_to_queue(), b"Unable to queue the key");
        assert_eq!(
            msg_invalid_path(),
            b"Invalid path... Check $HOME or $SECRET_STORE"
        );
        assert_eq!(msg_strerror(b"/dev/tty", b"ok"), b"/dev/tty: ok");
    }

    #[test]
    fn error_mapping_uses_the_catalog() {
        let path = b"/x/.secret".to_vec();
        let body = |e: &Error| match error_outcome(e, &path) {
            Outcome::Fatal(m) => m,
            other => panic!("expected fatal, got {:?}", matches!(other, Outcome::Silent)),
        };
        assert_eq!(body(&Error::StoreNotFound), msg_store_missing(&path));
        assert_eq!(body(&Error::StoreExists), msg_store_exists(&path));
        assert_eq!(
            body(&Error::Name(NameError::Empty)),
            b"Empty keys are not allowed"
        );
        assert_eq!(
            body(&Error::Name(NameError::SpecialChar)),
            b"Special characaters are not allowed in keys"
        );
        assert_eq!(body(&Error::Name(NameError::TooLong)), msg_keys_limited());
        assert_eq!(
            body(&Error::Name(NameError::EntryTooBig)),
            msg_entry_too_big()
        );
        assert_eq!(
            body(&Error::Format(FormatError::UnsupportedVersion(9))),
            b"Unkown version 9"
        );
        assert_eq!(
            body(&Error::Format(FormatError::OpsLimitTooLow(1))),
            msg_opslimit_too_low()
        );
        assert_eq!(
            body(&Error::Format(FormatError::MalformedRecord)),
            b"Invalid secret"
        );
        assert_eq!(
            body(&Error::Format(FormatError::StoreLayout)),
            msg_unable_to_read(&path)
        );
        assert_eq!(body(&Error::Locked), msg_unable_to_lock(&path));
        assert_eq!(body(&Error::Busy), msg_unable_to_lock(&path));
        assert_eq!(
            body(&Error::PassphraseMismatch),
            msg_passphrases_dont_match()
        );
        assert_eq!(body(&Error::InvalidTotp), b"Invalid secret");
        assert_eq!(body(&Error::ConfirmationRequired), msg_ask_pass_failed());
        // Empty input / cancellation is upstream's silent exit 0.
        assert!(matches!(
            error_outcome(&Error::Cancelled, &path),
            Outcome::Silent
        ));
        // `"%s: %s"` strerror wrapper.
        let io = Error::Io(io::Error::from_raw_os_error(5));
        assert!(body(&io).starts_with(b"/x/.secret: "));
    }

    #[test]
    fn console_errors_render_catalog_bodies() {
        assert_eq!(
            console_message(&ConsoleError::InputTooLong),
            b"Input too long!"
        );
        assert_eq!(
            console_message(&ConsoleError::InvalidInput),
            b"Invalid input!"
        );
        assert_eq!(
            console_message(&ConsoleError::ConsoleIn(io::Error::other("x"))),
            b"CONIN$: x"
        );
        assert_eq!(
            console_message(&ConsoleError::ConsoleOut(io::Error::other("y"))),
            b"CONOUT$: y"
        );
    }

    // ---- store path resolution ---------------------------------------

    #[test]
    fn store_path_prefers_secret_store() {
        assert_eq!(
            resolve_store_path(
                Some(OsString::from(r"D:\s.store")),
                Some(OsString::from("C:\\home")),
                Some(OsString::from("C:\\up")),
            )
            .unwrap(),
            PathBuf::from(r"D:\s.store")
        );
    }

    #[test]
    fn store_path_falls_back_to_home_then_userprofile() {
        assert_eq!(
            resolve_store_path(None, Some(OsString::from("C:\\home")), None).unwrap(),
            PathBuf::from("C:\\home").join(".secret")
        );
        assert_eq!(
            resolve_store_path(Some(OsString::new()), None, Some(OsString::from("C:\\up")),)
                .unwrap(),
            PathBuf::from("C:\\up").join(".secret")
        );
        // Upstream empty-home literal.
        assert_eq!(
            resolve_store_path(None, None, None).unwrap(),
            PathBuf::from("/.secret")
        );
    }

    #[test]
    fn store_path_length_is_validated() {
        assert_eq!(
            resolve_store_path(Some(OsString::from("x")), None, None).unwrap_err(),
            msg_invalid_path()
        );
        let long = "y".repeat(1024);
        assert_eq!(
            resolve_store_path(Some(OsString::from(long)), None, None).unwrap_err(),
            msg_invalid_path()
        );
    }

    // ---- version -----------------------------------------------------

    #[test]
    fn version_prints_exactly_0_21() {
        let fx = Fixture::empty("version");
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"version"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, b"0.21\n");
        assert!(run.err.is_empty());
    }

    // ---- help / completion matrix (audit P8) --------------------------

    #[test]
    fn parser_help_is_the_254_path() {
        let fx = Fixture::empty("root-help");
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"help"]);
        assert_eq!(run.code, 254);
        assert_eq!(String::from_utf8_lossy(&run.parser_out), args::table_text());
        assert!(run.out.is_empty());
    }

    #[test]
    fn bare_invocation_prints_the_table_and_exits_zero() {
        let fx = Fixture::empty("bare");
        let run = dispatch(&fx.path, FakePlatform::new(), &[]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(String::from_utf8_lossy(&run.parser_out), args::table_text());
    }

    #[test]
    fn help_on_console_prints_usage_and_exits_255() {
        let fx = Fixture::empty("usage");
        let run = dispatch(&fx.path, FakePlatform::tty(), &[b"show", b"help"]);
        assert_eq!(run.code, EXIT_USAGE);
        assert_eq!(run.parser_out, b"Usage: show KEY\n");
        assert!(run.out.is_empty());
    }

    #[test]
    fn authorized_redirected_help_lists_names_and_exits_255() {
        let fx = Fixture::new(
            "names",
            &[(b"alpha", b"1"), (b"BETA", b"2"), (b"DELETED:old", b"3")],
        );
        for command in [b"show".as_slice(), b"dump", b"renew", b"update"] {
            let run = dispatch(&fx.path, FakePlatform::authorized(), &[command, b"help"]);
            assert_eq!(run.code, EXIT_USAGE, "command: {:?}", command);
            // Physical order, tombstones included (upstream quirk).
            assert_eq!(run.out, b"alpha\nBETA\nDELETED:old\n");
            assert!(run.parser_out.is_empty(), "no usage on a redirected stdout");
        }
    }

    #[test]
    fn unauthorized_redirected_completion_is_silent_and_exits_zero() {
        let fx = Fixture::new("names-unauth", &[(b"alpha", b"1")]);
        for command in [b"show".as_slice(), b"dump", b"renew", b"update"] {
            let run = dispatch(&fx.path, FakePlatform::new(), &[command, b"help"]);
            assert_eq!(run.code, EXIT_OK, "command: {:?}", command);
            assert!(run.out.is_empty());
            assert!(run.err.is_empty());
            // The silent path must never open the console.
            assert!(run.prompts.is_empty());
        }
    }

    #[test]
    fn redirected_new_and_set_help_print_nothing_and_exit_255() {
        let fx = Fixture::new("new-set-help", &[(b"alpha", b"1")]);
        for command in [b"new".as_slice(), b"set"] {
            let run = dispatch(&fx.path, FakePlatform::authorized(), &[command, b"help"]);
            assert_eq!(run.code, EXIT_USAGE, "command: {:?}", command);
            assert!(run.out.is_empty(), "no names for {command:?}");
            assert!(run.parser_out.is_empty(), "no usage on a redirected stdout");
        }
    }

    #[test]
    fn list_help_never_lists_names() {
        let fx = Fixture::new("list-help", &[(b"alpha", b"1")]);
        let run = dispatch(&fx.path, FakePlatform::authorized(), &[b"list", b"help"]);
        assert_eq!(run.code, EXIT_USAGE);
        assert!(run.out.is_empty());
    }

    #[test]
    fn agent_help_prints_cmd_word_on_redirected_stdout() {
        let fx = Fixture::empty("agent-help");
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"agent", b"help"]);
        assert_eq!(run.code, EXIT_USAGE);
        assert_eq!(run.parser_out, b"CMD\n");
    }

    // ---- argz `Option %s …` messages (parser level) -------------------

    #[test]
    fn option_messages_are_the_literal_argz_strings() {
        let fx = Fixture::empty("opts");
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[b"bogus"], b"Option bogus is unknown"),
            (
                &[b"init", b"opslimit"],
                b"Option opslimit requires a number",
            ),
            (
                &[b"init", b"opslimit", b"xyz"],
                b"Option opslimit is not a valid number",
            ),
            (
                &[b"init", b"opslimit", b"9999"],
                b"Option opslimit must be a number greater than or equal to 10000",
            ),
            (
                &[b"init", b"opslimit", b"1x"],
                b"Option opslimit is badly suffixed",
            ),
            (
                &[b"init", b"opslimit", b"99999999999999999999999999"],
                b"Option opslimit is out of range",
            ),
            (
                &[b"init", b"opslimit", b"50000", b"opslimit", b"6"],
                b"Option opslimit is already set",
            ),
        ];
        for (words, expected) in cases {
            let run = dispatch(&fx.path, FakePlatform::new(), words);
            assert_eq!(run.code, EXIT_USAGE, "words: {words:?}");
            let mut want = (*expected).to_vec();
            want.push(b'\n');
            assert_eq!(run.parser_err, want, "words: {words:?}");
        }
    }

    #[test]
    fn init_opslimit_help_prints_the_default_value() {
        let fx = Fixture::empty("opslimit-help");
        let run = dispatch(
            &fx.path,
            FakePlatform::new(),
            &[b"init", b"opslimit", b"help"],
        );
        assert_eq!(run.code, EXIT_USAGE);
        assert_eq!(run.parser_out, b"100000\n");
    }

    // ---- init --------------------------------------------------------

    #[test]
    fn init_creates_the_512_byte_header_block() {
        let path = temp_path("init");
        let run = dispatch(&path, FakePlatform::new(), &[b"init"]);
        assert_eq!(run.code, EXIT_OK);
        let bytes = std::fs::read(&path).expect("store written");
        assert_eq!(bytes.len(), 512);
        let block: [u8; 512] = bytes.try_into().unwrap();
        let header = Header::parse(&block).expect("header");
        assert_eq!(header.version, VERSION.0);
        assert_eq!(header.ops_limit, wsecret_core::format::OPS_LIMIT_DEFAULT);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn init_honors_the_opslimit_option() {
        let path = temp_path("init-ops");
        let run = dispatch(
            &path,
            FakePlatform::new(),
            &[b"init", b"opslimit", b"25000"],
        );
        assert_eq!(run.code, EXIT_OK);
        let bytes = std::fs::read(&path).expect("store written");
        let block: [u8; 512] = bytes.try_into().unwrap();
        assert_eq!(Header::parse(&block).unwrap().ops_limit, 25_000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn init_twice_fatals_already_exists() {
        let path = temp_path("init-twice");
        assert_eq!(
            dispatch(&path, FakePlatform::new(), &[b"init"]).code,
            EXIT_OK
        );
        let run = dispatch(&path, FakePlatform::new(), &[b"init"]);
        assert_eq!(run.code, EXIT_FATAL);
        let path_bytes = path.as_os_str().as_encoded_bytes();
        assert_eq!(run.err, fatal(&msg_store_exists(path_bytes)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn init_under_agent_fatals_agent_running() {
        let path = temp_path("init-agent");
        let platform = FakePlatform {
            agent_env: true,
            ..FakePlatform::new()
        };
        let run = dispatch(&path, platform, &[b"init"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Agent is running..."));
        assert!(!path.exists(), "no store created");
    }

    // ---- list --------------------------------------------------------

    #[test]
    fn list_prints_names_in_physical_order() {
        let fx = Fixture::new(
            "list",
            &[(b"alpha", b"1"), (b"BETA", b"2"), (b"DELETED:x", b"3")],
        );
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"list"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, b"alpha\nBETA\nDELETED:x\n");
    }

    #[test]
    fn list_filters_with_ascii_case_insensitive_substring() {
        let fx = Fixture::new(
            "list-needle",
            &[(b"Alpha", b"1"), (b"beta", b"2"), (b"gamma", b"3")],
        );
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"list", b"AL"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, b"Alpha\n");
    }

    #[test]
    fn list_with_wrong_passphrase_prints_nothing_and_exits_zero() {
        let fx = Fixture::new("list-wrong", &[(b"alpha", b"1")]);
        let platform = FakePlatform {
            passphrase: b"wrong".to_vec(),
            ..FakePlatform::new()
        };
        let run = dispatch(&fx.path, platform, &[b"list"]);
        assert_eq!(run.code, EXIT_OK, "never claim password verification");
        assert!(run.out.is_empty());
        assert!(run.err.is_empty());
    }

    // ---- show / dump -------------------------------------------------

    #[test]
    fn show_writes_exact_value_bytes_when_redirected() {
        let value = b"hello\n\n".to_vec();
        let fx = Fixture::new("show", &[(b"test", &value)]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"test"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, b"hello\n\n", "no added newline when redirected");
    }

    #[test]
    fn show_on_console_renders_base64_for_non_printable_and_adds_newline() {
        let fx = Fixture::new("show-b64", &[(b"bin", &[0x00, 0xff])]);
        let run = dispatch(&fx.path, FakePlatform::tty(), &[b"show", b"bin"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, b"AP8=\n");
    }

    #[test]
    fn show_totp_names_render_six_digits() {
        let fx = Fixture::new("show-totp", &[(b"svc/totp", b"JBSWY3DPEHPK3PXP")]);
        for tty in [false, true] {
            let platform = FakePlatform {
                stdout_tty: tty,
                ..FakePlatform::new()
            };
            let run = dispatch(&fx.path, platform, &[b"show", b"svc/totp"]);
            assert_eq!(run.code, EXIT_OK);
            let expected_len = if tty { 7 } else { 6 };
            assert_eq!(run.out.len(), expected_len);
            assert!(run.out[..6].iter().all(u8::is_ascii_digit));
        }
    }

    #[test]
    fn dump_bypasses_totp_only() {
        let value = b"JBSWY3DPEHPK3PXP";
        let fx = Fixture::new("dump-totp", &[(b"svc/totp", value)]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"dump", b"svc/totp"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out, value, "original value, no TOTP substitution");
    }

    #[test]
    fn show_on_invalid_totp_secret_fatals_invalid_secret() {
        // `totp32` names base32-decode the value first (plan §1.10): `!!!`
        // fails the decode → upstream's empty `struct s_totp` →
        // `Fatal: Invalid secret`, printed before any stdout byte.
        let fx = Fixture::new("show-totp-bad", &[(b"x/totp32", b"!!!")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"x/totp32"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Invalid secret"));
        assert!(run.out.is_empty(), "fatal before any stdout byte");
    }

    // ---- C8 base32 quirk matrix end to end (real store + dispatcher) ----
    //
    // Time is not injectable through `dispatch` (`s_show` samples
    // `time(NULL)` upstream), so these assert the time-independent parts:
    // acceptance vs the verbatim `Fatal: Invalid secret` fatal, and
    // `show`/`dump` byte dispatch. Exact codes for the same inputs are
    // pinned KATs in `wsecret-core::totp` and `output` (fixed counters).

    #[test]
    fn c8_cli_accepts_the_full_base32_quirk_matrix() {
        let accepted: &[(&[u8], &[u8])] = &[
            (b"a/totp32", b"JBSWY3DPEHPK3PXP"),  // canonical, 10 bytes
            (b"b/totp32", b"JBSWY3DPEHPK3PXP="), // '=' terminates
            (b"c/totp32", b"AB=CD"),             // decodes as "AB" only
            (b"d/totp32", b"JBSWY3DPEHPK3PX"),   // 15 chars: non-canonical, accepted
            (b"e/totp32", b"MY"),                // trailing partial zero-padded
            (b"f/totp32", &[b'A'; 102]),         // capacity boundary: accepted
        ];
        let fx = Fixture::new("c8-accept", accepted);
        for (name, _) in accepted {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", name]);
            assert_eq!(run.code, EXIT_OK, "name {name:?}");
            assert!(run.err.is_empty(), "name {name:?}");
            assert_eq!(run.out.len(), 6, "name {name:?} out {:?}", run.out);
            assert!(
                run.out.iter().all(u8::is_ascii_digit),
                "name {name:?} out {:?}",
                run.out
            );
        }
    }

    #[test]
    fn c8_cli_rejects_lowercase_cr_digits_0189_and_103_a() {
        let rejected: &[(&[u8], &[u8])] = &[
            (b"r1/totp32", b"jbswy3dpehpk3pxp"), // lowercase
            (b"r2/totp32", b"my"),               // lowercase
            (b"r3/totp32", b"MY\r\n"),           // '\r' is invalid (only '\n' terminates)
            (b"r4/totp32", b"JBSWY3DPEHPK3PX0"), // '0' outside the alphabet
            (b"r5/totp32", &[b'A'; 103]),        // capacity: rejected, NOT truncated
        ];
        let fx = Fixture::new("c8-reject", rejected);
        for (name, _) in rejected {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", name]);
            assert_eq!(run.code, EXIT_FATAL, "name {name:?}");
            assert_eq!(run.err, fatal(b"Invalid secret"), "name {name:?}");
            assert!(run.out.is_empty(), "name {name:?}: fatal before stdout");
        }
    }

    #[test]
    fn c8_cli_show_dispatches_totp_dump_returns_seed_bytes() {
        let value = b"JBSWY3DPEHPK3PXP";
        let fx = Fixture::new("c8-dispatch", &[(b"/totp", value), (b"/totp32", value)]);

        // `show` on both names: exactly six code bytes (any counter).
        for name in [b"/totp".as_slice(), b"/totp32"] {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", name]);
            assert_eq!(run.code, EXIT_OK, "name {name:?}");
            assert_eq!(run.out.len(), 6, "name {name:?} out {:?}", run.out);
            assert!(
                run.out.iter().all(u8::is_ascii_digit),
                "name {name:?} out {:?}",
                run.out
            );
        }

        // Deterministic proof that `totp32` decodes first while plain
        // `totp` keys on the raw bytes: the same value `!!!` is an invalid
        // base32 secret but a perfectly fine 3-byte raw key.
        let fx2 = Fixture::new(
            "c8-dispatch2",
            &[(b"a/totp", b"!!!"), (b"b/totp32", b"!!!")],
        );
        let raw = dispatch(&fx2.path, FakePlatform::new(), &[b"show", b"a/totp"]);
        assert_eq!(raw.code, EXIT_OK, "raw key path accepts the bytes");
        assert_eq!(raw.out.len(), 6);
        assert!(raw.out.iter().all(u8::is_ascii_digit));
        let dec = dispatch(&fx2.path, FakePlatform::new(), &[b"show", b"b/totp32"]);
        assert_eq!(dec.code, EXIT_FATAL);
        assert_eq!(dec.err, fatal(b"Invalid secret"), "base32 decode fails");
        assert!(dec.out.is_empty());

        // `dump` bypasses TOTP ONLY: the original seed bytes, nothing else.
        for name in [b"/totp".as_slice(), b"/totp32"] {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"dump", name]);
            assert_eq!(run.code, EXIT_OK, "name {name:?}");
            assert_eq!(run.out, value, "name {name:?}: dump emits seed bytes");
        }
    }

    #[test]
    fn c8_cli_raw_seed_length_boundaries() {
        // Raw `s_totp` keys: 1..=64 bytes valid (end extremes exercised),
        // empty and >64 bytes are `Invalid secret`.
        let fx = Fixture::new(
            "c8-len",
            &[
                (b"len1/totp", &[0x0b]),
                (b"len64/totp", &[0x0b; 64]),
                (b"len0/totp", b""),
                (b"len65/totp", &[0x0b; 65]),
            ],
        );
        for name in [b"len1/totp".as_slice(), b"len64/totp"] {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", name]);
            assert_eq!(run.code, EXIT_OK, "name {name:?}");
            assert_eq!(run.out.len(), 6, "name {name:?} out {:?}", run.out);
            assert!(run.out.iter().all(u8::is_ascii_digit), "name {name:?}");
        }
        for name in [b"len0/totp".as_slice(), b"len65/totp"] {
            let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", name]);
            assert_eq!(run.code, EXIT_FATAL, "name {name:?}");
            assert_eq!(run.err, fatal(b"Invalid secret"), "name {name:?}");
            assert!(run.out.is_empty(), "name {name:?}: fatal before stdout");
            // `dump` on the same names bypasses TOTP and returns the seed
            // bytes verbatim (empty or 65 raw bytes) with exit 0.
            let dump = dispatch(&fx.path, FakePlatform::new(), &[b"dump", name]);
            assert_eq!(dump.code, EXIT_OK, "dump {name:?}");
            assert!(dump.err.is_empty(), "dump {name:?}");
            let expected: &[u8] = if name == b"len0/totp" {
                b""
            } else {
                &[0x0b; 65]
            };
            assert_eq!(dump.out, expected, "dump {name:?}: seed bytes verbatim");
        }
    }

    #[test]
    fn show_missing_key_fatals_not_found_with_the_key_bytes() {
        let fx = Fixture::new("show-missing", &[(b"alpha", b"1")]);
        // Valid key rule (upstream `s_keylen`): no empty keys and no bytes
        // `<= 0x20`; raw high bytes are legal and echoed verbatim.
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"\x80miss"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Secret \x80miss not found"));
    }

    #[test]
    fn show_rejects_control_bytes_in_keys_before_lookup() {
        // Upstream `s_get_secret` runs `s_keylen` first: a control byte in
        // the key never reaches the not-found path.
        let fx = Fixture::new("show-ctrl", &[(b"alpha", b"1")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"no\x00pe"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(
            run.err,
            fatal(b"Special characaters are not allowed in keys")
        );
    }

    // ---- new / set / renew / update ----------------------------------

    #[test]
    fn new_prints_the_generated_secret_then_creates_the_record() {
        let fx = Fixture::new("new", &[(b"other", b"x")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"new", b"gen1"]);
        assert_eq!(run.code, EXIT_OK);
        // ≤25 printable chars, no newline when redirected (plan §1.6).
        assert!(!run.out.is_empty() && run.out.len() <= 25);
        assert!(run.out.iter().all(|b| (0x21..=0x7e).contains(b)));

        // The record now exists and holds exactly the printed secret.
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"gen1"]);
        assert_eq!(show.out, run.out);
    }

    #[test]
    fn new_appends_console_newline_on_a_tty() {
        let fx = Fixture::empty("new-tty");
        let run = dispatch(&fx.path, FakePlatform::tty(), &[b"new", b"gen2"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(run.out.last(), Some(&b'\n'));
        assert_eq!(
            run.out.len() - 1,
            run.out.iter().filter(|b| **b != b'\n').count()
        );
    }

    #[test]
    fn new_on_existing_key_fatals_exists() {
        let fx = Fixture::new("new-exists", &[(b"alpha", b"1")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"new", b"alpha"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Secret alpha exists!"));
    }

    #[test]
    fn new_on_empty_partition_asks_for_the_retype_confirmation() {
        let fx = Fixture::empty("new-confirm");
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"new", b"gen3"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(
            run.prompts,
            vec![PROMPT_PASSPHRASE.to_owned(), PROMPT_CONFIRM.to_owned(),]
        );
    }

    #[test]
    fn confirmation_mismatch_fatals_passphrases_dont_match() {
        let fx = Fixture::empty("new-mismatch");
        let platform = FakePlatform {
            confirm: Some(b"other".to_vec()),
            ..FakePlatform::new()
        };
        let run = dispatch(&fx.path, platform, &[b"new", b"gen4"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Passphrases don't match!"));
    }

    #[test]
    fn set_stores_the_entered_value() {
        let fx = Fixture::empty("set");
        let run = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(b"my value"),
            &[b"set", b"k1"],
        );
        assert_eq!(run.code, EXIT_OK);
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"k1"]);
        assert_eq!(show.out, b"my value");
    }

    #[test]
    fn set_with_empty_input_exits_zero_without_a_write() {
        let fx = Fixture::new("set-empty", &[(b"other", b"x")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"set", b"k2"]);
        assert_eq!(run.code, EXIT_OK);
        assert!(run.out.is_empty());
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"k2"]);
        assert_eq!(show.code, EXIT_FATAL, "nothing stored");
    }

    #[test]
    fn set_on_existing_key_fatals_exists() {
        let fx = Fixture::new("set-exists", &[(b"alpha", b"1")]);
        let run = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(b"v"),
            &[b"set", b"alpha"],
        );
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Secret alpha exists!"));
    }

    #[test]
    fn set_rejects_oversized_entries() {
        let fx = Fixture::new("set-big", &[(b"x", b"y")]);
        let big = vec![b'v'; 474];
        let run = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(&big),
            &[b"set", b"name"],
        );
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Entry too big!"));
    }

    #[test]
    fn renew_replaces_the_value_in_place() {
        let fx = Fixture::new("renew", &[(b"old", b"v1"), (b"other", b"x")]);
        let size_before = std::fs::metadata(&fx.path).unwrap().len();
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"renew", b"old"]);
        assert_eq!(run.code, EXIT_OK);
        assert!(!run.out.is_empty() && run.out.len() <= 25);
        let size_after = std::fs::metadata(&fx.path).unwrap().len();
        assert_eq!(size_before, size_after, "slot rewritten in place");
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"old"]);
        assert_eq!(show.out, run.out);
    }

    #[test]
    fn renew_missing_key_fatals_not_found() {
        let fx = Fixture::new("renew-missing", &[(b"old", b"v1")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"renew", b"nope"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Secret nope not found"));
    }

    #[test]
    fn update_replaces_the_value() {
        let fx = Fixture::new("update", &[(b"k", b"old")]);
        let run = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(b"new value"),
            &[b"update", b"k"],
        );
        assert_eq!(run.code, EXIT_OK);
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"k"]);
        assert_eq!(show.out, b"new value");
    }

    #[test]
    fn update_rename_with_empty_input_keeps_the_old_value() {
        let fx = Fixture::new("update-rename", &[(b"old", b"keep me")]);
        let run = dispatch(
            &fx.path,
            FakePlatform::new(),
            &[b"update", b"old", b"NEWKEY"],
        );
        assert_eq!(run.code, EXIT_OK);
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"NEWKEY"]);
        assert_eq!(show.out, b"keep me", "rename keeps the old value bytes");
        let gone = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"old"]);
        assert_eq!(gone.code, EXIT_FATAL);
    }

    #[test]
    fn update_bare_with_empty_input_exits_zero_and_changes_nothing() {
        let fx = Fixture::new("update-empty", &[(b"k", b"unchanged")]);
        let size_before = std::fs::metadata(&fx.path).unwrap().len();
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"update", b"k"]);
        assert_eq!(run.code, EXIT_OK);
        assert!(run.out.is_empty());
        assert_eq!(std::fs::metadata(&fx.path).unwrap().len(), size_before);
        let show = dispatch(&fx.path, FakePlatform::new(), &[b"show", b"k"]);
        assert_eq!(show.out, b"unchanged");
    }

    #[test]
    fn update_missing_key_fatals_not_found() {
        let fx = Fixture::new("update-missing", &[(b"k", b"v")]);
        let run = dispatch(
            &fx.path,
            FakePlatform::new().with_secret(b"v"),
            &[b"update", b"gone"],
        );
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(run.err, fatal(b"Secret gone not found"));
    }

    // ---- pass --------------------------------------------------------

    #[test]
    fn pass_is_deterministic_normalized_and_bounded() {
        let fx = Fixture::new("pass", &[(b"k", b"v")]);
        let first = dispatch(&fx.path, FakePlatform::new(), &[b"pass", b"KEY", b"sub"]);
        let second = dispatch(&fx.path, FakePlatform::new(), &[b"pass", b"KEY", b"sub"]);
        assert_eq!(first.code, EXIT_OK);
        assert_eq!(first.out, second.out, "deterministic for a fixed tuple");
        assert!(!first.out.is_empty() && first.out.len() <= 25);
        assert!(first.out.iter().all(|b| (0x21..=0x7e).contains(b)));
    }

    #[test]
    fn pass_on_empty_partition_requires_confirmation() {
        let fx = Fixture::empty("pass-confirm");
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"pass", b"KEY"]);
        assert_eq!(run.code, EXIT_OK);
        assert_eq!(
            run.prompts,
            vec![PROMPT_PASSPHRASE.to_owned(), PROMPT_CONFIRM.to_owned()]
        );
    }

    #[test]
    fn pass_rejects_invalid_subkeys() {
        let fx = Fixture::new("pass-bad", &[(b"k", b"v")]);
        let run = dispatch(&fx.path, FakePlatform::new(), &[b"pass", b"a b"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_eq!(
            run.err,
            fatal(b"Special characaters are not allowed in keys")
        );
    }

    // ---- agent -------------------------------------------------------

    #[test]
    fn agent_propagates_the_child_exit_code() {
        let fx = Fixture::empty("agent-code");
        let platform = FakePlatform {
            launch: LaunchScript::Code(7),
            ..FakePlatform::new()
        };
        let run = dispatch(
            &fx.path,
            platform,
            &[b"agent", b"cmd", b"/c", b"exit", b"7"],
        );
        assert_eq!(run.code, 7);
    }

    #[test]
    fn agent_launch_errors_render_the_catalog() {
        let fx = Fixture::empty("agent-errs");
        let cases: &[(LaunchScript, u32, &[u8])] = &[
            (
                LaunchScript::AlreadyRunning,
                EXIT_FATAL,
                b"Already running...",
            ),
            (
                LaunchScript::MissingShell,
                EXIT_FATAL,
                b"Missing env SHELL, nothing to exec!",
            ),
            (
                LaunchScript::QueueKey,
                EXIT_FATAL,
                b"Unable to queue the key",
            ),
            (
                LaunchScript::Exec("prog", "denied"),
                EXIT_FATAL,
                b"prog: denied",
            ),
            (
                LaunchScript::Mismatch,
                EXIT_FATAL,
                b"Passphrases don't match!",
            ),
            (LaunchScript::Cancelled, EXIT_OK, b""),
        ];
        for (script, code, body) in cases {
            let platform = FakePlatform {
                launch: script.clone(),
                ..FakePlatform::new()
            };
            let run = dispatch(&fx.path, platform, &[b"agent"]);
            assert_eq!(run.code, *code, "script: {script:?}");
            if body.is_empty() {
                assert!(run.err.is_empty(), "silent exit for {script:?}");
            } else {
                assert_eq!(run.err, fatal(body), "script: {script:?}");
            }
        }
    }

    #[test]
    fn agent_core_errors_use_the_catalog() {
        let fx = Fixture::empty("agent-core");
        let platform = FakePlatform {
            launch: LaunchScript::StoreMissing,
            ..FakePlatform::new()
        };
        let run = dispatch(&fx.path, platform, &[b"agent"]);
        assert_eq!(run.code, EXIT_FATAL);
        let path_bytes = fx.path.as_os_str().as_encoded_bytes();
        assert_eq!(run.err, fatal(&msg_store_missing(path_bytes)));
    }

    // ---- global modes (plan §4 additions) -----------------------------

    #[test]
    fn keys_hex_decodes_positional_keys() {
        // `--keys-hex` is stripped before the argz walk; the operand is hex.
        // argv[0] is the program word (flag stripping starts after it).
        let words: &[OsString] = &[
            OsString::from("wsecret"),
            OsString::from("--keys-hex"),
            OsString::from("show"),
            OsString::from("00ff6b6579"),
        ];
        let (stripped, flags) = strip_flags(words.to_vec());
        assert!(flags.keys_hex && !flags.pass_hex);
        let keys = encode_argv(&stripped, flags.keys_hex).unwrap();
        assert_eq!(keys[2], b"\x00\xffkey".to_vec());
        assert_eq!(keys.len(), 3, "program word + command + decoded key");
    }

    #[test]
    fn keys_hex_keeps_the_help_word_literal() {
        let words = vec![
            OsString::from("wsecret"),
            OsString::from("--keys-hex"),
            OsString::from("show"),
            OsString::from("help"),
        ];
        let keys = encode_argv(&strip_flags(words).0, true).unwrap();
        assert_eq!(keys[2], b"help".to_vec());
    }

    #[test]
    fn keys_hex_rejects_odd_or_non_hex_input() {
        let words = vec![
            OsString::from("wsecret"),
            OsString::from("--keys-hex"),
            OsString::from("show"),
            OsString::from("abc"),
        ];
        assert_eq!(
            encode_argv(&strip_flags(words).0, true).unwrap_err(),
            msg_invalid_input()
        );
        let words = vec![
            OsString::from("wsecret"),
            OsString::from("--keys-hex"),
            OsString::from("show"),
            OsString::from("zz"),
        ];
        assert_eq!(
            encode_argv(&strip_flags(words).0, true).unwrap_err(),
            msg_invalid_input()
        );
    }

    #[test]
    fn strip_flags_removes_only_the_global_modes() {
        let (words, flags) = strip_flags(vec![
            OsString::from("wsecret"),
            OsString::from("--pass-hex"),
            OsString::from("set"),
            OsString::from("--keys-hex"),
            OsString::from("k"),
        ]);
        assert!(flags.pass_hex && flags.keys_hex);
        assert_eq!(words.len(), 3);
        assert_eq!(words[1].as_encoded_bytes(), b"set");
        assert_eq!(words[2].as_encoded_bytes(), b"k");
    }

    // ---- Deterministic `pass` equality vs an independent oracle ----
    //
    // Plan §7.3 C4/C5 (cross-host deterministic-secret equality). The oracle
    // below never calls `wsecret-core::pass` or `Session::derive_chain`: it
    // rebuilds the whole chain from the store file's raw 41-byte header
    // through `libhydrogen_sys::pwhash_deterministic` directly and applies an
    // independent transcription of upstream `s_normalize_and_show`. That
    // makes the CLI `pass` output a checked result, not just self-consistent.
    //
    // Fixtures follow the plan §7.2 fixture convention: `F-default` is the
    // opslimit-100000 store with `P_A` records (the "fixture store" of the
    // C4 row); `F-maxops` is the same passphrase in an opslimit-10000 store
    // (the negative control for "opslimit is hashed in"). Both use the
    // plan's literal passphrases `P_A`/`P_B`/`P_C`.

    use wsecret_core::format::{BLOCK, HEADER_LEN, OPS_LIMIT_DEFAULT};

    /// Plan §7.2 fixture passphrases (literal).
    const P_A: &[u8] = b"P_A";
    const P_B: &[u8] = b"P_B";
    const P_C: &[u8] = b"P_C";

    /// `F-default`: the fixture store (opslimit 100000) with `P_A` records.
    struct FixtureDefault {
        path: PathBuf,
    }

    impl FixtureDefault {
        fn new(tag: &str, entries: &[(&[u8], &[u8])]) -> FixtureDefault {
            let path = temp_path(&format!("F-default-{tag}"));
            let (mut store, header, _) =
                Store::create(&path, OPS_LIMIT_DEFAULT).expect("F-default create");
            assert_eq!(
                header.ops_limit, OPS_LIMIT_DEFAULT,
                "F-default must run at opslimit 100000"
            );
            let session = Session::unlock(&header, &mut P_A.to_vec()).expect("unlock P_A");
            for (name, value) in entries {
                store
                    .append_or_reuse(None, &session, name, value)
                    .expect("append P_A record");
            }
            FixtureDefault { path }
        }
    }

    impl Drop for FixtureDefault {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// `F-maxops`: same `P_A` passphrase, opslimit 10000 — the negative
    /// control store.
    struct FixtureMaxOps {
        path: PathBuf,
    }

    impl FixtureMaxOps {
        fn new(tag: &str) -> FixtureMaxOps {
            let path = temp_path(&format!("F-maxops-{tag}"));
            let (mut store, header, _) =
                Store::create(&path, OPS_LIMIT_MIN).expect("F-maxops create");
            assert_eq!(header.ops_limit, OPS_LIMIT_MIN);
            let session = Session::unlock(&header, &mut P_A.to_vec()).expect("unlock P_A");
            store
                .append_or_reuse(None, &session, b"alpha", b"one")
                .expect("append P_A record");
            FixtureMaxOps { path }
        }
    }

    impl Drop for FixtureMaxOps {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Independent oracle: raw 41-byte header (upstream `s_header` layout:
    /// version byte at 0, random master at [1,33), LE64 opslimit at [33,41))
    /// → `libhydrogen_sys::pwhash_deterministic` MASTER derivation →
    /// `PASSWD` chain over the subkeys → upstream `s_normalize_and_show`
    /// mapping, transcribed here from `secret.c`, not imported from
    /// `wsecret-core::pass`.
    struct Oracle {
        key: [u8; 32],
        ops_limit: u64,
    }

    impl Oracle {
        fn from_store(path: &Path) -> Oracle {
            let raw = std::fs::read(path).expect("oracle: read store");
            assert!(
                raw.len() >= HEADER_LEN && raw.len() % BLOCK == 0,
                "oracle: store {} has unexpected length {}",
                path.display(),
                raw.len()
            );
            assert_eq!(raw[0], 0, "oracle: store version byte");
            let master: [u8; 32] = raw[1..33].try_into().expect("32-byte master");
            let mut ops_limit = 0u64;
            for (i, b) in raw[33..41].iter().enumerate() {
                ops_limit |= (*b as u64) << (8 * i);
            }
            assert!(
                ops_limit >= 10_000,
                "oracle: opslimit {ops_limit} below minimum"
            );
            let mut key = [0u8; 32];
            libhydrogen_sys::pwhash_deterministic(
                &mut key,
                P_A,
                &libhydrogen_sys::CTX_MASTER,
                &master,
                ops_limit,
            );
            Oracle { key, ops_limit }
        }

        /// k_i = pwhash_deterministic(32, subkey_i, "PASSWD\0\0", k_{i-1},
        /// opslimit); zero subkeys leaves k_0 (the MASTER key).
        fn derive(&self, subkeys: &[&[u8]]) -> [u8; 32] {
            let mut prev = self.key;
            let mut cur = [0u8; 32];
            for sub in subkeys {
                libhydrogen_sys::pwhash_deterministic(
                    &mut cur,
                    sub,
                    &libhydrogen_sys::CTX_PASSWD,
                    &prev,
                    self.ops_limit,
                );
                core::mem::swap(&mut prev, &mut cur);
            }
            libhydrogen_sys::memzero(&mut cur);
            prev
        }
    }

    impl Drop for Oracle {
        fn drop(&mut self) {
            libhydrogen_sys::memzero(&mut self.key);
        }
    }

    /// Upstream `s_normalize_and_show` mapping, transcribed independently:
    /// `'!' + (b % 94)` for each input byte `b < 188`, stop after 25 chars.
    fn oracle_normalize(key: &[u8; 32]) -> Vec<u8> {
        const N: usize = 1 + (b'~' - b'!') as usize; // 94
        let mut out = Vec::new();
        for &b in key {
            if out.len() >= 25 {
                break;
            }
            let b = b as usize;
            if b < 2 * N {
                out.push(b'!' + (b % N) as u8);
            }
        }
        out
    }

    /// Full oracle for one CLI `pass` invocation: output string for
    /// `pass KEY [SUBKEY...]` under `P_A` in the store at `path`.
    fn oracle_pass(path: &Path, subkeys: &[&[u8]]) -> Vec<u8> {
        let o = Oracle::from_store(path);
        let mut k = o.derive(subkeys);
        let out = oracle_normalize(&k);
        libhydrogen_sys::memzero(&mut k);
        out
    }

    /// One CLI invocation with an explicit passphrase (fresh PRNG seeding
    /// for every process, mirroring the real `main`).
    fn dispatch_with_pass(path: &Path, pass: &[u8], words: &[&[u8]]) -> Run {
        libhydrogen_sys::init();
        let platform = FakePlatform {
            passphrase: pass.to_vec(),
            ..FakePlatform::new()
        };
        dispatch(path, platform, words)
    }

    /// Assertion helper: hex + lossy rendering so failures show the exact
    /// bytes ("capture verbatim output on failure").
    fn assert_bytes_eq(what: &str, got: &[u8], want: &[u8]) {
        assert!(
            got == want,
            "{what} mismatch\n  got  ({}) = {:x?} ({})\n  want ({}) = {:x?} ({})",
            got.len(),
            got,
            String::from_utf8_lossy(got),
            want.len(),
            want,
            String::from_utf8_lossy(want),
        );
    }

    /// C4 (1-subkey): `pass me@domain.com` in the opslimit-100000 `P_A`
    /// fixture equals the independent oracle, byte-for-byte, variable
    /// length ≤ 25; piped (non-console stdout) there is NO trailing newline.
    #[test]
    fn pass_one_subkey_equals_oracle_piped_byte_exact() {
        let fx = FixtureDefault::new("pass1", &[(b"alpha", b"one")]);
        let want = oracle_pass(&fx.path, &[b"me@domain.com"]);
        assert!(
            !want.is_empty() && want.len() <= 25,
            "oracle output length must be 1..=25, got {}",
            want.len()
        );

        let run = dispatch_with_pass(&fx.path, P_A, &[b"pass", b"me@domain.com"]);
        assert_eq!(
            run.code,
            EXIT_OK,
            "stderr verbatim: {:?}",
            String::from_utf8_lossy(&run.err)
        );
        assert!(
            run.err.is_empty(),
            "no fatal output expected, got {:?}",
            String::from_utf8_lossy(&run.err)
        );
        assert_bytes_eq("pass me@domain.com (piped)", &run.out, &want);
        assert!(
            !run.out.ends_with(b"\n"),
            "piped output must have no trailing newline; got {:x?}",
            run.out
        );
    }

    /// C4 (2-subkey chain): `pass me@domain.com 2020` is a different string
    /// and equals the oracle's 2-link `PASSWD` chain.
    #[test]
    fn pass_two_subkey_chain_equals_oracle_and_differs_from_one_subkey() {
        let fx = FixtureDefault::new("pass2", &[(b"alpha", b"one")]);
        let one = oracle_pass(&fx.path, &[b"me@domain.com"]);
        let two = oracle_pass(&fx.path, &[b"me@domain.com", b"2020"]);
        assert_ne!(
            one, two,
            "oracle sanity: the 2-subkey chain must differ from the 1-subkey chain"
        );
        assert!(two.len() <= 25 && !two.is_empty());

        let run = dispatch_with_pass(&fx.path, P_A, &[b"pass", b"me@domain.com", b"2020"]);
        assert_eq!(
            run.code,
            EXIT_OK,
            "stderr verbatim: {:?}",
            String::from_utf8_lossy(&run.err)
        );
        assert_bytes_eq("pass me@domain.com 2020 (piped)", &run.out, &two);
        assert!(
            !run.out.ends_with(b"\n"),
            "piped output must have no trailing newline"
        );

        // And the CLI's one-subkey run is the other string.
        let run1 = dispatch_with_pass(&fx.path, P_A, &[b"pass", b"me@domain.com"]);
        assert_eq!(run1.code, EXIT_OK);
        assert_bytes_eq("pass me@domain.com (piped)", &run1.out, &one);
    }

    /// C4 new-partition flow: `pass x` under a brand-new `P_C` (records
    /// exist only for `P_A`, so nothing decrypts) prompts exactly
    /// `Passphrase: ` then `No secrets stored with this passphrase.\nPlease,
    /// retype it to confirm: `; a matching retype yields the oracle string
    /// for the `P_C` chain.
    #[test]
    fn pass_new_partition_matching_retype_prints_oracle_output() {
        let fx = FixtureDefault::new("P_C-match", &[(b"alpha", b"one")]);

        // Independent oracle for the `P_C` tuple: same store bytes, but the
        // MASTER derivation password is `P_C`, not `P_A`.
        let raw = std::fs::read(&fx.path).expect("read store");
        let master: [u8; 32] = raw[1..33].try_into().expect("32-byte master");
        let ops_limit = OPS_LIMIT_DEFAULT;
        let mut key = [0u8; 32];
        libhydrogen_sys::pwhash_deterministic(
            &mut key,
            P_C,
            &libhydrogen_sys::CTX_MASTER,
            &master,
            ops_limit,
        );
        let mut cur = [0u8; 32];
        libhydrogen_sys::pwhash_deterministic(
            &mut cur,
            b"x",
            &libhydrogen_sys::CTX_PASSWD,
            &key,
            ops_limit,
        );
        let want = oracle_normalize(&cur);
        assert!(!want.is_empty() && want.len() <= 25);
        libhydrogen_sys::memzero(&mut key);
        libhydrogen_sys::memzero(&mut cur);

        let platform = FakePlatform {
            passphrase: P_C.to_vec(),
            confirm: Some(P_C.to_vec()),
            ..FakePlatform::new()
        };
        let run = dispatch(&fx.path, platform, &[b"pass", b"x"]);
        assert_eq!(
            run.code,
            EXIT_OK,
            "stderr verbatim: {:?}",
            String::from_utf8_lossy(&run.err)
        );
        assert_eq!(
            run.prompts,
            vec![PROMPT_PASSPHRASE.to_owned(), PROMPT_CONFIRM.to_owned(),],
            "prompt order/text mismatch"
        );
        assert_eq!(PROMPT_PASSPHRASE, "Passphrase: ");
        assert_eq!(
            PROMPT_CONFIRM,
            "No secrets stored with this passphrase.\nPlease, retype it to confirm: "
        );
        assert_bytes_eq("pass x (P_C retype match)", &run.out, &want);
        assert!(
            !run.out.ends_with(b"\n"),
            "piped output must have no trailing newline"
        );
    }

    /// C4 new-partition flow, negative leg: a MISMATCHED retype fatals with
    /// `Fatal: Passphrases don't match!` and exit 1, no secret output.
    #[test]
    fn pass_new_partition_retype_mismatch_fatals_dont_match() {
        let fx = FixtureDefault::new("P_C-mismatch", &[(b"alpha", b"one")]);
        let platform = FakePlatform {
            passphrase: P_C.to_vec(),
            confirm: Some(P_B.to_vec()),
            ..FakePlatform::new()
        };
        let run = dispatch(&fx.path, platform, &[b"pass", b"x"]);
        assert_eq!(run.code, EXIT_FATAL);
        assert_bytes_eq(
            "retype mismatch fatal line",
            &run.err,
            b"Fatal: Passphrases don't match!\n",
        );
        assert!(
            run.out.is_empty(),
            "no secret may be printed on mismatch; got {:?}",
            String::from_utf8_lossy(&run.out)
        );
    }

    /// C5 negative control: the same passphrase `P_A` in `F-maxops`
    /// (opslimit 10000) and `F-default` (opslimit 100000) MUST produce
    /// different `pass` output — the opslimit is part of the hashed KDF
    /// input — and each must match its own oracle.
    #[test]
    fn opslimit_is_hashed_in_same_passphrase_differs_across_stores() {
        let fx_default = FixtureDefault::new("neg", &[(b"alpha", b"one")]);
        let fx_maxops = FixtureMaxOps::new("neg");

        let out_default = dispatch_with_pass(&fx_default.path, P_A, &[b"pass", b"me@domain.com"]);
        assert_eq!(out_default.code, EXIT_OK);
        let out_maxops = dispatch_with_pass(&fx_maxops.path, P_A, &[b"pass", b"me@domain.com"]);
        assert_eq!(out_maxops.code, EXIT_OK);

        // Each output equals its own independent oracle (chain + opslimit).
        assert_bytes_eq(
            "F-default pass output",
            &out_default.out,
            &oracle_pass(&fx_default.path, &[b"me@domain.com"]),
        );
        assert_bytes_eq(
            "F-maxops pass output",
            &out_maxops.out,
            &oracle_pass(&fx_maxops.path, &[b"me@domain.com"]),
        );

        assert_ne!(
            out_default.out, out_maxops.out,
            "opslimit must change the derived secret; F-default {:x?} vs F-maxops {:x?}",
            out_default.out, out_maxops.out
        );
    }

    /// Oracle self-check against the differential value observed from the
    /// pinned verbatim C (`secret.c` compiled with `-DNOMAIN`): the oracle
    /// chain + normalization must reproduce that string for a fixed tuple,
    /// proving the oracle is an independent transcription of upstream — not
    /// a re-run of the implementation under test.
    #[test]
    fn oracle_matches_pinned_c_differential_vector() {
        libhydrogen_sys::init();
        // Same tuple as wsecret-core's C differential test: pass
        // "correct horse battery staple", master [0x2a; 32], opslimit 10000,
        // subkeys ["alice", "bob", "carol"].
        let header_master = [0x2au8; 32];
        let ops_limit = 10_000u64;
        let mut key = [0u8; 32];
        libhydrogen_sys::pwhash_deterministic(
            &mut key,
            b"correct horse battery staple",
            &libhydrogen_sys::CTX_MASTER,
            &header_master,
            ops_limit,
        );
        let mut prev = key;
        let mut cur = [0u8; 32];
        for sub in [&b"alice"[..], b"bob", b"carol"] {
            libhydrogen_sys::pwhash_deterministic(
                &mut cur,
                sub,
                &libhydrogen_sys::CTX_PASSWD,
                &prev,
                ops_limit,
            );
            core::mem::swap(&mut prev, &mut cur);
        }
        let out = oracle_normalize(&prev);
        assert_bytes_eq(
            "oracle vs pinned-C vector",
            &out,
            b"6lbG><sw1:~+<s'6g45HM7?;}",
        );
    }
}
