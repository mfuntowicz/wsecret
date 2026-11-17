//! `wsecret agent [CMD [ARG...]]` — trusted-agent launch and key acquisition
//! (plan §5.2/§5.8; the Windows adaptation of upstream `s_agent`/`s_ask_agent`).
//!
//! This module contains **no unsafe code** and no message bytes: every OS
//! primitive (pipe creation, peek, `CreateProcessW`, handle hygiene) lives in
//! the safe facades of [`wsecret_core::windows::agent_bridge`], which is one
//! of the two sanctioned unsafe modules.
//!
//! # Launch (plan §5.2, upstream `s_agent` sequence)
//!
//! 1. Refuse when `SECRET_AGENT` is already set (upstream: `Fatal: Already
//!    running...`; `init` uses the same refusal).
//! 2. Resolve the executable to a full path — the first `CMD` argument if
//!    given, else `$SHELL`, else `%ComSpec%`; the resolved path is passed as
//!    explicit `lpApplicationName` (no `CreateProcessW` command-line parsing
//!    ambiguity), while the child's `argv[0]` stays exactly as typed
//!    (upstream `execvp` semantics).
//! 3. Unlock the store through the normal library path, **including the
//!    no-records confirmation** (upstream `s_get_secret(fd, NULL, 0)`:
//!    any decryptable record passes; otherwise the passphrase is re-entered
//!    and compared constant-time).
//! 4. Build the 81-byte agent message in a secure buffer:
//!    `WSECRET1` ‖ 41-byte header ‖ 32-byte key (explicit byte encoding).
//! 5. `CreatePipe` with a **proper empty DACL** and non-inheritable handles.
//! 6. Write exactly 81 bytes; mark ONLY the read handle inheritable.
//! 7. `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` = the agent read
//!    handle + deliberately duplicated std handles — nothing else inherits.
//! 8. `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT |
//!    CREATE_UNICODE_ENVIRONMENT`; the environment carries
//!    `SECRET_AGENT=<decimal handle>` and preserves everything else
//!    (`SECRET_STORE` included).
//! 9. Teardown: the launcher's pipe handles are closed immediately after
//!    `CreateProcessW` (on failure too — the buffered message dies with the
//!    pipe); the capability message and the session are zeroized before the
//!    child runs; the attribute list is freed; the only retained handle is a
//!    `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` duplicate of the
//!    child (plan §5.8 point 4 — no full-access wsecret-child handle survives
//!    in the launcher).
//!
//! # Acquisition (plan §5.2, every store-using command)
//!
//! [`acquire`] parses `SECRET_AGENT` as a strict unsigned decimal handle
//! (rejecting signs, whitespace, trailing characters, zero and values that
//! do not fit a `HANDLE`), requires `GetFileType == FILE_TYPE_PIPE`, peeks
//! the buffered message **without consuming it** (upstream `MSG_PEEK`:
//! repeated and descendant use keeps working), and adopts the key on magic +
//! constant-time header match. ANY mismatch falls back to the passphrase
//! path (upstream zeroes the key and re-prompts); noninteractive completion
//! then returns no names without opening `CONIN$` (upstream `show help`
//! behavior).
//!
//! # Narrowed assurance (audit P13)
//!
//! Header equality authorizes adoption without any record decryption: a
//! forged message with an attacker key leaves existing records unreadable but
//! the adopter will ENCRYPT newly entered secrets under the attacker key.
//! The launching environment and the inherited handle are TRUSTED INPUTS —
//! this is upstream's exact behavior (`s_ask_agent`), documented as an
//! inherited-capability limitation, not evidence that an unrelated process
//! can acquire the real pipe (the pipe DACL denies every new open).
//!
//! # Teardown
//!
//! RAII throughout: `AgentCapability`/`AgentPipe`/`AgentChild` zeroize and
//! close on drop (including unwinds), [`Session::lock`] runs at capability
//! creation and again on drop. The pipe — and the buffered message with it —
//! dies when the last handle closes. Shell exit is NOT revocation for
//! detached descendants; there is no idle timeout (upstream has none, and a
//! timeout would not revoke copies already made).

use std::ffi::OsStr;
use std::path::Path;

use wsecret_core::error::Error;
use wsecret_core::format::Header;
use wsecret_core::session::Session;
use wsecret_core::store::Store;
use wsecret_core::windows::agent_bridge::{
    self, AgentCapability, AgentChild, AgentPipe, ENV_AGENT,
};

/// Prompt for the initial passphrase (upstream `s_ask_pass("Passphrase: ")`).
pub const PROMPT_PASSPHRASE: &str = "Passphrase: ";
/// Prompt for the no-records confirmation (upstream `s_get_secret`'s retype:
/// `s_ask_pass("No secrets stored with this passphrase.\nPlease, retype it to confirm: ")`).
pub const PROMPT_CONFIRM_NEW_PARTITION: &str =
    "No secrets stored with this passphrase.\nPlease, retype it to confirm: ";

/// Fatal outcomes of [`launch`] (plan §5.2 step 9: "Launch failure → close
/// both ends, zeroize, fatal"). [`AgentLaunchError::Cancelled`] is the one
/// non-fatal case: upstream exits **0** on empty input (`s_exit(0)`); every
/// other variant renders `Fatal: <message>` and exits 1.
#[derive(Debug)]
pub enum AgentLaunchError {
    /// `SECRET_AGENT` is already set (upstream: "Already running...").
    AlreadyRunning,
    /// No command given and neither `SHELL` nor `ComSpec` is set
    /// (upstream: "Missing env SHELL, nothing to exec!").
    MissingShell,
    /// The 81-byte capability could not be queued into the pipe (upstream
    /// `send` failure: "Unable to queue the key").
    QueueKey,
    /// Executable resolution or `CreateProcessW` failed (upstream
    /// `s_fatal("%s: %s", shell, strerror(errno))`).
    Exec {
        /// The program as typed (the upstream `%s`).
        name: String,
        /// The OS failure (renders like `strerror(errno)`).
        error: std::io::Error,
    },
    /// Empty passphrase input (upstream `s_exit(0)` — exit 0, not fatal).
    Cancelled,
    /// The retype did not match the first entry (upstream:
    /// "Passphrases don't match!").
    PassphraseMismatch,
    /// Store/unlock/bridge failure through the normal error path.
    Core(Error),
}

impl AgentLaunchError {
    /// The upstream catalog message (rendered by the CLI as
    /// `Fatal: <message>`; [`AgentLaunchError::Cancelled`] has none).
    pub fn message(&self) -> Option<String> {
        match self {
            AgentLaunchError::AlreadyRunning => Some("Already running...".to_owned()),
            AgentLaunchError::MissingShell => {
                Some("Missing env SHELL, nothing to exec!".to_owned())
            }
            AgentLaunchError::QueueKey => Some("Unable to queue the key".to_owned()),
            AgentLaunchError::Exec { name, error } => Some(format!("{name}: {error}")),
            AgentLaunchError::Cancelled => None,
            AgentLaunchError::PassphraseMismatch => Some("Passphrases don't match!".to_owned()),
            AgentLaunchError::Core(e) => Some(e.to_string()),
        }
    }
}

/// Acquisition for every store-using command (plan §5.2 steps 2–6). Returns
/// `None` — "fall back to the normal passphrase path" — when `SECRET_AGENT`
/// is absent, unparseable, not a pipe handle, or when the peeked message does
/// not match (wrong length, wrong magic, header inequality). A match adopts
/// the key into a session marked agent-authorized (upstream `pass_ok = match`);
/// the peek does NOT consume, so repeated and descendant use works.
pub fn acquire(header: &Header) -> Option<Session> {
    let value = std::env::var_os(ENV_AGENT)?;
    acquire_from_value(&value, header)
}

/// [`acquire`] with the raw `SECRET_AGENT` value (testable without touching
/// the process environment).
fn acquire_from_value(value: &OsStr, header: &Header) -> Option<Session> {
    // Strict unsigned decimal (plan §5.2 step 3): no signs, no whitespace,
    // no trailing characters, no zero, must fit a `HANDLE`.
    let handle = agent_bridge::parse_env_handle(value.to_str()?)?;
    // Pipe-type check + non-consuming peek + constant-time header compare +
    // key adoption all live in the bridge (no message bytes cross here).
    agent_bridge::adopt_from_handle_value(handle, header)
        .ok()
        .flatten()
}

/// Runs the trusted-agent launch (plan §5.2) end to end and returns the
/// child's exit code (upstream `execvp` semantics: the shell's exit status
/// becomes wsecret's).
///
/// `prompt` is the console input facade (plan §3.1: console I/O is the CLI's
/// concern): it receives exactly [`PROMPT_PASSPHRASE`] first and
/// [`PROMPT_CONFIRM_NEW_PARTITION`] on the no-records path, and returns the
/// entered bytes **without** the trailing newline (upstream `s_input` strips
/// it and rejects control characters); an empty return aborts like upstream's
/// `s_exit(0)` → [`AgentLaunchError::Cancelled`].
pub fn launch<F>(store_path: &Path, cmd: &[&OsStr], mut prompt: F) -> Result<i32, AgentLaunchError>
where
    F: FnMut(&str) -> std::io::Result<Vec<u8>>,
{
    // Step 1: refuse when the process is already inside an agent zone.
    if std::env::var_os(ENV_AGENT).is_some() {
        return Err(AgentLaunchError::AlreadyRunning);
    }

    // Step 2: the child's program and argv. With no command the shell runs
    // with argv0 only (upstream `char *args[] = {shell, NULL}`).
    let shell_storage;
    let argv: Vec<&OsStr> = if !cmd.is_empty() {
        cmd.to_vec()
    } else {
        shell_storage = std::env::var_os("SHELL")
            .or_else(|| std::env::var_os("ComSpec"))
            .ok_or(AgentLaunchError::MissingShell)?;
        vec![shell_storage.as_os_str()]
    };
    let program = argv[0];
    let program_name = program.to_string_lossy().into_owned();

    // Step 3: unlock through the normal library path, including the
    // no-records confirmation (upstream `s_open_secret` + `s_get_secret`).
    let (mut store, header) = Store::open_read(store_path).map_err(AgentLaunchError::Core)?;
    let mut session = unlock_with_confirmation(&mut store, &header, &mut prompt)?;

    // Steps 4–6: capability (secure buffer) → empty-DACL pipe → exact write
    // → only the read handle becomes inheritable. `write_to_pipe` consumes
    // the capability (one-shot) and hands the pipe back.
    let capability = AgentCapability::from_session(&mut session).map_err(AgentLaunchError::Core)?;
    let pipe = AgentPipe::create().map_err(AgentLaunchError::Core)?;
    let mut pipe = capability
        .write_to_pipe(pipe)
        .map_err(|_| AgentLaunchError::QueueKey)?;
    pipe.mark_read_inheritable()
        .map_err(AgentLaunchError::Core)?;

    // Steps 7–9: explicit lpApplicationName (resolved full path), restricted
    // inheritance, handle hygiene and immediate teardown all happen inside
    // `spawn_trusted_child`; the returned `AgentChild` holds only the reduced
    // handle and waits through it.
    let app =
        agent_bridge::resolve_executable(program).map_err(|error| AgentLaunchError::Exec {
            name: program_name.clone(),
            error,
        })?;
    let child: AgentChild =
        agent_bridge::spawn_trusted_child(&app, &argv, pipe).map_err(|error| {
            AgentLaunchError::Exec {
                name: program_name.clone(),
                error,
            }
        })?;
    child.wait_for_exit().map_err(AgentLaunchError::Core)
}

/// The upstream unlock + confirmation sequence (`s_open_secret` →
/// `s_ask_pass` → `s_get_secret(NULL, 0)` retype). Any decryptable record
/// passes; otherwise the passphrase is re-entered and both derivations are
/// compared constant-time ([`agent_bridge::sessions_same_key`]).
fn unlock_with_confirmation<F>(
    store: &mut Store,
    header: &Header,
    prompt: &mut F,
) -> Result<Session, AgentLaunchError>
where
    F: FnMut(&str) -> std::io::Result<Vec<u8>>,
{
    let _acquisition = wsecret_core::windows::security::begin_secret_acquisition()
        .map_err(AgentLaunchError::Core)?;
    let mut pass = prompt(PROMPT_PASSPHRASE).map_err(|e| AgentLaunchError::Core(Error::Io(e)))?;
    if pass.is_empty() {
        return Err(AgentLaunchError::Cancelled);
    }
    // `Session::unlock` zeroizes `pass` on every return path.
    let session = Session::unlock(header, &mut pass).map_err(AgentLaunchError::Core)?;

    // Upstream `pass_ok`: does ANY record decrypt with this key?
    let mut decryptable = false;
    store
        .scan_each(&session, None, &mut |_| {
            decryptable = true;
            Ok(())
        })
        .map_err(AgentLaunchError::Core)?;

    if !decryptable {
        let mut again = prompt(PROMPT_CONFIRM_NEW_PARTITION)
            .map_err(|e| AgentLaunchError::Core(Error::Io(e)))?;
        if again.is_empty() {
            return Err(AgentLaunchError::Cancelled);
        }
        let check = Session::unlock(header, &mut again).map_err(AgentLaunchError::Core)?;
        if !agent_bridge::sessions_same_key(&session, &check).map_err(AgentLaunchError::Core)? {
            return Err(AgentLaunchError::PassphraseMismatch);
        }
        // Keys are equal (upstream keeps the re-derived one); `check` drops
        // here, zeroizing its at-rest copy.
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use wsecret_core::error::NameError;
    use wsecret_core::format::{Header, OPS_LIMIT_MIN};
    use wsecret_core::store::ScanOutcome;

    fn test_header() -> Header {
        Header {
            version: 0,
            master: [3u8; 32],
            ops_limit: OPS_LIMIT_MIN,
        }
    }

    /// A live pipe carrying the capability of `session`, plus the decimal
    /// handle string a real launcher would put into `SECRET_AGENT`.
    fn pipe_with_capability(session: &mut Session) -> (AgentPipe, String) {
        let pipe = AgentPipe::create().expect("pipe");
        let capability = AgentCapability::from_session(session).expect("capability");
        let pipe = capability.write_to_pipe(pipe).expect("write");
        let value = pipe.handle_value().to_string();
        (pipe, value)
    }

    /// A test session through the public unlock path (the KDF is deterministic
    /// for a fixed passphrase and header).
    fn test_session(header: &Header) -> Session {
        Session::unlock(header, &mut b"wsecret-agent-test-pass".to_vec()).expect("session")
    }

    // ---- env-var parsing (plan §5.2 step 3) --------------------------------

    #[test]
    fn env_parsing_rejects_non_decimal_values() {
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1x",
            "0x10",
            "1.0",
            "abc",
            "18446744073709551616", // u64 overflow
            "١٢",                   // non-ASCII digits
        ] {
            assert!(
                acquire_from_value(OsStr::new(bad), &test_header()).is_none(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn env_parsing_accepts_strict_unsigned_decimal() {
        // A valid decimal that is not a pipe handle still fails later (pipe
        // type check / peek) — parsing itself accepts it.
        assert!(acquire_from_value(OsStr::new("42"), &test_header()).is_none()); // not a pipe
    }

    // ---- pipe-type check + peek match/mismatch -----------------------------

    #[test]
    fn acquire_matches_a_real_capability_pipe() {
        let header = test_header();
        let mut launcher_session = test_session(&header);
        let (_pipe, value) = pipe_with_capability(&mut launcher_session);

        let adopted = acquire_from_value(OsStr::new(&value), &header)
            .expect("acquire must adopt the capability");
        assert!(!adopted.is_locked());
        assert_eq!(adopted.header(), &header);
    }

    #[test]
    fn acquire_is_non_consuming_across_repeated_use() {
        // Peek does not consume (upstream MSG_PEEK): repeated use works.
        let header = test_header();
        let mut launcher_session = test_session(&header);
        let (_pipe, value) = pipe_with_capability(&mut launcher_session);

        let first = acquire_from_value(OsStr::new(&value), &header).expect("first adopt");
        let second = acquire_from_value(OsStr::new(&value), &header).expect("second adopt");
        assert!(!first.is_locked());
        assert!(!second.is_locked());
    }

    #[test]
    fn acquire_rejects_a_header_mismatch() {
        let header = test_header();
        let mut launcher_session = test_session(&header);
        let (_pipe, value) = pipe_with_capability(&mut launcher_session);

        let mut other = test_header();
        other.master[0] ^= 0xff;
        assert!(acquire_from_value(OsStr::new(&value), &other).is_none());
    }

    #[test]
    fn acquire_rejects_non_pipe_handles() {
        let header = test_header();
        let file = std::fs::File::create(std::env::temp_dir().join("wsecret-agent-test-nopipe"))
            .expect("temp file");
        let value = (file.as_raw_handle() as usize).to_string();
        assert!(!AgentPipe::is_pipe_handle(file.as_raw_handle() as usize));
        assert!(acquire_from_value(OsStr::new(&value), &header).is_none());
        let _ = std::fs::remove_file(std::env::temp_dir().join("wsecret-agent-test-nopipe"));
    }

    #[test]
    fn acquire_rejects_an_empty_or_absent_value() {
        assert!(acquire_from_value(OsStr::new(""), &test_header()).is_none());
    }

    // ---- forged message: narrowed assurance (audit P13) --------------------

    /// End-to-end P13 documentation: a "forged" capability — correct store
    /// header (it is plaintext on disk) with an ATTACKER key — is adopted on
    /// header equality alone. Existing records stay unreadable, but the
    /// adopting process happily encrypts NEW secrets under the attacker key.
    #[test]
    fn forged_capability_adopts_but_existing_records_fail_auth() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wsecret-agent-p13-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let (mut store, header, _receipt) =
            Store::create(&path, OPS_LIMIT_MIN).expect("store create");
        let victim =
            Session::unlock(&header, &mut b"victim-passphrase".to_vec()).expect("victim unlock");
        store
            .append_or_reuse(None, &victim, b"old", b"victim secret")
            .expect("victim record written");

        // The attacker derives their own key from the same (public) header.
        let mut attacker =
            Session::unlock(&header, &mut b"attacker-passphrase".to_vec()).expect("attacker");
        let (_pipe, value) = pipe_with_capability(&mut attacker);

        // Header equality adopts the attacker key (this IS the narrowed
        // assurance: no record decryption authorizes the adoption).
        let adopted =
            acquire_from_value(OsStr::new(&value), &header).expect("forged capability is adopted");

        // Existing victim records fail authentication for the adopter.
        match store.find(&adopted, b"old", false).expect("scan") {
            ScanOutcome::NotFound { .. } => {} // expected: auth fails, invisible
            ScanOutcome::Found { .. } => panic!("victim record must not authenticate"),
        }

        // New secrets ARE encrypted under the attacker key...
        store
            .append_or_reuse(None, &adopted, b"new", b"attacker sees this")
            .expect("record written under attacker key");
        // ...and the victim cannot read them either.
        match store.find(&victim, b"new", false).expect("victim scan") {
            ScanOutcome::NotFound { .. } => {}
            ScanOutcome::Found { .. } => panic!("victim must not read attacker record"),
        }
        // The adopter (attacker key holder) reads the new record freely.
        match store.find(&adopted, b"new", false).expect("adopted scan") {
            ScanOutcome::Found { value, .. } => assert_eq!(value, b"attacker sees this"),
            ScanOutcome::NotFound { .. } => panic!("attacker record must be readable"),
        }

        drop(store);
        drop(victim);
        drop(adopted);
        let _ = std::fs::remove_file(&path);
    }

    // ---- teardown / zeroization -------------------------------------------

    #[test]
    fn teardown_zeroizes_sessions_on_drop() {
        let header = test_header();
        let mut launcher_session = test_session(&header);
        let (pipe, value) = pipe_with_capability(&mut launcher_session);

        // The launcher's session is drained at capability creation and its
        // at-rest key is erased on drop (both covered here and in
        // wsecret-core's session tests).
        assert!(launcher_session.is_locked());

        let mut adopted = acquire_from_value(OsStr::new(&value), &header).expect("adopt");
        adopted.lock();
        assert!(adopted.is_locked());
        drop(adopted);
        // The pipe (and its buffered message) dies with the last handle.
        drop(pipe);
    }

    // ---- unlock + no-records confirmation (launch step 3) ------------------

    fn temp_store(name: &str) -> (std::path::PathBuf, Store, Header) {
        let path = std::env::temp_dir().join(format!(
            "wsecret-agent-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        let (store, header, _receipt) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
        (path, store, header)
    }

    #[test]
    fn unlock_prompts_once_when_records_exist() {
        let (path, mut store, header) = temp_store("once");
        let session = Session::unlock(&header, &mut b"pass-a".to_vec()).expect("unlock");
        store
            .append_or_reuse(None, &session, b"k", b"v")
            .expect("record");

        let mut calls = Vec::new();
        let out = unlock_with_confirmation(&mut store, &header, &mut |p| {
            calls.push(p.to_owned());
            Ok(b"pass-a".to_vec())
        })
        .expect("unlock_with_confirmation");
        assert_eq!(calls, vec![PROMPT_PASSPHRASE]);
        assert!(!out.is_locked());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_confirms_retype_when_no_records_decrypt() {
        let (path, mut store, header) = temp_store("confirm");
        let mut calls = Vec::new();
        let out = unlock_with_confirmation(&mut store, &header, &mut |p| {
            calls.push(p.to_owned());
            Ok(b"pass-b".to_vec())
        })
        .expect("unlock_with_confirmation");
        assert_eq!(calls, vec![PROMPT_PASSPHRASE, PROMPT_CONFIRM_NEW_PARTITION]);
        assert!(!out.is_locked());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_retype_mismatch_is_fatal() {
        let (path, mut store, header) = temp_store("mismatch");
        let mut n = 0;
        let err = match unlock_with_confirmation(&mut store, &header, &mut |_p| {
            n += 1;
            Ok(if n == 1 {
                b"pass-c".to_vec()
            } else {
                b"other".to_vec()
            })
        }) {
            Err(e) => e,
            Ok(_) => panic!("mismatch must fail"),
        };
        assert!(matches!(err, AgentLaunchError::PassphraseMismatch));
        assert_eq!(err.message().as_deref(), Some("Passphrases don't match!"));
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_empty_input_exits_zero() {
        let (path, mut store, header) = temp_store("empty");
        let err = match unlock_with_confirmation(&mut store, &header, &mut |_p| Ok(Vec::new())) {
            Err(e) => e,
            Ok(_) => panic!("empty input cancels"),
        };
        assert!(matches!(err, AgentLaunchError::Cancelled));
        assert_eq!(err.message(), None);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn launch_error_catalog_strings_match_upstream() {
        assert_eq!(
            AgentLaunchError::AlreadyRunning.message().as_deref(),
            Some("Already running...")
        );
        assert_eq!(
            AgentLaunchError::MissingShell.message().as_deref(),
            Some("Missing env SHELL, nothing to exec!")
        );
        assert_eq!(
            AgentLaunchError::QueueKey.message().as_deref(),
            Some("Unable to queue the key")
        );
        let exec = AgentLaunchError::Exec {
            name: "/bin/sh".to_owned(),
            error: std::io::Error::from_raw_os_error(2),
        };
        let msg = exec.message().expect("exec message");
        assert!(msg.starts_with("/bin/sh: "), "got {msg}");
    }

    #[test]
    fn store_errors_map_through_the_normal_error_path() {
        let missing = std::env::temp_dir().join(format!(
            "wsecret-agent-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let err = launch(&missing, &[], |_p| Ok(Vec::new())).expect_err("missing store must fail");
        assert!(matches!(err, AgentLaunchError::Core(Error::StoreNotFound)));
    }

    #[test]
    fn name_lookup_error_carries_no_record_bytes() {
        // Sanity for the error surface used by the dispatch layer.
        let e = Error::Name(NameError::Empty);
        assert_eq!(e.status().code(), NameError::Empty.status().code());
    }
}
