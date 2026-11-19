//! WS-02 executable-resolution policy tests for the managed SSH launch
//! command `wsecret ssh agent KEY [CMD [ARG…]]`.
//!
//! (The general `agent CMD [ARG…]` command is gone with the trusted-agent
//! feature; `removed_agent_command_fails_closed_like_any_unknown_command`
//! below pins that it fails closed as an ordinary unknown command.)
//!
//! Everything here is **process-scoped**: each check spawns the real
//! `wsecret.exe` as a child with its own CWD and environment
//! (`Command::current_dir` / `Command::env` / `Command::env_remove`). This
//! test process never changes its own CWD, so there are no global CWD races
//! with parallel tests or other test binaries.
//!
//! # What is pinned
//!
//! 1. **Pre-prompt failure for the launch command.** Rejected names must fail
//!    with `Fatal: <name>: … (os error …)` BEFORE the store is opened and
//!    before the `Passphrase: ` prompt. The rejection cases run against a
//!    REAL store, so any ordering regression that resolves after unlock
//!    reaches the prompt and blocks on its private console — the [`run_cli`]
//!    deadline turns that into a loud failure instead of a hung test binary.
//!    (Children are spawned with `CREATE_NO_WINDOW`, so a blocking child
//!    waits on its own invisible console and never steals the test runner's
//!    console input.)
//! 2. **Resolution runs before the store is opened.** A rejected name plus a
//!    MISSING store must report the exec failure, not the store error.
//! 3. **Acceptance discriminators.** A valid explicit path (or a trusted bare
//!    name) plus a MISSING store must report `Fatal: Secret store … doesn't
//!    exist` — proving the name passed resolution and the run proceeded to
//!    store opening without ever prompting.
//! 4. **CWD independence.** A benign test executable (a copy of the system
//!    `cmd.exe`) sits in the child's CWD under the bait name; bare and
//!    relative forms of it must never resolve, from any CWD, while its fully
//!    qualified path resolves from any CWD.
//! 5. **Default-shell fallback.** `SHELL`/`ComSpec` values go through the
//!    same strict resolver: relative and bare-untrusted values are fatal
//!    pre-prompt (never trusted against the current directory), and the
//!    no-shell case keeps upstream's `Missing env SHELL, nothing to exec!`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `CREATE_NO_WINDOW`: the child gets its own invisible console, so a run
/// that (wrongly) reaches the `CONIN$` passphrase prompt blocks THERE —
/// detected by the deadline — instead of consuming the test runner's console.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long a correctly-ordered run needs to fail pre-prompt. A run that
/// reaches the unlock prompt instead blocks forever; the deadline converts
/// that regression into a failed assertion.
const DEADLINE: Duration = Duration::from_secs(20);

/// Well-formed key for the `ssh agent KEY [CMD…]` shape (same form the
/// existing SSH acceptance tests use).
const SSH_KEY: &str = "test/key";

/// `ssh agent KEY CMD…`: the one launch command shape under test.
fn ssh_args(program: &OsStr) -> Vec<OsString> {
    vec![
        "ssh".into(),
        "agent".into(),
        SSH_KEY.into(),
        program.to_owned(),
    ]
}

/// The same command with no CMD (the `SHELL`/`ComSpec` fallback).
fn ssh_args_no_program() -> Vec<OsString> {
    vec!["ssh".into(), "agent".into(), SSH_KEY.into()]
}

struct Run {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// The real CLI under test, pre-configured process-scoped.
fn wsecret() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wsecret"));
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Never inherit a legacy `SECRET_AGENT` value from the test runner.
    cmd.env_remove("SECRET_AGENT");
    cmd
}

/// Runs the child to completion. A child still alive after [`DEADLINE`] has
/// reached the unlock prompt (or hung) — the resolver must reject before the
/// store is opened and before any prompt — so the child is killed and the
/// check fails with that diagnosis.
fn run_cli(mut cmd: Command, what: &str) -> Run {
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("{what}: spawn failed: {e}"));
    let deadline = Instant::now() + DEADLINE;
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{what}: wsecret was still running after {DEADLINE:?} — it reached the \
                 unlock prompt; executable resolution must fail BEFORE unlock/prompt"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let out = child.wait_with_output().expect("collect output");
    Run {
        code: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// A fresh per-test scenario directory (unique per process + tag; no shared
/// state, no CWD mutation).
fn scenario(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wsecret-agent-resolution-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scenario directory");
    dir
}

/// The benign bait: a copy of the system `cmd.exe` under a unique name. If a
/// resolver regression ever trusted the current directory, it would pick up
/// THIS harmless image — and these tests would fail — instead of an
/// attacker-planted one.
fn plant_bait(dir: &Path) -> PathBuf {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    let cmd_exe = PathBuf::from(system_root).join("System32").join("cmd.exe");
    let bait = dir.join("wstest-benign.exe");
    fs::copy(&cmd_exe, &bait).expect("copy benign bait");
    bait
}

/// A real store: with a post-unlock resolver regression the run would reach
/// the passphrase prompt and trip the deadline instead of exiting on a store
/// error.
fn real_store(dir: &Path) -> PathBuf {
    let path = dir.join("store.secret");
    let (_, _, _) = wsecret_core::Store::create(&path, 10_000).expect("create store");
    path
}

/// A deliberately absent store path (the acceptance/before-open
/// discriminator).
fn missing_store(dir: &Path) -> PathBuf {
    dir.join("missing.secret")
}

/// The exec fatal of a pre-prompt rejection: exit 1, `Fatal: <name>: …`,
/// the expected `(os error N)`, nothing on stdout.
fn assert_exec_fatal(run: &Run, program: &str, os_error: i32, what: &str) {
    let err = run.stderr_text();
    let prefix = format!("Fatal: {program}: ");
    assert_eq!(
        run.code,
        Some(1),
        "{what}: expected exit 1, got {:?}; stderr: {err}",
        run.code
    );
    assert!(
        err.starts_with(&prefix),
        "{what}: expected `{prefix}…` (pre-prompt exec failure), got: {err}"
    );
    assert!(
        err.contains(&format!("(os error {os_error})")),
        "{what}: expected os error {os_error} in: {err}"
    );
    assert!(
        run.stdout.is_empty(),
        "{what}: unexpected stdout: {:?}",
        String::from_utf8_lossy(&run.stdout)
    );
}

/// The store-missing fatal: exit 1 and `Secret store … doesn't exist`. Its
/// presence proves resolution ACCEPTED the program and the run proceeded to
/// store opening without prompting.
fn assert_store_error(run: &Run, what: &str) {
    let err = run.stderr_text();
    assert_eq!(
        run.code,
        Some(1),
        "{what}: expected exit 1, got {:?}; stderr: {err}",
        run.code
    );
    assert!(
        err.contains("Secret store ") && err.contains(" doesn't exist"),
        "{what}: expected the store-missing fatal (resolution passed), got: {err}"
    );
}

/// The general `agent` command is gone with the trusted-agent feature: every
/// invocation is an ordinary unknown-command usage failure — no launch, no
/// store access, no prompt ([`run_cli`] deadline guards the prompt case).
#[test]
fn removed_agent_command_fails_closed_like_any_unknown_command() {
    for args in [&["agent"][..], &["agent", "cmd", "/c", "exit 0"], &["agent", "help"]] {
        let what = format!("wsecret {args:?}");
        let mut cmd = wsecret();
        cmd.args(args);
        let run = run_cli(cmd, &what);
        assert_eq!(run.code, Some(255), "{what}: {}", run.stderr_text());
        assert!(run.stdout.is_empty(), "{what}: unexpected stdout");
        assert!(!run.stderr.is_empty(), "{what}: expected a usage error");
    }
}

#[test]
fn bare_names_in_the_current_directory_are_not_trusted() {
    // The bait exists in the child's CWD under the exact bare name(s). Real
    // store: a CWD-searching resolver would resolve it and reach the prompt
    // (deadline failure); a post-unlock resolver would reach the prompt
    // (deadline failure). Correct behavior exits pre-prompt with the exec
    // fatal (bare names are not found outside the trusted OS directories).
    for program in ["wstest-benign", "wstest-benign.exe"] {
        let dir = scenario(&format!("bare-cwd-{program}"));
        let _bait = plant_bait(&dir);
        let store = real_store(&dir);
        let what = format!("ssh-agent {program} with the bait in the CWD");
        let mut cmd = wsecret();
        cmd.current_dir(&dir)
            .env("SECRET_STORE", &store)
            .args(ssh_args(OsStr::new(program)));
        let run = run_cli(cmd, &what);
        // Not found in the trusted directories (os error 2), never
        // resolved from the CWD.
        assert_exec_fatal(&run, program, 2, &what);
    }
}

#[test]
fn rejected_names_fail_before_the_store_is_opened() {
    // MISSING store + rejected name: the exec fatal must win — resolution
    // runs before `Store::open_read` for the launch command.
    let dir = scenario("before-open");
    let _bait = plant_bait(&dir);
    let missing = missing_store(&dir);
    let what = "ssh-agent wstest-benign with a missing store".to_owned();
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &missing)
        .args(ssh_args(OsStr::new("wstest-benign")));
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, "wstest-benign", 2, &what);
}

#[test]
fn relative_and_current_dir_paths_fail_before_prompt() {
    let dir = scenario("relative");
    let _bait = plant_bait(&dir);
    let sub = dir.join("wstest-sub");
    fs::create_dir_all(&sub).expect("subdirectory");
    fs::copy(dir.join("wstest-benign.exe"), sub.join("wstest-benign.exe"))
        .expect("second bait copy");
    let store = real_store(&dir);
    for program in [
        ".\\wstest-benign.exe",
        "wstest-sub\\wstest-benign.exe",
        "..\\wstest-benign.exe",
        "wstest-sub/wstest-benign.exe",
        ".",
        "..",
    ] {
        let what = format!("ssh-agent {program} (relative form)");
        let mut cmd = wsecret();
        cmd.current_dir(&dir)
            .env("SECRET_STORE", &store)
            .args(ssh_args(OsStr::new(program)));
        let run = run_cli(cmd, &what);
        assert_exec_fatal(&run, program, 123, &what);
    }
}

#[test]
fn namespace_unc_and_nt_paths_fail_before_prompt() {
    let dir = scenario("namespace");
    let bait = plant_bait(&dir);
    let store = real_store(&dir);
    // The verbatim/device/NT-object forms of the REAL bait path (the
    // bait is present behind every one of them), a remote UNC name and a
    // device path: all rejected as ambiguous/unsafe namespace forms.
    let drive_path = bait.to_string_lossy().into_owned();
    let programs = [
        format!("\\\\?\\{drive_path}"),
        format!("\\\\.\\{drive_path}"),
        format!("\\??\\{drive_path}"),
        "\\\\127.0.0.1\\c$\\wstest-benign.exe".to_owned(),
        "\\Device\\HarddiskVolume1\\wstest-benign.exe".to_owned(),
    ];
    for program in &programs {
        let what = format!("ssh-agent {program} (namespace/UNC form)");
        let mut cmd = wsecret();
        cmd.current_dir(&dir)
            .env("SECRET_STORE", &store)
            .args(ssh_args(OsStr::new(program)));
        let run = run_cli(cmd, &what);
        assert_exec_fatal(&run, program, 123, &what);
    }
}

#[test]
fn drive_relative_stream_and_device_names_fail_before_prompt() {
    let dir = scenario("odd-shapes");
    let bait = plant_bait(&dir);
    let store = real_store(&dir);
    let programs = [
        // Drive-relative: completed against the current drive/directory.
        "C:wstest-benign.exe".to_owned(),
        // Alternate data stream of the real bait.
        format!("{}:wstest-stream", bait.to_string_lossy()),
        // Device names Win32 would map into the device namespace.
        "NUL".to_owned(),
        "CON".to_owned(),
        "COM1".to_owned(),
    ];
    for program in &programs {
        let what = format!("ssh-agent {program} (ambiguous shape)");
        let mut cmd = wsecret();
        cmd.current_dir(&dir)
            .env("SECRET_STORE", &store)
            .args(ssh_args(OsStr::new(program)));
        let run = run_cli(cmd, &what);
        assert_exec_fatal(&run, program, 123, &what);
    }
}

#[test]
fn explicit_fully_qualified_paths_are_accepted_from_any_cwd() {
    // Acceptance discriminator: MISSING store + valid explicit path → the
    // store error surfaces, proving resolution passed pre-prompt. The same
    // program is run with two different child CWDs — the outcome must not
    // depend on the CWD.
    for from_bait_cwd in [true, false] {
        let dir = scenario(&format!(
            "fq-accept-{}",
            if from_bait_cwd {
                "bait-cwd"
            } else {
                "other-cwd"
            }
        ));
        let bait = plant_bait(&dir);
        let elsewhere = dir.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("other CWD");
        let missing = missing_store(&dir);
        let cwd = if from_bait_cwd { &dir } else { &elsewhere };
        let program = bait.to_string_lossy().into_owned();
        let what = format!(
            "ssh-agent explicit path {} from {}",
            program,
            cwd.display()
        );
        let mut cmd = wsecret();
        cmd.current_dir(cwd)
            .env("SECRET_STORE", &missing)
            .args(ssh_args(OsStr::new(&program)));
        let run = run_cli(cmd, &what);
        assert_store_error(&run, &what);
    }
}

#[test]
fn bare_trusted_system_names_resolve_from_any_cwd() {
    // `cmd`/`cmd.exe` live in the WinAPI system directory — a trusted root —
    // so they must resolve from any CWD (acceptance: the store error proves
    // resolution passed and never prompted).
    let dir = scenario("bare-trusted");
    let _bait = plant_bait(&dir);
    let missing = missing_store(&dir);
    for program in ["cmd", "cmd.exe"] {
        let what = format!("ssh-agent bare {program} from the bait CWD");
        let mut cmd = wsecret();
        cmd.current_dir(&dir)
            .env("SECRET_STORE", &missing)
            .args(ssh_args(OsStr::new(program)));
        let run = run_cli(cmd, &what);
        assert_store_error(&run, &what);
    }
}

#[test]
fn explicit_paths_must_exist_before_prompt() {
    let dir = scenario("fq-exists");
    let _bait = plant_bait(&dir);
    let store = real_store(&dir);
    // Missing file: (os error 2), pre-prompt — even though the path is
    // fully qualified and the store would unlock.
    let absent = dir.join("wstest-absent.exe");
    let program = absent.to_string_lossy().into_owned();
    let what = format!("ssh-agent explicit missing {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, &program, 2, &what);

    // Extension-less request where neither the name nor its `.exe` exists.
    let absent_stem = dir.join("wstest-absent-stem");
    let program = absent_stem.to_string_lossy().into_owned();
    let what = format!("ssh-agent explicit missing stem {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, &program, 2, &what);

    // A directory "exists but is not an executable": (os error 5).
    let dir = scenario("fq-exists-dir");
    let store = real_store(&dir);
    let program = dir.to_string_lossy().into_owned();
    let what = format!("ssh-agent explicit directory {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, &program, 5, &what);
}

#[test]
fn extension_candidates_match_the_lpapplicationname_contract() {
    // `lpApplicationName` "must include the file name extension; no default
    // extension is assumed": an extension-less request may denote the `.exe`
    // of the same stem; an exactly named extension-less file resolves as
    // typed; an extended name must exist exactly. The missing-store
    // discriminator marks every acceptance.
    let dir = scenario("ext-rule");
    let _bait = plant_bait(&dir); // wstest-benign.exe
    let missing = missing_store(&dir);

    // Extension-less request for the existing `.exe` of the stem: accepted.
    let stem = dir.join("wstest-benign");
    let program = stem.to_string_lossy().into_owned();
    let what = format!("ssh-agent extension-less stem {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &missing)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_store_error(&run, &what);

    // Exactly named extension-less file: accepted as typed.
    let raw = dir.join("wstest-noext");
    fs::write(&raw, b"decoy").expect("decoy file");
    let program = raw.to_string_lossy().into_owned();
    let what = format!("ssh-agent extension-less file {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &missing)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_store_error(&run, &what);

    // Its `.exe` form is a different name and does not exist: rejected.
    let program = format!("{program}.exe");
    let what = format!("ssh-agent absent .exe form {program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &missing)
        .args(ssh_args(OsStr::new(&program)));
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, &program, 2, &what);
}

#[test]
fn default_shell_fallback_never_trusts_relative_or_bare_untrusted_names() {
    let dir = scenario("fallback");
    let _bait = plant_bait(&dir);
    let store = real_store(&dir);

    // `SHELL` pointing at a CWD-relative bait: fatal pre-prompt, the
    // relative value rendered exactly as set.
    let what = "ssh-agent SHELL=.\\wstest-benign.exe".to_owned();
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .env("SHELL", ".\\wstest-benign.exe")
        .args(ssh_args_no_program());
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, ".\\wstest-benign.exe", 123, &what);

    // `SHELL` pointing at a bare name outside the trusted directories:
    // fatal pre-prompt even though the bait sits in the CWD.
    let what = "ssh-agent SHELL=wstest-benign".to_owned();
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .env("SHELL", "wstest-benign")
        .args(ssh_args_no_program());
    let run = run_cli(cmd, &what);
    assert_exec_fatal(&run, "wstest-benign", 2, &what);
}

#[test]
fn default_shell_fallback_requires_an_absolute_or_trusted_shell() {
    // Neither `SHELL` nor `ComSpec`: upstream's missing-shell fatal, before
    // any prompt.
    let dir = scenario("no-shell");
    let store = real_store(&dir);
    let what = "ssh-agent without SHELL/ComSpec".to_owned();
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .env_remove("SHELL")
        .env_remove("ComSpec")
        .args(ssh_args_no_program());
    let run = run_cli(cmd, &what);
    let err = run.stderr_text();
    assert_eq!(run.code, Some(1), "{what}: expected exit 1; stderr: {err}");
    assert!(
        err.starts_with("Fatal: Missing env SHELL, nothing to exec!"),
        "{what}: expected the missing-shell fatal, got: {err}"
    );

    // A relative `ComSpec` (with `SHELL` absent) is equally fatal: the
    // fallback chain never trusts a relative path.
    let dir = scenario("fallback-comspec-relative");
    let _bait = plant_bait(&dir);
    let store = real_store(&dir);
    let what = "ssh-agent ComSpec=.\\wstest-benign.exe";
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &store)
        .env_remove("SHELL")
        .env("ComSpec", ".\\wstest-benign.exe")
        .args(ssh_args_no_program());
    let run = run_cli(cmd, what);
    assert_exec_fatal(&run, ".\\wstest-benign.exe", 123, what);

    // An explicit fully qualified `ComSpec` IS accepted: the missing-store
    // error proves resolution passed and no prompt happened.
    let missing = missing_store(&dir);
    let bait = dir.join("wstest-benign.exe");
    let program = bait.to_string_lossy().into_owned();
    let what = format!("ssh-agent ComSpec={program}");
    let mut cmd = wsecret();
    cmd.current_dir(&dir)
        .env("SECRET_STORE", &missing)
        .env_remove("SHELL")
        .env("ComSpec", &bait)
        .args(ssh_args_no_program());
    let run = run_cli(cmd, &what);
    assert_store_error(&run, &what);
}
