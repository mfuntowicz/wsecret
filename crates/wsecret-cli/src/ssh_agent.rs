//! `wsecret ssh keygen` / `wsecret ssh agent` support.
//!
//! Private keys never touch the filesystem. `ssh keygen` stores a standard
//! 64-byte Ed25519 secret key in the encrypted store. `ssh agent` sends that
//! key directly to the existing Windows OpenSSH agent over its named pipe,
//! launches a trusted child with the verified `SSH_AUTH_SOCK` endpoint name
//! and the ordinary standard handles — and nothing else: never `SECRET_AGENT`,
//! never a vault capability — and removes the identity on every clean return
//! path. The Windows agent performs all SSH signatures.
//!
//! Coordination (WS-04): cooperating wsecret clients serialize per user and
//! public key with [`IdentityLock`], held from before the agent listing
//! through add, child wait, removal and exit. A key already loaded in the
//! agent is refused and left exactly as found. External SSH clients do not
//! participate in the lock: adding or removing the same identity externally
//! during a run is unsupported (README).

use std::ffi::OsStr;
use std::path::Path;

use wsecret_core::error::Error;
use wsecret_core::store::{Limits, ScanOutcome, Store};
use wsecret_core::windows::agent_bridge::{self, ENV_AGENT};
use wsecret_core::windows::security::IdentityLock;
use wsecret_core::windows::ssh_agent::{SshAgentClient, is_canonical_endpoint};

use crate::agent::unlock_with_confirmation;
use crate::output;

/// Optional endpoint override. A nonempty value is accepted ONLY when it
/// names the canonical Windows OpenSSH agent endpoint verbatim
/// (`\\.\pipe\openssh-ssh-agent`); any other value is rejected — there is no
/// custom trust path and third-party endpoints are unsupported.
pub const ENV_WSECRET_SSH_AGENT_PIPE: &str = "WSECRET_SSH_AGENT_PIPE";

/// Fatal outcomes of the SSH-agent launch. `Cancelled` is the upstream
/// empty-input exit-0 case; every other variant renders `Fatal: …`.
#[derive(Debug)]
pub enum SshAgentError {
    AlreadyRunning,
    MissingShell,
    SecretNotFound(Vec<u8>),
    InvalidKey,
    Cancelled,
    Core(Error),
    Exec {
        name: String,
        error: std::io::Error,
    },
    /// `WSECRET_SSH_AGENT_PIPE` named something other than the standard
    /// Windows OpenSSH agent endpoint (no custom trust).
    UntrustedEndpoint(String),
    /// Another cooperating wsecret client holds the per-user/per-public-key
    /// identity lock; contention is refused, never waited out.
    IdentityBusy,
    /// The public key is already loaded in the agent. It is refused and left
    /// exactly as found: never adopted, never removed, never overwritten (a
    /// blind add would replace the stored entry's comment/blob).
    IdentityLoaded,
    /// The child ran but the identity could not be removed afterwards; it may
    /// remain loaded in the shared agent (recovery: `ssh-add -l`, then
    /// `ssh-add -d` for THIS key only).
    RemoveFailed(Error),
    /// The launch failed AND the identity could not be removed: both facts
    /// are reported because the stale identity outlives the failed run.
    LaunchAndCleanupFailed {
        launch: Box<SshAgentError>,
        cleanup: Error,
    },
}

impl SshAgentError {
    pub fn message(&self) -> Option<String> {
        match self {
            Self::AlreadyRunning => Some("Already running...".to_owned()),
            Self::MissingShell => Some("Missing env SHELL, nothing to exec!".to_owned()),
            Self::SecretNotFound(key) => {
                Some(format!("Secret {} not found", String::from_utf8_lossy(key)))
            }
            Self::InvalidKey => Some("Invalid Ed25519 secret key (expected 64 bytes)".to_owned()),
            Self::Cancelled => None,
            Self::Core(error) => Some(error.to_string()),
            Self::Exec { name, error } => Some(format!("{name}: {error}")),
            Self::UntrustedEndpoint(value) => Some(format!(
                "WSECRET_SSH_AGENT_PIPE must name the standard Windows OpenSSH agent endpoint, got {value}"
            )),
            Self::IdentityBusy => Some(
                "Another wsecret ssh agent is using this key; try again when it finishes"
                    .to_owned(),
            ),
            Self::IdentityLoaded => {
                Some("Key already loaded in ssh-agent; refusing to take ownership".to_owned())
            }
            Self::RemoveFailed(error) => Some(format!(
                "Unable to remove the identity from ssh-agent: {error}; it may remain loaded \
                 (inspect ssh-add -l and remove only this key with ssh-add -d)"
            )),
            Self::LaunchAndCleanupFailed { launch, cleanup } => {
                let primary = launch
                    .message()
                    .unwrap_or_else(|| "Launch failed".to_owned());
                Some(format!(
                    "{primary}; additionally, the identity could not be removed from ssh-agent: {cleanup}"
                ))
            }
        }
    }
}

/// Generates a standard Ed25519 keypair using the OS RNG. The returned
/// 64-byte secret is `seed || public`, exactly OpenSSH's agent-add encoding.
/// No private-key file or second signing implementation is involved.
pub fn generate_ed25519() -> ([u8; 32], [u8; 64]) {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let public = signing.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&signing.to_bytes());
    secret[32..].copy_from_slice(&public);
    (public, secret)
}

/// OpenSSH public-key text line. Only the public key and a non-secret comment
/// are emitted; the 64-byte private key is never printed.
pub fn public_key_line(public: &[u8; 32], key: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(public);

    let mut line = b"ssh-ed25519 ".to_vec();
    line.extend_from_slice(&output::base64_encode(&blob));
    line.extend_from_slice(b" wsecret:");
    line.extend_from_slice(key);
    line.push(b'\n');
    line
}

/// Adds `key` to the Windows OpenSSH agent, launches the trusted child, and
/// removes the identity on every clean return path.
///
/// The child receives ONLY the verified `SSH_AUTH_SOCK` endpoint name (the
/// full agent path, preserved verbatim) and the ordinary standard handles —
/// never `SECRET_AGENT` and never a vault capability (WS-04).
///
/// Ordering (WS-04): the endpoint policy and [`agent_bridge::resolve_executable`]
/// run BEFORE the vault is unlocked (a bad program name or untrusted endpoint
/// fails before any passphrase is read and before the store is opened); the
/// agent service is authenticated before the key is sent. A per-user/
/// per-public-key [`IdentityLock`] is held from before the agent listing
/// through add, child wait, removal and exit, so cooperating clients cannot
/// race on the same key. A key already loaded in the agent is refused and left
/// untouched. The session and the extracted key are dropped before the child
/// is waited on.
///
/// Failure/cleanup: once the identity has been added, EVERY return path
/// attempts removal; a removal failure is reported explicitly
/// ([`SshAgentError::RemoveFailed`], or combined with the launch error in
/// [`SshAgentError::LaunchAndCleanupFailed`]) instead of being hidden. If the
/// process is killed outright, removal is not guaranteed; the documented
/// recovery is `ssh-add -l` followed by `ssh-add -d` for THIS key only (never
/// `ssh-add -D`).
///
/// Limits: external, non-cooperating tools (e.g. `ssh-add`) do not take
/// [`IdentityLock`]. Modifying the identity externally during a run is
/// unsupported: an external add may be removed by our cleanup, an external
/// remove may make cleanup report [`SshAgentError::RemoveFailed`], and an
/// externally preloaded identity is refused rather than adopted.
pub fn launch<F>(
    store_path: &Path,
    key: &[u8],
    cmd: &[&OsStr],
    limits: Limits,
    mut prompt: F,
) -> Result<i32, SshAgentError>
where
    F: FnMut(&str) -> std::io::Result<Vec<u8>>,
{
    // Refuse inside an agent zone (parity with `wsecret agent`).
    if std::env::var_os(ENV_AGENT).is_some() {
        return Err(SshAgentError::AlreadyRunning);
    }

    // Endpoint policy (no custom trust): a nonempty override must name the
    // canonical Windows OpenSSH agent endpoint verbatim; anything else is
    // rejected before any I/O or unlock.
    if let Some(override_value) = std::env::var_os(ENV_WSECRET_SSH_AGENT_PIPE) {
        let name = override_value.to_string_lossy();
        if !name.is_empty() && !is_canonical_endpoint(&name) {
            return Err(SshAgentError::UntrustedEndpoint(name.into_owned()));
        }
    }

    // The child's program and argv: the first `CMD` argument if given, else
    // `$SHELL`, else `%ComSpec%` (upstream `wsecret agent` semantics).
    let shell_storage;
    let argv: Vec<&OsStr> = if !cmd.is_empty() {
        cmd.to_vec()
    } else {
        shell_storage = std::env::var_os("SHELL")
            .or_else(|| std::env::var_os("ComSpec"))
            .ok_or(SshAgentError::MissingShell)?;
        vec![shell_storage.as_os_str()]
    };
    let program = argv[0];
    let program_name = program.to_string_lossy().into_owned();

    // Resolve the executable BEFORE the vault is unlocked and before the
    // store is opened: a bad program name fails before any passphrase is
    // read.
    let app = agent_bridge::resolve_executable(program).map_err(|error| SshAgentError::Exec {
        name: program_name.clone(),
        error,
    })?;

    // Open the store, then authenticate the Windows OpenSSH agent service
    // (pre-flight; the key is never sent to an unverified endpoint).
    let (mut store, header) =
        Store::open_read_with_limits(store_path, limits).map_err(SshAgentError::Core)?;
    let client = SshAgentClient::new();
    client.verify_service().map_err(SshAgentError::Core)?;

    let mut session = unlock_with_confirmation(&mut store, &header, &mut prompt).map_err(
        |error| match error {
            crate::agent::AgentLaunchError::Cancelled => SshAgentError::Cancelled,
            crate::agent::AgentLaunchError::Core(error) => SshAgentError::Core(error),
            _other => SshAgentError::Core(Error::Agent(
                wsecret_core::error::AgentError::ProtocolMismatch,
            )),
        },
    )?;
    let mut secret = match store
        .find(&session, key, false)
        .map_err(SshAgentError::Core)?
    {
        ScanOutcome::Found { value, .. } => value,
        ScanOutcome::NotFound { .. } => {
            return Err(SshAgentError::SecretNotFound(key.to_vec()));
        }
    };
    if secret.len() != 64 {
        secret.clear();
        return Err(SshAgentError::InvalidKey);
    }
    let public: [u8; 32] = secret.as_slice()[32..64]
        .try_into()
        .expect("64-byte key checked");

    // Per-user/per-public-key exclusive lock for cooperating clients: held
    // from here — before the agent listing — through add, child wait, removal
    // and exit (RAII at return). Contention is refused, never waited out.
    let _identity_lock = IdentityLock::acquire(&public).map_err(|error| match error {
        Error::Busy => SshAgentError::IdentityBusy,
        other => SshAgentError::Core(other),
    })?;

    // A key already loaded in the agent is refused and left exactly as found.
    let already_loaded = client
        .identities()
        .map_err(SshAgentError::Core)?
        .iter()
        .any(|identity| identity.public == public);
    if already_loaded {
        return Err(SshAgentError::IdentityLoaded);
    }

    let mut comment = b"wsecret:".to_vec();
    comment.extend_from_slice(key);
    client
        .add_ed25519(secret.as_mut_slice(), &comment)
        .map_err(SshAgentError::Core)?;
    secret.clear();

    // The vault session and the extracted key are gone BEFORE the child is
    // spawned and waited on.
    session.lock();
    drop(session);

    // From here the identity is loaded: every return path must attempt
    // removal before the lock is released at return.
    let result = (|| {
        let child = agent_bridge::spawn_ssh_child(&app, &argv, OsStr::new(client.pipe_name()))
            .map_err(|error| SshAgentError::Exec {
                name: program_name.clone(),
                error,
            })?;
        child.wait_for_exit().map_err(SshAgentError::Core)
    })();
    let removal = client.remove_ed25519(&public);
    match (result, removal) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(SshAgentError::RemoveFailed(cleanup)),
        (Err(error), Err(cleanup)) => Err(SshAgentError::LaunchAndCleanupFailed {
            launch: Box::new(error),
            cleanup,
        }),
    }
}
