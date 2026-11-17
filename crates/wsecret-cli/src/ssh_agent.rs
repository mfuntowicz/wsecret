//! `wsecret ssh-keygen` / `wsecret ssh-agent` support.
//!
//! Private keys never touch the filesystem. `ssh-keygen` stores libhydrogen's
//! 64-byte Ed25519 secret key in the encrypted store. `ssh-agent` sends that
//! key directly to the existing Windows OpenSSH agent over its named pipe,
//! launches a trusted child with `SSH_AUTH_SOCK`, and removes the identity on
//! every clean return path. The Windows agent performs all SSH signatures.

use std::ffi::OsStr;
use std::path::Path;

use wsecret_core::error::Error;
use wsecret_core::store::{ScanOutcome, Store};
use wsecret_core::windows::agent_bridge::{self, AgentCapability, AgentPipe, ENV_AGENT};
use wsecret_core::windows::ssh_agent::SshAgentClient;

use crate::agent::unlock_with_confirmation;
use crate::output;

/// Environment variable consumed by Win32 OpenSSH clients.
pub const ENV_SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";
/// Optional endpoint override for tests and non-Microsoft agents.
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
    Exec { name: String, error: std::io::Error },
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

/// Adds `key` to the Windows agent, launches the trusted child, and removes
/// the identity on every clean return path. If the process is killed, removal
/// is not guaranteed; the Windows agent's normal `ssh-add -D` teardown still
/// applies and is documented rather than hidden.
pub fn launch<F>(
    store_path: &Path,
    key: &[u8],
    cmd: &[&OsStr],
    mut prompt: F,
) -> Result<i32, SshAgentError>
where
    F: FnMut(&str) -> std::io::Result<Vec<u8>>,
{
    if std::env::var_os(ENV_AGENT).is_some() {
        return Err(SshAgentError::AlreadyRunning);
    }

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

    let (mut store, header) = Store::open_read(store_path).map_err(SshAgentError::Core)?;
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
        libhydrogen_sys::memzero(&mut secret);
        return Err(SshAgentError::InvalidKey);
    }
    let public: [u8; 32] = secret[32..64].try_into().expect("64-byte key checked");
    let mut comment = b"wsecret:".to_vec();
    comment.extend_from_slice(key);

    let client = match std::env::var_os(ENV_WSECRET_SSH_AGENT_PIPE) {
        Some(path) if !path.is_empty() => SshAgentClient::with_pipe(&path.to_string_lossy()),
        _ => SshAgentClient::new(),
    };
    client
        .add_ed25519(&mut secret, &comment)
        .map_err(SshAgentError::Core)?;
    libhydrogen_sys::memzero(&mut secret);

    // From here on, every clean path removes the identity before returning.
    let result = (|| {
        let capability =
            AgentCapability::from_session(&mut session).map_err(SshAgentError::Core)?;
        let pipe = AgentPipe::create().map_err(SshAgentError::Core)?;
        let mut pipe = capability
            .write_to_pipe(pipe)
            .map_err(SshAgentError::Core)?;
        pipe.mark_read_inheritable().map_err(SshAgentError::Core)?;
        let app =
            agent_bridge::resolve_executable(program).map_err(|error| SshAgentError::Exec {
                name: program_name.clone(),
                error,
            })?;
        let child = agent_bridge::spawn_trusted_child_with_env(
            &app,
            &argv,
            pipe,
            Some((
                OsStr::new(ENV_SSH_AUTH_SOCK),
                OsStr::new(client.pipe_name()),
            )),
        )
        .map_err(|error| SshAgentError::Exec {
            name: program_name.clone(),
            error,
        })?;
        child.wait_for_exit().map_err(SshAgentError::Core)
    })();
    let removal = client.remove_ed25519(&public);
    match (result, removal) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(SshAgentError::Core(error)),
    }
}
