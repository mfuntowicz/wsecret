//! Store-backed Ed25519 SSH agent acceptance tests (Windows OpenSSH).
//!
//! No private key file is created anywhere. Signing tests drive the REAL
//! `wsecret.exe` and Microsoft ssh-agent, then verify returned signatures
//! independently with OpenSSL.
//!
//! Isolation rules (WS-04): every test uses a UNIQUE synthetic identity and
//! its own scenario directory; the RAII [`TestIdentity`] guard removes ONLY
//! keys the test itself loaded (never `ssh-add -D`, never a foreign key).
//! No test dumps the environment: [`vault_probe`] checks only three named
//! variables and uses redirected `show help` to observe a synthetic record
//! NAME, never its value or the SSH private key.
//! Prerequisites: the Windows OpenSSH Authentication Agent service running
//! and verifiable, `openssl` on PATH, Windows PowerShell 5.1 present.

mod harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use harness::{ChildStdout, ConsoleSession};
use wsecret_core::error::Error;
use wsecret_core::windows::security::IdentityLock;
use wsecret_core::windows::ssh_agent::SshAgentClient;
use wsecret_core::{Session, Store};

const PASS: &str = "correct horse battery staple";
const SSH_ENDPOINT: &str = r"\\.\pipe\openssh-ssh-agent";
// Not zero: a launcher that skips the probe must not appear to have passed.
const VAULT_PROBE_OK: u32 = 42;

fn scenario(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wsecret-ssh-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scenario directory");
    dir
}

fn b64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u8;
    for b in text.bytes() {
        if b == b'=' {
            break;
        }
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 byte {b:#x}"),
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

fn b64_encode(value: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for chunk in value.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(ALPHABET[((n >> 18) & 63) as usize]);
        out.push(ALPHABET[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize]
        } else {
            b'='
        });
    }
    out
}

fn public_from_line(line: &[u8]) -> [u8; 32] {
    let text = std::str::from_utf8(line).expect("public line UTF-8");
    let b64 = text
        .strip_prefix("ssh-ed25519 ")
        .expect("public algorithm prefix")
        .split(' ')
        .next()
        .expect("public base64");
    let blob = b64_decode(b64);
    assert_eq!(&blob[..4], &11u32.to_be_bytes());
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &32u32.to_be_bytes());
    assert_eq!(blob.len(), 19 + 32);
    blob[19..].try_into().expect("32-byte public key")
}

/// Creates `store` with the given `(name, value)` records under `PASS`.
fn create_store_with(store: &Path, records: &[(&str, &[u8])]) {
    let (mut store, header, _) = Store::create(store, 10_000).expect("create store");
    let mut session = Session::unlock(&header, &mut PASS.as_bytes().to_vec()).expect("unlock");
    for (name, value) in records {
        store
            .append_or_reuse(None, &session, name.as_bytes(), value)
            .expect("store record");
    }
    session.lock();
}

fn create_key_store(store: &Path, key: &str, secret: &[u8; 64]) {
    create_store_with(store, &[(key, &secret[..])]);
}

/// Every generated public key gets a guard before it can be loaded, by the
/// test or the CLI. On return or unwind, remove only this synthetic identity.
struct TestIdentity {
    client: SshAgentClient,
    public: [u8; 32],
}

impl TestIdentity {
    fn generate() -> (Self, [u8; 64]) {
        let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let public = signing.verifying_key().to_bytes();
        assert_eq!(
            agent_count(&public),
            0,
            "generated key already exists; refusing to claim it for cleanup"
        );
        let mut secret = [0u8; 64]; // OpenSSH agent-add encoding: seed || public
        secret[..32].copy_from_slice(&signing.to_bytes());
        secret[32..].copy_from_slice(&public);
        let guard = Self {
            client: SshAgentClient::new(),
            public,
        };
        (guard, secret)
    }

    /// Loads this identity (the secret copy is zeroized by the client).
    fn add(&self, secret: &mut [u8; 64], comment: &[u8]) {
        self.client
            .add_ed25519(secret, comment)
            .expect("load test-owned identity");
    }

    /// How many agent entries currently match this public key.
    fn count(&self) -> usize {
        self.client
            .identities()
            .expect("agent identities")
            .iter()
            .filter(|identity| identity.public == self.public)
            .count()
    }

    /// Comment of the entry currently stored for this key, if any.
    fn comment(&self) -> Option<Vec<u8>> {
        self.client
            .identities()
            .expect("agent identities")
            .into_iter()
            .find(|identity| identity.public == self.public)
            .map(|identity| identity.comment)
    }
}

impl Drop for TestIdentity {
    fn drop(&mut self) {
        for _ in 0..8 {
            if self
                .client
                .identities()
                .is_ok_and(|list| list.iter().all(|key| key.public != self.public))
                || self.client.remove_ed25519(&self.public).is_ok()
            {
                return;
            }
        }
        let failure = format!(
            "could not confirm removal of synthetic Ed25519 public key {:02x?}",
            self.public
        );
        if std::thread::panicking() {
            // Do not replace the original failure with a second panic.
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(), "{failure}");
        } else {
            panic!("{failure}");
        }
    }
}

/// Independent OpenSSL verification of a raw 64-byte Ed25519 signature.
fn verify_with_openssl(dir: &Path, public: &[u8; 32], data: &[u8], signature: &[u8]) {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(public);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        String::from_utf8(b64_encode(&der)).expect("base64")
    );
    let public_pem = dir.join("public.pem");
    let sig_path = dir.join("signature.bin");
    let data_path = dir.join("data.bin");
    fs::write(&public_pem, pem).expect("public PEM");
    fs::write(&sig_path, signature).expect("signature file");
    fs::write(&data_path, data).expect("data file");
    let verified = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(&public_pem)
        .args(["-keyform", "PEM", "-rawin", "-in"])
        .arg(&data_path)
        .arg("-sigfile")
        .arg(&sig_path)
        .output()
        .expect("run OpenSSL verify");
    assert!(
        verified.status.success(),
        "OpenSSL verification failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
}

/// One framed SSH2_AGENTC_SIGN_REQUEST (`type 13` + key blob + data + zero
/// flags), the exact wire shape `SshAgentClient::sign_ed25519` sends.
fn sign_request(public: &[u8; 32], data: &[u8]) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut blob = Vec::new();
    put(&mut blob, b"ssh-ed25519");
    put(&mut blob, public);
    let mut body = Vec::new();
    body.push(13u8); // SSH2_AGENTC_SIGN_REQUEST
    put(&mut body, &blob);
    put(&mut body, data);
    body.extend_from_slice(&0u32.to_be_bytes());
    let mut request = Vec::new();
    request.extend_from_slice(&(body.len() as u32).to_be_bytes());
    request.extend_from_slice(&body);
    request
}

// Interpolate only base64 into PowerShell source, not a path supplied by the
// environment (including paths containing PowerShell quotation characters).
fn ps_string(value: &str) -> String {
    let value = String::from_utf8(b64_encode(value.as_bytes())).expect("base64");
    format!("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{value}'))")
}

/// The child-side signing probe (Windows PowerShell 5.1, one `-Command`
/// line): connects only to the exact `SSH_AUTH_SOCK` endpoint received,
/// sends the prebuilt sign request, accepts only an Ed25519 signature frame,
/// and writes the returned signature to `sig_path`. No private key is passed.
fn sign_probe(request: &[u8], sig_path: &Path) -> String {
    let request = String::from_utf8(b64_encode(request)).expect("base64");
    let out = ps_string(&sig_path.to_string_lossy());
    format!(
        "& {{ $ErrorActionPreference='Stop'; \
         $s=$env:SSH_AUTH_SOCK; \
         if(-not [string]::Equals($s,'{SSH_ENDPOINT}',[StringComparison]::Ordinal)){{ exit 2 }}; \
         $c=[IO.Pipes.NamedPipeClientStream]::new('.',$s.Substring(9),\
             [IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous,\
             [Security.Principal.TokenImpersonationLevel]::Identification); \
         try {{ \
           $c.Connect(8000); $clock=[Diagnostics.Stopwatch]::StartNew(); \
           function RemainingMs {{ [int][Math]::Max(0L,8000L-$clock.ElapsedMilliseconds) }}; \
           function ReadExact([byte[]]$b) {{ \
             $o=0; while($o -lt $b.Length){{ \
               $read=$c.ReadAsync($b,$o,$b.Length-$o); \
               if(-not $read.Wait((RemainingMs))){{ exit 5 }}; \
               if($read.Result -eq 0){{ exit 3 }}; $o+=$read.Result \
             }} \
           }}; \
           function Be32([byte[]]$b,[int]$i) {{ \
             [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($b,$i)) \
           }}; \
           $req=[Convert]::FromBase64String('{request}'); \
           $write=$c.WriteAsync($req,0,$req.Length); if(-not $write.Wait((RemainingMs))){{ exit 5 }}; \
           $h=[byte[]]::new(4); ReadExact $h; if((Be32 $h 0) -ne 88){{ exit 3 }}; \
           $r=[byte[]]::new(88); ReadExact $r; \
           if($r[0] -ne 14 -or (Be32 $r 1) -ne 83 -or (Be32 $r 5) -ne 11 -or \
              [Text.Encoding]::ASCII.GetString($r,9,11) -cne 'ssh-ed25519' -or \
              (Be32 $r 20) -ne 64){{ exit 4 }}; \
           $sig=[byte[]]::new(64); [Array]::Copy($r,24,$sig,0,64); \
           [IO.File]::WriteAllBytes({out},$sig) \
         }} finally {{ $c.Dispose() }}; \
         exit 0 }}"
    )
}

fn agent_count(public: &[u8; 32]) -> usize {
    SshAgentClient::new()
        .identities()
        .expect("agent identities")
        .iter()
        .filter(|identity| identity.public == *public)
        .count()
}

/// Both agent children run exactly the same noninteractive completion. With
/// redirected stdout, `show help` returns 255 and names under a capability;
/// without one it must return 0 silently. It never needs a record value.
/// A private console is NOT a no-prompt guarantee: bound the probe and its
/// pipe drains, and kill only its own grandchild if a regression prompts.
fn vault_probe(store: &Path, expected_marker: Option<&str>) -> String {
    let exe = ps_string(&harness::wsecret_exe().to_string_lossy());
    let store = ps_string(&store.to_string_lossy());
    let (contract, status, names) = match expected_marker {
        Some(marker) => (
            "if($null -eq $env:SECRET_AGENT){ exit 10 }".to_owned(),
            255,
            format!("({} + [char]10)", ps_string(marker)),
        ),
        None => (
            format!(
                "if($null -ne $env:SECRET_AGENT){{ exit 10 }}; \
                 if(-not [string]::Equals($env:SSH_AUTH_SOCK,'{SSH_ENDPOINT}',[StringComparison]::Ordinal)){{ exit 11 }}"
            ),
            0,
            "''".to_owned(),
        ),
    };
    format!(
        "$ErrorActionPreference='Stop'; {contract}; \
         if(-not [string]::Equals($env:SECRET_STORE,{store},[StringComparison]::Ordinal)){{ exit 12 }}; \
         $psi=[Diagnostics.ProcessStartInfo]::new({exe},'show help'); \
         $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; \
         $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; \
         $p=[Diagnostics.Process]::Start($psi); \
         try {{ \
           $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync(); \
           if(-not $p.WaitForExit(10000)){{ exit 16 }}; \
           if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),2000)){{ exit 16 }}; \
           if($p.ExitCode -ne {status}){{ exit 13 }}; \
           if(-not [string]::Equals($stdout.Result,{names},[StringComparison]::Ordinal)){{ exit 14 }}; \
           if($stderr.Result.Length -ne 0){{ exit 15 }} \
         }} finally {{ \
           if(-not $p.HasExited){{ $p.Kill(); $null=$p.WaitForExit(2000) }}; $p.Dispose() \
         }}; exit {VAULT_PROBE_OK}"
    )
}

#[test]
fn ssh_keygen_prints_only_public_key_and_stores_64_byte_secret() {
    let dir = scenario("keygen");
    let store = dir.join("store.secret");
    let output = dir.join("stdout.bin");
    let (_, _, _) = Store::create(&store, 10_000).expect("initialize store");
    let console = ConsoleSession::new();
    let run = harness::run_wsecret_lines(
        &console,
        &store,
        &["ssh", "keygen", "test/ssh"],
        &[PASS, PASS],
        None,
        ChildStdout::CaptureFile(&output),
    );
    assert_eq!(
        run.code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stderr.is_empty());
    let line = fs::read(&output).expect("public output");
    assert!(line.ends_with(b" wsecret:test/ssh\n"));
    let public = public_from_line(&line);

    let (mut store, header) = Store::open(&store).expect("open store");
    let session = Session::unlock(&header, &mut PASS.as_bytes().to_vec()).expect("unlock");
    let value = match store.find(&session, b"test/ssh", false).expect("find key") {
        wsecret_core::ScanOutcome::Found { value, .. } => value,
        other => panic!("key not found: {other:?}"),
    };
    let stored = value.as_slice();
    assert_eq!(stored.len(), 64);
    assert_eq!(
        &stored[32..],
        &public,
        "stored public half must match output"
    );
    assert!(
        !line.windows(32).any(|window| window == &stored[..32]),
        "private scalar must never be printed"
    );
}

#[test]
fn ssh_agent_adds_signs_and_removes_without_plaintext_key_files() {
    let dir = scenario("agent");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    let public = owned.public;
    create_key_store(&store, &key, &secret);
    libhydrogen_sys::memzero(&mut secret);
    let comment = format!("wsecret:{key}");
    let output = dir.join("stdout.bin");

    let console = ConsoleSession::new();
    // The signer runs concurrently with the real console-driven wsecret child.
    // It waits until the identity appears, then uses the production sign
    // request path against the SAME Microsoft agent.
    let signer = std::thread::spawn(move || {
        let client = SshAgentClient::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(identities) = client.identities() {
                if identities.iter().any(|identity| identity.public == public) {
                    break;
                }
            }
            if std::time::Instant::now() > deadline {
                panic!("Ed25519 identity did not appear in Windows ssh-agent");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let signature = client
            .sign_ed25519(&public, b"wsecret ssh-agent acceptance\n")
            .expect("Windows agent signature");
        // The child only waits; this listing is issued by the same signer
        // thread AFTER signing, never concurrently with another ssh-add.
        let listing = Command::new("ssh-add")
            .arg("-l")
            .output()
            .expect("ssh-add listing")
            .stdout;
        (signature, listing)
    });

    let run = harness::run_wsecret(
        &console,
        &store,
        &["ssh", "agent", &key, "cmd", "/c", "ping 127.0.0.1 -n 4"],
        PASS,
        None,
        ChildStdout::CaptureFile(&output),
    );
    let (signature, listing) = signer.join().expect("signer thread");
    assert_eq!(
        run.code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&listing).contains(&comment),
        "ssh-add listing did not contain the synthetic identity's comment"
    );

    // Clean child exit removes the identity from the real Windows agent.
    assert_eq!(owned.count(), 0, "identity remained after wsecret exited");

    // Independent OpenSSL verification of the Microsoft agent's signature.
    verify_with_openssl(&dir, &public, b"wsecret ssh-agent acceptance\n", &signature);

    // Every artifact left by the test is non-private. In particular, neither
    // the 32-byte private scalar nor the full 64-byte secret was written.
    let (mut store, header) = Store::open(&store).expect("reopen store");
    let session = Session::unlock(&header, &mut PASS.as_bytes().to_vec()).expect("unlock");
    let secret = match store
        .find(&session, key.as_bytes(), false)
        .expect("find secret")
    {
        wsecret_core::ScanOutcome::Found { value, .. } => value,
        other => panic!("secret missing: {other:?}"),
    };
    let secret = secret.as_slice();
    for entry in fs::read_dir(&dir).expect("scenario files") {
        let path = entry.expect("directory entry").path();
        let bytes = fs::read(&path).expect("read artifact");
        assert!(
            !bytes.windows(32).any(|window| window == &secret[..32])
                && !bytes.windows(64).any(|window| window == secret),
            "plaintext private key found in {}",
            path.display()
        );
    }
}

/// Positive: the CHILD actually signs through the verified endpoint it was
/// given. The probe connects to the `SSH_AUTH_SOCK` pipe, refuses anything
/// that is not the full `\\.\pipe\` agent path, and the returned signature is
/// verified independently with OpenSSL.
#[test]
fn ssh_child_signs_through_the_verified_endpoint() {
    let dir = scenario("child-sign");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-sign-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    create_key_store(&store, &key, &secret);
    libhydrogen_sys::memzero(&mut secret);

    let data = b"wsecret ssh-agent child sign probe";
    let sig_path = dir.join("child-signature.bin");
    let script = sign_probe(&sign_request(&owned.public, data), &sig_path);

    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &[
            "ssh",
            "agent",
            &key,
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code,
        0,
        "child sign probe failed (2 = endpoint, 3/4 = agent frame, 5 = I/O timeout)\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let signature = fs::read(&sig_path).expect("child signature file");
    assert_eq!(signature.len(), 64, "agent signature must be 64 bytes");
    verify_with_openssl(&dir, &owned.public, data, &signature);
}

/// The child receives `SSH_AUTH_SOCK` (full verified agent path) and the
/// expected store — but never `SECRET_AGENT` and no vault capability: the
/// shared [`vault_probe`] verifies ONLY those contract points (no environment
/// dump) and then requires silent, unauthorized name completion in the
/// presence of a harmless same-partition marker.
#[test]
fn ssh_child_receives_no_vault_access_or_capability() {
    let dir = scenario("no-vault");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-novault-{}", std::process::id());
    let marker_name = format!("test/marker-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    create_store_with(
        &store,
        &[
            (key.as_str(), &secret[..]),
            (marker_name.as_str(), b"unused by completion"),
        ],
    );
    libhydrogen_sys::memzero(&mut secret);

    let script = vault_probe(&store, None);
    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &[
            "ssh",
            "agent",
            &key,
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code, VAULT_PROBE_OK,
        "SSH probe: 10 = SECRET_AGENT present, 11 = SSH_AUTH_SOCK, 12 = SECRET_STORE, \
         13 = completion status, 14 = names disclosed, 15 = stderr, 16 = timeout"
    );
    assert!(
        run.stdout.is_empty() && run.stderr.is_empty(),
        "unexpected probe output"
    );
    assert_eq!(owned.count(), 0, "identity remained after the SSH probe");
}

/// Positive control: the same completion must list exactly the marker name
/// under the general agent's capability, without access to typed input.
#[test]
fn trusted_agent_child_reads_marker_without_reprompt() {
    let dir = scenario("agent-marker");
    let store = dir.join("store.secret");
    let marker_name = format!("test/marker-{}", std::process::id());
    create_store_with(&store, &[(marker_name.as_str(), b"unused by completion")]);

    let script = vault_probe(&store, Some(&marker_name));
    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &[
            "agent",
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code, VAULT_PROBE_OK,
        "general-agent probe: 10 = SECRET_AGENT absent, 12 = SECRET_STORE, \
         13 = completion status, 14 = wrong names, 15 = stderr, 16 = timeout"
    );
    assert!(
        run.stdout.is_empty() && run.stderr.is_empty(),
        "unexpected probe output"
    );
}

/// Identities that were in the shared agent before the run must survive it
/// untouched; only the key wsecret added is removed on exit.
#[test]
fn general_agent_identities_survive_the_ssh_agent_flow() {
    let dir = scenario("unaffected");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-flow-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    create_key_store(&store, &key, &secret);
    libhydrogen_sys::memzero(&mut secret);

    // A pre-existing, test-owned bystander identity.
    let (bystander, mut bystander_secret) = TestIdentity::generate();
    bystander.add(&mut bystander_secret, b"wsecret-test-bystander");

    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &["ssh", "agent", &key, "cmd", "/c", "exit 0"],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        bystander.count(),
        1,
        "pre-existing identity was disturbed by the flow"
    );
    assert_eq!(owned.count(), 0, "flow identity remained loaded");
    // `bystander` drops here: removes only the test-owned key.
}

/// A key already loaded in the agent is refused and left exactly as found:
/// not adopted, not removed, not overwritten (the real service would let an
/// add replace the stored entry's comment/blob).
#[test]
fn preloaded_identity_is_refused_and_left_unmodified() {
    let dir = scenario("preloaded");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-preloaded-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    create_key_store(&store, &key, &secret);

    // The SAME identity is already loaded (as `ssh-add` would leave it).
    owned.add(&mut secret, b"preloaded-by-test");

    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &["ssh", "agent", &key, "cmd", "/c", "exit 0"],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code,
        1,
        "preloaded key must be refused\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("refusing to take ownership"),
        "missing refusal message: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    // Left exactly as found: same single entry, original comment untouched.
    assert_eq!(owned.count(), 1, "preloaded identity count changed");
    assert_eq!(
        owned.comment().as_deref(),
        Some(&b"preloaded-by-test"[..]),
        "preloaded identity entry was modified"
    );
    // `owned` drops here: removes only this test-owned key.
}

/// Overlap rejection: while a cooperating client holds the per-user/
/// per-public-key identity lock, the real CLI refuses the same key with zero
/// mutation (the key is never added).
#[test]
fn real_cli_refuses_while_the_same_key_identity_lock_is_held() {
    let dir = scenario("lock-busy");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-busy-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    let public = owned.public;
    create_key_store(&store, &key, &secret);
    libhydrogen_sys::memzero(&mut secret);

    // The holder acquires the lock on ITS thread and releases it there
    // (Windows mutexes are thread-owned).
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let lock = IdentityLock::acquire(&public).expect("test-side identity lock");
        held_tx.send(()).expect("signal held");
        release_rx.recv().expect("release signal");
        drop(lock);
    });
    held_rx.recv().expect("lock held");

    let console = ConsoleSession::new();
    let run = harness::run_wsecret(
        &console,
        &store,
        &["ssh", "agent", &key, "cmd", "/c", "exit 0"],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code,
        1,
        "overlapping same-key run must be refused\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stderr)
            .contains("Another wsecret ssh agent is using this key"),
        "missing contention message: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    // Zero mutation: the refused run never loaded the identity.
    assert_eq!(
        owned.count(),
        0,
        "identity was added despite lock contention"
    );
    release_tx.send(()).expect("release holder");
    holder.join().expect("holder thread");
}

/// Positive span check: while the CLI's child is running, the per-user/
/// per-public-key identity lock is demonstrably held (a competing acquisition
/// fails), and it is free again after the run cleans up.
#[test]
fn identity_lock_is_held_while_the_child_runs() {
    let dir = scenario("lock-span");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-span-{}", std::process::id());
    let (owned, mut secret) = TestIdentity::generate();
    let public = owned.public;
    create_key_store(&store, &key, &secret);
    libhydrogen_sys::memzero(&mut secret);

    let console = ConsoleSession::new();
    // The probe starts only once this test owns the console lock, so its
    // deadline covers the run itself.
    let probe = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if agent_count(&public) > 0 {
                // The CLI has added the key; it must still hold the lock
                // until cleanup, so a competing acquisition fails here.
                let outcome = IdentityLock::acquire(&public);
                let busy = matches!(outcome, Err(Error::Busy));
                drop(outcome);
                return busy;
            }
            if std::time::Instant::now() > deadline {
                panic!("identity never appeared in the agent");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let run = harness::run_wsecret(
        &console,
        &store,
        &["ssh", "agent", &key, "cmd", "/c", "ping 127.0.0.1 -n 8"],
        PASS,
        None,
        ChildStdout::CaptureFile(&dir.join("stdout.bin")),
    );
    assert_eq!(
        run.code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        probe.join().expect("probe thread"),
        "identity lock was not held while the child ran"
    );
    // Cleanup removed the identity and released the lock.
    assert_eq!(owned.count(), 0, "identity remained after exit");
    let free = IdentityLock::acquire(&public).expect("lock must be free after the run");
    drop(free);
}

/// Characterization of the REAL Windows OpenSSH service (unique synthetic
/// identity only): keys live in one registry entry per key fingerprint
/// (openssh-portable `contrib/win32/win32compat/ssh-agent/keyagent-request.c`,
/// `process_add_identity`), so adding the same key twice OVERWRITES the entry
/// instead of creating a duplicate. This is exactly why `ssh agent` refuses a
/// preloaded key instead of adding over it. Cleanup removes only the
/// test-owned keys.
#[test]
fn real_agent_duplicate_add_collapses_to_one_entry() {
    let (owned, mut first) = TestIdentity::generate();
    let public = owned.public;
    let (bystander, mut bystander_secret) = TestIdentity::generate();
    bystander.add(&mut bystander_secret, b"wsecret-test-bystander");

    let client = SshAgentClient::new();
    let mut second = first;
    client
        .add_ed25519(&mut first, b"wsecret-dup-one")
        .expect("first add");
    client
        .add_ed25519(&mut second, b"wsecret-dup-two")
        .expect("second add");

    assert_eq!(
        owned.count(),
        1,
        "duplicate add of the same key must collapse to one entry"
    );
    assert_eq!(
        owned.comment().as_deref(),
        Some(&b"wsecret-dup-two"[..]),
        "second add must overwrite the entry (comment replaced)"
    );
    assert_eq!(bystander.count(), 1, "unrelated identity was disturbed");

    // RAII semantics: dropping the guard removes ONLY the test-owned key.
    drop(owned);
    assert_eq!(agent_count(&public), 0, "test-owned key was not removed");
    assert_eq!(bystander.count(), 1, "cleanup removed a key it did not own");
}
