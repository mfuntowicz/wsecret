//! Store-backed Ed25519 SSH agent acceptance tests (Windows OpenSSH).
//!
//! No private key file is created anywhere. The signing test drives the REAL
//! `wsecret.exe` and Microsoft ssh-agent, then verifies the returned signature
//! independently with OpenSSL.

mod harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use harness::{ChildStdout, ConsoleSession};
use wsecret_core::windows::ssh_agent::SshAgentClient;
use wsecret_core::{Session, Store};

const PASS: &str = "correct horse battery staple";

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

fn create_key_store(store: &Path, key: &str) -> [u8; 32] {
    let (mut store, header, _) = Store::create(store, 10_000).expect("create store");
    let mut session = Session::unlock(&header, &mut PASS.as_bytes().to_vec()).expect("unlock");
    let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let public = signing.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&signing.to_bytes());
    secret[32..].copy_from_slice(&public);
    store
        .append_or_reuse(None, &session, key.as_bytes(), &secret)
        .expect("store Ed25519 secret");
    libhydrogen_sys::memzero(&mut secret);
    session.lock();
    public
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
    assert_eq!(value.len(), 64);
    assert_eq!(
        &value[32..],
        &public,
        "stored public half must match output"
    );
    assert!(
        !line.windows(32).any(|window| window == &value[..32]),
        "private scalar must never be printed"
    );
}

#[test]
fn ssh_agent_adds_signs_and_removes_without_plaintext_key_files() {
    let dir = scenario("agent");
    let store = dir.join("store.secret");
    let key = format!("test/ssh-{}", std::process::id());
    let public = create_key_store(&store, &key);
    let comment = format!("wsecret:{key}");
    let output = dir.join("stdout.bin");

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

    let console = ConsoleSession::new();
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
        "ssh-add listing did not contain {comment}: {}",
        String::from_utf8_lossy(&listing)
    );

    // Clean child exit removes the identity from the real Windows agent.
    let client = SshAgentClient::new();
    let remaining = client.identities().expect("post-exit identities");
    assert!(
        !remaining.iter().any(|identity| identity.public == public),
        "identity remained after wsecret exited"
    );

    // Independent OpenSSL verification of the Microsoft agent's signature.
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&public);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        String::from_utf8(b64_encode(&der)).expect("base64")
    );
    let public_pem = dir.join("public.pem");
    let sig_path = dir.join("signature.bin");
    let data_path = dir.join("data.bin");
    fs::write(&public_pem, pem).expect("public PEM");
    fs::write(&sig_path, signature).expect("signature file");
    fs::write(&data_path, b"wsecret ssh-agent acceptance\n").expect("data file");
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
