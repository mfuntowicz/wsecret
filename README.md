# wsecret

`wsecret` is a Windows implementation of [`angt/secret`](https://github.com/angt/secret), written in Rust with a small wrapper around the pinned upstream **libhydrogen C** implementation.

It stores encrypted names and values in one portable `.secret` file, supports multiple passphrases, deterministic secrets, TOTP, and a trusted-agent workflow. The command-line interface is compatible with the pinned upstream release.

**Current status:** the library and CLI are implemented. The full workspace suite passes on Windows 11 x64. ARM64 cross-compilation works; native ARM64 execution is still unverified. See [Proof status](#proof-status).

## Requirements

- Windows 11 x64 for the tested path.
- Rust **1.100.0** (pinned by `rust-toolchain.toml`).
- MSVC and a Windows SDK with x64/ARM64 libraries.
- Optional for upstream-oracle tests: WSL with a Linux distribution and Python 3.
- Optional for independent SSH signature verification: OpenSSL 3.x with `pkeyutl`.

## Build

From the repository root:

```powershell
cargo build --workspace --release --locked
```

The executable is:

```text
target\release\wsecret.exe
```

For a smaller test build, use `cargo build --workspace --locked`.

## Quick start

These PowerShell examples use a store in the current directory so they do not touch your normal `~/.secret` file:

```powershell
$env:SECRET_STORE = "$PWD\demo.secret"

# Create the store. The default KDF cost is 100000 iterations.
.\target\release\wsecret.exe init

# Generate and print a new secret, then save it as "example".
.\target\release\wsecret.exe new example

# Read it back.
.\target\release\wsecret.exe show example

# List names protected by that passphrase.
.\target\release\wsecret.exe list
```

The first use of a new passphrase asks for confirmation. Names and values belonging to other passphrases remain encrypted and are preserved during mutations.

To create a store with a different KDF cost:

```powershell
.\target\release\wsecret.exe init opslimit 250000
```

`opslimit` must be at least `10000`; the default is `100000`. It is stored in the file and participates in key derivation.

## Commands

| Command | Purpose |
|---|---|
| `wsecret init [opslimit N]` | Create a new store. Fails if it already exists. |
| `wsecret list [NEEDLE]` | List names visible to the entered passphrase, optionally filtered by a case-insensitive substring. |
| `wsecret show KEY` | Print a value. Names containing `totp` produce a six-digit code. |
| `wsecret dump KEY` | Dump the stored bytes without TOTP transformation. |
| `wsecret new KEY` | Generate, print, and store a new random secret. Fails if `KEY` exists. |
| `wsecret set KEY` | Store a value read from the console or redirected stdin. Fails if `KEY` exists. |
| `wsecret renew KEY` | Replace an existing value with a newly generated secret. |
| `wsecret update KEY [NEWKEY]` | Replace a value, optionally renaming the record. |
| `wsecret pass KEY [SUBKEY ...]` | Derive and print a deterministic secret without storing it. |
| `wsecret agent [CMD [ARG ...]]` | Launch a trusted child process with agent access. |
| `wsecret ssh keygen KEY` | Generate and store an Ed25519 key without writing a private key file; print only the public key. |
| `wsecret ssh agent KEY [CMD [ARG ...]]` | Add the stored key to Windows `ssh-agent`, launch a trusted child, and remove the identity on clean exit. |
| `wsecret version` | Print the upstream-compatible version (`0.21`). |

Exit codes are `0` for success or an intentional empty result, `1` for `Fatal: …`, `254` for parser help, and `255` for usage errors or completion.

### Store a value yourself

```powershell
# Prompts for the value on the console.
.\target\release\wsecret.exe set api-token

# Replace the value.
.\target\release\wsecret.exe update api-token

# Rename without changing the value: press Enter at the Secret prompt.
.\target\release\wsecret.exe update api-token old-api-token
```

There is no separate delete command. Rename a record to the `DELETED:` namespace to mark its slot for reuse:

```powershell
.\target\release\wsecret.exe update old-api-token DELETED:old-api-token
```

Press Enter at the value prompt to keep the old value during a rename.

### TOTP

A name containing `totp` treats the stored value as a TOTP seed:

```powershell
# Store a base32-encoded seed; totp32 performs base32 decoding.
.\target\release\wsecret.exe set example/totp32

# Print the current six-digit code.
.\target\release\wsecret.exe show example/totp32

# Read the original stored seed bytes instead of a code.
.\target\release\wsecret.exe dump example/totp32
```

### Deterministic secrets

`pass` derives output from the session key and every supplied component; it does not create a record:

```powershell
.\target\release\wsecret.exe pass me@example.com 2026
```

The same store, passphrase, and component sequence produces the same output on upstream and wsecret.

### Trusted agent

```powershell
# Start PowerShell with agent access for itself and its descendants.
.\target\release\wsecret.exe agent powershell
```

With no `CMD`, wsecret uses `$SHELL`, then `%ComSpec%`. Do not set `SECRET_AGENT` yourself; wsecret creates it for the trusted child.

### SSH keys without private key files

Ed25519 keys can be generated and used without ever writing the private key to disk:

```powershell
# Generate a key in memory and store it encrypted. Only the public key is printed.
.\target\release\wsecret.exe ssh keygen github

# Start PowerShell with that key available through Windows ssh-agent.
.\target\release\wsecret.exe ssh agent github powershell
```

The `ssh keygen` output is an ordinary OpenSSH public-key line (`ssh-ed25519 …`) suitable for `authorized_keys`. It contains no private material.

`ssh agent` sends the 64-byte private key directly to the existing Windows `ssh-agent` service over its named pipe, sets `SSH_AUTH_SOCK` for the child, and removes the identity when the child exits cleanly. The Microsoft agent performs all SSH signatures. Standard Ed25519 key generation uses the pinned `ed25519-dalek` crate; no private key file or temporary export is created. If wsecret is killed, removal is not guaranteed; use `ssh-add -D` to clear agent identities in that case.

Only Ed25519 keys are supported. The Windows `ssh-agent` service must be running. Set `WSECRET_SSH_AGENT_PIPE` only when you intentionally need a non-default agent endpoint.

## Store location and byte handling

Store lookup order:

1. Nonempty `SECRET_STORE`.
2. `$HOME/.secret`.
3. `%USERPROFILE%\.secret`.

Examples:

```powershell
$env:SECRET_STORE = 'D:\Secrets\work.secret'
.\target\release\wsecret.exe list
```

Two optional modes handle arbitrary bytes:

| Option | Meaning |
|---|---|
| `--keys-hex` | Decode key, needle, and subkey operands as hexadecimal pairs. |
| `--pass-hex` | Read the passphrase at the prompt as hexadecimal pairs rather than text. |

Example: read the record named `test` using its hex-encoded name:

```powershell
.\target\release\wsecret.exe --keys-hex show 74657374
```

For binary values, use `dump` and a byte-preserving redirection mechanism. Avoid text-mode PowerShell pipelines for arbitrary binary data.

## Compatibility and security model

- The store uses upstream format version 0 and 512-byte blocks. Names and values are encrypted independently for each passphrase.
- The file is **not** tied to a Windows account or machine. DPAPI protects the unlocked session key **in memory**, not the portable store.
- Process and thread DACLs, `OWNER_RIGHTS`, child-birth descriptors, reduced launcher handles, and a residency watchdog enforce the same-user, non-privileged boundary.
- Secret buffers are page-locked, zeroized, and excluded from WER dumps where supported. Idle session keys are `CryptProtectMemory` ciphertext; plaintext exists only during operation windows.
- Cooperating writers serialize through a canonical named mutex and per-record `LockFileEx`. Mutations preserve records belonging to other passphrases.
- Malformed and truncated inputs are rejected with bounded parsing; upstream-compatible read tolerance is retained where documented.

Important limits:

- Administrators, `SeDebugPrivilege`, kernel tools, and malicious code already inside the trusted zone are outside the same-user boundary.
- An external launcher may retain a full-access handle to wsecret. This is a documented residual; wsecret-controlled launches reduce their retained handles.
- A newly created unregistered thread can exist for one watchdog poll interval before detection.
- The format has no whole-store anti-rollback or authenticated header. These are inherited upstream limitations, not claims of stronger file integrity.
- Process-kill tests are not power-loss durability proof.

## Verify

Run the complete suite on Windows 11 x64:

```powershell
cargo test --workspace --locked -- --test-threads=1
```

Run only the process-protection acceptance harness:

```powershell
cargo test -p wsecret-cli --test p4 --locked
```

Build both release targets:

```powershell
cargo build --workspace --release --locked
rustup target add aarch64-pc-windows-msvc
cargo build --workspace --target aarch64-pc-windows-msvc --release --locked
```

The complete suite includes unit tests, pinned libhydrogen KATs, real CLI cross-checks, malformed-store cases, P4 process probes, concurrent writers, crash consistency, commit states, and overlapping-unlock residency. Some upstream-oracle checks require WSL; they fail loudly rather than silently skipping a missing prerequisite.

## Proof status

Evidence below was collected on **2026-11-17**, Windows 11 x64, unless stated otherwise.

| Area | Established evidence | Still pending / not claimed |
|---|---|---|
| Workspace | **365 tests passed across 15 suites** | No claim beyond the executed host/configuration |
| Upstream compatibility | Real upstream-generated Linux store passes byte-exact `dump`/`list`/`show` checks; same-window upstream TOTP parity passes | Real macOS-origin and Windows→macOS round-trip evidence |
| Fixture provenance | `upstream-linux-origin.secret` was generated by the pinned upstream binary on Fedora 44/WSL2 | `linux-origin.secret` and `mac-origin.secret` are wsecret-generated stand-ins, not upstream-origin proof |
| x64 | Native debug tests and optimized release build pass | — |
| ARM64 | `aarch64-pc-windows-msvc` release build passes; PE machine field is `0xAA64` | Native Windows 11 ARM64 execution and tests |
| Process protection | P4a/b/d/e/f/g/h/i/j probes pass | P4c privileged controls require an elevated `SeDebugPrivilege` runner |
| SSH agent | 2/2 live tests pass: public-key-only generation, real Windows-agent add/sign/remove, OpenSSL signature verification, no plaintext-key artifacts | Only Ed25519; clean-exit removal is not guaranteed after a process kill |
| Concurrency/crash model | Commit-state 10/10, concurrent-writers 7/7, crash-consistency 11/11, R2-A 2/2 | No power-loss durability claim |
| Filesystems | NTFS rows executed on C:, D:, E:, F:, and G: | ReFS, FAT32, exFAT, and SMB rows have no evidence |
| Security review | Behavior-focused tests and an implementation-plan audit were performed | No formal cryptographic audit or proof of security |

Machine-readable fixture provenance and detailed evidence live in:

- `fixtures/stores/upstream-linux-origin.manifest.json`
- `fixtures/stores/manifest.json`
- `fixtures/e6-filesystem-matrix.json`
- `crates/libhydrogen-sys/PENDING.md`

## Rust library

`wsecret-core` exposes `Store`, `Session`, `Header`, `Limits`, `ScanOutcome`, and the shared error taxonomy. A host must initialize process protection before creating a session:

```rust
use wsecret_core::{NameError, ScanOutcome, Session, Store};

fn read_secret(path: &std::path::Path, pass: &mut [u8]) -> Result<Vec<u8>, wsecret_core::Error> {
    wsecret_core::windows::security::init_process_protection()?;
    let (mut store, header) = Store::open(path)?;
    let mut session = Session::unlock(&header, pass)?;
    let result = match store.find(&session, b"example", false)? {
        ScanOutcome::Found { value, .. } => value,
        ScanOutcome::NotFound { .. } => return Err(wsecret_core::Error::Name(NameError::NotFound)),
    };
    session.lock();
    Ok(result)
}
```

Hosts creating threads must use `spawn_hardened_thread`, or harden and register each host thread before session use. Production session creation fails closed if initialization is skipped.

The future WinUI 3 C ABI is a design contract only; **no C ABI crate or GUI application is shipped**.

## Project layout

| Path | Contents |
|---|---|
| `crates/libhydrogen-sys/` | Pinned libhydrogen C, safe Rust wrapper, and upstream KATs |
| `crates/wsecret-core/` | Store format, sessions, cryptography dispatch, Windows security, and core tests |
| `crates/wsecret-cli/` | `wsecret.exe`, console/agent behavior, and CLI acceptance tests |
| `fixtures/upstream/` | Minimal pinned upstream sources required by compatibility oracles |
| `fixtures/` | Store fixtures, manifests, oracle tools, and filesystem evidence |

## Pinned upstream revisions

- `angt/secret`: `e98103def4e062a6f9a8fa5e7693abe15f20817a`
- `libhydrogen`: `6c58976b3b9178441218c12bca2cc414d9efe30d`
- `argz`: `9aeb9e035c80236dfc86c2b3bd124044419d9531`

## Licenses

Preserve the applicable notices when redistributing source or binaries:

- Upstream `secret`: BSD-2-Clause — `fixtures/upstream/LICENSE`
- `argz`: `fixtures/upstream/LICENSE.argz`
- libhydrogen: ISC — `crates/libhydrogen-sys/vendor/LICENSE`
