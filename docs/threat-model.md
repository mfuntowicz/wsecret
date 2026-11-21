# WSecret Quick Access — threat model and data flow

Status: this document specifies the **design contract** implemented by the Quick Access
delivery (WinUI 3 app + Rust broker). It records what the design guarantees, what it does
not, and where evidence is still owed. See [Evidence status](#13-evidence-status) for the
executed x64 checks and the scenarios that remain unverified. Related documents:
[quick-access.md](quick-access.md) (feature and byte-mapping contract),
[build.md](build.md) (build/package/run).

## 1. Scope

In scope:

- The packaged C# WinUI 3 app (`WSecret.exe`, MSIX, unelevated) and the Rust broker
  (`wsecret-broker.exe`) it launches for one Quick Access session over one `.secret` store.
- The private launch-bound IPC channel between them, broker-owned secure input, Windows
  Hello PRF unlock, the Windows clipboard during sensitive copy, writes through the core
  writer-lock protocol, and the session lifecycle
  `Locked → Unlocking → Unlocked → Locking → Locked`.
- The portable store file as an untrusted, user-relocatable artifact (stolen-store and
  malicious-store threats).

Out of scope (explicitly):

- Kernel, hypervisor, administrator, `SeDebugPrivilege`, firmware, and DMA attackers.
- Malware already running inside the trusted zone (as the interactive user before
  hardening applies, or inside the broker/UI processes).
- The `wsecret` CLI, its OpenSSH agent path, and any SSH functionality. Quick Access does
  not use, spawn, or expose them.
- VBS enclaves. No enclave component exists; no enclave guarantee is claimed.
- Power-loss durability of the store, cloud sync, browser extensions, remote favicons,
  and screenshot capture by the user.

## 2. System components

| Component | Process / location | Privilege | Secret material held |
|---|---|---|---|
| Quick Access UI | `WSecret.exe` (C#/.NET 11/WinUI 3, MSIX full trust) | unelevated, interactive user | none; names and result metadata only, session-scoped |
| Broker | `wsecret-broker.exe` (Rust) | unelevated, interactive user | store handle, derived session keys, decrypted names/values, TOTP seeds and codes, passphrase scratch |
| Store | `.secret` file (portable, format v0) | user-readable file | all ciphertext; no plaintext |
| Hello binding record | `<store>.hello` sidecar next to the store (see §8) | exclusive-create hardened file path, reparse-rejecting reads | wrapped passphrase-equivalent (ciphertext) |
| Secure input control | native Win32 masked `EDIT` in the isolated `wsecret-broker.exe --native-prompt` helper | separate helper process, no vault/session | transient passphrase / new secret value while typing |
| Windows Hello | `webauthn.dll` → Hello platform passkey (NGC/TPM) | OS | PRF key (device-bound, non-exportable) |
| Clipboard | Windows clipboard | shared system surface | one secret value for a bounded window |

Broker startup order (fixed, mirrors the CLI's proven order): process/thread admission
hardening and verification first, then crypto initialization, then the control handler,
then IPC. The broker fails closed if hardening cannot be applied and verified.

Native Windows libraries (DPAPI/WER, WebAuthn, OLE/clipboard, and the native prompt) are
initialized while locked, followed by explicit discovery registration. Registration uses
owned kernel handles and unique tokens, not numeric IDs alone: a trampoline can unregister
only its own token, exited objects are pruned positively, and a snapshot entry is rejected
only if it is still live. Watchdog retirement is joined before acquisition/discovery, so
lock/unlock and native/UI Automation initialization cannot legitimize a recycled or
still-exiting thread. Between serial broker requests,
`register_discovered_threads_for_session` also hardens native threads Windows creates
while a session is unlocked (for example OLE/clipboard workers). The watchdog poisons and
drains only when such a thread appears during a KDF or key-use operation; an idle thread
is registered instead of disconnecting the vault. Each session-scoped request also has
one atomic admission (`begin_operation_batch`): all threads are validated before the
request starts, nested per-record key operations reuse that admission, and registration
is rejected until the request drains. Every plain key-use guard also closes with a
snapshot; nested operations inside a request batch reuse the batch's opening/closing
snapshots instead of paying per-record enumeration. A thread created during even a short
operation is caught at drain rather than excused by the next idle registration, and the
broker checks that result before responding. Acquisition/KDF guards close the same way:
publication failure poisons the process, and `Session::unlock` checks the acquisition
drain before returning success. It is never retroactively excused.

## 3. Assets

| ID | Asset | Sensitivity |
|---|---|---|
| A1 | Passphrase bytes (and the derived session key) | highest; typed once, erased on all paths; while unlocked the broker also holds a passphrase-equivalent capability envelope in locked memory (§8 residency disclosure) |
| A2 | Partition unlock capability (derived session key) | highest; DPAPI `CryptProtectMemory(SAME_PROCESS)` ciphertext at rest in memory, `VirtualAlloc`+`VirtualLock` plaintext during operation windows only |
| A3 | Secret values and TOTP seeds | high; decrypted on demand into zeroizing buffers |
| A4 | Record names / paths / breadcrumbs | sensitive metadata; session-only in the UI |
| A5 | TOTP codes | derived secret material; six ASCII digits, momentary |
| A6 | Hello PRF output / secretbox key | highest while live; zeroized after unwrap |
| A7 | Clipboard contents | high during the copy window |
| A8 | Store file | ciphertext; the v0 header is unauthenticated (see §12) |
| A9 | Item IDs / search text | sensitive metadata; session-scoped |

## 4. Data flow

```
            hotkey (RegisterHotKey) / tray
                        │
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ WSecret.exe  (C# WinUI 3, MSIX)                              │
 │  • metadata index (names, session-scoped IDs)                │
 │  • NO secrets, NO passphrase, NO session key, NO seeds       │
 └───────────────┬────────────────────────────▲─────────────────┘
                 │  two anonymous pipes       │
                 │  (versioned bounded frames)│
                 ▼                            │
 ┌──────────────────────────────────────────────────────────────┐
 │ wsecret-broker.exe  (Rust)                                   │
 │  • owns store handle, sessions, prompts, TOTP, writes        │
 │  • admission hardening + residency watchdog                  │
 └───┬──────────────┬──────────────────┬──────────────────┬─────┘
     ▼              ▼                  ▼                  ▼
 .secret store   broker-owned      webauthn.dll        Windows
 (portable,      masked native     → Hello PRF         clipboard
  format v0)     input (CONIN$/    (UV required;       (exclusions,
                 Win32 control)    wraps capability)    bounded window)
```

| ID | Flow | Content | Boundary |
|---|---|---|---|
| F1 | Launch | pipe handle values on the broker command line (inert without the handles) | UI → broker spawn |
| F2 | Handshake | protocol version, feature flags, broker build identity | UI ↔ broker |
| F3 | Unlock (passphrase) | keystrokes stay inside the broker-owned input; IPC carries only `Unlock` request and `Ok`/`Cancelled`/`PassphraseMismatch` | user → broker |
| F4 | Unlock (Hello) | assertion request and PRF output stay broker ↔ `webauthn.dll` | broker ↔ OS |
| F5 | Search / enumerate | exact raw name bytes and opaque item IDs (session generation bound) | broker → UI (metadata) |
| F6 | Copy password | value bytes go to the clipboard only, never to the UI | broker → clipboard |
| F7 | Copy code | derived six digits to the clipboard; seed never leaves the broker | broker → clipboard |
| F8 | Create/update value | new value typed into broker-owned masked input; IPC carries path/metadata only | user → broker |
| F9 | Lock | ordered invalidation; owned clipboard content cleared | both |
| F10 | Channel loss | pipe EOF → broker locks, drops sessions, exits | both |
| F11 | Hello enrollment | binding record written outside the store | broker → user state |
| F12 | Idle timer | five-minute lock armed by real user interaction only | internal |

## 5. Trust boundaries and IPC identity

### 5.1 The private channel

- The channel is **two anonymous pipes created by the UI at launch**; the broker receives
  exactly the inheritable ends. Capability = possession of the pipe handles.
- There is **no named endpoint, no listener, no rendezvous secret, and no network
  surface**. Nothing exists to squat, discover, or connect to. A pipe name, a PID, or a
  same-user ACL alone is never treated as proof of identity (PID reuse and same-user DACL
  are documented insufficient).
- Broker launch uses the hardened birth-spawn path: only the duplicated std handles and
  the two pipe ends are listed in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; the broker verifies
  its birth descriptors before handling any request; the UI keeps only
  `SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION` on the broker.
- The broker binary is launched from its **trusted absolute installed path inside the
  package** (`Package.Current.InstalledLocation.Path\wsecret-broker.exe`) with package
  identity verified; reparse points and path substitution are rejected (final-path check
  on an opened handle, per core file policy). A missing or substituted binary is a visible
  failure; there is no fallback.

### 5.2 Peer authentication

- **Broker → UI:** the peer is by construction the single process that holds the other
  pipe ends — the parent that created the launch. No other party can join the channel.
- **UI → broker:** the UI created the broker process from the trusted path and holds its
  process handle; the handshake (`F2`) exchanges a version and build identity so a
  mismatched binary fails closed.
- Both processes apply the core's process DACL hardening (deny-ACE for the current user
  covering `PROCESS_DUP_HANDLE`/`WRITE_DAC` and thread equivalents, `OWNER_RIGHTS` limited
  to `SYNCHRONIZE|PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION`, protected DACL),
  so a same-user peer cannot steal the pipe handles by handle duplication.

### 5.3 What an unrelated same-user process can and cannot do

| Action | Result |
|---|---|
| Connect to the running session's channel | **Cannot** — no named endpoint; handle theft blocked by the deny-ACE |
| Replay or inject frames | **Cannot** — no handle, no channel |
| Issue requests to the running broker | **Cannot** |
| Read the store file | Can, if the file's own ACL allows (same as the CLI's world); sees ciphertext only |
| Launch its own broker/CLI over the store | Can; still needs a passphrase; subject to writer-mutex conflicts on writes |
| Read broker/UI memory | **Cannot** through normal `OpenProcess` (deny-ACE); administrators/`SeDebugPrivilege` are out of scope |
| Observe the clipboard during a copy window | **Can** — clipboard is a shared surface (§9) |
| Log keystrokes at the OS input layer | Out of scope (keyboard filter drivers, assistive input) |

### 5.4 Wire protocol shape (contract)

Framing is explicit little-endian byte encoding, never native struct serialization: a
24-byte header (`magic "WSB1"`, `version u16 = 1`, `opcode u16`, `flags u32 = 0`,
`request_id u32`, `generation u32`, `payload_len u32`) followed by at most 65 536 payload
bytes. The first frame is a version handshake (`Hello`); there are no broker-initiated
push frames — exactly one response per request, matched by `request_id`. Requests carry
the session generation and opaque item IDs (store identity + session generation +
physical slot); stale IDs are rejected (`0x102 StaleGeneration`, `15 Conflict`, see
[quick-access.md](quick-access.md#broker-protocol)). Structural violations (bad
magic/flags/version, oversized or mis-sized frames) get one `1 InvalidArgument` response
and then the broker terminates the connection; semantic rejections answer a typed status
and the session continues. The byte-exact frame layout is normative in
`crates/wsecret-broker/src/protocol.rs`.

## 6. Threat analysis

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Stolen store file | KDF (opslimit in file, min 10 000), per-partition encryption, names+values encrypted | v0 header unauthenticated; CPU-only KDF; weak passphrase = offline guessing (§12) |
| T2 | Malicious store contents | bounded parsing, structural validation per record, store-size and `ops_limit` ceilings checked **before** derivation/allocation (`OPS_LIMIT_MAX` 1 000 000, trusted per-open override to raise), refusal with actionable errors | upstream read tolerance retained for documented cases; DoS via valid-but-huge KDF cost below the ceiling costs CPU time |
| T3 | Unrelated same-user process | §5.3; capability channel; deny-ACE hardening | P4 parity gap: Windows has no exact `PR_SET_DUMPABLE(0)` equivalent; elevated attackers out of scope |
| T4 | Compromised UI | UI can only invoke its permitted commands; no generic decrypt endpoint; no secrets in responses | A compromised UI can enumerate names of the unlocked partition, trigger copies, and issue writes — the permitted surface |
| T5 | Clipboard observers | §9: exclusions with no plaintext fallback, bounded window, generation-checked cleanup, clear on lock | Any local software reading the clipboard during the window sees the value; pre-existing history entries are not retroactively deletable |
| T6 | Input capture | broker-owned masked input; no CLR strings; caps (127-byte passphrase); zeroization on all paths (§7) | OS input stack, IME/TIP alternatives, on-screen/assistive keyboards are outside the boundary |
| T7 | Hello abuse / recovery | §8: UV-required PRF release, AEAD-wrapped capability, fail-disabled, explicit invalidation and passphrase fallback | PRF is deterministic and not challenge-bound; Hello PIN caching ticket semantics; PIN reset destroys enrolled keys |
| T8 | Lifecycle races | generation-checked publication; lock invalidates before clearing; late clipboard/search/Hello completions discarded (§10) | none known beyond crash during the ordering (broker exit closes everything) |
| T9 | Metadata leakage | names/session IDs are session-only; no plaintext index on disk; no recents/telemetry/dump payloads; redacted diagnostics; UIA nodes cleared on lock | A CLR string cannot be reliably overwritten; metadata exposure to the UI process is inherent to display |
| T10 | Concurrent writers | core writer mutex + per-block `LockFileEx` + 6b revalidation + `CommitOutcome` reconciliation; identity revalidated immediately before commit | cross-host writers on shared filesystems remain unsafe (documented CLI limitation) |
| T11 | Broker loss / restart | channel EOF → lock/drop/exit; UI shows locked state; item IDs die with the session generation | in-flight copy may already have published (window applies until timeout) |
| T12 | Store replacement | 6b identity binding (final path + file identity) → `Conflict`, session invalidated | attacker who can swap the file can also deny service |

## 7. Secure input ownership

Contract for passphrase entry and for secret values entered in the Quick Access editor:

- **Ownership:** passphrase and secret-value entry use a **native Win32 window in an
  isolated `--native-prompt` helper process**, not any WinUI element and not the process
  that holds vault sessions. The reusable topmost window has a masked `ES_PASSWORD`
  `EDIT`, prompt label, and OK/Cancel controls. The main broker launches the helper over
  private inherited anonymous pipes with bounded `WSP1` framing and a kill-on-close job;
  the helper owns only transient prompt bytes. Show/focus/hide, masked-character, and
  cross-thread UI Automation warm-ups happen before native-thread registration and before
  the first secret prompt. No XAML `PasswordBox` and no managed string is ever created
  from the input.
- **Buffer path:** native masked `EDIT` (OS-owned) → bounded `EM_GETLINE` UTF-16 scratch →
  UTF-8 decode/validation into a broker buffer → KDF input or store value. The edit text
  and undo buffer are cleared immediately after every read; UTF-16 and result scratch are
  zeroized on every path, including cancellation and queued/dropped replies. Embedded NUL
  and other control bytes are rejected rather than truncated. The window is destroyed and
  its hardened thread joined at teardown. Derived keys exist at rest only as
  `CryptProtectMemory(SAME_PROCESS)` ciphertext.
- **Limits:** passphrase ≤ 127 bytes (`PASSPHRASE_MAX_BYTES`, upstream `s_ask_pass` cap);
  hex entry ≤ 254 characters; secret value ≤ 511 bytes console (`SECRET_MAX_BYTES`).
  Oversized input is refused with an actionable error **before** derivation or allocation.
- **Never present in:** C# strings, view models, IPC frames, command lines, environment
  variables, temporary files, logs, crash dumps (WER excluded), or telemetry.
- **Erasure:** scratch zeroized on success, failure, cancellation, lock, hide, and
  shutdown; control content cleared at unlock end and at every lock; the passphrase is
  never retained for automatic retry.
- **Residual limits:** the keyboard input path below the application (kernel input
  drivers, assistive technology, hardware key loggers) is outside the boundary; a
  compromised broker process owns all secrets by design.

## 8. Windows Hello PRF binding and recovery

- **Provider and operation:** the Windows Hello platform passkey reached through
  `webauthn.dll` (documented Win32 WebAuthn API). The key operation is a **PRF evaluation
  (CTAP2 `hmac-secret`)** with **user verification required** (PIN or biometric). This is
  a capability release, not a signature (`KeyCredentialManager` signing is rejected:
  sign-only), and not consent + DPAPI (`UserConsentVerifier` is rejected: a consent prompt
  must not gate an ordinary DPAPI blob). Ceremonies supply a real foreground parent HWND
  and cancellation GUID. A hardened watcher calls `WebAuthNCancelCurrentOperation` at the
  request deadline so a modal ceremony cannot survive a stuck desktop indefinitely.
  WebAuthn-created broker threads are discovered, registered, and hardened after the
  ceremony and before the recovered passphrase or derived session key is admitted to
  protected memory.
- **Enrollment:** opt-in only, after a successful passphrase unlock of the target
  partition. A discoverable/resident credential is created with RP ID **`"wsecret.local"`** and
  WebAuthn user handle `hydro_hash(store_master ‖ user_sid_hash)` under context
  `"WSHLOUSR"` — distinct per store, so a second store's enrollment never overwrites the
  first credential — and `credProtect` = user-verification-required. **The enrollment PRF
  probe is the capability check**: registration's `bPrfEnabled` is treated as untrusted, a
  credential whose PRF output cannot be probed is not enrolled.
- **Binding record:** a binary sidecar **separate from the portable store**, at
  `<store path>.hello` (default store: `%USERPROFILE%\.secret.hello`), written through the
  store's exclusive-create hardened path (non-inheritable handle) and read with
  reparse-point rejection. Version-1 layout (`WSHB`):

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 4 | magic `"WSHB"` |
  | 4 | 1 | `version` = 1 |
  | 5 | 1 | `flags` = 0 |
  | 6 | 2 | `reserved` = 0 |
  | 8 | 32 | `store_master` — store header master field (store identity binding) |
  | 40 | 32 | `user_sid_hash` = `hydro_hash(current user SID)` ctx `"WSHLOSID"` (account binding) |
  | 72 | 2 | `cred_id_len` u16 LE (1..=1024) |
  | 74 | N | `cred_id` — WebAuthn credential ID (device binding) |
  | 74+N | 32 | `prf_salt` — PRF input (default WebAuthn-PRF hash mode; no raw-salt flag) |
  | 106+N | 24 | `nonce` |
  | 130+N | 2 | `sealed_len` u16 LE = 512 |
  | 132+N | 512 | `sealed` = `hydro_secretbox` (ctx `"WSHELLO1"`, key = 32-byte WebAuthn PRF output) over a 476-byte envelope |

  The sealed envelope is `u8 version = 1 ‖ u8 pass_len ‖ passphrase bytes ‖ zero
  padding` — a **broker-private capability envelope holding the master passphrase
  (passphrase-equivalent)**. The raw partition/session key is never persisted or exported
  anywhere. Binding scope: this Windows user (SID hash), this device (the
  device-bound platform credential), this store (`store_master`), and — through the
  sealed passphrase — this partition. The portable `.secret` file is untouched and stays
  host-independent.
- **Unlock:** assertion for the stored `credentialId` with required UV. The assertion's
  authenticator-data **UV (0x04) and UP bits are verified before any PRF output is used**
  (CTAP `CredRandomWithUV` vs `CredRandomWithoutUV`); `prf_salt` is evaluated in default
  WebAuthn-PRF hash mode; the 32-byte PRF output must open `sealed` (missing PRF output,
  wrong length, or MAC mismatch fails closed with the store untouched). The unwrapped
  passphrase-equivalent drives an ordinary broker unlock and is held only in locked
  memory; PRF/secretbox-key copies are zeroized.
- **Residency disclosure:** while a session is unlocked the broker additionally holds the
  passphrase-equivalent in locked memory (zeroizing `SecretBytes`) until Lock, disconnect,
  or drop. This is an explicit, sanctioned design decision (broker `main.rs` / `hello.rs`
  module docs): no raw key material is persisted and no re-prompt is needed within one
  epoch — at the cost that broker-memory compromise while unlocked yields the
  passphrase-equivalent.
- **Invalidation and recovery:** PIN reset (destructive by default: Hello deletes the old
  key material), credential deletion (including deleting the passkey in Windows Settings —
  that destroys the wrap key, so unlock reports `0x107 HelloFailed` until re-enrollment),
  Windows profile change, TPM key change/lockout, store replacement (identity mismatch),
  sidecar file deletion or the explicit **HelloForget** command → binding invalid →
  **fall back to passphrase** and require explicit re-enrollment after a passphrase
  unlock. The store remains passphrase-unlockable forever; the passphrase is never
  retained to power an automatic retry. If the cryptographic contract cannot be
  demonstrated for a configuration (absent hardware or policy, per-app passkey privacy
  denial on Windows 11 24H2+, unavailable platform authenticator), Hello stays unavailable
  and the UI says so **without exposing store metadata**.
- **Limits (documented, not hidden):** at-rest exposure of the sidecar is exactly
  `PRF(credential, prf_salt)` + required UV (biometric/PIN of the enrolled user) +
  device-bound credential + constant-time store/user binding checks (`hydro_equal`): a
  stolen sidecar alone reveals nothing. But sidecar **plus** a Hello compromise yields the
  passphrase-equivalent — which, unlike a session key, also unlocks that partition on any
  host that has the store; this is inherent to wrapping a passphrase and is the price of
  the no-key-export rule. PRF is deterministic and **not challenge-bound** — each gesture
  releases the same capability; the app rate-limits unlock attempts and never treats a PRF
  result as fresh authentication evidence. Microsoft documents Hello PIN caching as
  per-process tickets (first use prompts; later private-key operations may not re-prompt),
  so re-prompts are not guaranteed within one broker life. Hello keys are device-bound and
  do not roam.

## 9. Clipboard contract and limits

- The **broker** performs every sensitive copy, and only after an explicit user gesture.
  Secret bytes travel broker → clipboard; they never enter the UI process.
- **Mechanics:** `OpenClipboard` is retried at most 5 × 50 ms, then the copy fails with
  `ClipboardError`. Inside one clipboard hold: `EmptyClipboard` → publish the three
  registered exclusion formats first (**`ExcludeClipboardContentFromMonitorProcessing`**,
  **`CanIncludeInClipboardHistory`**, **`CanUploadToCloudClipboard`**, each with a
  serialized 4-byte DWORD 0 payload) → then `SetClipboardData` of `CF_UNICODETEXT` and of
  the registered raw format **`WSecret/Bytes`** (exact raw value bytes). If the exclusions
  cannot be installed, the copy **fails** — there is no plaintext fallback.
- **Text passwords** are published with exact content preserved (no newline, whitespace,
  or normalization changes). A value that is not valid UTF-8 text without an interior NUL
  is **refused with a typed error** (`0x109 ValueNotText`) and **nothing** is published —
  no raw-format-only success path; the UI explains and points at the CLI for binary
  values.
- **Timeouts:** 30 seconds for passwords and values (request override clamped 1..=30 s);
  for a code, the earlier of that timeout and the remaining code window. Owned content is
  cleared on lock and on channel loss wherever Windows allows.
- **Publication and cleanup are failure-atomic:** all exclusion/text/raw blocks are staged
  before opening the clipboard. UTF-16 is encoded directly into its publication allocation;
  no ordinary plaintext `Vec<u16>` is retained. A failed publication rolls back within the
  same hold, and locally owned secret blocks are zeroized before `GlobalFree`. If rollback
  itself fails, ownership is retained for retry.
- **Cleanup is ownership-checked:** the copier records the clipboard sequence number at
  publication; cleanup rechecks it under exclusive clipboard access and clears **only** an
  item still owned by this session — a newer item from another application is never
  erased. The clipboard hold is retained through clearing, and ownership survives
  contention/failed clearing for retry. A late cleanup after lock never publishes or
  resurrects anything (§10).
- **Expiry is event-driven:** the hardened expiry thread sleeps while unowned, wakes on
  publication/shutdown, and waits until the actual deadline. It does not poll every 250 ms
  in the hidden/locked steady state.
- **Limits (must be understood):** the system clipboard is readable by other local
  software during the copy window; exclusions are honored by Windows clipboard history
  and cloud sync, not by arbitrary third-party clipboard managers; content already copied
  before a failure is not retroactively erasable from third-party stores; screenshots,
  screen readers, and elevated observers are out of scope.

## 10. Session lifecycle and invalidation ordering

States: **Locked → Unlocking → Unlocked → Locking → Locked**.

| State | Legal operations | Everything else |
|---|---|---|
| Locked | unlock request (passphrase or Hello), quit | rejected; no IDs, no index, no owned clipboard |
| Unlocking | cancel | one in-flight derivation/PRF; superseded results discarded |
| Unlocked | search, enumerate, copy, code, write, enroll Hello, lock | stale IDs rejected (`Conflict`) |
| Locking | none | in-flight work cancelled; publication refused |

- **Lock triggers:** explicit Lock command, workstation lock, suspend, sign-out, private
  channel loss (pipe EOF / broker death), and inactivity — default **five minutes**,
  armed only by **actual user interaction** (keystroke, click, gesture). Background timer
  ticks, search completion, and code refreshes never reset the timer; the code countdown
  timer runs only while the Codes view is visible and unlocked.
- **Ordering rule:** the session generation increments when an unlock attempt finishes
  (success **or** failure) and when a lock finishes; every publication (clipboard write,
  search batch, Hello completion, write commit) revalidates the generation at its commit
  point. A late completion carrying a stale generation is dropped — a locked session is
  never resurrected.
- On lock: cancel work, invalidate IDs, clear the index and results, clear UI automation
  nodes and transient UI state, clear owned clipboard content (generation-checked), close
  and zeroize the session key, drop broker-side plaintext buffers.

## 11. Writes, conflicts, crash consistency

- Mutations reuse the core protocol unchanged: canonical writer mutex
  (`Global\wsecret-store-…`), per-512-byte-block `LockFileEx`, 6b identity revalidation,
  exact block writes, `FlushFileBuffers`, and the `CommitOutcome` trichotomy
  (`NotCommitted` / `Unknown` / `Committed`) with warning bits
  (`WARN_POST_COMMIT_PANIC`, `WARN_POST_COMMIT_CANCELLED`, `WARN_ABANDONED_MUTEX`).
- Record identity is revalidated immediately before commit (compare-and-set on the target
  slot's exact name bytes); a mismatch aborts with `Conflict`. On an `Unknown` commit
  result the broker re-reads and reconciles before any retry.
- Only the target record is rewritten; other records and other passphrase partitions
  remain byte-preserved. Tombstone (`DELETED:`) reuse keeps upstream semantics and is not
  secure deletion.

## 12. Residual risks and non-claims

- Inherited v0 format limits: **unauthenticated header**, no whole-store integrity or
  anti-rollback protection, CPU-only KDF (constant zero salt), and a valid-but-expensive
  `ops_limit` bounded only by the configured ceiling.
- Windows has no exact equivalent of upstream's `PR_SET_DUMPABLE(0)`/`PT_DENY_ATTACH`;
  the process/thread DACL hardening is best-effort against ordinary same-user processes
  and is not a claim of parity with those primitives. Elevated attackers are out of scope.
- Tombstone rename is not secure deletion; deleted values may survive in the file's
  padding or in prior copies of the store.
- A CLR string cannot be reliably overwritten; this is why no secret or passphrase ever
  enters the UI process, and why names and metadata are released at lock.
- No statement in this document constitutes a formal cryptographic audit, and file-format
  compatibility with upstream does not imply that upstream-inherited weaknesses are fixed.
- Hello enrollment wraps a **passphrase-equivalent** under the Hello PRF output in the
  `<store>.hello` sidecar (§8): sidecar plus a Hello compromise exposes the passphrase
  (portable across hosts), and every unlocked broker epoch holds that equivalent in locked
  memory. Both are explicit design decisions, not incidental exposure.

## 13. Evidence status

Native x64 builds, automated tests, UI acceptance, clipboard behavior, Hello PRF
enrollment/unlock/recovery, MSIX installation, packaged passphrase/lock acceptance, and
performance samples were executed on 2026-11-20; see
`../evidence/quick-access-20261120.md` for commands, environment, results, and review
remediation. ARM64 execution, packaged UI Hello on an unlocked desktop,
warm-summon/keystroke/secure-copy timings, actual sign-in activation, and elevated
SeDebugPrivilege controls remain **unverified**. Cross-cutting evidence already on file for the library and CLI (see the
root `README.md` proof-status table) predates Quick Access and does not extend to it.
