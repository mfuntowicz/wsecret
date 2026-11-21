# WSecret Quick Access — feature and integration contract

Quick Access is a small floating palette for Windows 11: type `git`, choose the account,
press one shortcut, and the password or current one-time code is on the clipboard. This
document is the concrete contract for that feature: components and package identity,
session lifecycle, **exact-byte name mapping**, Codes rules, copy and write behavior,
Hello unlock, and the broker protocol surface. Security analysis lives in
[threat-model.md](threat-model.md); build/package/run commands live in
[build.md](build.md).

**Evidence status:** native x64 tests, clipboard behavior, Hello PRF enrollment/unlock/
recovery, MSIX installation, and packaged passphrase/lock acceptance are recorded in
[Evidence](#10-evidence). ARM64 execution, packaged UI Hello on an unlocked desktop,
warm-summon/keystroke/secure-copy timing, and actual sign-in activation remain unverified.

## 1. Components and package identity

| Piece | Value |
|---|---|
| UI | `WSecret.exe` — C#/.NET 11/WinUI 3, MSIX full trust, `src/WSecret/` |
| Broker | `wsecret-broker.exe` — Rust (`crates/wsecret-broker`), launched from the package install directory |
| Store | portable `.secret` file (format v0), shared byte-for-byte with the `wsecret` CLI |
| Hello binding | `<store path>.hello` sidecar (see threat-model §8) |

Package identity (`src/WSecret/Package.appxmanifest`):

- Identity `Name=com.wsecret.QuickAccess`, `Publisher=CN=WSecret`, `Version=0.2.1.1`.
- Application `Id=WSecret`, `EntryPoint=Windows.FullTrustApplication`; display name
  **WSecret**; `PublisherDisplayName` **Morgan Funtowicz** (author metadata); minimum OS
  Windows 11 build **26100**.
- AUMID at runtime: `Package.Current.Id.FamilyName + "!WSecret"`
  (i.e. `com.wsecret.QuickAccess_<publisher-hash>!WSecret`).
- Launch-at-sign-in is a packaged `windows.startupTask` (`TaskId=WSecretStartup`).

Boundary rule: **the CLR only ever holds metadata.** Passphrases, values, seeds, session
keys, and codes never enter the UI process; the broker owns all secret material and every
session (threat-model §2).

## 2. Invocation and surface

- Global hotkey via `RegisterHotKey`, default **Ctrl+Alt+W**, modifier set + virtual key
  configurable. Registration failure is shown in-app (InfoBar naming the combination and
  the Win32 error) — never silently dropped. No global keyboard hook.
- Tray: Show/Hide, Lock now, Launch at sign-in toggle, Exit. Opening a second instance
  activates the existing window.
- The unlocked palette opens centered at 580 × 400 DIPs. Search has keyboard focus;
  results fill the width, with a service or item icon, a title, and a breadcrumb.
  The first match is selected. The lock screen does not expose search or item actions.
- **↑ / ↓** move the selection without leaving search. **Enter** copies the current
  value (a derived code for a code entry). **Ctrl+Enter** requests a code for this exact
  record; multiple linked codes open a chooser, and no link gives feedback without
  changing the clipboard. The footer exposes the same three actions as clickable buttons.
- **Ctrl+O** or double-click opens Details. Back or **Esc** returns to the same search
  and selection. The overflow menu opens Codes and Editor or locks the vault.
  **Esc** from the search field or list hides the palette; summoning it again selects
  the query for replacement. A successful palette copy briefly confirms the clipboard
  expiry, then hides unless the user has already moved on. Errors keep the window open.
- Only metadata is rendered. Settings contains the store location and matching count;
  neither occupies space in the default search view. There is no value reveal or dump.

## 3. Session lifecycle

`Locked → Unlocking → Unlocked → Locking → Locked` (contract details and ordering rules:
threat-model §10).

- Lock triggers: explicit Lock, workstation lock, suspend, sign-out, channel loss, and
  five-minute inactivity — reset **only** by actual user interaction.
- On lock the session generation advances first; item IDs, the index, results, UIA nodes,
  and owned clipboard content are invalidated/cleared; a late search batch, clipboard
  cleanup, or Hello completion can never resurrect the session.
- The code countdown timer runs only while the Codes view is visible and unlocked; the
  hidden/locked steady state has no periodic UI/search/OTP polling (the core residency
  watchdog is accounted for separately while a session is unlocked).

## 4. Exact-byte mapping

**Identity is exact raw name bytes plus the physical slot.** Display is a lossy,
escapable projection and is never used for lookup, copy, update, or rename.

Record facts (format v0, `wsecret-core::format`):

- Name: 1..=255 raw bytes, no byte `<= 0x20`, bytes `> 0x7F` allowed (names need not be
  UTF-8). Value: opaque binary, at most `473 − name_len` bytes.
- Duplicate raw names are reachable (rename does not check that the new name is free);
  the core's name lookup is first-match, so Quick Access addresses records by
  session-scoped opaque item IDs (store identity + session generation + slot), never by
  display label. Ambiguous targets disable copy/mutation-by-guess.
- Tombstones (`DELETED:` name prefix) are hidden from normal results; their slots stay
  eligible for reuse; tombstone rename is not secure deletion.

### 4.1 Display projection

Split on ASCII `/` (0x2F) **only**; never normalize as a filesystem path.

| Stored name | Projection |
|---|---|
| `token` | **Default (ungrouped)** → item `token` at the root |
| `GitHub/password` | **Default (ungrouped)** → GitHub → password |
| `Work/GitHub/password` | **Work** → GitHub → password |
| `Work/Engineering/Platform/GitHub/deploy/prod/token` | **Work** → Engineering → Platform → GitHub → deploy → prod → token (every component preserved) |
| `Work/GitHub/key` + `Work/GitHub/key/public` | `key` is both an item and a container: two distinct actions (own value / browse children) |
| `Default/GitHub/password` + `GitHub/password` | **Default (named)** vs **Default (ungrouped)** — distinct internal roots, both addressable |
| `Work//GitHub/token`, `/lead/x`, `trail/`, `a/./b`, `a\b`, non-UTF-8 bytes | empty segments kept (marker `⌀`), dots and backslashes are data, offending bytes escaped |

Root rule: 1 segment → item at the root of *Default (ungrouped)*; 2 segments →
group + item under *Default (ungrouped)*; ≥ 3 segments → first segment is the displayed
vault, the middle segments are groups, the last segment is the item. A virtual root never
adds bytes to a key.

Segment escaping (injective per segment): bytes `0x21..0x7E` render literally except
`\` (renders `\\`); every other byte renders `\xNN` (lowercase hex), which also defuses
bidi controls and look-alike bytes; an empty segment renders `⌀` (U+2300) and literal
marker text can only appear escaped. Rows truncate long labels visually; the tooltip and
accessible name expose the full path. A terminal `password` field uses its owning item's
name as the title, so `Work/Engineering/GitHub/password` reads **GitHub** over **Work › Engineering**.

For new or renamed records the exact resulting key path is shown before save; no literal
`Default/` prefix is ever implied. A breadcrumb is never converted back into a key.

### 4.2 Search

An unlocked session caches a complete, bounded names-only listing when available.
Typing filters those names locally by ASCII-case-insensitive raw-byte substring, in
store order. If the initial listing was truncated, typing instead queries the broker
so later records remain searchable. Explicit refresh and writes discard the cache;
locking releases it. Neither the title nor the breadcrumb is an action target.

## 5. Codes

One adapter owns discovery **and** seed decoding; nothing else guesses TOTP semantics.

- **Auto-index discovery** (what enters the Codes view): an exact, case-sensitive path
  component `totp`, `totp32`, or the display alias `topt`, or an explicit supported import
  type. A label like `totp-notes` does **not** by itself enter the Codes list.
- **Decoding:** component `totp32` anywhere → base32-first (upstream `s_totp32` quirks:
  stops at NUL/`=`/LF, rejects lowercase and digits 0/1/8/9); `totp` and the `topt` alias →
  raw key bytes (alias is raw by default, consistent with `totp`; explicit import metadata
  may select base32). The `topt` alias is never passed blindly to the core `totp_for`
  matcher. The core generator (upstream-exact HMAC-SHA-1, 30 s period, 6 digits, counter
  `unix_now / 30`) computes all codes.
- **Explicit per-item code** (Ctrl+Enter) additionally follows the CLI's historical
  name-contains-`totp` substring convention on raw bytes (e.g. `mytotpkey`); this is a
  documented divergence from the auto-index rule and does not change CLI behavior.
- Copy produces the six digits **at the moment of the action**, leading zeros included;
  the seed never leaves the broker and is never the fallback copy result. The Codes view
  shows account metadata and the countdown only — the digits themselves go straight to
  the clipboard at copy time (displaying them is permitted but not done). Invalid seed →
  "Code unavailable". Expiry display: 30 at rollover, 1 in the final second.
- Linking a code to a password record only happens through explicit import metadata or a
  unique full account path in the same displayed vault **and** cryptographic partition.
  Identical service names across vaults never cross-link. Opening the Codes view performs
  zero imports, duplications, or store writes.
- Covered cases (`fixtures/quick-access/manifest.json` `codes_cases`): `totp32/GitHub`,
  `GitHub/totp32`, `Work/totp32/GitHub/alex`, `Work/topt/GitHub/alex`, `example/totp`,
  `totp-notes`, `mytotpkey`.

## 6. Copy behavior (summary)

Full contract and limits: [threat-model.md](threat-model.md) §9.

- Broker-owned copy after an explicit gesture; secret bytes never enter the UI.
- Text values copy with exact content; values that are not valid UTF-8 text without an
  interior NUL are refused with `ValueNotText` and nothing is published (use the CLI for
  binary values).
- Clipboard history/cloud exclusions are installed before the secret format within one
  clipboard hold; failure to install them fails the copy (no plaintext fallback).
- TTL 30 s for passwords/values (clamp 1..=30 s); for codes the earlier of the TTL and the
  remaining code window. Cleanup is sequence-number ownership-checked; lock and channel
  loss clear owned content.

## 7. Writes

- A compact detail/editor covers create, set, renew, update, and rename of individual
  password/OTP records. Generate-and-store (`New`, 0x0030) has two modes: `gen` = 0 is the
  upstream `new`-style random secret; `gen` = 1 is a **deterministic secret** — the
  upstream `pass` derivation chain over the request's subkey components, then stored under
  the target name. Components are exact bytes: each 1..=255 bytes with no byte `<= 0x20`
  (commas are ordinary legal bytes), and `gen` = 1 requires at least one component. In
  both modes the fresh value goes to the secure clipboard (never displayed) and the
  response carries `clipboard_ttl_ms`. Path preview and validation errors never print
  secret values.
- New values are typed into **broker-owned masked input** (threat-model §7) — never into
  the WinUI app.
- Mutations reuse the core writer protocol: writer mutex + per-block `LockFileEx` + 6b
  identity revalidation + exact block write + flush + `CommitOutcome`. Record identity is
  revalidated immediately before commit (compare-and-set on the target slot's exact name
  bytes). On an unknown commit result the broker re-reads and reconciles before retry.
  Only the target record is rewritten; other records and other partitions stay
  byte-preserved.
- Write responses carry the commit warning bits `0x1` post-commit contained panic (write
  durable), `0x2` post-commit cancellation (write durable), `0x4` abandoned-writer-mutex
  recovery (no integrity claim), and `CommitState` (1 not committed / 2 committed /
  3 unknown).
- Bulk operations, SSH management, browser extensions, cloud sync, and a second dashboard
  are outside this delivery. External store changes invalidate stale results and IDs.

## 8. Hello unlock (summary)

Windows Hello platform passkey via `webauthn.dll`, **PRF (hmac-secret) evaluation with
required user verification** — a capability release, not a signature and not
consent+DPAPI. Enrollment is opt-in after a successful passphrase unlock; the wrapped
passphrase-equivalent capability envelope lives in the `<store path>.hello` sidecar
(version-1 `WSHB` layout; RP ID `wsecret.local`), bound to this user, device, store, and
partition — the raw partition key is never persisted or exported. Any failure or absence
keeps Hello **unavailable** (fail-disabled) with passphrase fallback; full contract,
recovery, and limits: [threat-model.md](threat-model.md) §8.

## 9. Broker protocol

The channel and its identity contract: [threat-model.md](threat-model.md) §5. Summary:

- **Transport:** two anonymous pipes created by the UI at launch and inherited by the
  broker (no named endpoint, no listener, no network):
  `wsecret-broker.exe --rd-handle <dec> --wr-handle <dec> [--store <PATH>]`. Handle values
  are decimal and inert without the handles; the broker rejects anything that is not a
  distinct non-null pipe-handle pair. Store resolution: `--store`, else `%SECRET_STORE%`,
  else `%HOME%\.secret`, else `%USERPROFILE%\.secret` (upstream order).
- **Framing:** 24-byte little-endian header followed by `payload_len` body bytes
  (bounded: `MAX_PAYLOAD` = 65 536):

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 4 | `magic` = `0x3142_5357` (`"WSB1"` LE) |
  | 4 | 2 | `version` = 1 |
  | 6 | 2 | `opcode` |
  | 8 | 4 | `flags` = 0 (nonzero = protocol violation) |
  | 12 | 4 | `request_id` (client-chosen, nonzero, echoed) |
  | 16 | 4 | `generation` (session epoch; 0 = none) |
  | 20 | 4 | `payload_len` (≤ 65 536) |

  The first frame must be `Hello` with `version = 1`; a mismatch answers
  `0x100 VersionMismatch` (`aux` = broker max version) and the broker exits. There are no
  broker-initiated push frames: exactly one response per request, matched by
  `request_id`; the client must reject responses to request IDs it did not issue and drop
  stale-generation responses. Deadlines: handshake 15 s, inter-byte 10 s, whole request
  120 s (covers prompts and WebAuthn) → `0x104 Timeout`.
- **Scoping:** requests carry the session generation and opaque item IDs bound to store
  identity, session generation, and slot; stale IDs are rejected before any sensitive
  operation. The generation counter starts at 0 and increments when an unlock attempt
  finishes (success **or** failure) and when a lock finishes.
- **Operations:**

  | Opcode | Name | Behavior |
  |---|---|---|
  | 0x0001 | `Hello` | handshake / state / capabilities; MUST be the first frame |
  | 0x0002 | `Ping` | liveness + state + generation |
  | 0x0003 | `Cancel` | cancel the in-flight request by `request_id` → `16 Cancelled` |
  | 0x0004 | `Shutdown` | teardown and exit 0 |
  | 0x0010 | `Unlock` | broker-native masked prompt, or Hello PRF (no passphrase bytes on the wire) |
  | 0x0011 | `Lock` | wipe the session; optionally clear the owned clipboard |
  | 0x0020 | `List` | bounded page of exact raw names with their physical slots and the total match count |
  | 0x0021 | `Meta` | slot, kind, value length, countdown (metadata only) |
  | 0x0022 | `Copy` | checked value/automatic code copy to the broker clipboard |
  | 0x0023 | `Code` | checked current TOTP copy; no digits in the reply |
  | 0x0024 | `CodeTargets` | selected slot + raw name → up to 64 unique same-partition code targets (slots + names only); ambiguity, stale identity or incomplete index fails closed |
  | 0x0030 | `New` | generate and store a secret; `gen`=0 = upstream `new`-style random value, `gen`=1 = deterministic secret (upstream `pass` derivation chain over the request's subkey components, then stored); the fresh value goes to the secure clipboard in both cases and the response carries `clipboard_ttl_ms` |
  | 0x0031 | `Set` | create/replace with broker-native masked value entry |
  | 0x0032 | `Update` | rename and/or replace/regenerate one record |
  | 0x0040 | `HelloEnroll` | bind the epoch secret under WebAuthn PRF + required UV |
  | 0x0041 | `HelloForget` | delete the Hello binding record (idempotent, any state) |

  The palette appends the expected slot (`u64`) to every `Copy`/`Code` request. The
  broker accepts v1 frames without the guard for older clients, but never picks the
  first duplicate name. With a guard, a name moved to another slot is a conflict.

  **Record values never cross the channel in either direction.** The client sees metadata
  only (raw name bytes, slots, counts, kinds, TTLs, countdowns, statuses); secret material
  enters the broker only through its masked native Win32 prompt and leaves only as a
  broker-owned clipboard write or a Hello PRF operation. Session-scoped requests are legal
  only in `Unlocked` with the current generation (`0x101 WrongState` / `0x102
  StaleGeneration` otherwise); during `Unlocking`/`Locking` only `Hello`, `Ping`, `Cancel`,
  `Shutdown`, and `HelloForget` are answered (`0x103 Busy` otherwise).
- **Errors:** one catalog. The wire `status` field (`u16`, first field of every response)
  carries the core `wsecret_core::error::Status` numbering **verbatim** for `0`–`25`
  (same meanings; several stay reserved) plus protocol-only codes at `0x100`+:

  | Code | Meaning | Code | Meaning |
  |---|---|---|---|
  | 0 | Ok | 0x100 | VersionMismatch (wire version; aux = broker max version) |
  | 1 | InvalidArgument (structural violations and semantic rejections — see below) | 0x101 | WrongState (illegal in the current lifecycle state) |
  | 2 | InvalidName | 0x102 | StaleGeneration |
  | 3 | EntryTooBig | 0x103 | Busy (lifecycle transition / request in flight) |
  | 4 | StoreNotFound | 0x104 | Timeout (frame/prompt/assertion deadline) |
  | 5 | StoreExists (reserved) | 0x105 | HelloUnavailable (fail-disabled; never a weaker fallback) |
  | 6 | UnsupportedVersion (store format version) | 0x106 | HelloNotEnrolled |
  | 7 | MalformedStore | 0x107 | HelloFailed (assertion/UV/unseal refused) |
  | 8 | ResourceLimit (KDF `ops_limit` refused) | 0x108 | ClipboardError |
  | 9 | NotFound | 0x109 | ValueNotText (binary/unrepresentable; text copy refused) |
  | 10 | AlreadyExists | 0x10A | NoConsole (masked input impossible) |
  | 0x10B | InputInvalid (broker prompt input rejected: too long / control bytes / invalid UTF-16) | | |
  | 12 | PassphraseMismatch (retype mismatch) | 15 | Conflict (CAS: record changed since the slot you saw) |
  | 16 | Cancelled (Cancel or empty/EOF at a prompt) | 13 / 14 / 21 / 22 | Locked / MutexBusy (reserved; see 0x103) / UnsupportedFilesystem (reserved) / AgentUnavailable (reserved) |
  | 17 / 18 / 19 / 20 | Io / Crypto / NoMemory / MemoryProtection | 23 | Panic (contained) |
  | 24 | CommitUncertain (aux `CommitState=3` = Unknown) | 25 | InvalidTotp (name says totp, value yields no code) |

  `aux` carries `CommitState` (1 not committed / 2 committed / 3 unknown) on writes and is
  0 otherwise (except `VersionMismatch`, where it is the broker's max wire version). The
  authoritative implementation table is `crates/wsecret-broker/src/protocol.rs`.
- **Structural vs semantic errors:** *structural* protocol violations (bad magic, bad
  flags, wrong frame version, oversized frame, short or trailing payload) get exactly one
  `1 InvalidArgument` response and then the broker **terminates** the connection.
  *Semantic* rejections answer their typed status and the connection **continues** —
  name-rule violations `2`/`3`; bad mode bytes, generation/subkey pairing, an out-of-range
  count, or a `Cancel` targeting request 0 → `1 InvalidArgument`. A UI typo never tears
  the session down. Status numbers are unchanged by the split.
- **Unlock semantics:** per the v0 format, a wrong passphrase and an empty partition are
  indistinguishable — Unlock succeeds and the retype confirmation surfaces the evidence;
  the UI shows "No records unlocked with this passphrase" when that is all the evidence
  supports. A real retype mismatch is `12`; an empty entry at the broker prompt is
  `16 Cancelled`.
- **Disconnect:** pipe EOF at the broker (client death) locks and drops all sessions and
  terminates the broker; the UI treats broker death as an immediate lock.

## 10. Evidence

Planned checks and their expected observables are enumerated in
`fixtures/quick-access/test-evidence.template.md` (correctness/security/end-to-end rows)
and `fixtures/quick-access/bench-evidence.template.md` (performance rows with
preregistered budgets in `fixtures/quick-access/bench-budgets.json`). The fixtures and
expected outcomes for the exact-byte mapping and Codes rules are machine-readable in
`fixtures/quick-access/manifest.json`; `scripts/test.ps1` and `scripts/bench.ps1` fill the
templates when actually run.

Initial performance targets (packaged Release, named Windows 11 reference machine, AC
power, no debugger; report percentiles, sample count, hardware, build, and baseline;
keep cold launch, unlock/KDF, and warm summon separate):

| Measurement | Target |
|---|---|
| Warm hotkey → search field accepting the first keystroke | p95 ≤ 100 ms over ≥ 100 summons (first character present, not just painted) |
| Keystroke → correct results painted | p95 ≤ 50 ms for 10 000 synthetic names after indexing |
| Hidden/locked steady state | no periodic UI/search/OTP polling; idle CPU, UI and broker private bytes, and wakeups measured separately; core watchdog accounted for while unlocked |
| Security costs | bounded-open rejection, cold unlock/index time, secure copy latency, lock invalidation time — protective settings enabled |

Executed on 2026-11-20: 116 core library tests, 13/13 Quick Access role tests, 197 CLI
lib/bin tests, 16 broker tests, P4/R2-A suites (except the documented elevated
prerequisite), x64/ARM64 builds and development-signed MSIX packaging. Native x64 UI runs
verified broker idle survival, UIA-driven native-prompt unlock, search, typed Set,
lock/re-unlock, Codes discovery/countdown, and committed-write reporting on clipboard
failure. Clipboard content/exclusion/TTL behavior and Windows Hello PRF enrollment,
unlock, and passphrase recovery were executed. The final x64 MSIX was installed and
passed packaged passphrase unlock and explicit Lock; its startup task is registered and
enabled. The 100-sample unlock/index benchmark measured p50 200.455 ms, p95 219.973 ms,
p99 225.161 ms (min 179.311 ms, max 226.494 ms) with ops_limit 100000 unchanged.

Full commands, environment, raw sample paths, package hashes, and blocked scenarios are in
`../evidence/quick-access-20261120.md`. ARM64 execution, packaged UI Hello on an unlocked
desktop, warm-summon/keystroke/secure-copy timings, actual sign-in activation, and elevated
SeDebugPrivilege controls remain unexecuted. Packaged lock invalidation has five
UIA-observed samples (p50 2320 ms, p95 2341 ms), explicitly including automation overhead.
Cross-host data compatibility (Linux/macOS-origin stores) reuses the CLI fixtures under
`fixtures/stores/` whose provenance is recorded in their manifests.
