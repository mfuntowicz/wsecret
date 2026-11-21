# Quick Access — test evidence

> Fill one copy of this template per run into `evidence/` (git-ignored), produced by
> `scripts/test.ps1` where possible. **A row may only be marked PASS/FAIL/BLOCKED when a
> real run supports it.** Everything else stays `UNEXECUTED`. Never infer results from
> code inspection, sibling rows, or a different machine/configuration.

## Environment

| Field | Value |
|---|---|
| Date (UTC) | UNEXECUTED |
| Machine (model/CPU/RAM) | UNEXECUTED |
| OS edition/build | UNEXECUTED |
| Architecture (x64/ARM64 native?) | UNEXECUTED |
| .NET SDK / Rust / MSVC versions | UNEXECUTED |
| Build configuration & git revision | UNEXECUTED |
| Store fixture (manifest id / sha256) | UNEXECUTED |
| Debugger attached | none allowed for evidence runs |

## A. Data compatibility (synthetic fixtures + CLI/core cross-checks)

Oracle: byte-exact `wsecret dump` output and file sha256 before/after.

| # | Check | Expected | Status | Evidence |
|---|---|---|---|---|
| A1 | Every projection case P01–P15 (`fixtures/quick-access/manifest.json`) renders the documented root/path | mapping table matches | UNEXECUTED | |
| A2 | Maximum name length (255 B) accepted; 256 B rejected | `InvalidName` at boundary+1 | UNEXECUTED | |
| A3 | Deep path (12 segments) round-trips | components preserved in order | UNEXECUTED | |
| A4 | Two passphrase partitions (P_A/P_B) | unlock exposes only own records | UNEXECUTED | |
| A5 | Dual item/container nodes (`Work/GitHub/key` + `…/key/public`) | two distinct actions; values correct per ID | UNEXECUTED | |
| A6 | Malformed/truncated store | bounded rejection, actionable error, no crash | UNEXECUTED | |
| A7 | Invalid UTF-8 name (`Work/\xff/x`) | addressable; display shows `\xff` | UNEXECUTED | |
| A8 | Duplicate raw names | both slots addressable by ID; no copy/mutation-by-guess | UNEXECUTED | |
| A9 | Open/list/search/copy leaves bytes unchanged | sha256 before == after | UNEXECUTED | |
| A10 | Write under P_A preserves all P_B records byte-for-byte | decrypted entry hashes unchanged | UNEXECUTED | |
| A11 | Codes cases C01–C09 discovery + decoding | matches `codes_cases` expectations | UNEXECUTED | |
| A12 | Clipboard cases K01–K05 | K03/K04 refused (`0x109`), nothing published | UNEXECUTED | |

## B. Security

Use synthetic secrets only. Check logs, persisted files, and UI automation surfaces for
accidental exposure after every row.

| # | Check | Expected | Status | Evidence |
|---|---|---|---|---|
| B1 | Threat model + data-flow reviewed against implementation | `docs/threat-model.md` matches code | UNEXECUTED | |
| B2 | IPC identity review (launch-bound pipes, birth descriptors, deny-ACE) | as documented; no named endpoint exists | UNEXECUTED | |
| B3 | Secure entry review (broker-owned console input; erasure) | no managed string ever created | UNEXECUTED | |
| B4 | Memory ownership review (zeroizing owners, redacted diagnostics) | no secret bytes in logs/dumps/errors | UNEXECUTED | |
| B5 | Clipboard exclusions + ownership cleanup review | exclusions precede secret format; foreign items never cleared | UNEXECUTED | |
| B6 | Writer ACL lifetime review (mutex DACL validated before writes) | effective permissions as designed | UNEXECUTED | |
| B7 | Unrelated same-user process cannot use the channel | no handle → no requests; observable refusal | UNEXECUTED | |
| B8 | Stale item ID / stale generation rejected before any sensitive op | `0x102`/`15` | UNEXECUTED | |
| B9 | Excessive KDF cost rejected before derivation/allocation | `8 ResourceLimit`, actionable message | UNEXECUTED | |
| B10 | Revoked/locked session cannot copy, code, or write | `0x101 WrongState`/`0x102` | UNEXECUTED | |
| B11 | Broker crash / channel loss → immediate lock; no resurrection by late completions | session dead; clipboard owned content cleared | UNEXECUTED | |
| B12 | Residual OS/input-control limitations recorded | limitations documented, not hidden | UNEXECUTED | |

## C. End to end on Windows

| # | Scenario | Expected | Status | Evidence |
|---|---|---|---|---|
| C1 | Locked startup (incl. launch-at-sign-in) | locked palette; no stale results flash | UNEXECUTED | |
| C2 | Passphrase unlock + retype confirmation | "No records unlocked with this passphrase" when that is all evidence supports | UNEXECUTED | |
| C3 | Enrolled Hello unlock (UV required) | capability released; store untouched on failure | UNEXECUTED | |
| C4 | Hello cancellation / unavailability | fail-disabled; passphrase fallback; no metadata leak | UNEXECUTED | |
| C5 | Multiple indistinguishable results | distinct breadcrumbs; no first-match copy | UNEXECUTED | |
| C6 | Enter-to-copy password (unambiguous target) | feedback, palette hides, focus restored | UNEXECUTED | |
| C7 | OTP rollover + invalid seed | 30→1 s countdown; "Code unavailable" for bad seed | UNEXECUTED | |
| C8 | Another app replaces clipboard content mid-TTL | cleanup never erases the foreign item | UNEXECUTED | |
| C9 | Manual / workstation / idle lock during search, copy, unlock | ordered invalidation; late results dropped | UNEXECUTED | |
| C10 | Hide/show without lost keystrokes | query and selection preserved | UNEXECUTED | |
| C11 | Broker loss mid-session | app locks visibly; no secrets in UI | UNEXECUTED | |
| C12 | Store replacement while unlocked | `15 Conflict`; stale results invalidated | UNEXECUTED | |
| C13 | Safe writes (create/update/renew/rename) incl. CAS conflict | commit semantics honored; other partitions preserved | UNEXECUTED | |
| C14 | Keyboard-only navigation, Narrator, high contrast, 100–200% scaling | usable; labels match actions | UNEXECUTED | |

## D. Delivery

| # | Check | Expected | Status | Evidence |
|---|---|---|---|---|
| D1 | Buildable sources from clean checkout | documented commands succeed | UNEXECUTED | |
| D2 | Signed or explicitly development-signed package builds | MSIX produced; Publisher `CN=WSecret` | UNEXECUTED | |
| D3 | Package/build/test instructions accurate | commands in `docs/build.md` match reality | UNEXECUTED | |
| D4 | Test/performance results carry their exact environments | this file + bench evidence complete | UNEXECUTED | |
| D5 | Unavailable hardware / unexecuted tests marked unverified | no silent gaps | UNEXECUTED | |

## Automated runs (filled by scripts/test.ps1)

| Command | Exit code | Result summary | Log |
|---|---|---|---|
| (none yet) | | | |

## Notes / deviations

(Record any deviation from the documented contract here; never paper over a failure.)
