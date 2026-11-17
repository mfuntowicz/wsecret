# Pending work (not done in this crate yet)

Scope of this crate is currently raw `extern "C"` declarations plus the pinned
vendored C sources and their build glue. The following milestones are explicitly
NOT implemented here and remain pending:

1. ~~**`wsecret_totp.c` verbatim excerpt from `secret.c`**~~ — **SUPERSEDED by
   user decision (2026-11-17)**: TOTP is reimplemented in Rust in
   `wsecret-core/src/totp.rs` (behavior port of upstream's hand-rolled
   SHA-1/HMAC + base32 decoder, with the full upstream quirk matrix as
   acceptance tests). The earlier C excerpt was removed from the workspace;
   this crate now vendors only libhydrogen itself.

2. ~~**Safe Rust wrappers**~~ — **DONE (2026-11-17)**: `src/safe.rs` provides
   the §3.3 surface (`init`, `pwhash_deterministic`, `secretbox_encrypt`,
   `secretbox_decrypt`, `random_buf`, `memzero`, `equal`, `hash`, plus
   `CTX_MASTER`/`CTX_SECRET`/`CTX_PASSWD` and the entry-size constants). The
   raw `extern "C"` declarations are private to the crate; `pub use safe::*;`
   is the public API. Documented quirk: upstream `hydro_equal` returns false
   for identical pointers; the wrapper special-cases that alias-only case
   (verified upstream call sites never rely on it). No zeroization-on-drop
   wrapper types or error mapping (handled in `wsecret-core` per §3.4).

3. **`wsecret-core` crate** — the reusable Rust library implementing the store
   format, record operations, passphrase handling, deterministic secrets, and
   TOTP (porting the behavior of upstream `secret.c`) is not present.

4. **`wsecret-cli` crate** — the terminal/CLI front end (commands `init`,
   `list`, `show`, `dump`, `new`, `set`, `renew`, `update`, `pass`, `agent`,
   `version`) is not present.

5. **Reference-oracle compatibility checks** — the bidirectional
   Linux/macOS-origin and Windows-origin fixture tests against upstream's
   output are planned but not executed.
   - **DONE subset (2026-11-17): pinned libhydrogen KATs (plan §7.2/§7.5 K1)** —
     upstream `tests/tests.c` (commit `6c58976b…`) is vendored at
     `vendor/tests/tests.c` and built by `build.rs` into the standalone
     `hydrogen_tests.exe` binary; `tests/kat.rs` runs it and passed on Win11
     x64 (debug + release). Covers `hydro_hash_hash`, `hydro_kdf_derive_from_key`,
     `hydro_secretbox`, `hydro_pwhash_deterministic`, `hydro_random_buf_deterministic`,
     `hydro_sign`, `hydro_kx` (N/KK/XX/NK), and core utilities. RFC 4226 HOTP
     KATs (K2) are the `wsecret-core` TOTP tests and remain tracked in that
     crate.

6. **ARM64 verification** — no `aarch64-pc-windows-msvc` **execution** evidence
   has been gathered; only the host `x86_64-pc-windows-msvc` target has been
   built and tested here. See the "ARM64 cross-compile (build-only evidence)"
   section below for what *has* been established.

## ARM64 cross-compile (build-only evidence)

**BUILD-ONLY EVIDENCE — NOT RUNTIME PROOF.** No native ARM64 execution has
occurred; no ARM64 binary was run anywhere (and none was run on the x64 host —
emulation would not be runtime proof). R1 (native ARM64 test execution)
requires a Win11 ARM64 host/runner and remains **pending**.

- **Date:** 2026-11-17
- **Host:** Windows 11 x64 (`x86_64-pc-windows-msvc`)
- **Command:** `cargo build --workspace --target aarch64-pc-windows-msvc --release`
- **Outcome:** **SUCCESS** — `Finished release [optimized] target(s)`; no
  errors. Revalidated after the P4 process-protection changes on the same
  date/host. All workspace crates compiled: `libhydrogen-sys` (including the
  pinned libhydrogen C via `cc`/MSVC), `wsecret-core`, `wsecret-cli`
  (`wsecret.exe`). Examples were not built (`cargo build` builds libs/bins
  only).
- **KAT build-script marker** (`build/libhydrogen-sys/*/out/kat_exe_path.txt`):
  `skip TARGET (aarch64-pc-windows-msvc) != HOST (x86_64-pc-windows-msvc); KAT
  binary not built` — confirms the expected cross-compile skip path was taken.
- **Toolchain:** rustc 1.100.0 (0ef1bc386 2026-11-09), cargo 1.100.0
  (3acc79c0c 2026-11-05); Rust target `aarch64-pc-windows-msvc`
  (rust-std, added 2026-11-17); MSVC 14.44.35207 (VS 2022 Community);
  Windows SDK 10.0.26100.0 / 10.0.28000.0 (ARM64 libs present).
- **Binary check:** `target/aarch64-pc-windows-msvc/release/wsecret.exe` PE
  header machine field reads `0xAA64` (ARM64) — verified genuinely
  cross-compiled, not a host artifact.
- **Expected cross-compile warning (by design):**
  `TARGET (aarch64-pc-windows-msvc) != HOST (x86_64-pc-windows-msvc); the
  libhydrogen KAT binary is not built and the KAT test is skipped` —
  `build.rs` skips the KAT executable under cross-compilation since it cannot
  run on this host. The `hydrogen` static library itself was compiled for the
  ARM64 target as usual.
- **Remaining proof gap:** R1 native ARM64 execution of the build outputs and
  the KAT/tests on a Win11 ARM64 host or CI runner.

## P4 same-user process protection (Windows 11 x64 evidence)

- **Date/host:** 2026-11-17, native `x86_64-pc-windows-msvc`.
- **Implementation:** `wsecret-core/src/windows/security.rs` owns the exact
  process/thread deny DACLs, `OWNER_RIGHTS`, startup enumeration, hardened
  suspended-thread creation, host-thread registration, unlock admission,
  250 ms residency polling, operation/acquisition drain, watchdog erasure,
  and independent heartbeat monitor. `session.rs` keeps the at-rest key in a
  watchdog-erased mutex slot and transient plaintext in guarded secure
  buffers. `agent_bridge.rs` supplies and verifies both birth descriptors,
  reduces the retained child handle, and closes the full-access originals.
  The CLI hardens before argument dispatch/store access/prompting.
- **Acceptance command:** `cargo test -p wsecret-cli --test p4` (custom
  process-isolated harness; test-only hooks require `fault-injection`).
- **Passed:** P4a individual process/thread right denial; P4b explicit
  `WRITE_DAC` denial plus no-`OWNER_RIGHTS` success/DACL-update control;
  P4d child+primary-thread birth denial from the launcher and an external
  helper; P4e external-launcher retained-handle duplication; P4f worker,
  unhardened-operation, pre-unlock admission, bounded residency poisoning,
  drain/auto-lock, watchdog `THREAD_TERMINATE` denial, watchdog-death
  `ExitProcess` while the main thread is in a long KDF, registered-host
  stability, and overlapping-unlock rejection; P4g real-CLI fatal startup
  before store/prompt/KDF; P4h immediate and external handle-table checks
  (originals absent, reduced handle present with limited rights, no access
  amplification); P4i idle ciphertext; P4j plaintext observed only in the
  deliberate operation window and absent afterward.
- **P4c prerequisite not met:** the available token is not elevated with
  `SeDebugPrivilege`. The harness exits with an explicit prerequisite status;
  the privileged positive and elevated-without-debug negative controls were
  NOT executed and remain pending an elevated runner.
- **Probe-shape limits:** P4d uses the coordinated `CreateProcessW` return as
  the birth observation plus an immediate external helper, not a WMI/ETW
  process-creation subscription. P4e uses an unhardened native external
  launcher with a known retained child handle, not literal `cmd /c`; the OS
  handle-duplication path and documented residual are the same.
- **Regression evidence:** core 93/93, CLI unit 140/140, crosscheck 15/15,
  malformed-store 17/17, all on x64. No ARM64 runtime claim is made.

## Concurrent writers and crash model (Windows 11 x64 evidence)

- **Suites:** commit-state 10/10, concurrent-writers 7/7, crash-consistency
  11/11, residency R2-A 2/2. The full workspace run also includes the P4,
  compatibility, malformed-store, KAT, and unit suites.
- **CLI critical-section fix:** `Store::lock_writers_scoped` provides RAII
  release; `new`/`set`/`renew`/`update` now hold the named writer mutex across
  `find` + mutation, including prompt/generation early returns. Regression
  `cli_set_holds_writer_mutex_across_prompt_and_write` proves a second CLI
  writer receives `Unable to lock …` while the first is between scan and
  commit, and does not write its record.
- **E6 filesystem matrix:** `fixtures/e6-filesystem-matrix.json` records
  executed NTFS rows (C:, D:, E:, F:, G:). ReFS/FAT32/exFAT/SMB rows are
  explicitly NO EVIDENCE because those volumes/shares were unavailable.
  Process-kill write-back visibility is not a power-loss durability claim.
- **Protocol interpretation:** tests follow the authoritative §5.6 in-place
  slot-write model: torn slots are skipped, append suffixes are read-tolerated
  but mutation-rejected, partial init is unreadable, and no temporary file is
  created. The withdrawn atomic-replace wording is not used as an assertion.
