# Quick Access — performance evidence

> Fill one copy per run into `evidence/` (git-ignored), produced by `scripts/bench.ps1`
> where possible. Budgets are preregistered in `fixtures/quick-access/bench-budgets.json`.
> **No measurement row may be filled without an actual run**; unmeasured rows stay
> `UNEXECUTED`. Report percentiles, sample count, hardware, build, and baseline for every
> executed row. Packaged Release build, AC power, no debugger.

## Environment

| Field | Value |
|---|---|
| Date (UTC) | UNEXECUTED |
| Reference machine (model) | UNEXECUTED |
| CPU / RAM | UNEXECUTED |
| OS edition/build | UNEXECUTED |
| Architecture (x64/ARM64 — native execution?) | UNEXECUTED |
| Build configuration & git revision | UNEXECUTED |
| Store corpus (manifest recipe / record count / sha256) | UNEXECUTED |
| Power state / debugger | AC / none |
| Baseline (build compared against) | UNEXECUTED |

## Measurements

Separate cold launch, unlock/KDF, and warm summon. Protective settings stay enabled.

| ID | Measurement | Samples | p50 | p95 | p99 | min | max | Budget | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| warm-summon | Warm hotkey → first keystroke accepted (typed char present) | UNEXECUTED | | | | | | p95 ≤ 100 ms (≥100 samples) | UNEXECUTED |
| keystroke-results | Keystroke → correct results painted (10 000 names, post-index) | UNEXECUTED | | | | | | p95 ≤ 50 ms | UNEXECUTED |
| cold-launch | Cold launch → first paint (locked) | UNEXECUTED | | | | | | record | UNEXECUTED |
| unlock-index | Passphrase unlock + names-only index (ops_limit 100 000) | UNEXECUTED | | | | | | record | UNEXECUTED |
| secure-copy | Copy gesture → clipboard published (incl. exclusions) | UNEXECUTED | | | | | | record | UNEXECUTED |
| lock-invalidate | Lock → full invalidation (IDs/index/clipboard) | UNEXECUTED | | | | | | record | UNEXECUTED |

## Steady state (idle-steady, 60 s window)

| Metric | Hidden/locked | Unlocked (watchdog active) | Notes |
|---|---|---|---|
| Periodic UI/search/OTP polling | UNEXECUTED | UNEXECUTED | must be *none* in the hidden/locked column |
| Idle CPU (%) | UNEXECUTED | UNEXECUTED | measured separately per column |
| UI process private bytes (MiB) | UNEXECUTED | UNEXECUTED | |
| Broker process private bytes (MiB) | UNEXECUTED | UNEXECUTED | |
| Wakeups / minute | UNEXECUTED | UNEXECUTED | core residency watchdog accounted for while unlocked |

## Harness provenance

| Measurement | Harness command | Stdout parse | Log |
|---|---|---|---|
| (rows run by scripts/bench.ps1 are recorded here) | | | |

## Notes / deviations

(Budget misses, machine noise, harness gaps, or methodology changes go here — never
silently adjust a budget after seeing data.)
