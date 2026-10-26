# BB-DI-001 — persisted monotonic sample cadence and worker timing (WIP)

This incremental slice captures **real elapsed time between accepted external
counter snapshots**, using the same `PsutilProbe.start` monotonic origin in
schema1 `samples.elapsed_ms`. It cannot prove the number of missed OS
observations, scheduling cause, a GUI hang, or a target-process hang.

## Contract

- The Qt sampler retains the user-selected interval **at worker creation**.
  After the worker's existing SQLite commit, the Qt owner compares its new
  monotonic `Sample.elapsed_ms` with the previous accepted snapshot.
- The comparison is only valid for adjacent accepted snapshots at an
  **unchanged requested interval**. First snapshots and interval-change
  boundaries are not called gaps. A backward clock or invalid interval fails
  closed and must not update the in-memory baseline.
- When actual spacing is greater than
  `max(2 * configured_interval_ms, configured_interval_ms + 500)`, a
  size-bounded `sampling_gap / EXTENDED_MONOTONIC_SAMPLE_SPACING` event is
  committed **before** the new observation is presented as accepted.
  It stores the two actual millisecond timestamps, their delta, requested
  interval, threshold, and explicit `missing_sample_count = null`.
  Source is `BLACKBOX_MONOTONIC_SAMPLE_CLOCK`, classification is
  `DERIVED_ADJACENT_OS_COUNTER_SNAPSHOTS` and root cause remains unknown.
- The older `BASE_TIMER_CALLBACK_SKIPPED_BUSY` event counts *delivered Qt
  callbacks while the worker was busy*. These two observations are
  independent; one is never treated as a substitute for the other. Qt
  coalesced callbacks remain unknowable from the busy-callback counter.
- The same worker records three nanosecond monotonic brackets: start of
  `psutil`, end of `psutil` (before SQLite), and end of SQLite transaction.
  The Qt receiver timestamps actual signal handling. After sequence and
  clock validation, the UI accumulates max **sensor time**, **SQLite time**
  and **signal delivery time** (floor milliseconds) plus the number of
  successfully delivered worker results.
- Normal Stop writes one `worker_health /
  BASE_SAMPLE_WORKER_TIMING_SUMMARY` event before session metadata closure.
  It includes completed workers, maxima, compared pairs, extended intervals,
  interval changes and maximum observed spacing. Failure to commit this
  summary cannot yield a `COMPLETED` session. A process crash/forced exit
  can prevent this final summary; do not infer zero performance cost.

The original session SQLite **schema1 is unchanged**; all information is
additional bounded JSON in the existing `events` table. GUI periodic
sampling uses Qt workers; old direct `ReadOnlyProbe.tick()` is a separate,
synchronous compatibility API and is not covered by worker-bracket telemetry.

## Report and trust

Read-only report extraction validates source names, timestamps, thresholds
and basic counter bounds. Malformed imported gap or worker-health data are
listed as invalid, not added to valid counts. JSON and static bilingual HTML
distinguish real sample-spacing anomalies, observed skipped GUI callbacks,
and unverified stored worker timing summaries.

All displayed values are from locally stored files without a cryptographic
signature. They are not independent OS attestation, WCT/ETW evidence, or a
causal explanation for the target's responsiveness.

## Tests and limits

`tests/test_bbdi_monotonic_cadence.py` covers first-pair baselines,
unchanged intervals, user interval changes, clock rollback, exact
real elapsed spacing, failed persistence without baseline advancement,
schema1 roundtrip, malformed imported records, monotonic worker-bracket
validation and actual Qt worker execution while the synchronous GUI tick
API is forbidden.

**Still required:** strict per-request OS timeouts, cancellation and
bounded stop/report deadlines, all-event async UI acknowledgements, full
session schema2 and V1 read-only V2 SessionView, program-level evidence of
HWND/WCT, 8-hour/1-hour performance and 12 Windows fixtures, complete frozen
EXE vertical E2E, and 128 requirement acceptance proofs. M-027/M-066 and
interval requirements remain PARTIAL; Draft PR #17 must not be merged or
released based on this slice.
