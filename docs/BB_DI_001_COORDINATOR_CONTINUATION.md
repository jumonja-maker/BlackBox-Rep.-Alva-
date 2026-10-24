# BB-DI-001 — continuation in PR #17

Base: `4e048becf8382b2296fb8a9fd72d195e8ced66c4`, normalized contract 2.1.
The base Windows job timed out in its 200% DPI capture; its 254 unit tests and
Python deep scenario were successful, but logged Qt callback exceptions.
The current base was **not** a verified portable build.

## Owner and public API

The production `app.py` creates `UniversalWindow(isolated=True)`. A QProcess
starts the same source/frozen executable with a fixed bounded JSONL protocol.
The helper owns attach/start, primary SQLite, durable action acknowledgements,
sampling, journal drain, stop and report generation. No connection created in
Qt is handed to another thread. A command acknowledgement follows completion;
an unacknowledged command is never presented as committed. Compatibility
`UniversalWindow()` / `ReadOnlyProbe` still support synchronous embedders.
The public app explicitly preserves its normal update preference; library and
QA constructors do not schedule network checks implicitly.

The implementation reuses the reviewed research work on PR #18, adapted to
the current PR #17 contract and 2–20-repeat requirement. PR #18 and main are not
modified. Source evidence links into normalized 2.1; legacy databases remain
read-only. Cooperative events preserve their own clocks and are never OS
attestation. WindowCapture remains the sole continuous HWND/WCT collector;
explicit snapshots do not start a second periodic collector.

The close deadline remains armed after a quit acknowledgement until the owned
process actually exits. This matters for non-daemon native cleanup. A forced
helper termination retains committed data as incomplete; it never terminates
the observed application. Complete optional native-resource cleanup and all
long endurance conditions still need their own evidence.

## QA and evidence corrections

The selected HWND no longer overwrites the boolean process-selected state.
Qt callback exceptions fail the isolated GUI tests. DPI capture disables
scheduled update checks, records the current page and has an external timeout;
diagnostics are uploaded even if capture fails. Installed Segoe UI Symbol is
registered only in the Windows offscreen process, and shaped chrome glyphs are
checked in addition to Latin/Cyrillic. No fonts are downloaded or redistributed.

`workflow_event_sha` is the event merge ref. `actual_source_sha` is read from
the actual source checkout, or a frozen build manifest generated from that
checkout. A pinned QA run fails on a mismatched/dirty source identity. No Git
or Python installation is required at the frozen destination.

## Acceptance boundary

This closes concrete paths in M-027/M-058/M-066/M-071 and source integration
for M-020. It does not certify the full original 128-item order. Sensor registry,
all incident policies, resource experiments/history, ETW TTL/budget/recovery,
8h/1h endurance, physical Windows and observer benchmarking remain explicit
work, not inferred from a green unit suite. Update the normative evidence
ledger only against the exact published candidate and its actual CI.

## Disposable optional operations and sensor contract

The next continuation keeps the primary recording connection in its owner.
Native snapshots, DbgHelp, CDB, preparation, indexed reads, verification,
recovery and ZIP creation now execute in one disposable operation process at a
time. Admission is bounded to eight; command IDs remain pending until an actual
result/error. A start failure retains the ID. Results are bounded to 4 MiB.
Target-sensitive operations recheck PID/birth before and after collection and
again before the owner commits evidence. No observed process is terminated.

Windows uses a private Job Object with KILL_ON_JOB_CLOSE and a launch barrier
before optional tools can start; cancellation/deadline kills only the owned
operation tree. The frozen EXE invokes itself. Linux uses an owned process
group. A cancelled export is explicitly unconfirmed, not a fictional success;
a hard interruption can leave unpublished staging material on disk. Final
staging recovery/cleanup remains work. Base samples continue while an optional
process is delayed; the regression measures actual committed sample rows.

The fixed Sensor protocol has capabilities/start/sample(deadline)/stop/health.
The registry reports errors, consecutive failures, bounded exponential backoff,
cooperative overruns and heartbeat ages. It adapts the existing base collector
and detailed/window owners rather than starting duplicate samplers. Health-read
and actual producer heartbeat are separate fields. A cooperative Python budget
is not presented as a hard syscall timeout.

## Multi-signal incident windows

Opt-in incident capture adds RSS/private/handle growth and paired-counter I/O
throughput. Actual sample times, counter resets/gaps, missing values and source
references are retained. Private/handle signals require a fresh committed detail
DTO. CPU and growth windows have rearm/cooldown/session limits. Exit is observed
exit, not a proven crash. Post-context stopped by exit/end is explicitly partial.
Incident windows reference base, normalized detail/threads/children and native
events; complete human-readable cross-source cards and all policy UI remain
outstanding. No ETW or dump starts from these triggers.

## WPR guardian

An explicit user command starts a separate WPR guardian with a private random
instance, circular memory recording, a 1–60 second TTL (UI: 30 seconds), stdin
ownership lease, journal and SHA-256 of output/tool. EOF after a recorder crash
requests only this instance's stop. It never calls global stop/cancel. The size
policy is checked after the memory-mode flush; it is **not a hard disk quota**.
Failed cleanup is CLEANUP_REQUIRED with retained journal; automatic recovery of
all historical orphan journals remains outstanding. Sensitive export refuses a
journal that is still recording. The CI scenario explicitly exercises actual
WPR TTL on its disposable Windows runner. Availability, raw ETL creation and
independent provider-content acceptance are distinct.

## Visual evidence correction

The 2c4b46c Windows font coverage test passed, but downloaded actual DPI PNGs
still exposed missing symbol boxes in bold buttons. This was not accepted as
legibility proof. Chrome action icons now use original QIconEngine vectors;
translation keeps stable English keys, while text no longer depends on a symbol
font. Actual pixel tests and new exact-head DPI captures verify this change.

## Verification boundary

2c4b46c: CI 40064589234 completed Windows, Linux and portable/frozen paths;
release skipped. This success belongs only to that SHA. New continuation checks
must run on their own head. Local unmodified full suite cannot select its own
PID in this executor's mismatched /proc namespace. An external QA-only
sitecustomize translates self PID to /proc/self/status; it is not product code
or a hosted-CI modification. Counter values/times remain actual OS observations.
The unmodified Windows/Linux CI remains authoritative for normal PID semantics.
The original 128-item acceptance ledger is not reduced by this continuation.

## Resource experiments and privacy of share copies

Completed action intervals now have separate CPU-time, RSS/private peaks and
changes, handle peaks/changes, observed I/O deltas and native timeout-episode
counts. Standard and Detailed are never added together. Only valid adjacent
counter pairs inside the actual action bounds are integrated; resets, gaps,
missing fields and missing boundary coverage are explicit. A short action may
have no resource pair. Quantiles use a small temporary indexed SQLite store;
preview is capped to 20 runs, all runs contribute to statistics. Warmups and
small-N warnings remain explicit. Comparison includes absolute/percentage
median changes; a zero reference cannot produce an invented percentage.
Reports exposes a bilingual human summary with opt-in technical JSON. Full
experiment history/catalog and all acceptance metadata UI remain unfinished.

Default ZIP creation now redacts **copies** of known JSON columns and derives
HTML/JSON/CSV from those same copies. Raw application attributes, debugger
previews, known internal full paths and recognizable paths/URLs are omitted.
Secure-delete plus VACUUM prevents the copied SQLite pages from retaining the
removed payload. The original databases/hashes remain unchanged. Explicit
sensitive export retains original fields; the UI label describes this scope.
The manifest declares the privacy transformation and that arbitrary secrets
hidden in other free text cannot be universally detected. A redacted package
is never marked a complete original package.

A continuation audit found that the isolated owner's synchronous sampling path
had bypassed the earlier monotonic-cadence tracker. Production now calls its
existing durable cadence acceptance path and preserves an absolute sampling
schedule without catch-up bursts. This does not invent Qt signal-delivery
measurements or lost OS sample counts. A real delayed owner regression verifies
the persisted extended-spacing event with missing_sample_count=NULL.

## Evidence obtained during continuation

- 2b6a7a3: unmodified Windows suite 332 total, 329 PASS / 3 platform SKIP;
  Linux and source E2E passed. Actual WPR guardian TTL created a 9,437,184-byte
  ETL, stopped with TTL_EXPIRED and recorded SHA-256
  `6d2732c15a2697cd79d7a582836c3df6fa890ea5c8240464fe4b0b84a6e05d16`.
  Event loss remains unknown; provider payloads were not independently decoded.
- WPR artifact 12549521847 archive digest:
  `c541ef16e4690af1b0059e149bc2ebf71ae923bac3027f8b828ca3a159603796`.
- Actual vector-icon DPI images reviewed from artifact 12549447429, digest
  `110dae96e03f1e645ce747cbeb9a63eb24d0627bf0e6bcc7d24e870c6d8136a1`.
  The earlier missing action-icon boxes are resolved in that capture.
- Resource/export/privacy/cadence additions require the next exact-head CI;
  preceding green checks are not their acceptance evidence.

Original order remains WIP: no claim of 8h/1h endurance, 300/100 native scale,
complete source coverage, physical Windows acceptance or full 128-item closure.
