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
