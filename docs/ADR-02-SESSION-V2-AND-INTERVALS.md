# ADR-02 — live normalized sidecar and read-only SessionView

Status: implemented on PR #17, **not full BB-DI-001 acceptance**.

## Contract and API changes

Every new `ReadOnlyProbe.start()` now creates an exclusive `session-v2.sqlite3`
alongside its original schema1 compatibility database. It is a **live recording**,
not a migration or invented enrichment of a historical v1 file. Public CLI
`SessionStore` callers remain schema1 unless `enable_v2(context)` is requested.
`app.py`, five PySide6 pages and existing exports remain compatible.

`SessionV2Writer.submit(kind, DTO)` serializes an immutable finite message before
enqueue, with one 64-slot queue and one SQLite owner thread. Samples, quality,
TID and child rows in a message share one transaction. `finish()` closes
admission, drains accepted messages and checkpoints. Overflow/fault records
`STORAGE_ERROR`, the exact count of discarded **commands**, and a sensor error.
Commands are not synonymous with OS missed samples. The soft 256 MiB budget
counts DB/WAL/SHM; a single transaction can overshoot. It never deletes sessions.

Tables: `sessions`, `targets`, `process_instances`, `samples`, `thread_samples`,
`child_process_samples`, `windows`, `events`, `action_intervals`, `incidents`,
`measurements_quality`, `experiments`, `experiment_runs`, `artifacts`,
`sensor_errors`, `capabilities`. `PRAGMA user_version=2`,
`contract_version=bb-di-001/session/2.0`; schema is defined in `session_v2.DDL`.
Empty `windows`/`artifacts` tables do **not** implement native Windows sensors or
an artifact inventory. Experiment metadata remains UNSPECIFIED_SCENARIO until
a separate editing/compare workflow is implemented. Those requirements remain
partial/absent in the matrix.

Root/process identity is PID+creation time with a stable instance key. Child
history retains observed absence, **not exact death time**. Missing children in
denied/truncated enumeration do not acquire manufactured exit timestamps.
Root Standard, root Detailed and CHILD series remain distinct. A root's CPU
is never replaced by a tree sum. No shared-page-adjusted physical-tree-memory
claim is made.

`PsutilProbe.last_observation` carries cumulative user/system CPU, I/O ops and
actual monotonic capture brackets. A fresh Process birth check follows reads.
DetailedCapture mirrors successfully captured real thread/child observations
to the v2 owner; its old detail sidecar remains compatible. If a blocked sensor
outlives Stop, it is detached from the closing v2 queue, an explicit error is
recorded and its independent legacy worker stays owned until it finishes.

## Read-only API and trust

`with SessionView.open(folder) as view:` chooses `SchemaV2Reader` for the exact
new contract, otherwise `SchemaV1Reader`. It does not silently fall back from
a corrupt new contract. Connections use mode=ro, query_only, trusted_schema=OFF,
a 1 MiB SQLite value limit, a 4 MiB page-cache target, disk-backed temporary
sorting and a progress/cancellation deadline. One read transaction supplies a
consistent snapshot to all queries. No user file is migrated or rewritten.
Windows reparse paths, symlink ancestors, UNC and ADS paths are rejected.

Read APIs: `bounds`, `interval`, `thread_summary`, `process_page`, `event_page`.
`interval(start_ns,end_ns)` streams **all selected samples**, retaining bounded
statistics and first/min/max/last per track/bucket. Python memory does not grow
with total session length or all historic TIDs. SQLite window queries partition
TIDs into observed continuity segments, sort by **cumulative** valid CPU and
return Top-N with omitted count/CPU and observed snapshot-presence fraction.
SQLite temporary files can grow with queried TID churn; the query has a deadline,
but this is not a demonstrated hard total temporary-disk quota.

No range is limited to a recent tail. New v2 has indexed interval queries.
Historical v1 cannot receive an index without mutation: its reads stream a
scan, so indexed v2 latency guarantees must **not** be claimed for v1.

CPU% = 100*(delta user+delta system)/actual monotonic seconds, allowing >100%.
Rates require consecutive, increasing snapshots without counter reset or an
excessive spacing gap. Selection boundary pairs are excluded, not prorated.
NULL means missing, measured 0 remains 0. A gap creates a new plot segment;
no line joins through it. Whole-interval stats do not use plotted buckets.
The observer's exact count of OS missed samples remains NULL. Expected slots
between samples are explicitly an estimate, including sampling jitter.

All reopened files have `file_trust=UNVERIFIED_IMPORT`. Original producer source
and verification stay available separately. In particular user event strings
cannot promote a marker to a WIN32/OS fact; live event classification is chosen
by the producer kind, and imported events always cross the reader trust boundary.

## UI / export

Reports now starts with a human interval summary and a peak-preserving nine-track
timeline. Wheel/+/- zoom, drag A/B selection, middle/right pan, arrow keys, Home
reset query the selected range on a cancellable QThread. The Processes page
shows persisted instance history and cumulative TID stats for that range;
selecting a child never rebinds the root recording. Events has cursor-based
pages and selection navigates to the timeline. Saved sessions open read-only.
Legacy raw JSON is behind an explicit checkbox. There are still five pages.

The privacy dialog selects identifiers, notes and optional ZIP (all off by
default). `export_interval` streams the **full** selected CSV and paged events,
with schema2 summary JSON, offline escaped HTML/SVG and checksum manifest.
Only its generated files enter ZIP; no arbitrary paths/databases/dumps/traces.
Publication uses exclusive hard links; rollback checks stage inode ownership.
Previous SQLite/HTML/JSON files remain untouched on repeated analysis.

## Evidence and known gaps

`python -m unittest discover -s tests -p 'test_bbdi_schema2_sessions.py' -v`
tests real producer integration, v1 SHA invariance, atomic rollback, overflow,
100 child identities/PID reuse in a **test-only** DTO fixture, TID churn and
cumulative ranking, concurrent exporters, 6000-row CSV/ZIP checksums, Qt zoom,
and an accelerated **100001-row test-only history** (early minute + complete
stats/peak + tracemalloc bound). This is **not** real 8h/1h endurance, real 100
OS children, Windows physical QA, WCT/ETW or full order acceptance.

Remaining: synchronous primary journal command acknowledgements and finish,
startup psutil/SQLite on Qt, no hard cancellation of stalled OS/filesystem calls,
no HWND/WCT/ETW implementation, full capability adapters, saved experiment
metadata/resource compare, all trigger types, incident investigation cards,
local indexed session library, real endurance/observer benchmarks and complete
frozen/native Windows acceptance. Keep Draft. No merge or release.
