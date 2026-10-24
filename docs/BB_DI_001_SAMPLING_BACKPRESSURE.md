# BB-DI-001 — GUI timer backpressure observation (WIP)

**Scope:** bounded detection of *delivered Qt timer callbacks* that cannot launch a
base sampler because the previous `BaseSampleWorker` is still outstanding.
This is **not** a Windows OS sample-gap detector and cannot detect Qt's
coalesced/undelivered callbacks.

## Source semantics and persistence

The production Qt timer uses one sampler worker without an unbounded queue.
When it fires while the sampler is in-flight, `BusyTickTracker` records the
actual monotonic callback time, configured interval and a saturated counter
(max 1,000,000 callbacks per episode). It does **not** create fake process
samples or fill missing data with CPU/RSS zero. Once the worker finishes,
`UniversalWindow` drains the episode into one SQLite event:

- `kind=sampling_gap`, `code=BASE_TIMER_CALLBACK_SKIPPED_BUSY`
- `source=QT_TIMER_SCHEDULER`
- `verification_class=OBSERVED_GUI_CALLBACK_ONLY`
- `missed_callback_count`, first/last callback `monotonic_ns`, selected
  interval (null if changed during the episode), clock-quality/truncation flag
- `limitations=QT_COALESCED_CALLBACKS_NOT_COUNTED`,
  `root_cause_proven=false`

The event is durability-acknowledged through the existing background SQLite
journal before stopping the session or rendering a report. If event
persistence fails, the UI recording ends as `STORAGE_ERROR`, **not**
`COMPLETED`. A window close during an outstanding sample also waits for
the sample and its callback-loss evidence before finalization.

## Report and live state

`summarize()` reads these records as distinct from already existing
`SAMPLING_GAP_OBSERVED` incident records. JSON and offline bilingual HTML
show `observed_busy_timer_callbacks`, `observed_busy_timer_episodes`,
invalid imported records and saturation warnings. Malformed/untrusted
counts do not inflate metrics; files remain unauthenticated stored evidence.

`ReadOnlyProbe.snapshot()` carries the same per-session counters for the
live UI state. They reset on a new target/recording. An actual OS sample
interval may be much longer because system scheduling, a blocked Qt event loop
or a slow filesystem prevented *timer callbacks from being delivered*.
These cases remain **unobserved by this mechanism**.

## Regression limits

`tests/test_bbdi_sampling_health.py` verifies bounded aggregation,
callback-clock reversal, interval change, real blocked-worker Qt callbacks,
durable one-event summaries, delayed Stop behavior, storage-error fail-closed
finalization, and validation of malformed imported counts.

Outstanding: accurate OS sample interval gap contract, explicit missed-tick
telemetry from actual monotonic sampling deadlines, GUI display of queue
health, full 8-hour/1-hour stress tests, robust Windows sensor deadlines,
schema2/full SessionView and frozen Windows BB-DI-001 end-to-end scenario.

**Acceptance:** M-027 / M-066 and related health controls remain **PARTIAL**.
Keep PR #17 Draft, no main merge or release.
