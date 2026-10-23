# BB-DI-001 — asynchronous schema1 base sampler vertical slice (WIP)

This document describes an incremental production Qt change, **not** the complete
schema2 producer/writer architecture or acceptance of M-027 / M-066.

## Production path

The existing five-page `UniversalWindow` now connects its ordinary 1/2/5
second Qt timer to `_request_background_sample`, not to synchronous
`ReadOnlyProbe.tick()`. The timer launches at most one
`BaseSampleWorker(QThread)` job. While it remains outstanding, subsequent
timer ticks do not enqueue more work. This is deliberate bounded backpressure,
but does not yet include a user-facing dropped-tick counter.

Inside the worker:

1. `PsutilProbe.sample()` observes the bound PID/creation-time instance through
   external, read-only psutil calls.
2. `write_sample_from_worker()` opens a **separate worker-owned SQLite
   connection** to the existing session's `session.sqlite3` with `mode=rw`
   (not `mode=rwc`), verifies the schema1 row and `exit_code IS NULL`,
   obtains the next sample sequence inside `BEGIN IMMEDIATE`, inserts one
   real sample, commits, and closes the connection on every code path.
3. The worker signals the committed Sample and sequence back to the Qt owner;
   it does **not** modify Qt controls, action state, incident state or
   `ReadOnlyProbe.history`.

On the Qt thread, `accept_background_sample` updates the existing
`ActionCycle`, incident boundary observations, GUI cache and the session's
sample sequence *after* the worker commit. User commands still write via the
original `SessionStore` connection on the Qt thread, so old action and marker
semantics, ordered durable event writes and schema1 remain intact. The
**periodic sample** uses its own worker-owned connection; it cannot proceed
when a completed session has `exit_code` set.

`ReadOnlyProbe.tick()` remains the synchronous non-Qt compatibility API for
CLI and explicit legacy callers/tests. **It is not connected to the Qt timer**.

## Lifecycle and failure semantics

Stop during an outstanding worker merely records the pending reason and
disables user controls. The Qt event loop does not `wait()`/`join()` for
psutil. The in-flight worker is never discarded until its
`finished` signal; only then does the owner finalize the SQLite session and
render reports. The window-close path similarly defers destruction of the
Qt window and store until completion. A failed worker persists an explicit
`observer_error` event and completes the recording with a matching failure
status instead of making a false claim of `COMPLETED`.

A blocking OS call may still block the dedicated worker indefinitely.
This slice prevents GUI-thread blocking and unsafe store finalization but
**does not guarantee forced cancellation, fixed shutdown latency, lost-tick
evidence, full backpressure visibility or a bounded local disk quota**.

GUI-originated event writes, synchronous attach/start and report building
remain on the GUI thread. Therefore it is **not correct** to claim that all
SQLite IO has been moved off Qt, or that WCT/ETW/complete v2 contracts have
been delivered. A final queue-owned session worker is still required.

## Evidence and limits

`tests/test_bbdi_base_worker.py` checks genuine schema1 independent
connection writes, real SQLite event compatibility, no reopen of finalized
sessions, one-worker limit, GUI responsiveness while injected sensor blocks,
deferred Stop and UI close, and correct failure status/audit event. These are
deterministic local regression fixtures, **not** an 8-hour recording or
Windows native responsiveness test.

Acceptance status: M-027 / M-066 **PARTIAL**, plus M-033 / M-034
remaining **PARTIAL**. Keep PR #17 Draft; never merge or release based on
this incremental slice alone.
