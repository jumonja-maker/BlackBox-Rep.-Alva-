# BB-DI-001 — bounded background event writer for schema1 (WIP)

> Historical checkpoint. Current live normalized v2/native implementation and limitations: ADR-01..04, BB_DI_001_IMPLEMENTATION_STATUS.md and BB_DI_001_QA_20261024.md.
**Scope:** current Windows GUI sessions only. The existing independent schema1
`session.sqlite3` is unchanged. This improves M-027 and M-066 but does **not**
complete the required single-owner schema2 architecture.

## Ownership and event ordering

`UniversalWindow` constructs `ReadOnlyProbe(background_events=True)`.
After `SessionStore` creates a fresh schema1 database, a session-owned
`BoundedEventJournal` starts one Python thread and opens an independent
SQLite connection with `mode=rw`, never create-if-missing.
The bounded FIFO queue has a maximum of **64 pending tasks**; excess
noncritical lifecycle entries fail explicitly with `STORAGE_ERROR`
rather than silently dropping or fabricating a persisted event.

All **SQLite INSERTs into the events table** for a GUI recording execute on
this worker, not inside Qt callbacks. Event record validation and size limits
stay in `contracts.bounded`.

- **Lifecycle events** use nonblocking enqueue; their queue position is
  accepted, not falsely claimed to be disk-durable at enqueue.
- **User problem markers, action transitions and incident boundaries** wait
  for the worker's successful commit acknowledgement before returning. This
  is deliberate: `ActionCycle` must not advance if a marker failed to save.
- FIFO order is preserved between buffered lifecycle messages and durable
  user commands. Each INSERT is an individual committed SQLite transaction.
  `SessionStore.finish()` first enqueues and awaits an ordered flush
  barrier, then marks the session ended; `close()` retires the writer thread
  before destroying the session store.
- The worker verifies schema version and active `exit_code IS NULL` before
  every insert. A SQLite or unexpected Python error rolls back and fails
  closed; pending acknowledged commands wake with an error, never success.

The existing `ReadOnlyProbe()` API defaults to synchronous event storage for
CLI, independent core callers and older tests. The production GUI activates
the journal explicitly; no schema migration is performed.

## What remains blocking / not proven

This is **not** an entirely asynchronous user interface: user actions wait
for the durable event acknowledgement, and stop/close wait for FIFO drain;
rare blocked OS disk calls may still stall the GUI. Starting the session,
updating exit metadata, report generation and synchronous legacy sample
`tick()` are also not offloaded. The periodic Qt timer has already been
changed separately to use `BaseSampleWorker` with an independent DB
connection and one-at-a-time backpressure. Queue depth is advisory and is
not yet exposed in the UI; there is no durable dropped-tick record or hard
disk budget. This implementation cannot forcibly cancel a stuck filesystem
operation without risking a later ghost event.

The next mandatory phase is an owner-managed, fully asynchronous session
writer with explicit callback acknowledgements and bounded stop
deadlines, integrated schema2 semantics, and full Windows frozen E2E and
long-duration acceptance. All M-027/M-066 stay **PARTIAL**.

## Regression evidence

`tests/test_bbdi_event_journal.py` verifies FIFO ordering, worker-owned
thread IDs for actual INSERTs, commit-before-action semantics, finite queue
overload behavior, non-acknowledgement on unexpected writer failure,
original schema1 behavior when opt-in is absent, and real Qt-session
action/problem-marker compatibility. CI must be matched to the exact
PR #17 HEAD. Do not merge or release until the full BB-DI-001 contract is
independently accepted.
