# BB-DI-001 — Qt report generation ownership slice (PARTIAL)

This increment moves **JSON/HTML report generation** off the Qt GUI event
thread after the original schema1 recording is finalized. It does not move
the *entire* SessionStore lifecycle to the worker and does not claim to
solve indefinitely blocking OS/filesystem operations.

## Ownership contract

1. `UniversalWindow._stop` is the GUI entrypoint. If a
   `BaseSampleWorker` still owns an in-flight process measurement/INSERT,
   the window retains the existing deferred-stop gate; no premature
   SessionStore closure.
2. After all sample workers have finished, `_complete_base_stop` runs
   `ReadOnlyProbe.stop(reason, defer_report=True)` on the Qt owner thread.
   This safely aborts any incomplete ActionCycle, records incidents,
   acknowledges pending journal events and closes the original
   `SessionStore.db`, which was created on the Qt thread.
   **These operations can still block Qt** (journal acknowledgement,
   metadata transaction, sidecar stop up to 0.5s).
3. Only after that owner-thread SQLite connection is finalized and closed,
   an owned `ReportWorker(QThread)` receives **only the completed session
   folder path**. It runs the existing atomic `write_report()` offline,
   opening a separate read-only SQLite connection. It is never passed a live
   `ReadOnlyProbe` or the owner SQLite connection.
4. A Qt queued result carries either the completed report payload or
   `REPORT_UNAVAILABLE`. Only the GUI owner calls
   `ReadOnlyProbe.complete_report` and updates badges, event log and report
   buttons. No successful-report UI appears before the worker finishes.
5. Start, target switch, action controls, current-session Investigation and
   report opening are disabled or guarded while report generation is pending.
   The five main application pages, language choices, old SQLite v1 schema,
   CLI and direct-core synchronous stop API are unchanged.
6. A close request during an in-flight sample or report worker is deferred;
   the window retains worker ownership and schedules close after `finished`.
   There is no `QThread.wait()` or `join()` on the GUI thread.

The report worker does not change the target process and does not access any
remote network service. Its errors are reported as **report unavailable**
rather than a target-process failure, and existing SQLite evidence is
retained. The main database may correctly have `exit_code=COMPLETED`
even when HTML/JSON creation fails: measurement lifecycle and artifact
availability are separate pieces of evidence.

## What still needs implementing

- The owner-thread `SessionStore.finish()`, event queue drain, session
  initialization, action acknowledgement and detailed-capture stop still
  have blocking paths. A true full asynchronous session-finalization owner
  requires a more extensive queue/SQLite lifecycle refactor.
- There are no hard timeouts on a Python worker stuck in a filesystem
  syscall; a window close can remain pending to avoid use-after-free.
- No global writer queue, v2 normalized SessionView, 8h endurance,
  disk-power-loss recovery or frozen Windows BB-DI-001 multi-step E2E has
  been fully accepted.
- This is **not** OS-proof of hang, app root cause or a WCT/ETW trace.

## Tests

`tests/test_bbdi_report_worker.py` covers blocking synthetic report IO
without blocking Qt navigation, prevention of reattach/restart, window close
deferral, report failure separation and synchronous CLI compatibility.
Legacy Qt tests now await the report worker's completed signal before
asserting artifact presence and cleaning up temporary session directories.

**M-027/M-066 remain PARTIAL. Keep PR #17 Draft, no merge or release.**
