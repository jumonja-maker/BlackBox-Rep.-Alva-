# BB-DI-001 — forensic v1/v2 consistency and stop handoff

## Observation retained from 2026-10-24 (source SHA aecc74fe)

Original preserved owner-controlled QA archive: `BB_DI_001_QA_20261024.zip`,
`local/aecc74f_export_refusal/`. This is a **historic controlled
read-only copy**, not the exact set of live SQLite files at one guaranteed
post-stop instant.

- The source QA summary claims **43 accepted primary process snapshots**, 3
  completed actions, and an export failure `EXPORT_HANDLER_FAILED`.
- The retained JSON records original v1 metadata `exit_code=COMPLETED`.
  The complete original v1 SQLite/WAL pair is **not in the forensic subset**.
- The retained `CONTROLLED_QA_SESSION_V2.sqlite3` holds
  **27 STANDARD + 13 DETAILED = 40 normalized rows** (not 40 STANDARD
  rows). Its metadata is `status=RECORDING, ended_monotonic_ns=NULL,
  exit_code=NULL`; 25 normalized events; of three action intervals,
  two are `COMPLETED` and the third is `RUNNING`.
  The retained WAL contains 0 bytes. The copy's main-file SHA-256 is
  `1eba4e12bd0edbeeac5cb1fb64f4e92e0e20df7aed877e867cc65eb42a4eb495`.
- Export refused `EXPORT_REQUIRES_CLOSED_SESSION` correctly. No export
  guard was disabled, and no original source bytes were changed.

**Conclusion:** two asynchronously observed/archived sources disagree.
Neither an exact producer-side failure time nor a causal trace of the v2
writer's final STOP transaction is present. The root cause of the *historical*
aecc discrepancy is **NOT_ESTABLISHED**. Do not report it as a proved
filesystem race, lost SQLite COMMIT, queue overflow, corrupt input or failed
application. The old snapshot cannot be silently repaired or promoted to
COMPLETED.

One important controlled alternative has been reproduced in
`tests/test_storage_completion_gate.py`: taking a read-only SQLite backup
**before** STOP legitimately retains `RECORDING`, while the live source
later reaches `CLOSED` and its primary v1 metadata reaches `COMPLETED`.
This shows that snapshot timing *can* create the same status pattern, **not**
that this caused the historical aecc incident.

## Production safeguards in Draft PR #17

1. Existing `SessionV2Writer.finish()` drains accepted bounded commands,
   commits normalized `CLOSED` and joins the writer. The forced WAL
   `TRUNCATE` checkpoint was removed in the preceding integration work;
   SQLite FULL-synchronous WAL COMMIT remains the durability boundary.
2. Existing `confirm_v2_completion()` opens normalized v2 read-only and
   requires the matching UUID, monotonic origin, schema, `CLOSED`,
   end timestamp and exit code; a committed WAL row is accepted without a
   checkpoint or source mutation.
3. **Additional invariant:** after the v2 writer exits but *before* setting
   v1 exit metadata to success, `SessionStore.finish()` reads actual
   committed v1 `samples` count/min/max sequence. Only consecutive
   `1..N` base rows qualify. It passes `N` to the v2 read-only
   verification, which counts **only STANDARD** rows and requires
   `instance_id=1`, `series_seq=1..N` and every explicit
   `correlation_key='schema1:' || series_seq`. DETAILED/CHILD samples
   do not substitute for missing base observations.
4. A missing/excess normalized STANDARD row, wrong source link, unreadable
   primary counter table, absent v2 `CLOSED` commit or identity mismatch
   **cannot certify v1 COMPLETED**. V1 is instead finalized
   `STORAGE_ERROR` with a stable recorded reason when its metadata is
   writable; otherwise an explicit failure is propagated. The original
   recording is retained unchanged except the ordinary failure metadata
   and append-only diagnostic entry. No silent repair, re-created samples,
   inferred OS-missed-sample counts or export bypass.
5. Source and frozen `--deep-smoke` now independently reopen both databases
   after the STOP acknowledgement and check their persisted statuses, exact
   normalized STANDARD counts and correlation mappings **before** continuing
   to interval analysis and selected export. The usual 3-action GUI/EXE
   scenario is otherwise unchanged.

Regression tests include real asynchronous writer/SQLite commits, missing
v2 base rows, excess v2 rows, malformed source-correlation links,
independent optional DETAILED samples and a controlled mid-recording
read-only copy. The original `SessionView` and legacy schema1-only exports
remain available.

## Acceptance boundaries

These safeguards close a **detectable false-completion class**. They are
not evidence that the old specific aecc incident's producer failure has been
identified. Distinct files and capture instants cannot prove causality.
Incident forensic root-cause disposition remains **UNRESOLVED**; gather an
atomic pair of source SQLite files, a writer STOP acknowledgement with
monotonic issue/received times, worker error/queue health and a common
captured SHA if it occurs again.

Completing this engineering safeguard does **not** substitute for the
8-hour Standard / 1-hour Detailed runs, physical Win10/Win11/ACL/AV/
accessibility/upgrade testing or acceptance of all 128 requirements.
PR #17 remains Draft; no main merge or release.
