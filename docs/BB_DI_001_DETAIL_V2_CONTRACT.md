# BB-DI-001 — additive detail-v2 clock and quality contract (WIP)

> Historical checkpoint. Current live normalized v2/native implementation and limitations: ADR-01..04, BB_DI_001_IMPLEMENTATION_STATUS.md and BB_DI_001_QA_20261024.md.
**Scope:** opt-in process/threads/children sidecar `detail-v2.sqlite3` only. This is **not** the full BB-DI-001 schema2 / SessionView / independent worker architecture, and must not be reported as M-028..032 complete. Core `session.sqlite3` remains schema1 as in v0.3.6. No in-place migration of customer files is attempted.

## Producer and source policy

`DetailedCapture` is a user-enabled Python background worker using external `psutil` process counters. New sidecars preserve the earlier `detail_metadata`, `process_samples`, `thread_samples`, `child_samples`, and `sensor_errors` tables and add:

- `detail_clock_mapping`: one monotonic↔UTC anchor (`monotonic_anchor_ns`, `utc_anchor_ns`, `uncertainty_ns`, `clock_source`). Created using `time.monotonic_ns()` before/after `time.time_ns()`. The midpoint and half-interval represent sampling uncertainty **at the anchor**, not a guarantee against future system UTC clock adjustments.
- `detail_capabilities`: seven known field classes, each with unit, `source_kind=PSUTIL` and `verification_class=OS_OBSERVED` as a **producer claim** about external counters. This is not a statement that a Windows hang/deadlock was observed.
- `detail_sample_quality`: one record per successfully committed process sample with matching `sample_seq`, `utc_estimate_ns`, source/verification classification and separate bounded statuses for RSS, Private, USS, handles, I/O, threads and children. The `sample_seq` matches `process_samples` for correlation; its actual sample monotonic timestamp is retained at nanosecond precision in `process_samples`. The computed UTC timestamp is an **estimate**, not an independent wall-time measurement.

Supported per-field statuses: `OK`, `NOT_OBSERVED`, `NOT_APPLICABLE`, `ACCESS_DENIED`, `UNSUPPORTED`, `SENSOR_TIMEOUT`, `SAMPLED_GAP`, `TRUNCATED`, `INVALID`. An exact numeric **zero** with `OK` means measured zero; missing/denied is NULL with its status. If there are omitted thread or child rows, `TRUNCATED` replaces a whole-snapshot `OK`; it does **not** claim complete coverage.

`PSUTIL` external-counter provenance must never be confused with a native `WIN32` responsiveness timeout, `WCT` wait chain, `ETW` trace or code-level root cause. If optional read is denied, the base monitoring path remains independent. No window titles, command lines, executable paths or stacks are captured by this slice.

## Reader and historical compatibility

`summarize_detail()` opens the file read-only and returns `provenance` containing `contract_status`, `clock_mapping`, `capabilities`, `latest_quality`, `quality_samples`, `quality_coverage`, and explicit `file_trust=UNVERIFIED_IMPORT`.

Opening a local or externally provided SQLite file **does not cryptographically attest the values**. The recorded producer classification is kept for interpretation, while `file_trust` prevents it being presented as independently OS-verified after import. The HTML report shows source, status, approximate UTC anchor and the unverified-file caveat.

Previous detail-v2 sidecars without the additive tables are supported by the reader as `LEGACY_DETAIL_V2_NO_PROVENANCE`; their missing fields stay absent, not zero. On invalid new metadata the reader reports `INVALID_DETAIL_PROVENANCE` and does not synthesize a clock.

All writes to the three per-sample tables (`process_samples`, `thread_samples`, `child_samples`) and `detail_sample_quality` share the same SQLite transaction. A data-shape failure rolls back all partial rows **before** writing a bounded sensor-error event. The existing soft storage quota accounts for SQLite/WAL/SHM but is not a hard atomic disk quota. Graceful shutdown is not equivalent to crash recovery; complete lifecycle, checkpoint/replay policy, base GUI writer isolation and 8h performance remain required.

## Test scope and acceptance gaps

`tests/test_bbdi_detail_contracts.py` verifies clock math and nanosecond presentation, real zero vs NULL, untrusted status rejection, SQLite sidecar contract/capabilities and source, read-only legacy handling, rollback of late malformed thread data, schema1 coexistence and report rendering. Other regression suites continue to test opt-in Qt capture and worker lifetime.

**Still required:** complete schema2 normalized entities, session UUID and cross-sensor capture-time clock mapping, standalone schema1/schema2 readers with stable SessionView, per-column source/error and access reason where possible, write quotas under high churn, native Windows sensor capabilities/deadlines, non-blocking base Qt sampling/SQLite writer, and frozen EXE full vertical E2E. Keep PR #17 Draft and do not publish v0.4.0.
