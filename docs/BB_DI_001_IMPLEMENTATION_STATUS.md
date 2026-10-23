# BB-DI-001 — implementation and acceptance evidence ledger

**Scope:** 75 MUST (M-001..075), 5 A (A-001..005), 36 acceptance (AC-01..36), 12 Windows fixtures (FIX-01..12), **128 total**. Normative descriptions and acceptance tests: `BLACKBOX_BigPatch_Technical_Spec_BB-DI-001_RU.md` from the original owner's `Original_Full_Order.zip`. This ledger is a **conservative WIP assessment, not a release certification**.

**Repository target:** PR #17, `review/bb-di-001-action-integration-20261023`; baseline `main` v0.3.6 SHA `7be5e3899c115b1703d67aee5a575647aec17615`. CI and test evidence MUST be checked against live PR HEAD, not an inherited successful run on an earlier SHA. Historical exact-head success: Windows/Linux/portable CI #40018093140 for SHA `592f4ab7d8aea00eca83e100340079ffb45f4c65`. New thread CPU slice requires another **exact-head CI**; never inherit older success.

**Counts (initial conservative assessment):** PARTIAL: 50; NOT-IMPLEMENTED: 29; NOT-RUN: 49.

Status rules: **PASS** needs actual user-facing integration, automated tests and full required acceptance evidence. **PARTIAL** means only a verified code path/subfeature, **not** a complete MUST. **NOT-IMPLEMENTED** means the specified capability is absent from the reviewed slices. **NOT-RUN** means independent full-contract verification is absent; it does not assert absence of all legacy code. No item is yet promoted to full PASS based solely on a unit test. Evidence paths point to implementation/tests for **subfeatures**; they are **not** per-item sign-off certificates.

## Control-by-control matrix

| Requirement | Assessment | Relevant code / subfeature evidence | Gaps / limitations |
| --- | --- | --- | --- |
| M-001 | PARTIAL | blackbox_universal/monitor.py; src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | PID + birth checked; formal target provenance not complete |
| M-002 | PARTIAL | blackbox_universal/monitor.py; tests/test_bbdi_action_slice.py | Target switch denied while active; full PID-reuse Windows E2E unverified |
| M-003 | PARTIAL | src/blackbox_core/detailed_capture.py; blackbox_universal/window.py | Opt-in detailed channel; no complete profiles or Incident Burst |
| M-004 | PARTIAL | src/blackbox_core/detail_contracts.py; src/blackbox_core/detailed_capture.py; tests/test_bbdi_detail_contracts.py | Clock anchor and approximate UTC mapping now persisted for opt-in detailed sidecar only; no full session UUID / cross-sensor mapping |
| M-005 | PARTIAL | src/blackbox_core/probe.py; src/blackbox_core/detailed_capture.py | Stored cumulative CPU; missing full v2 interval semantics |
| M-006 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | RSS/Private/USS/handles best effort; per-field quality incomplete |
| M-007 | PARTIAL | src/blackbox_core/detailed_capture.py | Cumulative byte and ops counters; safe per-interval rates not wired |
| M-008 | PARTIAL | src/blackbox_core/detailed_capture.py | Child records, no complete tree aggregation/history |
| M-009 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/detail_analysis.py; tests/test_bbdi_thread_analysis.py; blackbox_universal/thread_detail_worker.py; blackbox_universal/window.py | Read-only adjacent-snapshot TID CPU% in existing Qt Processes table/JSON/HTML; no full lifetime intervals, OS birth identity, long session whole-history or complete coverage |
| M-010 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-011 | PARTIAL | src/blackbox_core/detailed_capture.py | Observed child identity/RSS/CPU, but missing full tree IO/handles/lifetime |
| M-012 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-013 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-014 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-015 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-016 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-017 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-018 | PARTIAL | src/blackbox_core/actions.py; blackbox_universal/window.py; tests/test_bbdi_action_slice.py | Action cycle wired; complete integrated E2E absent |
| M-019 | PARTIAL | src/blackbox_core/actions.py; tests/test_bbdi_action_slice.py | Real USER-command monotonic timestamps; no OS execution attestation |
| M-020 | PARTIAL | blackbox_universal/monitor.py; src/blackbox_core/actions.py | Problem marker exists; no app instrumented channel and all marker types |
| M-021 | PARTIAL | src/blackbox_core/experiments.py; tests/test_bbdi_experiment_slice.py | Same-session repeats; saved experiment library absent |
| M-022 | PARTIAL | src/blackbox_core/experiments.py; src/blackbox_core/report.py | Duration aggregation/compare partial; no resource delta comparability |
| M-023 | PARTIAL | src/blackbox_core/incidents.py; tests/test_bbdi_incident_slice.py | Only CPU/gap triggers, not HWND/IO/private/handles |
| M-024 | PARTIAL | src/blackbox_core/incidents.py | Pre/post sample sequence bounded; not full multi-sensor ring |
| M-025 | PARTIAL | src/blackbox_core/incidents.py; tests/test_bbdi_incident_slice.py | Cooldown and incident bounds; incomplete disk/trigger policy |
| M-026 | PARTIAL | src/blackbox_core/incidents.py; src/blackbox_core/report.py | Explicit external-counter provenance, incomplete sensor coincidence |
| M-027 | PARTIAL | blackbox_universal/base_sample_worker.py; src/blackbox_core/event_journal.py; src/blackbox_core/storage.py; tests/test_bbdi_event_journal.py; tests/test_bbdi_base_worker.py | Qt timer's base samples and SQLite events now use separate workers; durable action callbacks/stop can still wait on disk, initial session and reports run on GUI |
| M-028 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/detail_contracts.py; docs/BB_DI_001_DETAIL_V2_CONTRACT.md | Additive v2 clock/capability/quality tables and conservative legacy reader; full normalized schema2/session lifecycle not implemented |
| M-029 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/detail_contracts.py | Added clock/capabilities/sample-quality rows; sessions, targets, incident, experiment, artifacts and other required entities missing |
| M-030 | PARTIAL | src/blackbox_core/detail_analysis.py; src/blackbox_core/detail_contracts.py; src/blackbox_core/detailed_capture.py | New PSUTIL/OS_OBSERVED producer metadata per detailed sample, read-only file_trust UNVERIFIED_IMPORT; full event sensor/source/permission contract still missing |
| M-031 | PARTIAL | src/blackbox_core/detail_contracts.py; tests/test_bbdi_detail_contracts.py | Explicit field statuses on new detailed samples: OK vs NOT_OBSERVED/ACCESS_DENIED/UNSUPPORTED/TRUNCATED; other sensors and complete reason granularity missing |
| M-032 | PARTIAL | src/blackbox_core/detail_contracts.py; src/blackbox_core/detailed_capture.py | Precise monotonic timestamps and approximate nanosecond UTC mapping for detailed sidecar; old GUI sample timestamps and system-clock drift remain unaddressed |
| M-033 | PARTIAL | blackbox_universal/investigation_worker.py; tests/test_bbdi_interval_slice.py | Read-only selected legacy interval with max_samples bound; no full 8h streaming |
| M-034 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py; tests/test_bbdi_detail_contracts.py | Sample/quality rows atomic on malformed data and WAL+soft quota remain; power-loss recovery/checkpoint/8h NOT RUN |
| M-035 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-036 | PARTIAL | blackbox_universal/window.py; blackbox_universal/monitor.py | Action and incident controls; no complete status architecture |
| M-037 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-038 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-039 | PARTIAL | blackbox_universal/window.py; tests/test_bbdi_detailed_slice.py | Overview controls; no complete investigation timeline |
| M-040 | PARTIAL | blackbox_universal/window.py; blackbox_universal/thread_detail_worker.py; src/blackbox_core/detail_analysis.py | User-loadable bounded TID CPU table; full process tree, child detail rows, historic interval and sort/zoom absent |
| M-041 | PARTIAL | blackbox_universal/window.py; src/blackbox_core/incidents.py | User/CPU events; no native HWND/WCT/ETW timeline |
| M-042 | PARTIAL | src/blackbox_core/report.py; blackbox_universal/window.py | JSON/HTML summaries but full evidence-driven Investigation incomplete |
| M-043 | PARTIAL | blackbox_universal/window.py | Partial controls; complete profiles/privacy/quota UI missing |
| M-044 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-045 | NOT-RUN | — | Not yet independently audited end-to-end against full original criterion |
| M-046 | PARTIAL | .github/workflows/shell-qa.yml | Offscreen DPI screenshots; full keyboard/screen reader/physical Windows NOT RUN |
| M-047 | PARTIAL | src/blackbox_investigation/engine.py; src/blackbox_investigation/sqlite_adapter.py | Legacy investigation, no full v2 timeline |
| M-048 | PARTIAL | src/blackbox_investigation/model.py; src/blackbox_core/report.py | Provenance disclaimers, full source-class contracts missing |
| M-049 | PARTIAL | src/blackbox_core/incidents.py; src/blackbox_investigation/engine.py | CPU episodes supported, incomplete signals |
| M-050 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-051 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-052 | PARTIAL | blackbox_universal/investigation_worker.py; tests/test_bbdi_interval_slice.py | Bounded legacy interval, not full coverage streaming |
| M-053 | PARTIAL | src/blackbox_core/report.py; src/blackbox_core/detail_contracts.py; src/blackbox_core/detail_analysis.py | Saved JSON/HTML now include detailed-source clock/status/quality and bounded TID deltas; complete schema2 CSV/bundle unavailable |
| M-054 | PARTIAL | src/blackbox_core/experiments.py; src/blackbox_core/report.py | Duration-only experiment comparison |
| M-055 | PARTIAL | src/blackbox_investigation/sqlite_adapter.py | Read-only v1 interval works; full v1/v2 SessionView missing |
| M-056 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-057 | PARTIAL | src/blackbox_core/probe.py; src/blackbox_core/detailed_capture.py | Read-only psutil sample; full capabilities/permission matrix not verified |
| M-058 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-059 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/report.py | No command line/title/path capture in added slice; full privacy tests missing |
| M-060 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-061 | PARTIAL | src/blackbox_core/storage.py; src/blackbox_core/report.py | Existing 0.3.6 hardening retained; all BB-DI security cases not proven |
| M-062 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-063 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | Thread/child/size limits; 8h performance not verified |
| M-064 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-065 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-066 | PARTIAL | blackbox_universal/base_sample_worker.py; src/blackbox_core/event_journal.py; blackbox_universal/monitor.py; src/blackbox_core/storage.py; tests/test_bbdi_event_journal.py | Bounded FIFO SQLite event writer and periodic sample QThread, but no fully async action acknowledgements, global unified queue, deadlines, measured backpressure or hard quota |
| M-067 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-068 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-069 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-070 | PARTIAL | src/blackbox_investigation/sqlite_adapter.py; src/blackbox_core/detailed_capture.py | V1 read-only and V2 sidecar; no unified SessionView |
| M-071 | PARTIAL | app.py; blackbox_universal/window.py | Existing launch and five tabs kept; complete E2E not proven |
| M-072 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-073 | PARTIAL | .github/workflows/shell-qa.yml; PR #17 | Draft/no release so far; final merge gate pending |
| M-074 | PARTIAL | tests/test_bbdi_action_slice.py; tests/test_bbdi_incident_slice.py; tests/test_bbdi_detailed_slice.py | Several Qt controls tested; full acceptance matrix absent |
| M-075 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-001 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-002 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-003 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-004 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-005 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| AC-01 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-02 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-03 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-10 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-11 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-12 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-13 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-14 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-15 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-16 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-17 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-18 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-19 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-20 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-21 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-22 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-23 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-24 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-25 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-26 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-27 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-28 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-29 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-30 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-31 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-32 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-33 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-34 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-35 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-36 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-01 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-02 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-03 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-10 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-11 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-12 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |

## Bounded GUI SQLite event journal slice (still PARTIAL)

- `src/blackbox_core/event_journal.py` and `src/blackbox_core/storage.py`: one session-owned 64-slot FIFO for schema1 events, external SQLite worker connection, nonblocking lifecycle enqueue, **durable** action/incident/user marker acknowledgement before state changes, ordered barrier before session finish.
- `blackbox_universal/monitor.py` and `window.py`: opt in automatically for real GUI sessions, leaving original CLI APIs and schema1 files intact; no new UI section or cloud interaction.
- `tests/test_bbdi_event_journal.py`: worker-thread identity, queue exhaustion, fail-closed writer fault, FIFO, schema1 backward compatibility and actual Qt action/marker integration. See `docs/BB_DI_001_EVENT_JOURNAL_ARCHITECTURE.md` for the remaining blocking calls and unproven durability on forced process crash. **M-027/M-066 still PARTIAL.**

## Background base sampler / SQLite writer slice (still PARTIAL)

- Production `UniversalWindow` timer launches one bounded `BaseSampleWorker` (`psutil` sampling + independent schema1 SQLite sample insert); user commands and `ActionCycle` still run through existing Qt-owned `SessionStore` event connection.
- Stop and close are deferred until the outstanding worker exits; an external-counter failure persists `observer_error` before finalization; no QThread is destroyed while it owns the sample database connection.
- Deterministic concurrency, failure and schema1 regression tests: `tests/test_bbdi_base_worker.py`. See `docs/BB_DI_001_BASE_WORKER_ARCHITECTURE.md` for unsupported cases. This is not the full bounded queue/async writer for **all** record types and does not prove 8h endurance or OS deadlines.

## Additive provenance / clock sidecar slice (still PARTIAL)

- `src/blackbox_core/detail_contracts.py`, `detailed_capture.py`: opt-in detailed sidecar now stores an anchored monotonic↔UTC nanosecond estimate, explicit PSUTIL source/verification, per-sample RSS/Private/USS/handles/I/O/thread/child statuses and unit metadata; late sensor data failures rollback all partial sample rows.
- `summarize_detail` keeps legacy v2 read-only, reports `LEGACY_DETAIL_V2_NO_PROVENANCE` for absent additive tables, and marks reopened-file trust as `UNVERIFIED_IMPORT`; JSON/HTML surface contract quality without claiming Windows hangs.
- `tests/test_bbdi_detail_contracts.py` covers these contracts; see `docs/BB_DI_001_DETAIL_V2_CONTRACT.md` for semantics and explicit limitations. The full schema2/SessionView/UI writer migration remains undone.

## New read-only per-thread CPU vertical subfeature (still PARTIAL)

- `src/blackbox_core/detail_analysis.py`: adjacent-sample delta `(user+system CPU seconds)/monotonic interval` converted into single-core-equivalent CPU percent, only for the same TID in consecutive process snapshots. First-seen/reappeared TIDs, nonadjacent snapshots and negative/reset counters **do not receive fabricated rates**. Possible unobserved TID reuse remains explicitly unproven.
- `blackbox_universal/thread_detail_worker.py` and `window.py`: explicit, background-loaded bounded Top-TID table on the existing Processes page, 5 tabs unchanged; RU/EN status; no added runtime/cloud/sensor privilege.
- `report.py`: `thread_cpu_analysis` embedded in JSON plus safe HTML table, distinguished as PSUTIL/DERIVED, not WCT/OS-hang evidence. Legacy `session.sqlite3` schema1 is unchanged; sidecar is read-only.
- `tests/test_bbdi_thread_analysis.py`: fake source fixtures are test-only; exercise churn, gaps, reset, monotonic deltas, SQLite immutability, JSON/HTML, Qt worker and five-tab invariant. **No full Windows native fixture has been accepted from these synthetic examples.**

## Newly handled safety cases on this branch

- `ReadOnlyProbe` retains the unfinished detailed collector as `_pending_detailed` on stop-timeout, blocks new attach/start/re-enable while it is alive, and reaps it without blocking UI once it exits. Tests explicitly hold an injected collector inside an OS-like blocking wait. The worker cannot be forcibly killed by Python; this mitigates ownership/rebind, **not** a guaranteed deadline for a blocked Win32/psutil call.
- `DetailedCapture` now records an unexpected Python exception as `SENSOR_INTERNAL_FAILURE`, not a successful Stop.
- Detailed sidecar size checks count `detail-v2.sqlite3` plus live `-wal`/`-shm`. This is a **soft check at sample boundaries**, not a hard per-write quota. No 8-hour endurance claim.
- SQLite v1 remains unchanged; detailed v2 is still an incomplete opt-in sidecar and is **not** the formal schema2 architecture.

## Release blockers / next implementation order

1. Complete schema2 contracts, provenance/status/capability vocabulary, monotonic↔UTC mapping and V1 read-only/V2 readers with atomic lifecycle.
2. Finish fully async UI actions/acknowledgements, owner-managed session writer across samples/events/finish and reports, stop/join deadlines, worker health metrics and dropped-tick records; periodic base sample INSERT and GUI event INSERT now run in worker-owned connections.
3. Extend the **new bounded adjacent-snapshot TID CPU%** to selected full-session intervals, per-field quality, tree/history, charts, CSV and compare. Existing table/HTML/JSON only covers a recent bounded window; TID birth identity is unverified.
4. Add real bounded Windows HWND responsiveness and WCT with positive/negative Windows fixtures and explicit unsupported/denied states; opt-in ETW where capable.
5. Build complete evidence-led Investigation/compare/timeline/experiment history; 8h Standard, 1h Detailed, 12 fixtures, AC-01..36.
6. Run actual **frozen Windows EXE full vertical test** and physical-platform matrix; final report and human owner sign-off before merge/release.

**Gate:** keep PR #17 Draft; never merge `main`, never publish v0.4.0 until all mandatory DoD are proven. Owner is not a manual tester; unavailable hardware evidence remains NOT-RUN.
