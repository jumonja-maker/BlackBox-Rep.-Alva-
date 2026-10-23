# BB-DI-001 — implementation and acceptance evidence ledger

**Scope:** 75 M entries with normative MUST/MUST-IF-CAPABLE/SHOULD levels (M-001..075), 5 A (A-001..005), 36 acceptance (AC-01..36), 12 Windows fixtures (FIX-01..12), **128 total**. Normative descriptions and acceptance tests: `BLACKBOX_BigPatch_Technical_Spec_BB-DI-001_RU.md` from the original owner's `Original_Full_Order.zip`. This ledger is a **conservative WIP assessment, not a release certification**.

**Repository target:** PR #17, `review/bb-di-001-action-integration-20261023`; baseline `main` v0.3.6 SHA `7be5e3899c115b1703d67aee5a575647aec17615`. CI and test evidence MUST be checked against live PR HEAD, not an inherited successful run on an earlier SHA. Historical exact-head success: Windows/Linux/portable CI #40018093140 for SHA `592f4ab7d8aea00eca83e100340079ffb45f4c65`. New thread CPU slice requires another **exact-head CI**; never inherit older success.

**Counts (initial conservative assessment):** PARTIAL: 50; NOT-IMPLEMENTED: 29; NOT-RUN: 49.

Status rules: **PASS** needs actual user-facing integration, automated tests and full required acceptance evidence. **PARTIAL** means only a verified code path/subfeature, **not** a complete MUST. **NOT-IMPLEMENTED** means the specified capability is absent from the reviewed slices. **NOT-RUN** means independent full-contract verification is absent; it does not assert absence of all legacy code. No item is yet promoted to full PASS based solely on a unit test. Evidence paths point to implementation/tests for **subfeatures**; they are **not** per-item sign-off certificates.

## Control-by-control matrix

| Requirement | Assessment | Relevant code / subfeature evidence | Gaps / limitations |
| --- | --- | --- | --- |
| M-001 | PARTIAL | blackbox_universal/monitor.py; src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | PID + birth checked; formal target provenance not complete |
| M-002 | PARTIAL | blackbox_universal/monitor.py; tests/test_bbdi_action_slice.py | Target switch denied while active; full PID-reuse Windows E2E unverified |
| M-003 | PARTIAL | src/blackbox_core/detailed_capture.py; blackbox_universal/window.py | Opt-in detailed channel; no complete profiles or Incident Burst |
| M-004 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | New live session UUID and paired nanosecond clock anchor cover Standard/Detailed; system UTC drift and all sensor clocks not accepted |
| M-005 | PARTIAL | src/blackbox_core/probe.py; src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Live cumulative user/system counters and actual read tags, real-dt CPU >100%, logical CPU context; full CPU/observer acceptance not complete |
| M-006 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | RSS/Private/USS/handles best effort; per-field quality incomplete |
| M-007 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Cumulative bytes/ops and full-range valid-pair rates, reset/gap invalidation; full IO burst/native fixture acceptance incomplete |
| M-008 | PARTIAL | src/blackbox_core/detailed_capture.py | Child records, no complete tree aggregation/history |
| M-009 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/detail_analysis.py; tests/test_bbdi_thread_analysis.py; blackbox_universal/thread_detail_worker.py; blackbox_universal/window.py | Read-only adjacent-snapshot TID CPU% in existing Qt Processes table/JSON/HTML; no full lifetime intervals, OS birth identity, long session whole-history or complete coverage |
| M-010 | PARTIAL | src/blackbox_core/session_view.py; blackbox_universal/window.py; tests/test_bbdi_schema2_sessions.py | Full selected v2 TID segments ranked by cumulative CPU, presence/omitted CPU; native 300-thread acceptance pending |
| M-011 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Persisted child CPU/RSS/IO/handles/name/PID+birth history; 100 DTO identities tested, real 100 OS descendants pending |
| M-012 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Per-field status counts, full selected count, spacing gaps and estimated schedule slots; exact OS missed counts unknown |
| M-013 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f); src/blackbox_core/windows_observer.py | Actual HWND/PID/TID/visibility/lifecycle native test PASS; unseen HWND reuse/complete physical Win10/11 lifecycle coverage pending |
| M-014 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f); tests/test_bbdi_windows_observer.py | Independent WM_NULL worker and real consecutive Win32 error 1460 confirmed; final hardened-head/physical QA pending |
| M-015 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real timeout/recovery/window lifecycle and native incident persistence; complete burst/pre-post integration and final exact-head acceptance pending |
| M-016 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Actual mutex cycle: WCT OK, 5 nodes, is_cycle=true; UI snapshot without cycle also real. Native event evidence viewer implemented; hard cleanup deadlines/complete Win10/11 acceptance pending |
| M-017 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f); blackbox_universal/window.py | Actual non-GUI EnumWindows empty; NOT_APPLICABLE policy and HWND selector without root rebind; exhaustive physical multi-window QA pending |
| M-018 | PARTIAL | src/blackbox_core/actions.py; blackbox_universal/window.py; tests/test_bbdi_action_slice.py | Action cycle wired; complete integrated E2E absent |
| M-019 | PARTIAL | src/blackbox_core/actions.py; tests/test_bbdi_action_slice.py | Real USER-command monotonic timestamps; no OS execution attestation |
| M-020 | PARTIAL | blackbox_universal/monitor.py; src/blackbox_core/actions.py | Problem marker exists; no app instrumented channel and all marker types |
| M-021 | PARTIAL | src/blackbox_core/actions.py; src/blackbox_core/session_v2.py; tests/test_bbdi_action_slice.py | Persistent runs with 20-repeat UI/core limit, existing median/p95/MAD; scenario/app versions, saved experiment library and resource compare incomplete |
| M-022 | PARTIAL | src/blackbox_core/experiments.py; src/blackbox_core/report.py | Duration aggregation/compare partial; no resource delta comparability |
| M-023 | PARTIAL | src/blackbox_core/incidents.py; src/blackbox_core/windows_observer.py; blackbox_universal/window.py | CPU/gap plus native UI timeout; CPU threshold/duration Settings; all memory/handles/IO/exit/burst policies still incomplete |
| M-024 | PARTIAL | src/blackbox_core/incidents.py | Pre/post sample sequence bounded; not full multi-sensor ring |
| M-025 | PARTIAL | src/blackbox_core/incidents.py; tests/test_bbdi_incident_slice.py | Cooldown and incident bounds; incomplete disk/trigger policy |
| M-026 | PARTIAL | src/blackbox_core/incidents.py; src/blackbox_core/report.py | Explicit external-counter provenance, incomplete sensor coincidence |
| M-027 | PARTIAL | blackbox_universal/base_sample_worker.py; src/blackbox_core/event_journal.py; src/blackbox_core/storage.py; tests/test_bbdi_event_journal.py; tests/test_bbdi_base_worker.py | Qt timer's base samples and SQLite events now use separate workers; durable action callbacks/stop can still wait on disk, initial session and reports run on GUI |
| M-028 | PARTIAL | src/blackbox_core/session_v2.py; docs/ADR-02-SESSION-V2-AND-INTERVALS.md | Live normalized versioned schema2 sidecar for new GUI recordings; historical v1 never rewritten; crash/recovery acceptance pending |
| M-029 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Required normalized entities/FKs/indices exist; actual sample/event/action/incident/experiment writes; windows/artifact inventory and experiment metadata workflow incomplete |
| M-030 | PARTIAL | src/blackbox_core/session_v2.py; src/blackbox_core/session_view.py | Producer-selected source, typed quality and imported trust separation; full Windows/native sensor provenance absent |
| M-031 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_detail_contracts.py; tests/fixtures/bbdi_status_cases.json | Contract 2.1 distinguishes field and thread/child group statuses, 0 vs NULL, reason and clock resolution. Full per-source accuracy/ACL cases remain incomplete |
| M-032 | PARTIAL | src/blackbox_core/detail_contracts.py; src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | NS read tags/brackets, anchored UTC estimate plus reported resolution, observation-time event alignment; individual TID read/birth and calibrated UTC accuracy unavailable |
| M-033 | PARTIAL | src/blackbox_core/session_view.py; blackbox_universal/session_interval_worker.py; tests/test_bbdi_schema2_sessions.py | All selected v2/v1 rows streamed, exact statistics, first/min/max/last plots, full CSV; accelerated 100001-row early-minute test passed locally; 8h hardware latency pending |
| M-034 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py; tests/test_bbdi_detail_contracts.py | Sample/quality rows atomic on malformed data and WAL+soft quota remain; power-loss recovery/checkpoint/8h NOT RUN |
| M-035 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-036 | PARTIAL | blackbox_universal/window.py; blackbox_universal/monitor.py | Action and incident controls; no complete status architecture |
| M-037 | PARTIAL | blackbox_universal/timeline.py; blackbox_universal/window.py; tests/test_bbdi_schema2_sessions.py | Nine resource tracks, wheel/key zoom, A/B drag, pan/reset and full range requery; native Windows/ETW tracks absent |
| M-038 | PARTIAL | blackbox_universal/timeline.py; src/blackbox_core/session_view.py | Peak-preserving buckets, gap segment breaks, cancellable background range reload; full endurance/physical Windows pending |
| M-039 | PARTIAL | blackbox_universal/window.py; tests/test_bbdi_detailed_slice.py | Overview controls; no complete investigation timeline |
| M-040 | PARTIAL | blackbox_universal/window.py; src/blackbox_core/session_view.py | Persisted paged child history, per-child interval, cumulative TID table/presence; no root rebind; full hierarchical tree widget/native load QA pending |
| M-041 | PARTIAL | blackbox_universal/window.py; src/blackbox_core/session_view.py | Paged observation-time timeline, native/user source distinction and selected event evidence/WCT nodes in UI; full filters/ETW stream absent |
| M-042 | PARTIAL | blackbox_universal/window.py; src/blackbox_core/interval_report.py | Human selected-interval summary before hidden raw JSON; saved-session open and privacy-selected exports; full findings/cards/compare pending |
| M-043 | PARTIAL | blackbox_universal/window.py | Partial controls; complete profiles/privacy/quota UI missing |
| M-044 | PARTIAL | blackbox_universal/window.py; src/blackbox_core/session_view.py | Open saved session and paged process/event histories work; local indexed session library/delete/experiment history not implemented |
| M-045 | NOT-RUN | — | Not yet independently audited end-to-end against full original criterion |
| M-046 | PARTIAL | .github/workflows/shell-qa.yml | Offscreen DPI screenshots; full keyboard/screen reader/physical Windows NOT RUN |
| M-047 | PARTIAL | src/blackbox_investigation/engine.py; src/blackbox_investigation/sqlite_adapter.py | Legacy investigation, no full v2 timeline |
| M-048 | PARTIAL | src/blackbox_investigation/model.py; src/blackbox_core/report.py | Provenance disclaimers, full source-class contracts missing |
| M-049 | PARTIAL | src/blackbox_core/incidents.py; src/blackbox_investigation/engine.py | CPU episodes supported, incomplete signals |
| M-050 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-051 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-052 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Whole selected history statistics, paged events/processes, explicit Top-N truncation; legacy engine full findings pagination still missing |
| M-053 | PARTIAL | src/blackbox_core/interval_report.py; tests/test_bbdi_schema2_sessions.py | Schema2 interval JSON, offline escaped HTML/SVG, streamed full CSV/events, selected ZIP, SHA manifest and ownership-safe no-clobber; full finding/native/compare report absent |
| M-054 | PARTIAL | src/blackbox_core/experiments.py; src/blackbox_core/report.py | Duration-only experiment comparison |
| M-055 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Separate v1/v2 readers and SessionView; v1 LEGACY_LIMITED_DATA with unchanged hash; full Windows legacy fixture acceptance pending |
| M-056 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-057 | PARTIAL | src/blackbox_core/probe.py; src/blackbox_core/detailed_capture.py | Read-only psutil sample; full capabilities/permission matrix not verified |
| M-058 | PARTIAL | docs/ADR-04-WINDOWS-RESPONSIVENESS-WCT.md; tests/test_bbdi_windows_observer.py | Native async WCT cleanup and finite send timeout, non-daemon native owner and deferred GUI close; absolute OS cleanup deadline and ETW/dump isolation incomplete |
| M-059 | PARTIAL | src/blackbox_core/interval_report.py; tests/test_bbdi_schema2_sessions.py | Opt-in identifier/note export, allowlisted imported metadata/native data, no titles/commandline/env/object names capture; all original privacy/threat fixtures not accepted |
| M-060 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-061 | PARTIAL | src/blackbox_core/storage.py; src/blackbox_core/report.py | Existing 0.3.6 hardening retained; all BB-DI security cases not proven |
| M-062 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-063 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | Thread/child/size limits; 8h performance not verified |
| M-064 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-065 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Owned bounded writer, explicit fault/overflow and drain; complete sensor heartbeat/backoff and hard OS cancellation absent |
| M-066 | PARTIAL | src/blackbox_core/session_v2.py; blackbox_universal/session_interval_worker.py | v2 writes and streaming interval analysis/export outside Qt; original command journal acknowledgement/start/finish can still block |
| M-067 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| M-068 | PARTIAL | src/blackbox_core/session_v2.py | One process-counter capability record; full fixed sensor registry/native detection not implemented |
| M-069 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Finite immutable v2 queue with explicit discarded command count and fail-closed storage status; complete latency/adaptive policy absent |
| M-070 | PARTIAL | src/blackbox_core/session_view.py; docs/ADR-02-SESSION-V2-AND-INTERVALS.md | Separate read-only SchemaV1Reader/SchemaV2Reader share SessionView; no in-place migration; recovery/rollback full acceptance pending |
| M-071 | PARTIAL | app.py; blackbox_universal/window.py | Existing launch and five tabs kept; complete E2E not proven |
| M-072 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real x64 ABI/callback/node fixture PASS, exact API errors and observer deadline separate; full supported Windows/security matrix pending |
| M-073 | PARTIAL | .github/workflows/shell-qa.yml; PR #17 | Draft/no release so far; final merge gate pending |
| M-074 | PARTIAL | tests/test_bbdi_action_slice.py; tests/test_bbdi_incident_slice.py; tests/test_bbdi_detailed_slice.py | Several Qt controls tested; full acceptance matrix absent |
| M-075 | CONDITIONAL-PASS | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f); blackbox_universal/deep_smoke.py | Both Python/Qt and real frozen EXE creation/action/TID/incident/analysis/export PASS at checkpoint. Repeat exact-head CI for subsequent 2.1 hardening; not full 128-point acceptance |
| A-001 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-002 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-003 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-004 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-005 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| AC-01 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-02 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-03 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real two-native-worker frozen target and nonzero TID CPU confirmed; full specified graph/fixture acceptance still pending |
| AC-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-10 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real UI block, independent timeout code 1460 and responsive monitor workflow PASS on hosted Windows Server 2025; full platform gate pending |
| AC-11 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Actual timeout then recovery rows/observation bounds verified; complete final supported-platform evidence pending |
| AC-12 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Actual controlled Win32 mutex cycle returned 5 WCT nodes and true cycle; denied path is portable fake test, complete supported-platform gate pending |
| AC-13 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real non-GUI fixture enumeration empty and NOT_APPLICABLE path tested; final-head/platform gate pending |
| AC-14 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-15 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-16 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-17 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-18 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-19 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-20 | PARTIAL | tests/test_bbdi_schema2_sessions.py; docs/BB_DI_001_QA_20261024.md | Accelerated 100001-row history with arbitrary early minute, full stats/peak/bounded Python memory PASS. Real 8h recording NOT-RUN |
| AC-21 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-22 | PARTIAL | tests/test_bbdi_schema2_sessions.py; docs/BB_DI_001_QA_20261024.md | Legacy exact schema1 read/export and source SHA invariance tested; full old-release/platform acceptance pending |
| AC-23 | PARTIAL | tests/test_bbdi_schema2_sessions.py; src/blackbox_core/session_view.py | User source strings cannot become native producer class; reopened file class always UNVERIFIED_IMPORT. Complete import-attack suite pending |
| AC-24 | PARTIAL | tests/test_bbdi_schema2_sessions.py; src/blackbox_core/interval_report.py | Real full CSV/JSON/HTML, allowlists and escaped HTML/SVG; full comments/privacy attack matrix pending |
| AC-25 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-26 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-27 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-28 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-29 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-30 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-31 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-32 | CONDITIONAL-PASS | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Actual bundled EXE (no Python PATH/source working directory) passed 3 actions, 126 TID rows, 5 incidents and analysis/export. Subsequent 2.1 head requires its own CI |
| AC-33 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Checkpoint exact-head Windows/Linux/native/build/deep smoke/ZIP green; release SKIPPED by authorization gate. Subsequent final HEAD CI required |
| AC-34 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-35 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f); tests/test_bbdi_schema2_sessions.py | Frozen reanalysis/export preserved original v1/v2 DB and JSON/HTML hashes; concurrent export no-clobber PASS, full adversarial matrix incomplete |
| AC-36 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Source/units/status/unknown, full selected counts, actual errors, estimated slots, dropped command distinction. Complete all-sensor coverage validation pending |
| FIX-01 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Real two-native-hash-worker fixture included in bundled EXE and used in deep QA; configurable 1/2/N and full load matrix incomplete |
| FIX-02 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Native Qt freeze 2s/8s buttons and automatic 5s freeze/recovery; actual detection/recovery PASS, physical matrix pending |
| FIX-03 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Controlled two-mutex cycle, actual positive WCT evidence; complete negative/permission/platform fixture matrix pending |
| FIX-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-10 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-11 | PARTIAL | tests/test_bbdi_schema2_sessions.py; docs/BB_DI_001_QA_20261024.md; CI 40036985762 (a3b0bee1f6c51980b9263ea2dce4ea279b44900f) | Accelerated ordered 100001-row selection fixture PASS; actual 8h/1h endurance NOT-RUN |
| FIX-12 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |

## Qt background report generation (still PARTIAL)

- `blackbox_universal/report_worker.py`, `blackbox_universal/monitor.py` and `window.py`: after the **original Qt-owned SessionStore** is safely finished and closed, generate JSON/HTML on an owned QThread with its own read-only SQLite connection; never pass live owner SQLite connections into workers.
- UI prevents reattach/restart, explicit action entry, current-session Investigation and report opening while pending; window close defers instead of destroying live workers. Report failures remain distinct from session result; direct CLI synchronous Stop unchanged.
- `tests/test_bbdi_report_worker.py` plus compatibility test updates. See `docs/BB_DI_001_ASYNC_REPORT_OWNERSHIP.md`: SQLite session finish and queue-flush still occur on GUI owner and can block, so **M-027/M-066 stay PARTIAL**, not accepted.

## Monotonic sample spacing and worker timing (still PARTIAL)

- `MonotonicSampleCadence` now checks actual elapsed time **between accepted snapshots** against the requested interval held when each worker was created, excludes interval-change boundaries, and durably saves source-qualified `EXTENDED_MONOTONIC_SAMPLE_SPACING` only when spacing exceeds a conservative threshold. No numeric OS-missed-sample count is inferred.
- `BaseSampleWorker` captures monotonic brackets for external process sampling and its SQLite transaction; the Qt receiver separately bounds signal delivery. A bounded `BASE_SAMPLE_WORKER_TIMING_SUMMARY` is persisted before normal Stop; report JSON/HTML keep real snapshot spacing distinct from delivered skipped GUI callbacks and refuse malformed imported timings.
- See `tests/test_bbdi_monotonic_cadence.py` and `docs/BB_DI_001_MONOTONIC_CADENCE.md`. **No hard OS deadline, guaranteed worker cancellation, full session schema2 or Windows frozen deep vertical E2E**; related M-027/M-066 controls remain PARTIAL.

## Bounded sampling backpressure evidence (still PARTIAL)

- `src/blackbox_core/sampling_health.py`, `blackbox_universal/window.py` and `monitor.py`: deterministic, bounded count of delivered Qt timer callbacks skipped while the base sampler is in-flight, persisted **once per episode** before Stop, and exposed in live snapshots. An error persisting this observation ends the session as `STORAGE_ERROR`, not a false success.
- `src/blackbox_core/report.py`: separate source-qualified busy Qt timer callback count and episode count in JSON/HTML; imported malformed counts rejected. These are **not** OS sample gaps, do **not** count callbacks Qt coalesced, and do **not** prove a Windows hang.
- `tests/test_bbdi_sampling_health.py` and `docs/BB_DI_001_SAMPLING_BACKPRESSURE.md` document coverage, counter bounds, clock/interval anomalies, slow-sensor tests and limitations. Full monotonic measurement schedule coverage and 8-hour endurance are still NOT-RUN.

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
2. Finish fully async UI actions/acknowledgements, owner-managed session writer across samples/events/finish, stop/join OS deadlines and resource quotas. JSON/HTML report generation now runs off Qt after original schema1 close; original session finish and journal barriers still run synchronously. Observed Qt busy callbacks, monotonic adjacent snapshot spacing and bounded worker timing are recorded, but the count of OS missed samples and Qt-coalesced callbacks remains unknown.
3. Extend the **new bounded adjacent-snapshot TID CPU%** to selected full-session intervals, per-field quality, tree/history, charts, CSV and compare. Existing table/HTML/JSON only covers a recent bounded window; TID birth identity is unverified.
4. Add real bounded Windows HWND responsiveness and WCT with positive/negative Windows fixtures and explicit unsupported/denied states; opt-in ETW where capable.
5. Build complete evidence-led Investigation/compare/timeline/experiment history; 8h Standard, 1h Detailed, 12 fixtures, AC-01..36.
6. Run actual **frozen Windows EXE full vertical test** and physical-platform matrix; final report and human owner sign-off before merge/release.

**Gate:** keep PR #17 Draft; never merge `main`, never publish v0.4.0 until all mandatory DoD are proven. Owner is not a manual tester; unavailable hardware evidence remains NOT-RUN.

## Live schema2 and full selected-interval implementation (current stage)

See [ADR-02](ADR-02-SESSION-V2-AND-INTERVALS.md). Actual new GUI recordings
produce the normalized sidecar using an owned writer, while the compatibility
schema1 is retained. No old file is migrated. Human interval summary, peak/gap
preserving timeline, persisted process/event pages, full-range TID ranking and
privacy-selected JSON/HTML/CSV/ZIP exports are wired through existing pages.

New local evidence command: `QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -p 'test_bbdi_schema2_sessions.py' -v` — 12 PASS before the final integration regression run. These include real local psutil capture, Qt range selection and test-only accelerated 100001-row history/100 child DTO fixtures. **Not real 8h/1h endurance or native Windows acceptance.** Full original criteria and every AC/FIX remain unaccepted until exact-head Windows/Linux/frozen evidence and their additional required scenarios are recorded. CI for this stage must be checked on its new exact commit, not inherited from 7ab0bad.

## Windows-native and deep frozen QA stage

Real HWND/WM_NULL/WCT code, native fixtures and actual Qt/frozen deep scenario
are now implemented; see ADR-01..04. **CI is pending for the new stage.** The
first schema2 checkpoint `32f38da4aaadf466379fbeaa85ea4ebf8141bb75` failed CI
[40034664938](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40034664938):
Windows requires a writable staging handle for fsync; three Linux tests deleted
their temporary directory before background report completion. Both are fixed
in the next stage; the failing run is not successful acceptance evidence.

Local stage evidence: 242 tests, 237 PASS + 5 platform SKIP, plus ordinary smoke.
Real-process Python deep smoke passed: 3 completed actions, 42 sample rows,
42 actual TID rows, 1 automatic CPU incident, nonzero cumulative TID CPU,
privacy-selected 6-file export/ZIP and unchanged source hashes. This executor
has different control/proc PID namespaces; the QA fixture explicitly records
both and selects its actual `/proc/self/stat` PID for psutil. Two earlier wrong-
namespace runs remained FAIL; no metrics were fabricated to make them pass.

Windows/native/frozen results must be recorded against the next exact HEAD.
All acceptance rows still require their full original criterion, including
unavailable physical/endurance evidence. No release/merge authorization follows.

## Verified checkpoint and final precision hardening

See [QA evidence and remaining blockers](BB_DI_001_QA_20261024.md). Checkpoint
`a3b0bee1f6c51980b9263ea2dce4ea279b44900f` / CI 40036985762 is SUCCESS:
Windows 242 PASS + 1 SKIP, Linux 238 PASS + 5 SKIP, actual native WCT cycle and
UI recovery, Python deep workflow, portable build and actual frozen deep
workflow, ZIP; release SKIPPED. Frozen artifact ID 12537357880 was downloaded
and independently checked against its archive SHA and measured qa-summary.

`CONDITIONAL-PASS` is scoped automated evidence with explicit remaining gates;
it is not full-order sign-off. Later contract 2.1 clock/source/privacy/ownership
hardening requires a new exact-head run. Never reuse the above SHA's green
status for a different head. No real 8h/1h, complete AC/FIX, ETW or physical
Win10/11 acceptance is claimed. Old historical sections are checkpoints, not
the current source of truth; use this table and ADR-01..04.

**Current matrix counts (acceptance states, not implementation percentages):** CONDITIONAL-PASS=2, NOT-IMPLEMENTED=13, NOT-RUN=32, PARTIAL=81. Total 128.
