# BB-DI-001 — implementation and acceptance evidence ledger

**Scope:** 75 M entries with normative MUST/MUST-IF-CAPABLE/SHOULD levels (M-001..075), 5 A (A-001..005), 36 acceptance (AC-01..36), 12 Windows fixtures (FIX-01..12), **128 total**. Normative descriptions and acceptance tests: `BLACKBOX_BigPatch_Technical_Spec_BB-DI-001_RU.md` from the original owner's `Original_Full_Order.zip`. This ledger is a **conservative WIP assessment, not a release certification**.

**Repository target:** existing Draft PR #17, `review/bb-di-001-action-integration-20261023`; unchanged `main` v0.3.6 SHA `7be5e3899c115b1703d67aee5a575647aec17615`.

**Evidence:** measurement/ownership source `854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4`, [CI 40041993181](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40041993181), SUCCESS: Windows 252 PASS + 1 SKIP; Linux 248 PASS + 5 SKIP; Python/native and actual frozen workflow/portable ZIP PASS; release SKIPPED. Its offscreen screenshots had missing-font boxes and are **not legibility evidence**. The subsequent font/glyph QA fix requires its own checked-out SHA in [current PR checks](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/17/checks); see [evidence, commands, artifacts and rollback](BB_DI_001_QA_20261024.md).

**Current conservative counts:** PARTIAL: 81; NOT-IMPLEMENTED: 13; NOT-RUN: 32; CONDITIONAL-PASS: 2. These are acceptance states, not code completion percentages. Initial handoff counts were 50/29/49; none of the remaining MUSTs is implicitly accepted.

Status rules: **PASS** needs actual user-facing integration, automated tests and full required acceptance evidence. **PARTIAL** means only a verified code path/subfeature, **not** a complete MUST. **NOT-IMPLEMENTED** means the specified capability is absent from the reviewed slices. **NOT-RUN** means independent full-contract verification is absent; it does not assert absence of all legacy code. No item is yet promoted to full PASS based solely on a unit test. Evidence paths point to implementation/tests for **subfeatures**; they are **not** per-item sign-off certificates.

## Control-by-control matrix

| Requirement | Assessment | Relevant code / subfeature evidence | Gaps / limitations |
| --- | --- | --- | --- |
| M-001 | PARTIAL | blackbox_universal/monitor.py; src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | PID + birth checked; formal target provenance not complete |
| M-002 | PARTIAL | blackbox_universal/monitor.py; tests/test_bbdi_action_slice.py | Target switch denied while active; full PID-reuse Windows E2E unverified |
| M-003 | PARTIAL | src/blackbox_core/detailed_capture.py; blackbox_universal/window.py | Opt-in detailed channel; no complete profiles or Incident Burst |
| M-004 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | New live session UUID and paired nanosecond clock anchor cover Standard/Detailed; system UTC drift and all sensor clocks not accepted |
| M-005 | PARTIAL | src/blackbox_core/probe.py; src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Live cumulative user/system counters and actual read tags, real-dt CPU >100%, logical CPU context; full CPU/observer acceptance not complete |
| M-006 | PARTIAL | src/blackbox_core/detailed_capture.py; tests/test_bbdi_detailed_slice.py | RSS/Private/USS/handles best effort with per-field status; full Windows source/fixture acceptance incomplete |
| M-007 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Cumulative bytes/ops and full-range valid-pair rates, reset/gap invalidation; full IO burst/native fixture acceptance incomplete |
| M-008 | PARTIAL | src/blackbox_core/detailed_capture.py | Persisted bounded child resource records/history; exact tree aggregation/lifecycle coverage remains incomplete |
| M-009 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/detail_analysis.py; tests/test_bbdi_thread_analysis.py; blackbox_universal/thread_detail_worker.py; blackbox_universal/window.py | Full selected-interval adjacent-snapshot TID CPU in Qt/report; OS TID birth identity and complete real 300-thread/lifecycle coverage remain unaccepted |
| M-010 | PARTIAL | src/blackbox_core/session_view.py; blackbox_universal/window.py; tests/test_bbdi_schema2_sessions.py | Full selected v2 TID segments ranked by cumulative CPU, presence/omitted CPU; native 300-thread acceptance pending |
| M-011 | PARTIAL | src/blackbox_core/detailed_capture.py; src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Persisted child CPU/RSS/IO/handles/name/PID+birth history; 100 DTO identities tested, real 100 OS descendants pending |
| M-012 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Per-field status counts, full selected count, spacing gaps and estimated schedule slots; exact OS missed counts unknown |
| M-013 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4); src/blackbox_core/windows_observer.py | Actual HWND/PID/TID/visibility/lifecycle native test PASS; unseen HWND reuse/complete physical Win10/11 lifecycle coverage pending |
| M-014 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4); tests/test_bbdi_windows_observer.py | Independent WM_NULL worker and real consecutive Win32 error 1460 confirmed; actual hardened-head native PASS; full physical QA pending |
| M-015 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real timeout/recovery/window lifecycle and native incident persistence; complete burst/pre-post integration and original full acceptance pending |
| M-016 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Actual mutex cycle: WCT OK, 5 nodes, is_cycle=true; UI snapshot without cycle also real. Native event evidence viewer implemented; hard cleanup deadlines/complete Win10/11 acceptance pending |
| M-017 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4); blackbox_universal/window.py | Actual non-GUI EnumWindows empty; NOT_APPLICABLE policy and HWND selector without root rebind; exhaustive physical multi-window QA pending |
| M-018 | PARTIAL | src/blackbox_core/actions.py; blackbox_universal/window.py; tests/test_bbdi_action_slice.py | Three real Qt/frozen action cycles persisted; full ABORTED/state/interval acceptance remains incomplete |
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
| M-029 | PARTIAL | src/blackbox_core/session_v2.py; tests/test_bbdi_schema2_sessions.py | Required normalized entities/FKs/indices exist; actual sample/event/action/incident/experiment writes; Native window lifecycle persists; complete artifact inventory and experiment metadata workflow incomplete |
| M-030 | PARTIAL | src/blackbox_core/session_v2.py; src/blackbox_core/session_view.py | Producer-selected source, typed quality and imported trust separation; actual Win32/WCT producer provenance present; complete capability/accuracy matrix remains unaccepted |
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
| M-072 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real x64 ABI/callback/node fixture PASS, exact API errors and observer deadline separate; full supported Windows/security matrix pending |
| M-073 | PARTIAL | .github/workflows/shell-qa.yml; PR #17 | Draft/no release so far; final merge gate pending |
| M-074 | PARTIAL | tests/test_bbdi_action_slice.py; tests/test_bbdi_incident_slice.py; tests/test_bbdi_detailed_slice.py | Several Qt controls tested; full acceptance matrix absent |
| M-075 | CONDITIONAL-PASS | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4); blackbox_universal/deep_smoke.py | Both Python/Qt and real frozen EXE creation/action/TID/incident/analysis/export PASS at checkpoint. Subsequent font/glyph QA fix needs its own exact-head run; not full 128-point acceptance |
| A-001 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-002 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-003 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-004 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| A-005 | NOT-IMPLEMENTED | — | Required full capability not present; see original order |
| AC-01 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-02 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-03 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real two-native-worker frozen target and nonzero TID CPU confirmed; full specified graph/fixture acceptance still pending |
| AC-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-10 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real UI block, independent timeout code 1460 and responsive monitor workflow PASS on hosted Windows Server 2025; full platform gate pending |
| AC-11 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Actual timeout then recovery rows/observation bounds verified; complete final supported-platform evidence pending |
| AC-12 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Actual controlled Win32 mutex cycle returned 5 WCT nodes and true cycle; denied path is portable fake test, complete supported-platform gate pending |
| AC-13 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real non-GUI fixture enumeration empty and NOT_APPLICABLE path tested; final-head/platform gate pending |
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
| AC-32 | CONDITIONAL-PASS | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Actual bundled EXE (no Python PATH/source working directory) passed 3 actions, 126 TID rows, 5 incidents and analysis/export. Subsequent 2.1 head requires its own CI |
| AC-33 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Checkpoint exact-head Windows/Linux/native/build/deep smoke/ZIP green; release SKIPPED by authorization gate. Subsequent final HEAD CI required |
| AC-34 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| AC-35 | PARTIAL | docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4); tests/test_bbdi_schema2_sessions.py | Frozen reanalysis/export preserved original v1/v2 DB and JSON/HTML hashes; concurrent export no-clobber PASS, full adversarial matrix incomplete |
| AC-36 | PARTIAL | src/blackbox_core/session_view.py; tests/test_bbdi_schema2_sessions.py | Source/units/status/unknown, full selected counts, actual errors, estimated slots, dropped command distinction. Complete all-sensor coverage validation pending |
| FIX-01 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Real two-native-hash-worker fixture included in bundled EXE and used in deep QA; configurable 1/2/N and full load matrix incomplete |
| FIX-02 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Native Qt freeze 2s/8s buttons and automatic 5s freeze/recovery; actual detection/recovery PASS, physical matrix pending |
| FIX-03 | PARTIAL | blackbox_universal/qa_fixtures.py; docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Controlled two-mutex cycle, actual positive WCT evidence; complete negative/permission/platform fixture matrix pending |
| FIX-04 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-05 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-06 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-07 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-08 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-09 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-10 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |
| FIX-11 | PARTIAL | tests/test_bbdi_schema2_sessions.py; docs/BB_DI_001_QA_20261024.md; CI 40041993181 (854cd6bef1d35b1e541cbca77e6ff5a7dcea68f4) | Accelerated ordered 100001-row selection fixture PASS; actual 8h/1h endurance NOT-RUN |
| FIX-12 | NOT-RUN | — | No independent full-scenario Windows/EXE acceptance evidence for this exact item |

## Current integration and limits

- ADR-01..04 document capture ownership, live normalized 2.1/legacy readers,
  clock/status semantics and actual Windows APIs. New recordings keep schema1
  compatibility and a normalized schema2 writer; old files are never migrated.
- Full selected intervals stream every row on reader-owned workers. Statistics,
  cumulative TID CPU, peak/gap-preserving tracks, paged event/process history and
  privacy-selected export are integrated with the existing five pages.
- Source and frozen QA drive real action controls, actual OS counters, automatic
  incidents, Investigation and export; primary files remain hash-identical.
  WCT positive mutex-cycle, real UI timeout/recovery and non-GUI native fixtures
  passed on Windows Server 2025. Physical Windows 10/11 are still NOT-RUN.
- Subsequent visual QA fixes load installed Windows fonts for Qt offscreen,
  test real Latin/Cyrillic regular/bold glyphs, and translate interval labels,
  summary and table headers on language switch without requerying data. Fresh
  exact-head screenshots are required; previous tofu images are invalid.
- GUI base sampling, detailed/native capture, v2 writing and read-only reports
  have owned workers. Primary schema1/action acknowledgements/start/finish and
  journal barriers still can block Qt: M-027/M-066 remain PARTIAL. Pending
  collectors remain owned; no guaranteed hard cancellation of OS calls.
- 100001 ordered samples and 100 child DTOs are explicit synthetic test inputs;
  they prove range-query/history logic, not 8h endurance or 100 real descendants.
- Failed initial schema2 CI: 32f38da / run 40034664938 (read-only fsync handle
  on Windows, premature temporary-directory cleanup in three Linux tests).
  Both failures were fixed and verified in later successful exact-head runs.
- Earlier source a3b0bee / run 40036985762 was also successful, but no older green
  build establishes acceptance of a newer SHA. Current source links, runtime
  versions, artifact digests and known visual defect are in the QA document.

## Outstanding release blockers

1. Finish primary async command/finish ownership, all sensor registry/capability,
   heartbeat/backoff/cancel and OS deadlines; recovery and quota/ACL acceptance.
2. Complete memory/handles/I/O/exit/burst triggers, multi-sensor pre/post ring,
   incident cards and full evidence-led findings/pagination.
3. Saved scenario/version/environment editing, resource compare, indexed local
   session/experiment library, retention UI and all markers/instrumented channels.
4. Real opt-in ETW A-001 MUST-IF-CAPABLE and its cleanup/recovery; A-002..004
   SHOULD runtime/crash diagnostics remain absent; A-005 FUTURE is nonblocking.
5. Complete native/trace timeline/filter/accessibility; actual 8h Standard/1h
   Detailed, 300 real threads, 100 real descendants, observer benchmarks and all
   remaining AC/FIX/physical Windows 10/11/update/uninstall/privacy scenarios.

**Gate:** PR #17 stays Draft. No full PASS or order acceptance is claimed.
Do not merge main or publish a release without the owner's explicit decision.

## Continuation: isolated owner and cooperative evidence

See `BB_DI_001_COORDINATOR_CONTINUATION.md`. Public `app.py` now uses an isolated session owner for attach/start/actions/SQLite finish/report; synchronous APIs remain for embedders. Current 2.1 source/clock/privacy fixes are preserved, optional application events are explicitly unauthenticated. Quit acknowledgement no longer cancels the native-owner exit deadline. The base 4e048be Windows job timed out at DPI 200% and did not build a portable EXE; successful base unit/Python deep steps are not a successful frozen result. This section is an implementation delta, not promotion of every related row to full PASS. Exact new CI is pending.

### Continuation evidence — 24 October 2026

The normative rows above retain their original scope. The integrated recording
owner, disposable optional operations, fixed sensor contract/health/backoff,
multisignal windows, bounded WPR guardian, interval resource experiments and
privacy-transformed share copies are documented in
`BB_DI_001_COORDINATOR_CONTINUATION.md`. Exact-head CI and resource coverage
must be reviewed before promoting a row; no original mandatory requirement has
been removed. Real WPR raw capture/TTL is now evidenced on 2b6a7a3, separately
from independent provider-content, size-hard-quota and orphan-recovery acceptance.
The order is still NOT ACCEPTED; this appendix is not a blanket PASS update.
