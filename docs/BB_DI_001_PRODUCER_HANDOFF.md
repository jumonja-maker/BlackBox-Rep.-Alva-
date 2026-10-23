# BB-DI-001 — current producer state and architectural note

**Order input:** `BLACKBOX_BIG_PATCH_BB-DI-001_FULL_TASK_FOR_CONTRACTORS_FIXED.zip` (17-page spec, Markdown, DOCX, contractor README).
**Target repository:** `jumonja-maker/BlackBox-Rep.-Alva-`.
**Exact starting main:** `7be5e3899c115b1703d67aee5a575647aec17615` (v0.3.6).
**Product's requested acceptance:** one fully integrated PR with M-001..M-075, A-001..A-005, AC-01..AC-36, FIX-01..FIX-12, schema2, real Windows WCT/ETW, 8-hour/performance and PyInstaller full vertical smoke.

## Scope actually implemented here

**NOT A FINISHED BB-DI-001. Review-only partial contribution.** This deliberately does not claim the requested DoD, even if standard two-OS regression CI passes. The missing capabilities are *blocking* under section 0 of the original specification. The receiving 00 BLACK.BOX chat owns further implementation/review within this *one cumulative PR* or may refuse the incomplete review candidate. Do not merge it as release v0.4.0.

A real durable vertical *subfeature* is implemented across first-party app code, not a placeholder:

- `src/blackbox_core/actions.py`: pure Python bounded state machine for `IDLE → ARMED → BASELINE → RUNNING → COOL_DOWN → COMPLETED` plus `ABORTED`. Explicit monotonic nanosecond command timestamps, positive source provenance, baseline/cooldown limits, prior event must be durably persisted before any state transition.
- `blackbox_universal/monitor.py`: ties action markers to the actual active selected process, its creation time, current session and preceding sample ordinal. The recorded command time is *not* the previous sample timestamp. Interrupted sessions persist `ACTION_ABORTED`, not a synthetic success. Existing private session SQLite schema remains 1, preserving v0.3.6 compatibility; schema2 NOT YET IMPLEMENTED.
- `blackbox_universal/window.py`: four working action controls on Overview (prepare, begin, end, repeat), activation gated by recording and baseline; existing five tabs retained.
- `blackbox_universal/i18n.py`: RU/EN chrome, unchanged machine event IDs.
- `src/blackbox_core/report.py`: reports complete user command intervals and durations in JSON/HTML, explicitly described as *recorded user actions, not OS-attested function profiling*; counts omitted previews, malformed action markers and avoids treating them as OS observation errors.
- `tests/test_bbdi_action_slice.py`: real SQLite roundtrip, negative durability, clock/replay identity, abort, UI RU/EN/offscreen regressions.
- Additionally, `mark_problem` now records the actual monotonic time of a user command; the preceding sample is included separately and never confused with the command moment. This is a narrow correction for AC-14, not a source of OS-attested GUI unresponsiveness.
- No fake TID samples, WCT results, ETW events, performance measurements, available caps or claim of root cause.

## Internal design for full follow-on (not implemented by this candidate)

**ADR-01 — sources and clocks:** schema2 requires per-session UUID, true monotonic/UTC clock mapping, `sample_monotonic_ns` and per-source quality/uncertainty; no GUI-tick-generated OS attestation. All Windows calls need an owned bounded background collector; per-PID creation time verified before/after native observations.

**ADR-02 — persistence:** versioned schema2 with append-only samples per `PID+birth`, threads, process tree, windows, action/experiment/incident, capability refusals, clock mapping and partial-coverage indices. Write to owned SQLite WAL transaction; read existing schema1 read-only without upgrading or overwriting. No mixed v1/v2 reads until migrated adapter and 100k+ row tests pass.

**ADR-03 — metrics:** process CPU% is delta(user+system CPU seconds)/monotonic delta × 100 per logical CPU; PrivateBytes ≠ USS ≠ RSS; cumulative read/write I/O rates require positive dt and no counter reset. Child tree RSS sums must explicitly warn shared-page double counting. TID CPU deltas only within the same observed process instance, with documented TID reuse uncertainty.

**ADR-04 — Windows:** Win32 HWND enumerator plus `SendMessageTimeout` responsiveness worker, observation count/cooldown, WCT documented Win32 return-code handling; require real Windows runner/fixture for positive evidence. Optional ETW only with explicit consent, owned session, TTL and size cap; no artificial stack trace or guessed I/O latency. No native capabilities are implemented in this slice.

## Security and handoff

- This code does not inject, manipulate target processes, read window titles, use command-line/environment or exfiltrate data.
- Existing v0.3.6 report no-clobber and updater/junction protection remain unchanged.
- Owner is only the courier to 00 BLACK.BOX. A second human manual QA stage is not a default requirement for Forge; target-specific physical Windows checks can be marked `MANUAL-NOT-RUN`, not invented.
- Final acceptance is blocked until **all MUST tests**, Windows-native WCT/ETW where capable, schema2 back-compat, real full frozen EXE scenario and long-run measurements have evidence. Static compilation or a green legacy CI alone does not satisfy this order.

## Verification and continuation

The old v0.3.6 baseline had 148 tests on Windows and 146 PASS/2 SKIP on Linux. Record **new exact PR-head** Windows/Linux CI below when actually completed; never inherit counts from the old release. A new `test_bbdi_action_slice` suite is included.

Next receiving chat: independently inspect PR diff against exact base, reproduce all added positive and failure cases, then continue extending the same cumulative branch across the eight parties in the original §14. Return a status matrix and precise defects; do **not** merge as a v0.4.0 release solely because the narrow action slice passes.
