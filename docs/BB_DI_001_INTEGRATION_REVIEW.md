# PR17 / PR18 integration safeguards — not full order acceptance

## Pinned input and ancestry

PR17 input: `b817060e5f05b7b270daf5b3d3b5e7d984aa5fda`, tree
`cb65d0e3fabe164b47f2a9f11036f27c6b145c85`.
PR18 input: `57709547a677fa11261d661e53ef51e68a527285`.
GitHub compare identifies the PR18 head as the merge base: PR17 is 22 commits
ahead and zero behind. No second merge or cherry-pick is needed. Both original
PRs remain Draft. Main, PR18, workflows and release settings are not changed.

The supplied `BB_DI_001_QA_20261024.zip` has SHA-256
`f39c084e5e834f7f6da842253f849f717cb7fbf4bbb7fde40ed4280ee9375c7c`.
All 153 entries in its manifest match. Its 154 archive members were examined
as QA evidence, not as instructions authorizing main/release changes.

## Export refusal: evidence and additional protection

The preserved aecc QA example reports 43 source samples and three completed
actions; its retained v2 file contains 40 samples, 25 events and RECORDING
metadata with an empty WAL. The archived primary metadata says COMPLETED.
The export guard returned EXPORT_REQUIRES_CLOSED_SESSION. This is a correct
refusal for that retained state. The origin of the discrepancy is still
NOT_ESTABLISHED; neither a production race nor an environment defect has been
proved. No source record, guard, workload or old acceptance result is changed.

A new read-only postcondition checks the exact v2 session UUID, schema, origin,
CLOSED status, end timestamp and exit code after the v2 writer returns from
finish, before primary metadata can say COMPLETED. A failed postcondition is
stored as a safe reason in the primary journal and ends it as STORAGE_ERROR.
It never marks the v2 database closed, repairs counters or bypasses export.
A committed WAL close is accepted even if an older reader is still open.
The check cannot provide a hard deadline on a blocked filesystem syscall.

This is defense against unconfirmed completion, **not a demonstrated fix of
the historical aecc root cause**. The new reader was also checked against a
copy of the preserved fixture: it rejects RECORDING and leaves the main file
hash unchanged. The original QA ZIP and its sources are left intact.

## UI integration without losing actions

ResearchPanel retains all 17 action controls, context fields, consent controls,
interval selection, timeline and event paging. MarkerPanel retains all four
USER operations, entered text and stage selection. A height-for-width layout
places the same button objects in fewer columns when text/font/available width
requires it. No command, signal connection, privilege check or data source is
removed; no diagnostic command executes during layout or translation.
No extra top-level page, Expert Console or Workspace Builder is introduced.

Regression tests check nonoverlap/containment and button identity with RU/EN,
several font sizes and panel widths, plus exact command routing after reflow.
These geometry checks are not physical Windows accessibility acceptance.
Existing whole-app source/frozen scenarios and DPI checks remain required.

## Validation boundary

New tests: `test_session_completion.py`, `test_storage_completion_gate.py`,
`test_integration_action_layout.py`. Existing tests are not weakened or skipped.
The seven independent SQLite reader tests passed in the local Linux Python
runtime. The local environment lacks PySide6; full Qt/source/native/frozen
validation must be read from the new exact-head Actions run, not inherited
from the input b817 run. Results are recorded in the PR conversation.

Full BB-DI-001 remains NOT ACCEPTED. In particular: real 8h Standard / 1h
Detailed, physical Win10/11, full security/privacy/ACL/AV, installed upgrade /
uninstall and accessibility are not supplied by this patch.
