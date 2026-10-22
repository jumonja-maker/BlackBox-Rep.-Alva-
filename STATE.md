# BlackBox Rep. Alva — state / developer handoff (2026-10-22)

## Latest: integrated standalone + retro desktop (after Alva foundation)

- Integration Draft PR [#5](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/5),
  branch `feature/universal-integrated-desktop-v01`, stacked **on PR #3**
  and therefore including the complete PR #1→#2→#3 public platform base.
- Original design Draft PR #4 supplied the theme, widgets and UI layouts.
  **PR #4 should not also be merged separately**; it is superseded by #5.
- The GUI uses `blackbox_rep_alva.probe.PsutilProbe` and
  `blackbox_rep_alva.storage.SessionStore` for the single authoritative
  sampler and SQLite format. Save/Stop automatically creates
  `session.sqlite3`, `report.json`, `report.html` and an offline,
  untrusted `ai-handoff.json`. Reports can compare saved sessions.
- Alva Lab uses only the PR #2 `inspect_platform` on explicit CHECK.
  Alva's private code is neither imported during normal observation nor
  distributed in Windows builds. Permission-to-act stays false.
- **Executed Windows/Linux + frozen EXE CI PASS** on integrated commit
  `cb1aef6a7b3f341a5040866a63ee2ce29f7894b0`;
  Windows 31 tests PASS, real PyInstaller windowed startup smoke PASS.
  Details in `docs/QA_EVIDENCE.md`.
- Later revisions include an explicit Attach→Start PID-reuse check, plus
  additional QA; they require fresh CI validation. Real user Windows
  usability, third-party app stress and **genuine Alva** testing remain
  unverified. Do not merge into `main` or label a signed stable release
  solely from automated CI.

The following state describes the **earlier pre-GUI Alva platform stage**
and remains as historical evidence, not the current GUI feature list.

## Exact engineering checkpoint

Source repository: `jumonja-maker/BlackBox-Rep.-Alva-` (public), whose `main` was intentionally **not modified** during this delivery (base `0bc1bf94825fd6025a6e42d524581a2f1ca7bd4a`).

- Draft PR #1, `feature/universal-observer-core-20261022`: `81c8c68307c60263a08a4cb01a72482031100e67`; read-only PID sampling, SQLite, local reports, AI Handoff, core tests.
- Draft PR #2, `feature/alva-diagnostics-bridge-20261022`: `e508d2b573ab271d039f2d9d3f947b3c2390d83e`; parent is PR #1; optional private Alva preview API adapter and synthetic bridge tests.
- Draft PR #3, `docs/universal-product-release-20261022`: stacked on PR #2; adds safety tests, adapter contracts, release gates, QA and this handoff. The branch HEAD may move as the docs are completed; query GitHub for current SHA.

Alva private platform HEAD inspected: `a44297c5408628d9447bbf7db394b95ebd33fa20`; `0.0.1.dev0` Python >=3.11 PREVIEW, no top-level LICENSE observed. No Alva source copied to this public repository.

## What is really implemented

- User-selected accessible process by PID, psutil sample metadata only; no target modifications.
- Completely local running/reporting, SQLite WAL with per-sample commits; external summary data, HTML/JSON report, before/after observation comparison, low-data AI handoff.
- Optional adapter importing the actual Alva Python API if an authorized installation exists. One small `blackbox.report.inspect` operation via ComponentHost and scoped diagnostic outcome.
- Standalone mode without Alva, no cloud, no AI and no mandatory GUI.

## Execution evidence

Local Linux/Python 3.13.5/psutil 7.2.2. At the final staged workspace, `unittest` **18/18 PASS**, Python `compileall` PASS. The foundational core without the optional Alva module also passed 15/15 when the 5 additional safety tests were included locally. These are *local* tests; the exact GitHub SHA was not run on Windows or GitHub CI.

Real installed Alva code execution: **NOT RUN**; synthetic adapter contract test only. Windows EXE/UI: **NOT RUN / NOT IMPLEMENTED**. Full application-specific internals/causality: **NOT AVAILABLE from passive samples**. Main branch remains only README.

## NEXT SINGLE TASK

Run true consumer integration in a **private authorized** local environment using the exact Alva SHA above: build wheel in separate checkout, verify SHA and wheel digest, execute the actual Alva host/scoped diagnostic call and negative tests, capture exact OS/Python/test commands and outcomes. STOP if distribution/license or installed API problems exist. Do not publish the resulting Alva wheel or files.

Parallel product work may independently build a Windows GUI and portable EXE from the public observer layer only, but cannot claim tested Windows support until actually observed.

## Rollback

Each PR is stacked and Draft. No branch is merged. Reject PR #3 to remove documentation/release additions; reject #2 to retain a standalone app with no Alva dependency; reject #1 to leave original `main` unchanged. Do not rewrite, delete or force-update unrelated branches.
