# BlackBox Rep. Alva — state / developer handoff (2026-10-22)

## CURRENT OWNER DIRECTION — HUMAN-FIRST BLACK.BOX (2026-10-22)

BLACK.BOX Universal is a **program for people**. Alva is only internal diagnostic infrastructure, not an AI companion. This Draft branch `feature/human-first-no-ai-handoff-20261022` is stacked on the existing `feature/alva-evidence-pipeline-20261022` (Draft PR #10).

Current code change: normal Stop emits SQLite, JSON and browser-readable HTML only. **No `ai-handoff.json`**, no public `handoff` CLI command, no `handoff.py` module, no AI Handoff in Qt reports/About. Unit and GUI tests updated; new human-first contract test added. A previously authorized private Alva runtime still performs scoped component checks, a four-stage P4 evidence-quality pipeline, and structural classification/report review for BLACK.BOX-owned operations. Explicit `alva.build_ai_handoff` calls have been removed from public adapter code; the private Alva host may still assemble its own internal metadata, which BLACK.BOX does not publish. No private Alva source/wheel copied or modified. No extra Alva tab.

**Execution status:** all exact-branch local unit and Windows frozen EXE tests **NOT RUN**. Prior test results may describe a superseded AI Handoff workflow. Do not merge this Draft until actual Windows/Ubuntu tests, CLI rejection and first-run human reports pass. See `docs/HUMAN_FIRST_PRODUCT.md`.


## Latest UI integration — use evidence in ordinary BLACK.BOX Reports (2026-10-22)

The stacked Alva P4 branch also adds a **generic evidence-quality summary in
the normal Reports screen**, automatically updated after an authorized private
runtime finishes processing a saved session. Shows counts 4/4 or an
incomplete-evidence notice, translated EN/RU, **never a branded Alva page**.
With no authorized runtime, Reports remains fully functional with its own
offline observer evidence; no fabricated P4 result. No changes to private
Alva, its visibility or default branch. Added test cases, **not yet run**.

## Expanded real-Alva P4 consumer (Draft, 2026-10-22)

Branch `feature/alva-evidence-pipeline-20261022` is stacked on Draft PR #9 (unbranded internal diagnostics), not on `main`. Adds a **real external Alva** checked pipeline of four data-quality stages over the bounded BLACK.BOX session summary, plus Alva's evidence reviewer, structured AI Handoff and reuse of three completed host traces through real classifier/report APIs when installed. The publicly distributed sidecar includes **only new public BLACK.BOX helper code**, not any private Alva files. Parent now accepts strict bridge schema v2 and retains v1 for older allowed environments. Public EXE has no Alva tab.

**No claim of universal code tracing:** P4 observations are only about BLACK.BOX's own observer evidence. No root cause, foreign code access or automatic analysis by cloud AI.

- Added opt-in **real private Alva** acceptance script `tools/verify_authorized_alva.py`: positive and rejected-observer-evidence synthetic session through isolated worker; no new installation or public wheel. Created but **NOT RUN**. See `docs/ALVA_P4_INTERNAL_CONSUMER.md`.

**Current QA for this exact SHA:** static GitHub source review + synthetic test code added; actual local test execution, full-suite Windows/Ubuntu test, frozen EXE and real private Alva invocation **NOT RUN**. Tests are a labelled stand-in, not an installed Alva test. Do not merge/release until the gates in `docs/ALVA_P4_INTERNAL_CONSUMER.md` pass. Private Alva repository was not changed. No client-facing Alva UI was reintroduced.



## Product decision — internal Alva, no separate Alva UI (2026-10-22)

Owner decision: **Alva is implementation infrastructure**, not a BLACK.BOX-branded page or an end-user prerequisite. The new Draft branch `feature/internal-diagnostics-unbranded-20261022` is based on the latest `feature/release-v030-alva-integration-20261022` head `64a3941519fb4f9a0f79fcb7c831422e757fb9f7`. Five user screens only: Overview, Processes, Event Log, Reports, Settings. No Alva Lab, no Connect Alva buttons, no platform mark in About/title/sidebar. Standard reports are automatic on Stop.

Previously explicitly authorized Alva interpreter (existing per-user QSettings) can still be invoked internally after a finalized session, once per session; if absent, core processing succeeds without running private code. Never claim that the free public download contains or executes genuine Alva by default. **Platform private**; no code/wheel redistribution and no automatic unapproved installation. Full true-Alva one-download requires a separate distribution/license decision.

This branch has modified Qt source, navigation test assertions, background behavior and public README EN/RU; see `docs/INTERNAL_DIAGNOSTICS_NO_BRAND.md`. **Exact-commit Windows EXE testing, whole test suite and genuine Alva-at-SHA consumer tests: NOT RUN**. Review as Draft, do not merge/release until evidence is produced. Existing older historical status below may refer to the replaced six-page UI.


## Latest: integrated standalone + retro desktop (after Alva foundation)

- Integration Draft PR [#5](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/5),
  branch `feature/universal-integrated-desktop-v01`, now targets
  **main directly** as the single complete first-release candidate. Its
  cumulative diff includes all public platform work from PR #1→#2→#3
  plus the original retro GUI from PR #4. Older PRs stay unmerged.
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
