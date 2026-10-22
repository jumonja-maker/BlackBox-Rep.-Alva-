# QA evidence for BLACK.BOX Universal

## Current cumulative PR #12 — confirmed executed tests

- **GitHub Actions run:** [39837259498](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39837259498)
- **Exact tested source SHA:** `32b399b93f987bce3122164b2875f2de943cd236`.
- **Windows runner:** 65/65 Python tests PASS; actual Qt offscreen GUI smoke PASS.
- **Ubuntu runner:** 65/65 Python tests PASS; Qt offscreen GUI smoke PASS.
- **Windows portable:** PyInstaller windowed `BLACK.BOX-Universal.exe` and `BLACK.BOX-Maintenance.exe` built, frozen smoke PASS; artifact `BLACK.BOX-Universal-Windows` (ID `12451876396`) uploaded.
- **Functional verification in these tests:** ordinary sessions create SQLite, JSON, HTML and no `ai-handoff.json`; no Alva UI, five sections, RU/ENG; private sidecar and P4 API protocol checked against explicitly labeled **test doubles only**; basic CLI report and before/after comparison preserved. Test doubles do **NOT** prove real private Alva compatibility.
- **Post-test changes:** later branch revisions adjust UI translation catalog, report documentation and history reconciliation. The exact current branch head must have its own green Actions run before merging.
- **NOT RUN / BLOCKED:** genuine separately installed private Alva at pinned SHA, full Windows desktop manual exercise, actual in-place update/uninstall end-to-end, Windows reputation/AV and exact binary license audit.
- **Main unchanged by this PR.** Source/wheel of private Alva not copied to public repository or build.

## Earlier historical stages — not current branch proof

> The section below records the **earlier Alva CLI foundation**. The newest
> integrated GUI/EXE results are separately documented at the end.

**Repository:** `jumonja-maker/BlackBox-Rep.-Alva-`; review stack #1 → #2 → #3. **Environment:** local Linux / Python 3.13.5 / psutil 7.2.2. No GitHub Actions was configured or executed.

## Actual commands

```sh
PYTHONPATH=/mnt/data/blackbox_rep_alva_workspace/src python -W error::ResourceWarning -m unittest discover -s /mnt/data/blackbox_rep_alva_workspace/tests -v
# Ran 18 tests in 0.654s
# OK (exit code 0)

python -m compileall -q /mnt/data/blackbox_rep_alva_workspace/src /mnt/data/blackbox_rep_alva_workspace/tests
# PASS (exit code 0)
```

Local tests were run against code staged for these PRs; the standalone core branch is a subset without the Alva import path. GitHub build/CI of the exact branch SHA **NOT RUN**. The code was read back from the created branches, changes reviewed by compare API, and source tree files verified.

## Positive coverage — LIMITED/PASS on this one Linux host

- Real current-process read-only psutil sampling with session closure and persisted SQLite.
- Two-sample RSS/CPU aggregation and bounded JSON/HTML report with SHA256.
- Offline before/after metric deltas with explicitly unproven regression.
- AI handoff retaining `permission_to_act=false` and `root_cause=UNKNOWN`.
- Existing report data left untouched by read-only summarization.
- Optional Alva-free operation; read-only diagnostic API bridge with **fake isolated stand-in only**.

## Negative coverage — PASS on this one Linux host

- Process-exited fake probe -> explicit failed session, no false completion.
- Missing output root, missing/corrupt database, invalid sample and oversized event.
- Existing report is not overwritten; symlink output root is rejected.
- Interrupted/incomplete session cannot masquerade as closed; synthetic probe cannot trigger process terminate/kill.
- Missing Alva dependency returns `ALVA_UNAVAILABLE` without disabling independent reports.

## Outstanding evidence — NOT RUN/BLOCKED

- **Real Alva API invocation with actual installed package at pinned SHA**: NOT RUN; private distribution/packaging rights require review.
- **Windows** process observation and Windows portable EXE/GUI: NOT RUN / GUI NOT IMPLEMENTED.
- Independent QA runners or GitHub Actions: NOT RUN. No workflow created.
- Real application-specific telemetry, arbitrary process internal errors, quality/fidelity or provable root cause: NOT IMPLEMENTED.
- Disk-full, crash between JSON/HTML report exports, concurrent directory substitution/TOCTOU and symlink races: NOT RUN.
- Performance benchmark, third-party review and formal release gate: NOT RUN.

**Result:** 18/18 local tests PASS, *limited developer preview*. This does not certify a finished universal Windows product or a release of the private Alva platform.


## Integrated universal desktop — executed GitHub Actions QA (newer)

**Source:** [GitHub Actions run 39804565375](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39804565375), commit
`cb1aef6a7b3f341a5040866a63ee2ce29f7894b0`.

- Windows hosted runner / Python 3.11: **31 tests PASS**, 5.530 seconds;
  includes the Alva-provided core, true SQLite sessions, Qt offscreen
  navigation, process picker, full offline report and AI Handoff.
- Linux hosted runner / Python 3.11: **unit suite PASS** and offscreen
  GUI smoke PASS after installing required Qt shared libraries.
- Windows `--windowed` PyInstaller executable: **built and launched
  successfully in --smoke mode**, portable ZIP uploaded by GitHub Actions.
  The Python process in this smoke exits with code 0; a separate GUI
  usability review on an ordinary Windows desktop remains outstanding.
- All eight? **No.** This new public application has a basic read-only
  process observer, not the eight application-specific proprietary
  BLACK.BOX A.I.O diagnostic components.
- Private Alva runtime: **NOT RUN**. The public app imports Alva only
  if a user explicitly opts in to its bridge; platform provenance remains
  `false`. No private Alva source is packaged or uploaded.
- Later source revisions may add tests (e.g. checking PID reuse between
  Attach and Start). Those commit SHAs require **their own** fresh CI
  results before claiming release PASS. Do not apply this report to
  an untested future SHA.

**Known outstanding:** independent physical Windows desktop test with a
third-party app, Windows crash/disk-full/permission edge cases,
unsigned EXE reputation/AV, full performance characterization, genuine
Alva-at-exact-SHA integration and package redistribution rights.


## Internal unbranded diagnostics UI (2026-10-22; new Draft branch)

Source branch: `feature/internal-diagnostics-unbranded-20261022` (based on v0.3.0 release-candidate work; query GitHub for exact HEAD).

**Code implemented / static review:** five pages; public Alva page/buttons/title/sidebar removed, corresponding Qt tests rewritten; background optional authorized-sidecar execution on finalized session retained; default observation produces independent report with no Alva runtime. Documentation/translation synchronized.

**Execution evidence for this new commit:** automated unit tests, full PySide6 Qt GUI tests, Windows portable EXE, Linux smoke, genuine Alva runtime and security checks **NOT RUN**. No pass claim for the new SHA. Earlier Windows/Linux PASS at previous commit `cb1aef6a7b3f341a5040866a63ee2ce29f7894b0` is historical and cannot be generalized.

**Required before promoting:** `python -m unittest discover -s tests -v`, `python app.py --smoke`, frozen Windows EXE smoke with a clean user profile and a real accessible process, RU/EN five-page navigation, ordinary report persistence, negative missing-runtime, and separate approved-runtime sidecar test. No new workflow or runner has been enabled by this patch.

## Alva P4 real-runtime consumer proposal (2026-10-22, stacked Draft branch)

**New implementation:** `src/blackbox_rep_alva/alva_evidence_pipeline.py` is PUBLIC BlackBox-only integration code. The authorized external private Alva runtime performs four checked-pipeline operations, a real Alva structural review, an Alva AI Handoff, plus conditional re-review/classification/reporting for the three in-process host traces. Only bounded metadata returns on bridge schema 2. A schema-1 compatibility path remains for older allowed environments.

**Test source added:** `tests/test_alva_p4_evidence.py` includes 8 fake-Alva contract scenarios (success, missing measurements, ping, forged review, real-interface-shaped worker v2 handshake, forged proof, forged trace receipt, no hidden install). All test-double code is clearly labelled fake and does not authenticate or exercise private Alva.

**Execution status at this exact proposed HEAD:** focused tests **NOT RUN**, entire GUI suite **NOT RUN**, PyInstaller Windows build with helper **NOT RUN**, real private Alva import **NOT RUN**, real Windows and Ubuntu integration **NOT RUN**. Do not substitute historical CI on a different SHA. A GitHub Actions workflow was only amended to package the second PUBLIC helper file; **no new runner/workflow was created** and the new branch is not on its predefined automatic push trigger list.

**Required:** test on same SHA Windows + Ubuntu; smoke packaged EXE; private authorized venv with the exact pinned Alva SHA and verified wheel hash; verify all three host traces and four P4 stages, conservative provenance flags, bounded IPC, zero modification of observed app, fallback when private Alva missing.

## BLACK.BOX Reports integrated evidence-summary UI (new Draft change, 2026-10-22)

The standard five-page Qt Reports view now shows generic observer evidence
status and, after an authorized real P4 result, an accepted/total counter.
No platform branding or separate tab is introduced. Generic summary is
returned by the existing sidecar write routine; detailed unauthenticated
evidence remains in the sidecar's session-local file. A test for EN/RU GUI
states and a persistence test have been added.

**Actual Qt Windows and Linux execution for this new HEAD: NOT RUN**;
new P4 tests are also **NOT RUN**. Earlier CI evidence is for a different
commit. Exact SHA acceptance and one real private Alva installation test
remain blocking.

## Human-first no-AI-handoff refactor (2026-10-22 — new stacked Draft branch)

**Owner decision:** BLACK.BOX is for people and must not create AI-transfer files as normal output. A new source-only change removes `ai-handoff.json` auto-generation, removes `handoff` from CLI, deletes `src/blackbox_rep_alva/handoff.py`, removes explicit P4 `build_ai_handoff` calls and replaces `handoff_review_required` with `human_review_required` in the internal bridge. Ordinary human reports remain available; user-facing EN/RU text and tests have been adjusted. Historic Alva-host internal AI metadata is not displayed or shipped.

**Added tests:** `tests/test_human_first.py` covering real local-process session files and CLI rejection; updated `tests/test_core.py`, `tests/test_desktop_integration.py`, `tests/test_shell.py`, `tests/test_safety.py`, `tests/test_alva_sidecar.py` and `tests/test_alva_p4_evidence.py`. Tests are source files, not execution attestations.

**Current exact-SHA tests/Windows EXE/real authorized Alva:** **NOT RUN**. Earlier suite PASS does not certify this refactor; full test suite and Windows frozen-executable check are release gates.
