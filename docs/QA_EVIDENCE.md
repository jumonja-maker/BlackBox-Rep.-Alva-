# Executed local QA evidence — 2026-10-22

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
