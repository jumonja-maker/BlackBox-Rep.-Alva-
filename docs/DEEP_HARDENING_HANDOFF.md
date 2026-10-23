# BLACK.BOX deep hardening — single handoff candidate

**Original status at handoff: REVIEW-ONLY. Integrated into main after independent review with extra fixes for reparse ancestry and fail-closed errors; release target v0.3.6.**
**Target exact main:** `8368ccecfcc734a18e776a4db4401a829d2f537f` (BLACK.BOX Universal v0.3.5).
**Scope:** defensive patch to first-party report, trusted-release ZIP validation,
portable maintenance filesystem boundaries, multicore chart, and independent regression QA.

## Diagnosed issues and treatment

| ID | Location | Observed risk | Repair |
|----|----------|---------------|--------|
| H01 | `src/blackbox_core/report.py` | Existence check then `os.replace` can overwrite a newly created report; partial pair creation | Exclusive hard-link commit to same-volume temp files, JSON last; rollback owned HTML on conflicting target |
| H02 | `report.summarize` | Unbounded `fetchall()` event materialization, user-problem markers miscounted as observation errors | Stream events; count only actual observer_warning/error; malformed non-object event gives controlled error |
| H03 | `releases._extract_release` | Windows special device aliases, Unicode/case path aliases, ZIP special nodes, file-as-parent collisions | Prevalidate every entry with Windows-compatible rules and refuse conflicting trees before extraction |
| H04 | `releases._extract_release` | An existing staging root may be a symlink to another folder | Refuse any existing root; never follow it to extract |
| H05 | `maintenance` | Windows junction/reparse directory not always detected via `Path.is_symlink` | Detect `st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT` and block paths before destructive operations |
| H06 | `TrendChart` | Per-process CPU can exceed 100% on multicore; graph clamps at 100% yet prints 100% scale | Dynamically scale CPU axis above 100%, keep default 0–100 for ordinary samples |

### Integration scope / visual QA checklist

- Exactly five existing Qt pages and RU/EN remain. No new server, AI/Alva runtime, target-process manipulation, dependency or GitHub workflow.
- Qt offscreen render regression checks the graph above 100% (without claiming perceptual correctness).
- Windows 100/125/150/200% DPI screenshots on a physical screen remain **NOT_RUN**. Check chart ticks, legend, clipping, contrast, long Russian labels, keyboard navigation, dialogs.
- Update/uninstall: independent manual data-preservation checks on Win11 with real OneDrive/symlink/junction, antivirus file locks and failed download are **NOT_RUN**.
- Threat boundary: release ZIP and updater accept only trusted GitHub release plus expected digest; the code is not an OS sandbox. Hard links can be unavailable on some filesystems; report publication deliberately fails closed.
- Use exact-base review and target's approved GitHub Windows/Linux + frozen EXE CI. Do not merge without 00 BLACK.BOX review. No claim that these are *all* remaining bugs.

### Apply and rollback
Review the PR file diff; either cherry-pick the exact review commit onto matching base or download its unified patch. Reject automatic application against any other main SHA. Rollback is a revert of the scoped commit after testing; no user session data migration required.

### Explicit non-claims
Not a penetration test of all Windows configurations or rendered DPI themes; not a proof that arbitrary third-party applications' root causes are discoverable; not a new app release.

## Follow-up after independent review

PR #16 was merged into main after additional checks for inaccessible Windows path metadata, junctions in installation ancestors, rollback with a conflicting session directory, and simulated-DPI screenshots. The historical review-only instructions above refer to the original proposal, not the final integrated state. See [the independent review report](DEEP_HARDENING_REVIEW.md) for verified test results and remaining NOT RUN acceptance checks.
