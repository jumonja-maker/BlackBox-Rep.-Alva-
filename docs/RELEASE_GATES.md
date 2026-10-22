# Release checklist — not a release certificate

## Human-first release gate (current policy)

- [x] No private Alva source/wheel in public app or EXE; optional real runtime separately authorized.
- [x] Exactly five user pages, no Alva Lab or platform-setup controls.
- [x] Stop outputs SQLite + JSON + offline human-readable HTML; no `ai-handoff.json`; user CLI has no `handoff` or `alva-check` command.
- [x] Internal P4 checks use bounded observer evidence and never prove target root cause.
- [x] Automated Windows **66/66** + Ubuntu **66/66** + frozen EXE real-observer smoke at integration SHA `4b1dd4c3be1b2654e03e56b60272840a717b81b1` ([Actions #39838913391](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39838913391)); future changes require fresh exact-head CI.
- [ ] Authorized genuine Alva SHA-and-wheel-verified runtime test (not synthetic).
- [ ] Full clean Windows user acceptance of portable EXE, real target process, report, comparison and update/uninstall. See [manual test and evidence matrix](WINDOWS_RELEASE_ACCEPTANCE.md).
- [ ] Exact release dependency license inventory, privacy/security review and maintenance rollback under AV locks. See [binary dependency audit plan](DEPENDENCY_LICENSE_AUDIT.md).
- [ ] Approved final HEAD, documented acceptance and official tagged release. Do not merge merely because a Draft is mergeable.


**Current status:** integrated standalone GUI developer preview. A
Windows + Linux CI suite and real frozen Windows EXE smoke have passed on
one integrated commit; clean physical Windows desktop sign-off and
private Alva runtime QA remain outstanding. See docs/QA_EVIDENCE.md.

## Gate A — source, privacy and safety

- [x] New code stays in standalone public repository, not in private Alva.
- [x] No bundled private Alva or copied private BLACK.BOX files.
- [x] Explicit opt-in PID + output folder and no target process mutations in implemented read-only adapter.
- [ ] Re-review symlink/race/output atomicity under hostile concurrent local filesystem modification.
- [ ] Document third-party license inventory from exact resolved binaries and wheels.

## Gate B — product

- [x] Real CLI process observation and local SQLite/JSON/HTML reports implemented.
- [x] Human-first, offline default: SQLite/JSON/HTML reports only, no AI handoff or private Alva requirement.
- [ ] Windows-native tested process enumeration/attach/process-reuse/AccessDenied coverage.
- [x] Five-screen (Overview, Processes, Event Log, Reports, Settings) Qt GUI; no Alva Lab or consumer platform controls; Windows/Linux automated tests PASS at recorded SHA.
- [ ] Actual human visual review on Windows at target resolutions and scaling.
- [x] Portable Windows PyInstaller EXE built and `--smoke` launched by GitHub Actions.
- [ ] Clean end-user Windows host test, OS rights and antivirus behavior review.
- [ ] Stress test: 1k+ samples, process exit mid-write, unexpected kill, multiple sessions, disk full, path collision, symlink attacks.

## Gate C — Alva bridge and compatibility

- [x] Python-source API adapter implemented via real `alva.Component`, `ComponentHost`, scope and diagnostic outcome imports.
- [x] Unit tests with a **synthetic stand-in**, including missing Alva.
- [ ] Run exact private Alva SHA in authorized environment, verify wheel SHA, execute real host API and tests.
- [ ] Confirm diagnosis cannot leak application payload/data and does not double invoke handler under failures.
- [ ] Compare known defects before/after Alva in a blinded developer trial; do not claim ≥2x improvement without evidence.
- [ ] Owner decides public redistribution rights before bundling Alva in any release.

## Gate D — reproducibility

- [x] Executable local unittest command documented.
- [x] Windows/Ubuntu tests PASS on pinned integration commit `4b1dd4c3be1b2654e03e56b60272840a717b81b1` (66 tests each), frozen Windows GUI + Maintenance EXE smoke PASS.
- [ ] Re-run all release gates on final publication SHA and archive evidence.
- [ ] Manual rollback test of Alva wheel version and fallback standalone mode.
- [ ] Third-party independent newcomer can set up from docs and locate known seeded defect.

A standard GitHub Actions workflow was added for public Windows/Linux tests
and portable EXE smoke. Labels `PASS`, `LIMITED`, `NOT RUN`, `BLOCKED`
apply to individual checks, never to aspirational features. The standalone
public binary does not distribute the private Alva source or wheel.
