# Release checklist — not a release certificate

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
- [x] AI-independent/offline runtime paths with separate AI evidence export.
- [ ] Windows-native tested process enumeration/attach/process-reuse/AccessDenied coverage.
- [x] Six-screen functional Qt GUI built and automated Windows/Linux tests PASS.
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
- [x] Ubuntu and Windows automated test matrix on pinned commit `cb1aef6a`.
- [ ] Re-run all release gates on final publication SHA and archive evidence.
- [ ] Manual rollback test of Alva wheel version and fallback standalone mode.
- [ ] Third-party independent newcomer can set up from docs and locate known seeded defect.

A standard GitHub Actions workflow was added for public Windows/Linux tests
and portable EXE smoke. Labels `PASS`, `LIMITED`, `NOT RUN`, `BLOCKED`
apply to individual checks, never to aspirational features. The standalone
public binary does not distribute the private Alva source or wheel.
