# Release checklist — not a release certificate

**Current status:** developer preview with local Linux Python tests only. DO NOT label public Windows binary supported before executing a signed-off test protocol.

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
- [ ] Working and visually reviewed Windows desktop GUI.
- [ ] Portable Windows EXE packaging test, launch on clean Windows host, rights and antivirus behavior review.
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
- [ ] Ubuntu and Windows test matrix with exact source SHA, stdout/stderr, return code and environment.
- [ ] Manual rollback test of Alva wheel version and fallback standalone mode.
- [ ] Third-party independent newcomer can set up from docs and locate known seeded defect.

No new GitHub Actions or billable infrastructure was added. Labels `PASS`, `LIMITED`, `NOT RUN`, `BLOCKED` apply to individual checks, never to aspirational feature lists.
