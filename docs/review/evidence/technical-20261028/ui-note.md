# GUI audit fixes: BB-03, BB-04, BB-09 and completed-worker retention

Base: 765156068a2d2f0171be4d048e74c7676feba143. No commit/push performed by this agent.

## BB-03: Stop remains available during optional work

The previous stopping predicate treated every pending helper command as finalization. Actual isolated helper tests started recording, called the real ResearchPanel Verify/Export actions with temporary file-dialog paths and immediately observed Stop disabled. Both tests failed before the change. The helper API was not replaced by a stub. They exercise the real command/GUI/SQLite completion boundary; host PID namespace limitations mean they do not certify the identity/accuracy of native self-CPU observations.

ResearchBridge now exposes `stopping`: closing or an actual pending stop/quit. Other controls retain their prior conservative generic-pending predicate. The Stop button uses the precise finalization state, and the window's stop handler refuses to enqueue another Stop while one is already pending. The verify test clicks the actual button, checks one queued Stop even after a second delivered handler call, and checks the resulting session metadata is COMPLETED. Export receives its own positive cancellation/control test. This does not promise an absolute stop latency on every optional/native operation.

## BB-04: exactly-once retry across a modal nested Qt event loop

A genuine schema-1 SQLite session containing 4097 measurements makes the real InvestigationWorker return the long-session consent payload. A real QMessageBox.exec nested loop allows worker.finished to clear the worker before Yes. Before the fix that case produced no result or export; the existing immediate-consent order already worked.

Both `_investigation_ready` after Yes and `_investigation_finished` now invoke one scheduling method, which consumes a pending retry only after the worker is cleared and the busy flag is false. Tests cover Yes after finished, Yes before finished and No after finished. Each accepted case produces exactly one HTML + one JSON, reports 4096 selected measurements and invokes begin twice total. No produces no analysis export.

## BB-09: isolate the language test from real QSettings and suite order

The original test was loaded from Git in a separate process with a fresh XDG_CONFIG_HOME and failed: it required Russian details while a clean app defaulted to EN. This isolated reproduction is saved in ui-language-red.log. The fixture now supplies a temporary INI QSettings instance per test; the test explicitly selects RU and additionally checks EN. It neither reads nor overwrites the operator's language. Standalone execution with fresh settings passes (ui-language-green.log). Production language defaults are unchanged.

## Additional confirmed adjacent retention

Every finished InvestigationWorker remained a parent-owned QObject until window destruction. A regression found the old completed worker still in `findChildren(InvestigationWorker)` after Qt DeferredDelete processing. `_investigation_finished` now releases the old finished worker with deleteLater, like the existing ReportWorker path. Three completed investigations leave no InvestigationWorker children. This is a confirmed QObject-retention fix, not proof of whole-application RSS leak freedom.

## Evidence and tests

- Valid baseline six new scenarios: 4 FAIL (Verify, Export, modal Yes race, retained worker) and 2 positive PASS (immediate Yes and modal No). ui-red.log. The earlier fixture typo was corrected before this recorded six-scenario baseline; it is not a product defect.
- Final targeted group: 12/12 PASS, 0 SKIP (six new tests plus existing six Investigation integration tests), 8.609 s. ui-targeted-green.log.
- Original standalone translation fixture: 1 FAIL, 0.246 s. Corrected standalone test: 1 PASS, 0.331 s.
- Broader experimental UI run is NOT a passing acceptance: an existing library-export test failed and the process later stopped advancing after decoder test output. The library export was isolated and its real helper response was `NoSuchProcess: process PID not found (pid=13)`, recorded in ui-library-export-diagnostic.log. This is the known sandbox PID-namespace/psutil mismatch, not a demonstrated privacy or UI regression. The later decoder/teardown stall has not been diagnosed. The exploratory run remains in ui-green.log; root is informed and will use exact-source integration/CI. It must not inflate the PASS count above.

Runtime: Python 3.12, PySide6 6.11.3, psutil 7.2.2, QT_QPA_PLATFORM=offscreen; `PYTHONPATH=src:.:tests ../bb-venv/bin/python`. Real Windows GUI/frozen acceptance remains the parent integration run. Product source is frozen after these changes.
