# BLACK.BOX research product — implementation and acceptance

This is one additive patch preserving PR17 through `32f38da4aaadf466379fbeaa85ea4ebf8141bb75`.
It preserves that branch's work, main's five pages and legacy schema1 recordings.
The original BB-DI-001 matrix is not rewritten or signed off by this document.

## Production path

`app.py` starts `UniversalWindow(isolated=True)`. `ResearchBridge` owns a
`QProcess` running the **same source/frozen application** with
`--research-worker`. Its bounded JSONL protocol supports a fixed command set;
there is no shell command execution endpoint. The child creates and owns the
legacy recorder and additive `research.sqlite3`. GUI commands do not wait for
SQLite. A command acknowledgement follows the worker's operation. Snapshots
are bounded. The synchronous `UniversalWindow()` / `ReadOnlyProbe` interfaces
remain explicit compatibility APIs, with their original regression tests.

The helper handles EOF as a close request. A 90-second stop deadline can kill
only that owned helper, leaving committed SQLite data for explicit recovery.
An interrupted native trace can require cleanup; no claim of an atomic OS-wide
rollback is made. BLACK.BOX does not terminate the observed application.

## Implemented paths

| Requirement | Code | Verification |
|---|---|---|
| Isolated capture and GUI ownership | research_bridge.py, research_worker.py, app.py | source and frozen `--research-e2e`; GUI tests |
| Standard/admin capability reporting, explicit elevation | windows_research.py, research_panel.py | Windows native tests; token-specific evidence in E2E |
| Real HWND response checks | windows_research.py | controlled native window fixture |
| Real asynchronous WCT | windows_research.py | current-thread and controlled mutex fixture; denied/unsupported states retained |
| Explicit minidump | windows_research.py | actual owned child dump; MDMP signature |
| Explicit named ETW/WPR | WprCapture | real WPR roundtrip when runner supports the source |
| Optional EventPipe collection | runtime_trace.py | local installed dotnet-trace required; bounded subprocess lifecycle |
| Native PDB identity and offline stacks | symbols.py | actual DbgHelp identity; optional local CDB |
| Preparation and receipt verification | preparation.py, instrumentation.py | real standalone Python, C#, C++ and Node clients where toolchains exist |
| Electron instrumentation | generated CJS client | Node event protocol tested; Electron contentTracing hook uses explicit application integration |
| Source-linked interval evidence | casebook.py, research_panel.py | indexed interval queries, paging, linked operation boundaries |
| Timeline selection/zoom and large history paging | EvidenceTimeline, evidence_page | Qt event and SQL paging tests |
| Exact all-run action statistics | action_statistics | 101-run regression; no old twenty-run summary cap |
| Experiment comparison | compare_cases | workload/profile/environment/privilege mismatch flags; no causal speedup claim |
| Observer resource/coverage data | ResearchSession._health | real CPU/RSS/IO observations; missing loss counters remain NULL |
| Streaming HTML/JSON/CSV and portable ZIP | export_case | real roundtrip, checksums, adversarial HTML/ZIP tests |
| Recovery without source modification | recover_case | original hash preserved, active owner rejection |
| Bilingual errors and compact existing pages | research_messages.py, ResearchPanel | RU/EN UI checks; still exactly five pages |
| Controlled reproducible applications | research_fixtures.py | 12 actual behaviours, including native Windows fixtures |

## Deliberate evidence boundaries

ETL/nettrace/Chromium traces are preserved as raw artifacts. This patch does
not pretend to decode every provider or resolve every native frame. Optional
offline CDB output retains symbol uncertainty. Application events and imported
SQLite are untrusted observations; a token routes a cooperative stream and
does not establish OS attestation. Node runtime thread IDs never become native
Windows TIDs. Different source clocks retain identity; receipt time is used
for cross-source placement, not falsely called execution time.

Export omits raw artifacts by default and declares every omission. Structured
events and paths can still contain sensitive data. CSV formula prefixes are
escaped; original values remain in JSON/SQLite. Hashes establish integrity
relative to the manifest, not authenticity or correctness.

## Repeatable commands

```text
python -m unittest discover -s tests -v
python app.py --smoke
python app.py --research-e2e research-e2e
python -m blackbox_core research --help
python -m blackbox_core research record --pid PID --output ROOT --seconds 60
python -m blackbox_core research record --pid PID --output ROOT --seconds 28800
python -m blackbox_core research record --pid PID --output ROOT --seconds 3600 --detailed
python -m blackbox_core research export SESSION DESTINATION.zip
python -m blackbox_core research verify DESTINATION.zip
```

The 8-hour and 1-hour commands measure real elapsed time. Running a shorter
fixture or generating many synthetic rows never certifies endurance. The
ordinary frozen smoke remains separate from the new frozen action/client/
incident/evidence/export/verification/repeat/comparison roundtrip. Neither
roundtrip alone signs off every original BB-DI-001 requirement.

CI results must be attributed to the exact commit SHA. Native source skips,
optional missing tools, alternate Windows token testing and long endurance
runs must remain explicit in the final validation report. No merge/release is
performed by this patch.
