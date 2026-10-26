# BLACK.BOX independent engineering rules

- The public product is an independent Windows desktop process-observation tool. Do not add an external proprietary platform or user-installed runtime requirement.
- The production shell has six human-facing RU/EN pages: Overview, Processes, Event Log, Reports, Settings and Trace Decoder. Preserve the legacy five-page UniversalWindow embedding API; app.py uses DecoderWindow.
- Preserve local SQLite/JSON/HTML evidence, process selection, report comparison, updates and maintenance.
- Never infer a third-party application's internal root cause from CPU/RSS/I/O counters alone.
- The Python source package is `blackbox_core`; the Qt shell is `blackbox_universal`.
- Build portable Windows executables through the existing `.github/workflows/shell-qa.yml`; package GUI, maintenance helper and the self-contained open-source TraceEvent decoder with its licenses.
- MAIN pushes produce CI artifacts only. Do not create a tag/Release or dispatch publication without a separate explicit owner command. Do not add repeated PR/main/release runs for a development artifact.
- Gate any explicitly authorized published release on Windows/Linux tests, frozen EXE smoke, the proper version, exact asset filename and SHA-256.
- Do not publish a failing, unverifiable or partially packaged archive. No background cloud upload or hidden process injection.
- Imported traces are unverified observations. Keep unknown loss/clock alignment/symbols explicit; GC elapsed time is not a stop-the-world pause.
- Retired integration source and old historical commits may exist in Git history, but must never be part of the current source tree or distributed ZIP.
