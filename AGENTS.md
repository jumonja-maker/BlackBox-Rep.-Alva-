# BLACK.BOX independent engineering rules

- The public product is an independent Windows desktop process-observation tool. Do not add an external proprietary platform or runtime dependency.
- Keep exactly five human-facing Qt pages, bilingual RU/EN, local SQLite/JSON/HTML evidence, process selection, report comparison, updates and maintenance.
- Never infer a third-party application's internal root cause from CPU/RSS/I/O counters alone.
- The Python source package is `blackbox_core`; the Qt shell is `blackbox_universal`.
- Build portable Windows executables through the existing `.github/workflows/shell-qa.yml`; package both the GUI executable and the maintenance helper.
- Gate published releases on Windows/Linux tests, frozen EXE smoke, the proper version, exact asset filename and SHA-256.
- Do not publish a failing, unverifiable or partially packaged archive. No background cloud upload or hidden process injection.
- Retired integration source and old historical commits may exist in Git history, but must never be part of the current source tree or distributed ZIP.
