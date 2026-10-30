# BLACK.BOX independent engineering rules

## BB-DEEP-001 patch (2026-10-29)

- Work in `patch/bb-deep-001`, based on the released v0.5.2 source. Keep the
  completed decoder patch history intact.
- Implement the owner's BB-DEEP-001 specification inside Overview; preserve
  six primary pages and the legacy five-page embedding API.
- Run **all automated tests exclusively on GitHub-hosted runners**. Local
  source editing, inspection and Git operations are allowed; do not run local
  unit tests, GUI/native acceptance, compiler checks or endurance tests.
- Use isolated `bb-deep-qa.yml`; retain real evidence, exact source identity,
  skipped checks and unconfirmed recovery. Do not publish a Release or merge
  main without separate explicit approval.
- Keep memory contents and dumps out of automatic share exports. Never claim
  Secure Desktop or physical Windows 10/11 acceptance from a hosted runner.

## Owner-approved patch workflow (2026-10-28)

- The completed decoder work used `patch/trace-decoder-phase5`; do not push
  intermediate feature edits to `main`.
- Keep source, UI, failure handling, targeted tests and evidence together as a reviewed patch.
- Run isolated `decoder-patch-qa.yml` for this branch; it never publishes.
- Main merge and official Release each require separate explicit owner approval.
- Do not remove the bilingual personal README opening or change the Outlook feedback address.

## Explicit release authorization (2026-10-28)

The owner explicitly requested both completed decoder packets be moved to main
and released. Prepare v0.5.0 as one integrated candidate. Preserve v0.4.2 and
its tag/assets. The one-shot promotion workflow dispatches the exact-SHA release gate
only for this authorized candidate; all Windows/Linux/portable and native-decoder
checks remain mandatory. Future work returns to the patch workflow above.

## Product and evidence contracts

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
