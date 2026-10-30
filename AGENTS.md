# BLACK.BOX independent engineering rules

## BB-INV-003 patch (2026-10-30)

- Work in `patch/bb-inv-003` from released v0.5.3 commit
  `dafa9cdb4b0f4766fc8cd2d5fd0d43579459e485`; keep earlier decoder/Deep history.
- Implement the owner's BB-INV-003 as a bounded read-only correlation layer
  over existing collectors, Investigation Engine 2 and BB-DEEP-001.
- Preserve six primary pages and the legacy embedding API. Native actions
  retain the existing helper, explicit confirmation, UAC scope and lifecycle.
- Run every application test/build exclusively on GitHub-hosted runners using
  isolated `bb-inv-qa.yml`. Local source review, edits, Git, document creation
  and read-only artifact analysis are allowed; no local application/test runs.
- No mandatory repeat of 5h30 unless actual recording/sampler/helper/resource
  ownership changes require it. Do not publish, tag or merge main.
- Deliver one complete technical document with exact patch SHA, PR, actual CI
  evidence, defects and limitations. No large handoff ZIP is requested.
- Keep unknown clocks, missing identities, import trust and incomplete sources
  explicit. Do not infer root cause, lock ownership or a fix from coincidence.

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
