# BLACK.BOX Universal — UI shell contract v0.1

## Design sources and intentional differences

Original visual direction drawn from the owner's three references:

1. Windows 95-style classic desktop: teal wallpaper, horizontal taskbar,
   stacked raised panels, compact menus, precise widget boundaries.
2. Windows 95 welcome screen: rectangular dialogs, contextual help,
   safe start/close, legible typography and clear focus state.
3. Warm hand-drawn retro illustration: peach, lilac, coral, deep-outline
   strokes, pastel paper and friendly symbolic details.

The new shell **does not reproduce screenshots or redistribute their assets**.
Widgets, glyphs, color tokens, line work and QPainter chart are original.

## Pixel-inspired palette

- Desktop turquoise: #078B84
- Deep teal: #056C6D
- Warm cream: #FFF7E4
- Paper: #F7E3C9
- 90s warm beige: #DDD0B5
- Coral title stripe: #EC725D
- Peach emphasis: #FFB475
- Lilac title tabs: #CBB3D1
- Ink outline: #302C43
- Light mint signal: #83D5B3

No externally supplied font binaries: Segoe UI/Tahoma/Consolas and fallback.
System-wide text respects OS font availability; controls use 2px stepped
bevels for distinguishable hit regions. Avoid exact pixel fidelity to
Microsoft products in favor of usable modern Qt controls.

## Desktop layout

- Upper wallpaper wordmark and original drawn computer icon.
- Classical title bar with **functional** minimize, maximize/restore, close.
- File/View/Help menus, visible offline-state indicator.
- Left vertical navigation, fixed width (198px), six numbered sections.
- Scrollable content area for 1020px+ windows.
- Bottom Windows-style taskbar with Start menu and local clock.

### Six complete screens

**01 OVERVIEW** — friendly onboarding headline, four live readout cards,
CPU/RAM vector plot, current process status, choose/start/stop and latest
events. No invented sample values.

**02 PROCESSES** — searchable OS process table with PID, resident memory and
state. Explicit attachment; process names can be protected/unavailable.
Double-click row or choose Attach.

**03 EVENT LOG** — bounded in-memory observer timeline. Not a promise of
native application call traces.

**04 REPORTS** — real JSON snapshot preview (last 15 events/samples in the
preview only), full bounded snapshot export through user's save dialog.
No automatic export and no cloud upload.

**05 ALVA LAB** — visibly disconnected with three future contract stages:
observe/verify/handoff. This is an interface boundary, **not simulated
Alva execution**.

**06 SETTINGS** — polling interval selector wired to QTimer, security and
privacy disclosures.

## Minimum functional semantics

- Launch GUI locally with no network access.
- Never require administrator privileges for standard user processes.
- Process attach checks the PID and process creation time before each sample,
  preventing a reused PID from being mistaken for the selected process.
- Start/stop are wired to real read-only sampler; no simulated output.
- Keep at most 3600 samples and 300 observer events in memory.
- Status, chart, event log, report preview, buttons and navigation update.
- Child process events include only PID; no full command line or executable
  path is copied.
- Local export is user-triggered, committed with atomic os.replace, and
  contains the provenance and explicit diagnostic limitations.
- File/View/Help and taskbar Start menus work.
- Native maximize/minimize/close controls work.
- Read-only events are local and no sensitive dump attachments are made.

## Alva adapter policy

Do **not** vendor the current private Alva repository here. When an upstream
public foundation is available, introduce a dedicated adapter implementing
versioned evidence contracts, scoped read-only calls, fail-closed validation,
and a truthful AI handoff. The whole app must still work when Alva is absent.

State label remains **NOT CONNECTED** until tests prove the adapter works.
No tool-controlled model, tunnel, hidden upload, debugger injection or
unauthorized operation may be implied by a visual component.

## Test and acceptance gates

- Windows and Linux unit tests with Qt offscreen.
- Real offscreen GUI startup smoke.
- Real Windows frozen EXE smoke (not just Python import).
- Manual visual and keyboard-accessibility test on Windows 10/11.
- Actual process selection, termination/restart and PID reuse tests.
- Leak and overhead measurements during long sessions.
- No secret or absolute path material in default JSON snapshots.

A green result is claimed only after a real CI run supplies it; adding tests
and workflow YAML is not itself proof of execution.
