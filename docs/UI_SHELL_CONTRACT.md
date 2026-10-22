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
- Left vertical navigation, fixed width (198px), five numbered sections.
- Scrollable content area for 1020px+ windows.
- Bottom Windows-style taskbar with Start menu and local clock.

### Five complete screens

**01 OVERVIEW** — friendly onboarding headline, four live readout cards,
CPU/RAM vector plot, current process status, choose/start/stop and latest
events. No invented sample values.

**02 PROCESSES** — searchable OS process table with PID, resident memory and
state. Explicit attachment; process names can be protected/unavailable.
Double-click row or choose Attach.

**03 EVENT LOG** — bounded in-memory observer timeline. Not a promise of
native application call traces.

**04 REPORTS** — live JSON snapshot preview (last 15 events/samples in
preview), SQLite-backed finalized JSON/HTML human-readable evidence
stored automatically on Stop, comparison between two selected session folders,
and optional full local snapshot export via a user-selected path. No cloud upload.

**05 SETTINGS** — polling interval selector wired to QTimer, security and
privacy disclosures, portable maintenance.

The app exposes no user-facing branded platform page. Diagnostics are a
behind-the-scenes part of the completed-session evidence flow. See
`docs/INTERNAL_DIAGNOSTICS_NO_BRAND.md`.

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
- Every explicit Start begins a new durable SQLite WAL session under the
  user's Documents/BLACK.BOX Universal/sessions root. Stop finalizes the
  core JSON/HTML report for human review. Manual snapshot export is
  separately user-triggered, atomically committed with os.replace.
- File/View/Help and taskbar Start menus work.
- Native maximize/minimize/close controls work.
- Read-only events are local and no sensitive dump attachments are made.

## Internal platform adapter policy (not a screen)

The application automatically stores its own SQLite / JSON / HTML evidence on STOP. No private platform is needed for this.

If and only if a trusted external interpreter was **previously authorized**,
the already-integrated sidecar can run in the background after a finalized
session, without separate navigation or the former Alva Lab button.
The sidecar uses three limited scoped operations; it cannot infer root cause,
cannot attest installed package origin and never installs/downloads Alva.
The public EXE does not bundle the private library. In the absence of that
runtime, ordinary report generation remains unchanged and shall not claim
genuine Alva execution. Runtime setup/disconnect is now maintainer-facing,
not presented as an end-user feature.

## Test and acceptance gates

- Windows and Linux unit tests with Qt offscreen.
- Real offscreen GUI startup smoke.
- Real Windows frozen EXE smoke (not just Python import).
- Manual visual and keyboard-accessibility test on Windows 10/11.
- Actual process selection, termination/restart and PID reuse tests.
- Leak and overhead measurements during long sessions.
- No sensitive file contents or environment variables in default JSON
  snapshots. Local session path, process name and PID are intentionally
  visible to the owner; users must review exports before sharing.

A green result is claimed only after a real CI run supplies it; adding tests
and workflow YAML is not itself proof of execution.
