# BLACK.BOX Universal + Alva

**Retro Desktop Shell v0.1** · Windows-first · PySide6 · local-first · read-only by default

BLACK.BOX Universal is a standalone process-observation desktop built for people
who do **not** want to modify their programs, install a local AI, open tunnels,
or upload private diagnostics to a service.

This is the **new public product**, separate from the existing private
BLACK.BOX A.I.O monitor. They must not be confused or auto-merged.

## What is already implemented

A fully navigable original retro desktop UI combining early graphical OS
window geometry with warm peach/coral/pixel-art motifs:

- **Overview** — live CPU, RSS memory, process-tree count, sample count and
  a graph of actual process measurements (not generated demo telemetry).
- **Processes** — refresh, search by name/PID, select a Windows process,
  explicitly attach, start/stop observation.
- **Event log** — observer start/stop and visible child-process lifecycle.
- **Reports** — inspect real recorded observations, save JSON **only when
  you select a location**. No hidden uploads.
- **Alva lab** — deliberate **NOT CONNECTED** integration surface and
  diagnostic contract plan, ready for the official Alva foundation.
- **Settings** — working adjustable polling interval (1 / 2 / 5 seconds),
  privacy and limitation notices.

Additional desktop conventions: movable native application window, three
functional classic title controls, File/View/Help menus, Start menu,
taskbar clock, vector monitor icon and original retro-style QSS.
No external images, fonts, copyrighted Microsoft UI assets or runtime icon pack.

## For ordinary Windows users

A successfully built portable EXE is uploaded by the **Windows Portable**
GitHub Actions job. Download that job's artifact, extract the **whole**
BLACK.BOX-Universal folder and double-click BLACK.BOX-Universal.exe.
No Python or Alva installation is needed to **run** that artifact.

**Until CI proves the artifact passes, do not describe the Windows EXE as
released.** The CI workflow is provided, but availability is conditional on
successful GitHub Actions execution.

To run **from source** with Python 3.11+, use the included
Run-BLACK.BOX-Universal.bat (double-click it), or:

~~~sh
python -m pip install -r requirements.txt
python app.py
~~~

For developers and CI only:

~~~sh
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
QT_QPA_PLATFORM=offscreen python app.py --smoke
~~~

On Windows, set QT_QPA_PLATFORM=offscreen in the CI job (already configured).
You do not need that setting to run the normal desktop.

## Observation boundaries

| Available in shell v0.1 | Not yet implemented |
|---|---|
| Read-only process sampling using psutil | Deep call stacks inside arbitrary EXEs |
| Target identity + child-process lifecycle | ETW capture, Windows dump collection |
| CPU / process-tree RAM / thread counts | Kernel drivers, administrator escalation |
| Local structured JSON export | Auto-diagnosis of native root causes |
| Lightweight real event log | Connected Alva ComponentHost / AI Handoff |
| Offline GUI without account | Network service, server, tunnel, telemetry upload |

**A high CPU reading does not prove a bug. Memory growth does not prove a leak.**
Closed-source application internals are not observable without suitable OS
evidence, debug symbols or cooperative instrumentation.

Selected process name and PID appear in local JSON; inspect files before
sharing. BLACK.BOX does not collect documents, passwords, process memory
contents, full command lines or environment variables.

## Design

See [docs/UI_SHELL_CONTRACT.md](docs/UI_SHELL_CONTRACT.md) for layout,
colors, navigation, accessibility, theme implementation and Alva boundaries.
The three user-supplied visual references inspired a new original shell.
Their image files are **not** copied into this public project.

## Development

- Main entry: app.py
- Desktop shell: blackbox_universal/window.py
- Vector widgets: blackbox_universal/widgets.py
- Color system: blackbox_universal/theme.py
- Local process observer: blackbox_universal/monitor.py
- Offscreen UI and observer tests: tests/test_shell.py
- Windows/Linux CI and portable EXE: .github/workflows/shell-qa.yml

The Alva upstream foundation, public distribution terms and diagnostic APIs
should be agreed upon separately **before** adding Alva to this repository.
In particular, do not copy the private Alva platform into this public repo
without a deliberate license and distribution decision.

This is the standalone public shell baseline; the first official Alva MAIN
foundation can be layered on top through review, tests and a documented PR.
