# BlackBox Rep. Alva — universal local process observer (developer preview)

**An independent open-source application, not a subproject of Alva.** Select any accessible Windows process by PID, observe it without modifying it, store evidence locally, and generate offline reports that distinguish observations from inferred causes. Supported modes: standalone Python CLI and integrated retro Qt GUI; the Windows portable EXE is gated by CI.

## Integrated retro desktop — GUI + Alva-provided core

A real, original desktop shell inspired by early Windows system windows and
warm pastel pixel illustration. Its six screens are **Overview, Processes,
Event Log, Reports, Alva Lab, Settings**. Process selection, monitoring,
charts, persistent SQLite and session comparison are connected to the
standalone observer originally contributed through PR #1. The optional
Alva consumer bridge from PR #2 is available only through an explicit
CHECK button; it never enables private Alva by itself.

**For users on Windows:** once a GitHub Actions run has passed its release
checks, download the BLACK.BOX-Universal-Windows artifact, extract the
whole directory and double-click BLACK.BOX-Universal.exe. No Python, Git,
PowerShell or local AI is required for running the portable app.

**From source on Windows:** double-click Run-BLACK.BOX-Universal.bat
(Python 3.11+ must already be installed). The script installs the public
observer package into an isolated virtual environment and launches the GUI.

**In-app workflow:** Processes → choose a PID → Attach → Start Observing →
Stop Observing. Stop automatically finalizes a **new** session in
Documents/BLACK.BOX Universal/sessions with session.sqlite3, report.json,
report.html and ai-handoff.json. A separate manual JSON export is available.
Reports also lets the user select two saved session folders for comparison.
All results stay local. Private target source code and documents are not read.

**Important:** ai-handoff.json is the public offline evidence format,
**not** proof of an actual private Alva invocation. Alva Lab offers an
explicit, optional platform check; it returns UNAVAILABLE when Alva is
absent. No platform binaries or source are redistributed.

## Quick start (Python 3.11+)

Install from a local checked-out copy, with separately acquired `psutil` for recording (no network used **during execution**):

```sh
python -m pip install -e '.[process]'
python -m blackbox_rep_alva list
mkdir -p sessions
python -m blackbox_rep_alva record --pid 1234 --output sessions --duration 5 --interval 0.5
python -m blackbox_rep_alva summary sessions/session-<ID>
python -m blackbox_rep_alva export sessions/session-<ID>
python -m blackbox_rep_alva handoff sessions/session-<ID>
python -m blackbox_rep_alva compare sessions/session-<ID1> sessions/session-<ID2>
python -m blackbox_rep_alva alva-check
```

The `record` command creates **a new session directory** and prints its exact path. `export` writes a new `report.json` and `report.html` inside that session; re-export currently refuses overwrite. `handoff` is an **untrusted**, evidence-only structured packet; `permission_to_act=false` is not an AI command.

## Independence and safety

- No AI, cloud, server, account, network listener, or network dependency for operation. Runtime writes only in an explicitly selected local output directory.
- No injection, remote execution, service installation, process signals, termination, configuration mutation, or reading target document content.
- `psutil` is an optional external process-observation library; `Alva` is a **separate optional PREVIEW dependency**, loaded exclusively through `alva-check` (when explicitly installed by an authorized developer).
- A process's PID can be recycled. Binding includes its `create_time`. Access denied / process exit are explicit failures, not fake zero metrics.
- RSS rise is **not** proof of memory leak. A stalled process cannot be inferred solely from missing observations.
- SQLite is durable per committed sample (`WAL` and `synchronous=FULL`); a sudden kill can leave the session incomplete. Reports read the database without writing it.
- Do **not** redistribute the private Alva source or wheel from this public repository. See `docs/ALVA_INTEGRATION.md` and `docs/LICENSING.md`.

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m blackbox_rep_alva --help
```

See `docs/ARCHITECTURE.md`, `docs/DIAGNOSTIC_CONTRACT.md`, `docs/ALVA_INTEGRATION.md`, `docs/PRODUCT_SCOPE.md`, `docs/LICENSING.md`, `docs/QA_EVIDENCE.md`.

## Current release truth

This is a working **combined CLI + GUI candidate** in a Draft branch. Cross-platform GUI unit tests, real Windows frozen EXE CI, broad multi-app compatibility, remote/privileged observation, true per-task instrumentation, application-specific root-cause attribution, and a stable Alva consumer contract each require separate verified acceptance; do not treat the existence of tests as passing results. A process adapter cannot expose application internals without their opt-in telemetry. The source project `jumonja-maker/Alva` is private, `0.0.1.dev0` PREVIEW at pinned commit `a44297c5408628d9447bbf7db394b95ebd33fa20` (2026-10-22); this repository does not ship it.
