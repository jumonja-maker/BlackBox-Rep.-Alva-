# BlackBox Rep. Alva — universal local process observer (developer preview)

**An independent open-source application, not a subproject of Alva.** Select any accessible Windows process by PID, observe it without modifying it, store evidence locally, and generate offline reports that distinguish observations from inferred causes. Supported modes: standalone Python CLI and integrated retro Qt GUI; the Windows portable EXE is gated by CI.

## BLACK.BOX Universal v0.3.0 — first public release candidate

The v0.3.0 candidate unifies **the real, open-source process observer**
with the retro Qt desktop, session-local SQLite WAL, JSON/HTML and offline
AI Handoff. Works with any accessible process without modifying its code,
without an account or a local AI. The first official GitHub Release is
**not** the same as a Draft PR or Actions artifact; the candidate must
pass release acceptance before a public version tag.

### Genuine *optional* Alva runtime connection (without republishing Alva)

Open **Alva Lab → CONNECT EXTERNAL ALVA**, then select a trusted
`python.exe` from your *separately authorized* Alva environment.
BLACK.BOX uses a public `-I` isolated subprocess worker to execute
**three real scoped Alva ComponentHost operations** checking observer
samples, session lifecycle and observer-error evidence. After Stop, an
opted-in user also receives `alva-diagnostics.json` automatically.
Without a connected platform, standalone observation, reports,
comparison and ordinary `ai-handoff.json` continue as normal.

The private Alva package is **never bundled, downloaded or installed**
by the public EXE. Its API/commit provenance must be verified separately.
No automatic diagnosis of arbitrary native source-code root causes is
claimed. See [v0.3 external Alva protocol](docs/ALVA_EXTERNAL_RELEASE_V030.md).

## Retro desktop v0.2 — language, community and clean portable maintenance

The next version adds compact **GITHUB / E-MAIL / RU / ENG** buttons in the
lower left sidebar and **CHECK UPDATES** in the upper toolbar, integrated
with the existing Windows 95 + peach/lilac theme.

- GitHub opens the public repository; E-MAIL starts a local message to
  `jumonjescu@mail.ru`. No report is transmitted by these buttons.
- RU/ENG switches interface labels, menus, page titles, tips and graph text
  immediately, with locally remembered preference; raw observer evidence
  and JSON field names remain untranslated.
- The update indicator is **green only for a newer official GitHub Release**
  with an authenticated asset digest `sha256:...`. Checking metadata at
  startup can be disabled under Settings; it contacts GitHub but never uploads
  logs/process identifiers. Download/install needs user confirmation.
- Updating checks size, SHA-256 and ZIP paths before invoking the separate
  `BLACK.BOX-Maintenance.exe`. After the main EXE closes, the old portable
  directory is replaced, kept logs are transferred, and the old version is
  removed. An interrupted update has rollback protection.
- **Create Desktop Shortcut** builds a real Windows `.lnk` pointing to this
  app, using its original pixel-retro icon.
- **Uninstall Application** asks for confirmation, closes the app and removes
  the portable directory. `logs/`, `sessions/` and `reports/` inside it
  are moved into Documents; existing external session evidence is retained.

**Important:** GitHub Actions artifact builds are *not* release updates.
The updater will show a green indicator only when the maintainer publishes
a newer `vX.Y.Z` GitHub Release. The private Alva library is not included.
Portable uninstall and in-place update need additional manual Windows
acceptance; CI runs include unit/fault-injection and frozen EXE smoke.

Detailed behavior and safety rules:
[feedback, updating and uninstalling](docs/UPDATES_FEEDBACK_UNINSTALL.md).

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

- No AI, cloud, server, account or network listener needed for process observation. The optional GitHub Releases version check (enabled by default) uses an outbound HTTPS metadata request; it can be disabled in Settings and never uploads reports. Runtime writes only in an explicitly selected local output directory.
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
