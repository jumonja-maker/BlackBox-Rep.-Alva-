# BLACK.BOX Universal

**ENGLISH** · [Русский / README.ru.md](README.ru.md)

**v0.3.1 Standalone updater QA build** · Portable Windows desktop application · Local read-only process observer

BLACK.BOX Universal monitors a user-selected accessible Windows process. It records OS-level CPU, RSS and process I/O evidence locally without injecting or modifying the target. Optional evidence-quality checks run after Stop **only when the authorized private Alva runtime is actually bundled**.

**The public v0.3.1 test Release does NOT bundle Alva.** It exists to test the official GitHub Releases update channel from v0.3.0. The separately prepared private Alva-built ZIP remains under independent Windows, licensing and owner acceptance. No Python installation is required to run either portable Windows build.

**Download:** [GitHub Releases](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases), choose `BLACK.BOX-Universal-Windows.zip`. The Release is a user-directed QA/test build, not certified full-Alva production software.

## Download and start (Windows x64)

1. Open [GitHub Releases](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases) and download the `BLACK.BOX-Universal-Windows.zip` asset from the v0.3.1 test Release (or use the Actions standalone artifact while release QA is pending).
2. Extract the **entire** `BLACK.BOX-Universal` directory. Do not take `BLACK.BOX-Universal.exe` out of that folder: its `_internal` files and the maintenance EXE are required.
3. Double-click **`BLACK.BOX-Universal.exe`**. No account, terminal, or administrator elevation is requested for ordinary accessible processes.
4. Use **RU / ENG** at the bottom of the left sidebar to change interface language. The preference is saved.

The app is **portable**: it does not need a Windows installer or install a background service. Protected or elevated processes may be inaccessible under ordinary user rights.

## Features

| Screen / feature | What it does |
| --- | --- |
| **01 — Overview** | Current target, process CPU %, selected process RSS memory, target + visible child-process count, number of samples, live CPU/memory graph, Start / Stop controls and recent observer messages. |
| **02 — Processes** | Refresh the OS process list, search by process name or PID, choose a row and **Attach**. A double-click can also attach. Attaching alone does **not** start recording. |
| **03 — Event Log** | Local BLACK.BOX observer events such as process selection, start/stop, unavailable process or sampling/storage errors. **Not** the application's internal application log or Python stack trace. |
| **04 — Reports** | Show a JSON snapshot of current observations, explicitly save a snapshot, and **compare two saved session directories** (before/after CPU, RSS, sample count, children and elapsed time). Comparison does not prove a regression. |
| **05 — Settings** | Set sampling to **1 / 2 / 5 seconds**; enable/disable the GitHub Releases check at startup; create a Windows desktop shortcut; request portable app uninstallation. |
| **Sidebar / toolbar** | **GITHUB** opens this repository; **E-MAIL** opens a draft to `jumonjescu@mail.ru`; **RU / ENG** changes UI language. **Check Updates** checks official GitHub Releases. |

### Metrics actually collected

BLACK.BOX uses the read-only `psutil` process adapter. Each recorded sample may contain:

- Elapsed time, **CPU %** and **RSS resident memory** of the selected root process.
- Thread count and **number of child processes** (if accessible).
- Bytes read/written via OS **process I/O counters** (if supported/accessible).
- Explicit observer failure states such as `ACCESS_DENIED`, `PROCESS_EXITED`, `PID_REUSED`, `SAMPLE_UNAVAILABLE` and `STORAGE_ERROR`.

The CPU/memory graph is based on actual samples; unavailable metrics are not fabricated. The interface keeps a bounded recent history while each sample is committed to local SQLite. **RSS is the selected process's memory, not a proven total for every child process.**

## First observation: 6 steps

1. Open **02 PROCESSES**, press **REFRESH**, search by name or PID and select your program.
2. Press **ATTACH SELECTED PROCESS** (or double-click it). BLACK.BOX checks whether the process is accessible.
3. Return to **01 OVERVIEW** and press **START OBSERVING**. A new session folder and SQLite database are created.
4. Use the target program normally. Observe the live indicators and the **03 EVENT LOG**.
5. Press **STOP OBSERVING**. BLACK.BOX finalizes the session and generates HTML and JSON reports for human review automatically.
6. Open **04 REPORTS** for a snapshot, or **COMPARE TWO SESSIONS** and select two prior session folders.

If the observed program closes, its PID changes or access is denied, BLACK.BOX records the observer failure instead of claiming that the target application was diagnosed.

### Session files and location

Default Windows directory:

`%USERPROFILE%\Documents\BLACK.BOX Universal\sessions\session-<unique-id>`

| File | Contents |
| --- | --- |
| `session.sqlite3` | Durable timestamped sample series, session metadata and recorded observer error codes (SQLite WAL storage). |
| `report.json` | Session state, start/end time, number of samples, peak RSS, peak CPU, child count and observer errors. |
| `report.html` | Browser-readable version of the process observation report. |
| `alva-diagnostics.json` | **Internal developer evidence only:** emitted if an authorized external runtime was previously provisioned; never proof of the observed application's root cause. |

The Reports screen also offers an **explicit** JSON snapshot export to a location you select. Snapshots and saved sessions may contain process names, PIDs or paths: **review before sharing**.

## Alva integration: exact scope

The separate private Alva platform remains PRIVATE. BLACK.BOX already contains the public Python adapters for ComponentHost checked operations, three host traces, four P4 observer-quality checks and structural evidence review. The real Alva worker passed a Windows private-runner compatibility test, but the **public portable EXE is standalone and does not embed actual Alva modules**.

A full owner-built runtime bundle must pass its own Windows executable smoke and licensing checks. When genuinely included, Alva runs automatically after Stop and puts an unbranded evidence-quality section into the usual `report.html`, plus `evidence-checks.json`. The checks describe the quality of collected BLACK.BOX observations — never a proven root cause inside the target application. No Alva Lab or AI Handoff is added.

## Updates, shortcut, uninstall

**Updates:** click **CHECK UPDATES** on the upper toolbar. The button turns **green only if an official newer GitHub Release** has a matching approved Windows ZIP and a verifiable SHA-256 digest. Checks run at startup by default (disable in Settings). Downloads/installation require confirmation; the helper verifies the archive, replaces previous application files after the GUI closes, preserves local data and attempts to clean up the previous version. **CI artifacts and Draft PRs are not updates**; no green indicator is expected until an actual later Release exists.

**Shortcut:** in **Settings → CREATE DESKTOP SHORTCUT**. Creates a Windows `.lnk` pointing to the portable EXE. If the icon appears generic, it does not affect monitoring.

**Uninstall:** in **Settings → UNINSTALL APPLICATION**, confirm removal. A separate `BLACK.BOX-Maintenance.exe` waits for the main process to exit, removes the portable application directory and moves any `logs/`, `sessions/` or `reports/` inside it to a preserved folder under the user's Documents. Existing sessions in the default Documents location are **not deleted**. This is **portable-folder removal**, not registration in Windows “Installed Apps.” Manual physical-Windows update/uninstall acceptance is still pending.

[Update and removal details](docs/UPDATES_FEEDBACK_UNINSTALL.md)

## Source and developer CLI (optional)

Windows source users with Python 3.11+ can double-click `Run-BLACK.BOX-Universal.bat`. It creates a project virtual environment, installs the public dependencies and starts the GUI. Alternatively:

```sh
python -m pip install -r requirements.txt
python -m pip install -e .
python app.py
```

The core also has a separate Python CLI (not required for normal Windows users):

```sh
python -m blackbox_rep_alva list
mkdir sessions
python -m blackbox_rep_alva record --pid 1234 --output sessions --duration 10 --interval 0.5
python -m blackbox_rep_alva summary "sessions/session-REPLACE_WITH_ID"
python -m blackbox_rep_alva compare "sessions/session-REPLACE_WITH_FIRST_ID" "sessions/session-REPLACE_WITH_SECOND_ID"
```

For CLI recording, replace PID `1234` with the target PID and replace session placeholders with the actual folder name printed by `record`. The `export` CLI command is also available; see `python -m blackbox_rep_alva --help`. Run tests with `python -m unittest discover -s tests -v`.

## Privacy, limitations and project status

- **Local-first:** no cloud account, log upload, tunnel, debugger injection, target modification or background service for observation. The optional update check contacts GitHub for public release metadata only. GitHub/email buttons open the user's browser/email app; they do not send diagnostics.
- **Read-only scope:** ordinary accessible processes only. BLACK.BOX does **not** automatically read application source code, passwords, documents, stack traces or arbitrary internal exception logs; it does **not** prove leaks, defects or root causes from resource metrics.
- **Alva licensing:** new BLACK.BOX code is [MIT licensed](LICENSE); private Alva is **not relicensed or redistributed**. PySide6, psutil and other packaged dependencies have separate license obligations to review before final release.
- **Quality:** the v0.3.0 RC passed **49 Windows and 49 Linux automated tests** plus frozen Windows GUI/helper startup smoke on [Actions run #39822604822](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39822604822). **Real private-Alva integration, end-user update/uninstall and broad Windows compatibility have not been signed off.**

**Repository:** [BlackBox Rep. Alva](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-) · **Feedback:** [jumonjescu@mail.ru](mailto:jumonjescu@mail.ru) · [Architecture](docs/ARCHITECTURE.md) · [Release gates](docs/RELEASE_GATES.md)
