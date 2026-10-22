# BLACK.BOX Universal

**ENGLISH** · [Русский / README.ru.md](README.ru.md)

**v0.3.0 Release Candidate** · Portable Windows desktop application · Open-source observer · Optional private Alva integration

BLACK.BOX Universal monitors a **user-selected, accessible process** without installing an agent into that application. It collects OS-level performance evidence, stores each session locally, and creates reports for users, developers, or an AI chat **when the user chooses to share them**.

**No Python, local AI, Git, or PowerShell is required to run the Windows portable EXE.** Alva is **not** required for normal operation.

> **Release status:** v0.3.0 is a tested release candidate in [Draft PR #7](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/7), **not yet an official stable GitHub Release**. The current repository `main` remains separate until this PR is accepted. Windows/Linux automated tests and frozen-EXE startup checks have passed; manual Windows update/uninstall testing and a real private-Alva installation test are still outstanding.

## Download and start (Windows x64)

1. Open the [GitHub Actions builds](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions) for this candidate. In a **successful** *BLACK.BOX Universal - Shell QA and Windows portable* run, download the `BLACK.BOX-Universal-Windows` artifact. An official [Releases page](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases) will be used once the release is published.
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
| **05 — Alva Lab** | Check or connect a separately authorized Alva Python installation, inspect scoped diagnostic results, or disconnect it. Alva is optional and never installed by BLACK.BOX. |
| **06 — Settings** | Set sampling to **1 / 2 / 5 seconds**; enable/disable the GitHub Releases check at startup; create a Windows desktop shortcut; request portable app uninstallation. |
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
5. Press **STOP OBSERVING**. BLACK.BOX finalizes the session and generates HTML, JSON and an offline AI handoff automatically.
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
| `ai-handoff.json` | Small, **untrusted** evidence summary suitable for manually giving to a developer or AI chat. `permission_to_act=false`; it is **not** an automatic ChatGPT connection. |
| `alva-diagnostics.json` | **Optional:** bounded scoped Alva diagnostic outcome, only after a user has connected a separate Alva environment. |

The Reports screen also offers an **explicit** JSON snapshot export to a location you select. Snapshots and saved sessions may contain process names, PIDs or paths: **review before sharing**.

## Alva: private platform, optional integration

BLACK.BOX Universal has its **own public observation core** (process sampling, SQLite and basic reports). It also provides an integration with **Alva**, a **separate, private Python developer/diagnostics platform** maintained at [jumonja-maker/Alva](https://github.com/jumonja-maker/Alva) (access required).

**Important distribution distinction:**

- The public BLACK.BOX source and Windows EXE **do not include the private Alva package, source code or wheel**, and cannot silently install it.
- Authorized users may separately install Alva in a trusted Python **3.11+** environment. BLACK.BOX is fully functional without it.
- The Alva integration targets a **preview API**, pinned in the current engineering contract to commit `a44297c5408628d9447bbf7db394b95ebd33fa20`. Selecting Python or receiving an API response **does not verify** the installed package's Git provenance or redistribution rights.

### Connect an authorized Alva installation

1. Obtain Alva access/installation permission separately and install it **outside the public BLACK.BOX directory** in its own Python environment.
2. Launch BLACK.BOX and open **05 ALVA LAB**.
3. Click **CONNECT EXTERNAL ALVA** and select the `python.exe` belonging to that environment, for example `C:\path\to\authorized-env\Scripts\python.exe`. Only select a Python interpreter you trust.
4. BLACK.BOX starts a small **public** local worker with that interpreter (`python -I`, no tunnel, server or PowerShell). A successful check enables use of the connection; **DISCONNECT** disables subsequent calls.
5. Record a session and press **STOP**. With Alva connected, the worker checks three fixed boundaries using Alva's **`Component`**, **`ComponentHost`**, scoped permissions, **`invoke_with_diagnostics`** and checked adapter call: **samples**, **session lifecycle** and **observer errors**. Results are saved locally to `alva-diagnostics.json`.

Only bounded summary counters/flags are sent to that worker; **not** raw events, target PID/name, absolute target paths, documents, credentials or process memory. A failed/absent Alva installation does not disable standalone monitoring.

**Alva does not automatically reveal the failing line of code in an arbitrary third-party EXE.** Its scoped diagnostic result verifies BLACK.BOX's own component boundaries, **not** the observed program's internal execution or the true root cause. Genuine execution with the pinned private Alva package still requires separately documented acceptance testing.

See [Alva setup and exact contracts](docs/ALVA_EXTERNAL_RELEASE_V030.md) and [licensing](docs/LICENSING.md).

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

For CLI recording, replace PID `1234` with the target PID and replace session placeholders with the actual folder name printed by `record`. The `export`, `handoff` and `alva-check` CLI commands are also available; see `python -m blackbox_rep_alva --help`. Run tests with `python -m unittest discover -s tests -v`.

## Privacy, limitations and project status

- **Local-first:** no cloud account, log upload, tunnel, debugger injection, target modification or background service for observation. The optional update check contacts GitHub for public release metadata only. GitHub/email buttons open the user's browser/email app; they do not send diagnostics.
- **Read-only scope:** ordinary accessible processes only. BLACK.BOX does **not** automatically read application source code, passwords, documents, stack traces or arbitrary internal exception logs; it does **not** prove leaks, defects or root causes from resource metrics.
- **Alva licensing:** new BLACK.BOX code is [MIT licensed](LICENSE); private Alva is **not relicensed or redistributed**. PySide6, psutil and other packaged dependencies have separate license obligations to review before final release.
- **Quality:** the v0.3.0 RC passed **49 Windows and 49 Linux automated tests** plus frozen Windows GUI/helper startup smoke on [Actions run #39822604822](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39822604822). **Real private-Alva integration, end-user update/uninstall and broad Windows compatibility have not been signed off.**

**Repository:** [BlackBox Rep. Alva](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-) · **Feedback:** [jumonjescu@mail.ru](mailto:jumonjescu@mail.ru) · [Architecture](docs/ARCHITECTURE.md) · [Release gates](docs/RELEASE_GATES.md)
