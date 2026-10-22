# BLACK.BOX Universal

**Standalone Windows process observer — version 0.3.2**

BLACK.BOX lets ordinary Windows users select a running process, observe operating-system counters, and save offline reports. It does **not** inject code into, modify, or claim to identify internal faults of arbitrary third-party applications.

## Download and start

Download `BLACK.BOX-Universal-Windows.zip` from [GitHub Releases](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/latest). Extract the entire `BLACK.BOX-Universal` folder and double-click `BLACK.BOX-Universal.exe`. No separate Python installation, account or service is required. Keep `_internal` and `BLACK.BOX-Maintenance.exe` beside the main executable.

## Five pages

- **Overview:** CPU, selected-process RSS, process and thread counters, charts, Start and Stop.
- **Processes:** list and filter accessible Windows processes, select an explicit PID.
- **Event Log:** local observer messages; lifecycle events are stored with the session.
- **Reports:** read the current snapshot, open the saved HTML report, compare two sessions and export manually.
- **Settings:** language (Russian/English), sampling interval, update check, feedback, desktop shortcut and safe removal.

Stop saves `session.sqlite3`, `report.json` and `report.html` locally, usually under Documents. Missing measurements remain unknown, rather than being converted to zero. A disappearing process or an abnormal counter is evidence worth investigating, **not a verified explanation of an application's crash**.

## Updates and removal

The built-in update button checks **GitHub Releases**, not the latest source commit in `main`. Releases use monotonically increasing versions, a specifically named Windows ZIP asset and a published SHA-256 checksum. Updates use `BLACK.BOX-Maintenance.exe` after the main process closes. Keep a backup when testing a new build; data in Documents is preserved by the updater. Read [updater notes](docs/UPDATES_FEEDBACK_UNINSTALL.md).

## Source development

Python 3.11+, `pip install -r requirements.txt`, `pip install -e .`, then `python app.py`. Run `python -m unittest discover -s tests -v` and `python app.py --smoke`. The source package is `blackbox_core`; CLI commands are `list`, `record`, `summary`, `export`, `compare`.

This is a local observational tool, not an operating-system cleaner, automatic repair tool or internal debugger. Its use does not require administrative privileges, though protected processes may be inaccessible. See [architecture](docs/ARCHITECTURE.md) and [release gates](docs/RELEASE_GATES.md).
