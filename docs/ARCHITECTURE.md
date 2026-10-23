# BLACK.BOX independent architecture

The standalone Python core `src/blackbox_core` contains process probing, contracts, SQLite storage, recording, reports and a CLI. The user interface `blackbox_universal` contains Qt screens, a read-only probe facade, local language selection, charts, release checking, maintenance and shortcuts.

Data flow: user selects an accessible process → explicit Attach → Start → periodic OS counter observations → SQLite append-only data → Stop → saved JSON and bilingual offline HTML reports → optional report comparison. Lifecycle events are stored in SQLite and shown in the interface. Missing values are represented as unknown.

No other runtime, paid SDK, local service, account or external platform is needed. There is no process injection and no assertion about unobservable internal causes of failures. The user may view and export local evidence; online requests are only for update checking and explicitly opened external links.

## File-to-process selection (v0.3.3)

`blackbox_universal/file_targets.py` reads bounded local metadata, optionally computes SHA-256 for files up to 16 MiB, and validates PE architecture. It does not execute, load, or modify the selected file. The Qt Processes page exposes a file picker for EXE, DLL, MSI, SYS, COM, BAT, CMD, PS1, PY, JAR and arbitrary files. DLLs, installers and scripts are metadata-only. Windows EXE files with a valid PE header can be matched to running processes using the canonical executable path (never name-only matching). The GUI launches a user-selected EXE only after a separate, explicit confirmation, with `subprocess.Popen([...], shell=False)` semantics; merely choosing a file cannot start it. Observation remains PID-based and begins only after the user clicks Start.
