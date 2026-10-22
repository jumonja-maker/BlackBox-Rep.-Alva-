# BlackBox Rep. Alva — universal offline process observer (developer preview)

Independent open-source technical observer for any user-selected accessible process, even when the target does not use Alva. No AI, server or internet is required at runtime.

## Quick start (Python 3.11+)

Install `psutil>=6,<8` from your approved local wheelhouse, or install `.[process]` in an authorized Python environment.

```sh
PYTHONPATH=src python -m blackbox_rep_alva list
mkdir -p sessions
PYTHONPATH=src python -m blackbox_rep_alva record --pid 1234 --output sessions --duration 5
PYTHONPATH=src python -m blackbox_rep_alva summary sessions/session-<ID>
PYTHONPATH=src python -m blackbox_rep_alva export sessions/session-<ID>
PYTHONPATH=src python -m blackbox_rep_alva handoff sessions/session-<ID>
PYTHONPATH=src python -m unittest discover -s tests -v
```

See `docs/ARCHITECTURE.md`, `docs/DIAGNOSTIC_CONTRACT.md` and `docs/PRODUCT_SCOPE.md`.

## Safety and release status

The observer reads external CPU, RSS, threads, I/O and child process count without modifying the target. Local SQLite sessions and JSON/HTML reports contain bounded evidence; `root_cause=UNKNOWN` by default. It never copies command lines, documents or environment variables. PID reuse checks use process creation time. Existing session directories are not overwritten.

Current scope: functional **Linux-tested Python CLI**, no GUI/Windows EXE, no Windows acceptance and no proof of app-internal root cause. This branch intentionally has no Alva runtime dependency; a separate branch proposes the optional private-platform bridge. See LICENSE for new original code; Alva code is not bundled or relicensed.
