# BlackBox Rep. Alva — universal local process observer (developer preview)

**An independent open-source application, not a subproject of Alva.** Select any accessible Windows process by PID, observe it without modifying it, store evidence locally, and generate offline reports that distinguish observations from inferred causes. Supported modes: Python CLI now; GUI, Windows EXE, and other platform adapters are future product work.

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

This is a working **CLI-level developer preview**. Windows GUI/EXE, Windows CI, broad multi-app compatibility, remote/privileged observation, true per-task instrumentation, application-specific root-cause attribution, and a stable Alva consumer contract have **not** been accepted. A process adapter cannot expose application internals without their opt-in telemetry. The source project `jumonja-maker/Alva` is private, `0.0.1.dev0` PREVIEW at pinned commit `a44297c5408628d9447bbf7db394b95ebd33fa20` (2026-10-22); this repository does not ship it.
