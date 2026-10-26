"""QA-only polling of fixture command acknowledgements; no permission bypass.

A fixture replaces its own state.json atomically. Windows may briefly deny an
open while that file is being replaced. Retry only native access/share/lock
errors (including Windows CRT errno-only EACCES) within the original deadline.
Stale or absent acknowledgements never count as command success. This is not
a general-purpose imported-file reader.
"""
from __future__ import annotations

import errno
import json
import math
import os
from pathlib import Path
from time import monotonic, sleep

_IS_WINDOWS = os.name == "nt"


def wait_fixture_ack(path: Path, command_id: str, *, timeout: float = 5.0) -> dict:
    """Return the exact command's status, including any reported command error.

    The caller must still assert the command error and expected real resource
    counts. Permanent denial, missing files, malformed JSON, and a stale ACK
    cannot become PASS. No ACL, elevation, source record or file is modified.
    """
    if (type(command_id) is not str or not command_id or
            type(timeout) not in (int, float) or
            not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ValueError("INVALID_FIXTURE_ACK_WAIT")
    path = Path(path)
    deadline = monotonic() + timeout
    last_read_error = None
    while monotonic() < deadline:
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            native = getattr(exc, "winerror", None)
            # CPython FileIO uses _wopen/errno on Windows, so the same
            # sharing denial may arrive as EACCES with no winerror at all.
            # Do not extend that fallback to POSIX or unrelated Win32 codes.
            crt_denial = (_IS_WINDOWS and native is None and
                          exc.errno == errno.EACCES)
            if native not in (5, 32, 33) and not crt_denial:
                raise
            last_read_error = exc
        else:
            last_read_error = None
            if type(state) is not dict:
                raise ValueError("INVALID_FIXTURE_STATUS")
            if state.get("ack") == command_id:
                if monotonic() > deadline:
                    break
                return state
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(.02, remaining))
    raise TimeoutError("REAL_FIXTURE_COMMAND_TIMEOUT") from last_read_error


def wait_fixture_ready(path: Path, *, expected_pid: int, expected_mode: str,
                       expected_count: int, alive, timeout: float = 25.0) -> dict:
    """Read the actual QA producer's ready.json within one bounded deadline.

    Atomic publication prevents partial JSON, but Windows readers can still
    see brief sharing/access denials after the file becomes visible. Retry
    only those Windows denials and a not-yet-created file. Wrong identity,
    malformed JSON, unrelated access errors or a dead producer never PASS.
    """
    if (type(expected_pid) is not int or expected_pid <= 0 or
            type(expected_mode) is not str or not expected_mode or
            type(expected_count) is not int or expected_count <= 0 or
            type(timeout) not in (int, float) or
            not math.isfinite(timeout) or not 0 < timeout <= 30 or
            not callable(alive)):
        raise ValueError("INVALID_FIXTURE_READY_WAIT")
    path = Path(path)
    deadline = monotonic() + timeout
    last_denial = None
    while monotonic() < deadline and alive():
        try:
            ready = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            # Real fixture may still be spawning 100 child processes.
            last_denial = None
        except OSError as exc:
            native = getattr(exc, "winerror", None)
            crt_denial = native is None and exc.errno == errno.EACCES
            if not _IS_WINDOWS or (native not in (5, 32, 33) and not crt_denial):
                raise
            last_denial = exc
        else:
            if (type(ready) is not dict or
                    ready.get("fixture") != "REAL_OS_QA_ONLY" or
                    ready.get("mode") != expected_mode or
                    type(ready.get("pid")) is not int or
                    ready["pid"] != expected_pid or
                    type(ready.get("requested_count")) is not int or
                    ready["requested_count"] != expected_count or
                    type(ready.get("created")) not in (int, float) or
                    not math.isfinite(ready["created"]) or ready["created"] <= 0):
                raise ValueError("INVALID_REAL_FIXTURE_READY")
            if monotonic() > deadline:
                break
            return ready
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(.02, remaining))
    raise TimeoutError("REAL_FIXTURE_READY_TIMEOUT_OR_WORKER_EXITED") from last_denial
