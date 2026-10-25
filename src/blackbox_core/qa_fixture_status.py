"""QA-only polling of fixture command acknowledgements; no permission bypass.

A fixture replaces its own state.json atomically. Windows may briefly deny an
open while that file is being replaced. Retry only native access/share/lock
errors within the original deadline; stale or absent acknowledgements never
count as command success. This is not a general-purpose imported-file reader.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from time import monotonic, sleep


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
            if getattr(exc, "winerror", None) not in (5, 32, 33):
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
