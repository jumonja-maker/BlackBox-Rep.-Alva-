"""A bounded, synchronous recorder; deliberately no mutation of target process."""
from __future__ import annotations
from pathlib import Path
import time
from .contracts import ObserverError, event
from .probe import PsutilProbe
from .storage import SessionStore


def record(pid: int, output: Path, *, duration: float = 3.0, interval: float = 0.5,
           probe_factory=PsutilProbe, clock=time.monotonic, sleeper=time.sleep) -> dict:
    if type(duration) not in (float, int) or not 0 < duration <= 3600:
        raise ValueError("duration must be between 0 and 3600 seconds")
    if type(interval) not in (float, int) or not 0.1 <= interval <= 60:
        raise ValueError("interval must be between 0.1 and 60 seconds")
    if type(pid) is not int or pid <= 0:
        raise ValueError("positive PID required")
    probe = probe_factory(pid)  # Do not create a session if attach fails.
    store = SessionStore(output, pid)
    state = "COMPLETED"
    try:
        beginning = clock()
        deadline = beginning + duration
        while True:
            try:
                store.write_sample(probe.sample())
            except ObserverError as exc:
                state = exc.code
                if exc.code != "STORAGE_ERROR":
                    store.write_event(event("observer_error", exc.code, exc.stage,
                                            max(0, int((clock() - beginning) * 1000))))
                break
            remaining = deadline - clock()
            if remaining <= 0:
                break
            sleeper(min(interval, remaining))
    except KeyboardInterrupt:
        state = "INTERRUPTED"
    finally:
        try:
            store.finish(state)
        finally:
            store.close()
    return {"session": store.folder.name, "folder": str(store.folder),
            "state": state, "samples": store.seq}
