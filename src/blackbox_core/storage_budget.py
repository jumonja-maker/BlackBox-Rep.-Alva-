"""Bounded logical-size observation; never delete or claim a filesystem quota.

Stat calls are not interruptible. The monotonic budget is therefore a *soft*
metadata-work limit checked at bounded batches (32 entries), not an OS hard
deadline. A partial scan has no authoritative total; it may retain the bytes
actually stat'ed so the owner can fail closed once even that partial amount
already exceeds the configured recording budget.
"""
from pathlib import Path
import time


def recording_size(folder, *, max_entries=4096, max_seconds=.1):
    pending = [Path(folder)]
    deadline = time.monotonic() + max_seconds
    size = 0
    count = 0

    def incomplete():
        return {
            "bytes": None,  # never pass a partial count as the total
            "observed_partial_bytes": size,
            "status": "METADATA_BUDGET_EXHAUSTED",
            "entries": count,
        }

    while pending:
        parent = pending.pop()
        if parent.is_symlink():
            return {"bytes": None, "status": "UNSAFE_PATH", "entries": count}
        try:
            for path in parent.iterdir():
                count += 1
                if count > max_entries:
                    return incomplete()
                if path.is_symlink():
                    return {"bytes": None, "status": "UNSAFE_PATH", "entries": count}
                if path.is_dir():
                    pending.append(path)
                elif path.is_file():
                    size += path.stat().st_size

                # Finish a small directory (typically <32 owned session
                # files) even if a scheduling pause exceeded 100 ms. Large
                # trees still stop after a bounded batch rather than
                # iterating an unbounded number of entries past the budget.
                if count % 32 == 0 and time.monotonic() > deadline:
                    return incomplete()
        except OSError:
            return {"bytes": None, "status": "SIZE_UNAVAILABLE", "entries": count}
        if pending and time.monotonic() > deadline:
            return incomplete()
    return {"bytes": size, "status": "OBSERVED_LOGICAL_FILE_BYTES", "entries": count}
