"""Shared, bounded offline import policy; a deadline covers every import phase."""
from __future__ import annotations

import math
import time

MAX_INPUT_BYTES = 256 * 1024**2
MAX_INDEX_BYTES = 768 * 1024**2
MAX_WORK_BYTES = 1024**3
MAX_PAGE_BYTES = 8 * 1024**2
MAX_SUMMARY_BYTES = 256 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000


class DecodeBudget:
    def __init__(self, cancel=None, timeout=180):
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 1 <= timeout <= 600):
            raise ValueError("INVALID_DECODE_TIMEOUT")
        self.cancel = cancel
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.phase = "START"

    def interrupted(self):
        return bool((self.cancel is not None and self.cancel.is_set())
                    or time.monotonic() > self.deadline)

    def check(self, phase=None):
        if phase is not None:
            self.phase = phase
        if self.cancel is not None and self.cancel.is_set():
            raise InterruptedError("DECODER_CANCELLED")
        if time.monotonic() > self.deadline:
            raise TimeoutError("DECODER_TIMEOUT")


def check_json_shape(value):
    """Bound decoded nesting and node count before retaining imported objects."""
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise ValueError("JSON_STRUCTURE_BUDGET")
        if type(node) is dict:
            pending.extend((x, depth + 1) for x in node.values())
        elif type(node) is list:
            pending.extend((x, depth + 1) for x in node)


def failure_details(error):
    """Stable UI/report guidance; retry always starts a fresh private import."""
    code = str(error)
    if isinstance(error, InterruptedError):
        state = "CANCELLED"
    elif isinstance(error, TimeoutError):
        state = "TIMED_OUT"
    elif "BUDGET" in code or "SIZE_OR_TYPE" in code:
        state = "LIMIT_REACHED"
    else:
        state = "FAILED"
    return {"state": state, "code": code[:512], "retry_from_original": True,
            "partial_index_reused": False, "source_modified_by_decoder": False,
            "advice": "RETRY_NEW_IMPORT_OR_USE_A_SMALLER_TRACE; DO_NOT_REUSE_PARTIAL_INDEX"}
