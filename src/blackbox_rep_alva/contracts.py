"""Bounded, conservative observation contracts. No claims of external root cause."""
from __future__ import annotations
from dataclasses import dataclass
import json
import math
import re

SCHEMA_VERSION = 1
MAX_EVENT_BYTES = 8192
STAGES = frozenset({"discovery", "attach", "sample", "storage", "report", "platform"})
CODES = frozenset({"ACCESS_DENIED", "PROCESS_NOT_FOUND", "PID_REUSED", "PROCESS_EXITED",
                   "SAMPLE_UNAVAILABLE", "DEPENDENCY_MISSING", "STORAGE_ERROR", "INVALID_DATA",
                   "UNSUPPORTED_SCHEMA", "ALVA_UNAVAILABLE", "ALVA_FAILURE"})
CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)


class ObserverError(Exception):
    def __init__(self, code: str, stage: str):
        if code not in CODES or stage not in STAGES:
            raise ValueError("unknown observer error code/stage")
        self.code, self.stage = code, stage
        super().__init__(f"{stage}:{code}")


def bounded(value: object, *, max_bytes: int = MAX_EVENT_BYTES) -> bytes:
    """Small self-contained JSON, rejecting nonfinite values or arbitrary objects."""
    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False,
                             separators=(",", ":"), sort_keys=True).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ObserverError("INVALID_DATA", "storage") from None
    if len(encoded) > max_bytes:
        raise ObserverError("INVALID_DATA", "storage")
    return encoded


@dataclass(frozen=True)
class Sample:
    elapsed_ms: int
    rss_bytes: int | None
    cpu_percent: float | None
    num_threads: int | None
    read_bytes: int | None
    write_bytes: int | None
    children_count: int | None

    def as_dict(self) -> dict[str, int | float | None]:
        result = vars(self)
        for key, v in result.items():
            if v is not None and (type(v) not in (float, int) or isinstance(v, float) and not math.isfinite(v) or v < 0):
                raise ObserverError("INVALID_DATA", "sample")
        return result


def event(kind: str, code: str, stage: str, elapsed_ms: int) -> dict:
    if kind not in ("observer_warning", "observer_error", "observer_finished") or code not in CODES or stage not in STAGES:
        raise ObserverError("INVALID_DATA", "storage")
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        raise ObserverError("INVALID_DATA", "storage")
    return {"kind": kind, "code": code, "stage": stage, "elapsed_ms": elapsed_ms,
            "source": "BLACKBOX_LOCAL_OBSERVATION", "confidence": "OBSERVED_BOUNDARY_ONLY"}
