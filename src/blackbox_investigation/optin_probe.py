"""Optional read-only richer psutil observation; explicit owner action required.

Does not start threads, attach debuggers, read memory contents or access other PIDs
except already visible children of the explicitly selected process.
"""
from __future__ import annotations

import math
import time
from .model import InvestigationError


def observe_selected_process(pid: int, *, expected_created: float | None = None) -> dict:
    if type(pid) is not int or pid <= 0:
        raise InvestigationError("INVALID_PID")
    # Validate all caller-controlled parameters before accessing the OS.
    if expected_created is not None and (type(expected_created) not in (int, float) or
            not math.isfinite(expected_created) or expected_created <= 0):
        raise InvestigationError("INVALID_CREATION_TIME")
    try:
        import psutil
    except ImportError:
        raise InvestigationError("PSUTIL_NOT_INSTALLED") from None
    try:
        process = psutil.Process(pid)
        created = float(process.create_time())
        if expected_created is not None and abs(created-expected_created) > 0.000001:
            raise InvestigationError("PID_REUSED")
        with process.oneshot():
            rss = process.memory_info().rss
            counters = process.io_counters() if hasattr(process, "io_counters") else None
            threads = process.threads()
            number_threads = process.num_threads()
        try:
            full = process.memory_full_info()
            private = getattr(full, "private", None)
            uss = getattr(full, "uss", None)
        except (psutil.AccessDenied, OSError, NotImplementedError):
            private = None
            uss = None
        try:
            children = []
            for child in process.children(recursive=True)[:256]:
                try:
                    children.append({"pid": child.pid, "creation_time": child.create_time(),
                                     "rss_bytes": child.memory_info().rss})
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            children = None
        if abs(process.create_time()-created) > 0.000001:
            raise InvestigationError("PID_REUSED")
        return {"observed_monotonic": time.monotonic(), "pid": pid, "creation_time": created,
                "rss_bytes": rss, "private_bytes": private, "uss_bytes": uss,
                "memory_metric_sources": {"rss_bytes": "psutil.memory_info.rss",
                                          "private_bytes": "psutil.memory_full_info.private (only if provided)",
                                          "uss_bytes": "psutil.memory_full_info.uss (only if provided)"},
                "num_threads": number_threads,
                "read_bytes": getattr(counters, "read_bytes", None),
                "write_bytes": getattr(counters, "write_bytes", None),
                "threads": [{"tid": t.id, "cpu_seconds": t.user_time + t.system_time} for t in threads[:256]],
                "children": children, "side_effects": "READ_ONLY", "window_responsive": None,
                "wait_chain": None, "stacks": None}
    except InvestigationError:
        raise
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, ValueError):
        raise InvestigationError("PROCESS_UNAVAILABLE_OR_ACCESS_DENIED") from None
