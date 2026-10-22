"""Read-only psutil adapter: no signals, terminate, suspend, inject, or execute."""
from __future__ import annotations
import time
from .contracts import ObserverError, Sample


class PsutilProbe:
    """Bound to (PID, creation time); PID reuse fails closed."""
    def __init__(self, pid: int):
        if type(pid) is not int or pid <= 0:
            raise ObserverError("PROCESS_NOT_FOUND", "attach")
        try:
            import psutil
        except ImportError:
            raise ObserverError("DEPENDENCY_MISSING", "attach") from None
        self.psutil = psutil
        try:
            self.process = psutil.Process(pid)
            self.created = float(self.process.create_time())
            self.process.cpu_percent(interval=None)  # nonblocking baseline
        except psutil.AccessDenied:
            raise ObserverError("ACCESS_DENIED", "attach") from None
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            raise ObserverError("PROCESS_NOT_FOUND", "attach") from None
        self.pid = pid
        self.start = time.monotonic()

    def sample(self) -> Sample:
        psutil, p = self.psutil, self.process
        try:
            if abs(p.create_time() - self.created) > 0.000001:
                raise ObserverError("PID_REUSED", "sample")
            with p.oneshot():
                mem = p.memory_info()
                cpu = p.cpu_percent(interval=None)
                threads = p.num_threads()
                try:
                    io = p.io_counters()
                except (AttributeError, NotImplementedError, psutil.AccessDenied):
                    io = None
            try:
                children = len(p.children(recursive=True))
            except (psutil.AccessDenied, NotImplementedError):
                children = None
            return Sample(
                elapsed_ms=max(0, int((time.monotonic() - self.start) * 1000)),
                rss_bytes=int(mem.rss), cpu_percent=float(cpu), num_threads=int(threads),
                read_bytes=int(io.read_bytes) if io is not None else None,
                write_bytes=int(io.write_bytes) if io is not None else None,
                children_count=children,
            )
        except ObserverError:
            raise
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            raise ObserverError("PROCESS_EXITED", "sample") from None
        except psutil.AccessDenied:
            raise ObserverError("ACCESS_DENIED", "sample") from None
        except (OSError, ValueError):
            raise ObserverError("SAMPLE_UNAVAILABLE", "sample") from None


def list_processes() -> list[dict]:
    try:
        import psutil
    except ImportError:
        raise ObserverError("DEPENDENCY_MISSING", "discovery") from None
    found = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            info = p.info
            # Avoid executable path, command line, usernames and environment.
            name = info.get("name")
            found.append({"pid": int(info["pid"]), "name": str(name)[:96] if name else "unknown"})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError, TypeError):
            continue
    return sorted(found, key=lambda row: row["pid"])
