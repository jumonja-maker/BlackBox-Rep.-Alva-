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
        self.origin_ns = time.monotonic_ns()
        self.start = self.origin_ns / 1_000_000_000
        self.last_observation = None

    def sample(self) -> Sample:
        psutil, p = self.psutil, self.process
        try:
            began = time.monotonic_ns()
            if abs(p.create_time() - self.created) > 0.000001:
                raise ObserverError("PID_REUSED", "sample")
            with p.oneshot():
                mem = p.memory_info()
                cpu = p.cpu_percent(interval=None)
                cpu_times = p.cpu_times()
                counter_ns = time.monotonic_ns()
                threads = p.num_threads()
                try:
                    io = p.io_counters()
                except (AttributeError, NotImplementedError, psutil.AccessDenied):
                    io = None
            try:
                children = len(p.children(recursive=True))
            except (psutil.AccessDenied, NotImplementedError):
                children = None
            # A process can exit/recycle while individual fields are read.
            # Recheck with a fresh OS Process object, avoiding cached birth.
            if abs(psutil.Process(self.pid).create_time() - self.created) > 0.000001:
                raise ObserverError("PID_REUSED", "sample")
            ended = time.monotonic_ns()
            self.last_observation = {
                "time_ns": counter_ns, "capture_started_ns": began,
                "capture_ended_ns": ended, "pid": self.pid,
                "created": self.created, "rss_bytes": int(mem.rss),
                "cpu_percent": float(cpu), "cpu_user_s": float(cpu_times.user),
                "cpu_system_s": float(cpu_times.system), "thread_count": int(threads),
                "read_bytes": int(io.read_bytes) if io else None,
                "write_bytes": int(io.write_bytes) if io else None,
                "read_ops": int(io.read_count) if io else None,
                "write_ops": int(io.write_count) if io else None,
                "children_total": children,
            }
            return Sample(
                elapsed_ms=max(0, (ended-self.origin_ns)//1_000_000),
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
