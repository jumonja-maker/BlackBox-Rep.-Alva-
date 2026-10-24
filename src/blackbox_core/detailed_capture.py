"""Opt-in, bounded process-depth sampler on a dedicated Python thread.

The v2 sidecar is deliberately separate from immutable schema-1 sessions.
No injection, registry writes, dump capture, window titles, arguments or paths.
"""
from __future__ import annotations
from contextlib import closing
import os
from pathlib import Path
import sqlite3
from threading import Event, Thread
import time

from .detail_contracts import (
    ClockAnchor, FIELD_STATUS_COLUMNS, FIELD_UNITS, SOURCE_KIND,
    VERIFICATION_CLASS, capture_clock_anchor, read_provenance,
    sample_field_statuses,
)


class DetailSensorError(ValueError):
    pass


def sample_process(pid: int, created: float, *, thread_limit: int = 256,
                   child_limit: int = 256) -> dict:
    """Snapshot cumulative counters with NULL for unavailable fields."""
    if type(pid) is not int or pid <= 0 or type(created) not in (float, int) or created <= 0:
        raise DetailSensorError("INVALID_TARGET")
    try:
        import psutil
        p = psutil.Process(pid)
        if abs(float(p.create_time()) - created) > 0.000001:
            raise DetailSensorError("PID_REUSED")
        began = time.monotonic_ns()
        with p.oneshot():
            cpu = p.cpu_times()
            counter_ns = time.monotonic_ns()
            rss = p.memory_info().rss
            thread_count = p.num_threads()
            try:
                io = p.io_counters()
                io_status = "OK"
            except psutil.AccessDenied:
                io, io_status = None, "ACCESS_DENIED"
            except (AttributeError, NotImplementedError):
                io, io_status = None, "UNSUPPORTED"
            except OSError:
                io, io_status = None, "NOT_OBSERVED"
            try:
                tids = p.threads()
                threads_status = "OK"
            except psutil.AccessDenied:
                tids, threads_status = None, "ACCESS_DENIED"
            except NotImplementedError:
                tids, threads_status = None, "UNSUPPORTED"
            except OSError:
                tids, threads_status = None, "NOT_OBSERVED"
        try:
            full = p.memory_full_info()
            private = getattr(full, "private", None)
            uss = getattr(full, "uss", None)
            private_status = "OK" if private is not None else "UNSUPPORTED"
            uss_status = "OK" if uss is not None else "UNSUPPORTED"
        except psutil.AccessDenied:
            private, uss = None, None
            private_status = uss_status = "ACCESS_DENIED"
        except NotImplementedError:
            private, uss = None, None
            private_status = uss_status = "UNSUPPORTED"
        except OSError:
            private, uss = None, None
            private_status = uss_status = "NOT_OBSERVED"
        try:
            handles = p.num_handles() if hasattr(p, "num_handles") else None
            handle_status = "OK" if handles is not None else "UNSUPPORTED"
        except psutil.AccessDenied:
            handles, handle_status = None, "ACCESS_DENIED"
        except NotImplementedError:
            handles, handle_status = None, "UNSUPPORTED"
        except OSError:
            handles, handle_status = None, "NOT_OBSERVED"
        descendants = []
        children_total = None
        children_status = "OK"
        children_failed = 0
        try:
            all_children = p.children(recursive=True)
            children_total = len(all_children)
            for child in all_children[:child_limit]:
                try:
                    child_began = time.monotonic_ns()
                    child_created = float(child.create_time())
                    with child.oneshot():
                        child_mem = child.memory_info()
                        child_cpu = child.cpu_times()
                        child_counter_ns = time.monotonic_ns()
                        child_name = child.name()[:96]
                        child_parent = child.ppid()
                        child_threads = child.num_threads()
                        try:
                            child_io = child.io_counters()
                        except (psutil.AccessDenied, AttributeError, NotImplementedError, OSError):
                            child_io = None
                        try:
                            child_handles = child.num_handles() if hasattr(child,"num_handles") else None
                        except (psutil.AccessDenied, NotImplementedError, OSError):
                            child_handles = None
                    if abs(float(psutil.Process(child.pid).create_time()) - child_created) > 0.000001:
                        children_failed += 1
                        continue
                    descendants.append({
                        "pid": child.pid, "created": child_created,
                        "time_ns":child_counter_ns,"capture_started_ns":child_began,
                        "capture_ended_ns":time.monotonic_ns(),
                        "rss_bytes": int(child_mem.rss),
                        "cpu_user_s": float(child_cpu.user),
                        "cpu_system_s": float(child_cpu.system),
                        "name": child_name, "parent_pid": child_parent,
                        "thread_count": child_threads, "handle_count": child_handles,
                        "read_bytes": getattr(child_io,"read_bytes",None),
                        "write_bytes": getattr(child_io,"write_bytes",None),
                        "read_ops": getattr(child_io,"read_count",None),
                        "write_ops": getattr(child_io,"write_count",None),
                    })
                except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, OSError):
                    children_failed += 1
                    continue
        except psutil.AccessDenied:
            children_status = "ACCESS_DENIED"
        except (psutil.NoSuchProcess, OSError):
            children_status = "NOT_OBSERVED"
        if children_status == "OK" and children_failed:
            children_status = "TRUNCATED"
        if abs(float(psutil.Process(pid).create_time()) - created) > 0.000001:
            raise DetailSensorError("PID_REUSED")
        ended = time.monotonic_ns()
        return {
            "time_ns": counter_ns, "sampling_duration_ns": max(0, ended-began),
            "capture_started_ns":began,"capture_ended_ns":ended,
            "pid": pid, "created": created, "rss_bytes": int(rss),
            "private_bytes": private, "uss_bytes": uss, "handle_count": handles,
            "cpu_user_s": float(cpu.user), "cpu_system_s": float(cpu.system),
            "thread_count": thread_count,
            "read_bytes": getattr(io, "read_bytes", None),
            "write_bytes": getattr(io, "write_bytes", None),
            "read_ops": getattr(io, "read_count", None),
            "write_ops": getattr(io, "write_count", None),
            "threads": ([{"tid": item.id,
                          "cpu_user_s": float(item.user_time),
                          "cpu_system_s": float(item.system_time)}
                         for item in tids[:thread_limit]] if tids is not None else []),
            "thread_status": ("OK" if tids is not None else "ACCESS_DENIED_OR_UNSUPPORTED"),
            "threads_omitted": max(0, len(tids)-thread_limit) if tids is not None else None,
            "children": descendants, "children_total": children_total,
            "children_omitted": (max(0, children_total-len(descendants))
                                 if children_total is not None else None),
            "children_failed": children_failed,
            "source": "PSUTIL_EXTERNAL_COUNTERS_NOT_CAUSAL_PROOF",
            "sensor_status": {
                "rss_bytes": "OK", "private_bytes": private_status,
                "uss_bytes": uss_status, "handle_count": handle_status,
                "io": io_status, "threads": threads_status,
                "children": children_status,
            },
        }
    except DetailSensorError:
        raise
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        raise DetailSensorError("PROCESS_EXITED") from None
    except psutil.AccessDenied:
        raise DetailSensorError("ACCESS_DENIED") from None
    except (OSError, ValueError, OverflowError, AttributeError):
        raise DetailSensorError("SENSOR_UNAVAILABLE") from None


class DetailedCapture:
    """Independent thread with independent SQLite v2 sidecar connection."""

    def __init__(self, folder: Path, pid: int, created: float, origin_ns: int,
                 *, interval_s: float = 2.0, max_samples: int | None = None,
                 max_bytes: int = 256 * 1024 * 1024, collector=None):
        if (type(origin_ns) is not int or origin_ns < 0 or
                not 0.5 <= interval_s <= 30 or
                (max_samples is not None and (type(max_samples) is not int or not 1 <= max_samples <= 20000))):
            raise ValueError("INVALID_DETAILED_CAPTURE_POLICY")
        self.folder = Path(folder)
        self.path = self.folder / "detail-v2.sqlite3"
        self.pid = pid
        self.created = created
        self.origin_ns = origin_ns
        self.interval_s = interval_s
        self.max_samples = max_samples
        self.max_bytes = max_bytes
        self.collector = collector or sample_process
        self.stop_event = Event()
        self.thread: Thread | None = None
        self.status = "NOT_STARTED"
        self.error: str | None = None
        self.samples = 0
        self.session_writer = None

    def start(self) -> None:
        if (self.thread is not None or not self.folder.is_dir() or
                self.folder.is_symlink() or self.path.exists() or self.path.is_symlink()):
            raise DetailSensorError("DETAILED_SESSION_UNAVAILABLE")
        # Exclusive file reservation, even if a competing local writer races.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(self.path, flags, 0o600)
        os.close(fd)
        self.thread = Thread(target=self._run, name="blackbox-detailed-sampler",
                             daemon=True)
        self.thread.start()

    def stop(self, timeout: float = 0.5) -> bool:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout)
            return not self.thread.is_alive()
        return True

    def _storage_bytes(self) -> int:
        """Include live WAL and shared-memory sidecars in the disk budget.

        This is a bounded check at each sample boundary, not a hard
        per-write filesystem quota; one in-flight transaction may exceed it.
        """
        return sum(p.stat().st_size for p in (
            self.path,
            self.path.with_name(self.path.name + "-wal"),
            self.path.with_name(self.path.name + "-shm"),
        ) if p.exists())

    def _run(self) -> None:
        conn = None
        final = "STOPPED"
        try:
            conn = sqlite3.connect(self.path, timeout=2)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript("""
                CREATE TABLE detail_metadata (
                    schema_version INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    created REAL NOT NULL,
                    monotonic_origin_ns INTEGER NOT NULL,
                    status TEXT NOT NULL);
                CREATE TABLE process_samples (
                    seq INTEGER PRIMARY KEY,
                    time_monotonic_ns INTEGER NOT NULL,
                    elapsed_ms INTEGER NOT NULL,
                    sampling_duration_ns INTEGER NOT NULL,
                    rss_bytes INTEGER, private_bytes INTEGER, uss_bytes INTEGER,
                    handles INTEGER, cpu_user_s REAL, cpu_system_s REAL,
                    threads_reported INTEGER, read_bytes INTEGER,
                    write_bytes INTEGER, read_ops INTEGER, write_ops INTEGER,
                    threads_omitted INTEGER, children_total INTEGER,
                    children_omitted INTEGER, thread_status TEXT);
                CREATE INDEX ix_detail_samples_time ON process_samples(time_monotonic_ns);
                CREATE TABLE thread_samples (
                    sample_seq INTEGER NOT NULL, pid INTEGER NOT NULL,
                    tid INTEGER NOT NULL, cpu_user_s REAL NOT NULL,
                    cpu_system_s REAL NOT NULL,
                    PRIMARY KEY (sample_seq, pid, tid));
                CREATE INDEX ix_detail_tid ON thread_samples(pid, tid, sample_seq);
                CREATE TABLE child_samples (
                    sample_seq INTEGER NOT NULL, pid INTEGER NOT NULL,
                    created REAL NOT NULL, rss_bytes INTEGER,
                    cpu_user_s REAL, cpu_system_s REAL,
                    PRIMARY KEY (sample_seq, pid, created));
                CREATE INDEX ix_detail_child ON child_samples(pid, created, sample_seq);
                CREATE TABLE sensor_errors (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    time_monotonic_ns INTEGER, code TEXT NOT NULL);
                -- Additive provenance tables: legacy v2 readers ignore them.
                CREATE TABLE detail_clock_mapping (
                    monotonic_anchor_ns INTEGER NOT NULL,
                    utc_anchor_ns INTEGER NOT NULL,
                    uncertainty_ns INTEGER NOT NULL,
                    clock_source TEXT NOT NULL);
                CREATE TABLE detail_capabilities (
                    field_name TEXT PRIMARY KEY, source_kind TEXT NOT NULL,
                    verification_class TEXT NOT NULL, unit TEXT NOT NULL);
                CREATE TABLE detail_sample_quality (
                    sample_seq INTEGER PRIMARY KEY,
                    utc_estimate_ns INTEGER NOT NULL,
                    source_kind TEXT NOT NULL,
                    verification_class TEXT NOT NULL,
                    rss_status TEXT NOT NULL, private_status TEXT NOT NULL,
                    uss_status TEXT NOT NULL, handle_status TEXT NOT NULL,
                    io_status TEXT NOT NULL, threads_status TEXT NOT NULL,
                    children_status TEXT NOT NULL);
            """)
            anchor = capture_clock_anchor()
            conn.execute("INSERT INTO detail_metadata VALUES (2,?,?,?,?)",
                         (self.pid, self.created, self.origin_ns, "RUNNING"))
            conn.execute("INSERT INTO detail_clock_mapping VALUES (?,?,?,?)",
                         (anchor.monotonic_ns, anchor.utc_ns,
                          anchor.uncertainty_ns, anchor.source))
            conn.executemany("INSERT INTO detail_capabilities VALUES (?,?,?,?)",
                             ((field, SOURCE_KIND, VERIFICATION_CLASS, unit)
                              for field, unit in FIELD_UNITS.items()))
            conn.commit()
            self.status = "RUNNING"
            while not self.stop_event.is_set():
                if ((self.max_samples is not None and self.samples >= self.max_samples) or
                        self._storage_bytes() >= self.max_bytes):
                    final = "CAPTURE_LIMIT_REACHED"
                    break
                try:
                    x = self.collector(self.pid, self.created)
                    if x["time_ns"] < self.origin_ns:
                        raise DetailSensorError("INVALID_MONOTONIC_CLOCK")
                    seq = self.samples + 1
                    statuses = sample_field_statuses(x)
                    utc_estimate_ns = anchor.estimate_utc_ns(x["time_ns"])
                    conn.execute(
                        "INSERT INTO process_samples VALUES (" + ",".join(["?"]*19) + ")",
                        (seq, x["time_ns"],
                         (x["time_ns"]-self.origin_ns)//1_000_000,
                         x["sampling_duration_ns"], x["rss_bytes"],
                         x["private_bytes"], x["uss_bytes"], x["handle_count"],
                         x["cpu_user_s"], x["cpu_system_s"], x["thread_count"],
                         x["read_bytes"], x["write_bytes"], x["read_ops"],
                         x["write_ops"], x["threads_omitted"], x["children_total"],
                         x["children_omitted"], x["thread_status"]))
                    conn.executemany("INSERT INTO thread_samples VALUES (?,?,?,?,?)",
                                     ((seq, self.pid, t["tid"], t["cpu_user_s"],
                                       t["cpu_system_s"]) for t in x["threads"]))
                    conn.executemany("INSERT INTO child_samples VALUES (?,?,?,?,?,?)",
                                     ((seq, c["pid"], c["created"], c["rss_bytes"],
                                       c["cpu_user_s"], c["cpu_system_s"])
                                      for c in x["children"]))
                    conn.execute(
                        "INSERT INTO detail_sample_quality VALUES (" +
                        ",".join("?" for _ in range(4 + len(FIELD_STATUS_COLUMNS))) +
                        ")",
                        (seq, utc_estimate_ns, SOURCE_KIND, VERIFICATION_CLASS,
                         *(statuses[column] for column in FIELD_STATUS_COLUMNS)))
                    conn.commit()
                    self.samples += 1
                    if self.session_writer is not None:
                        field_status = {
                            "rss_bytes": statuses["rss_status"],
                            "private_bytes": statuses["private_status"],
                            "uss_bytes": statuses["uss_status"],
                            "handle_count": statuses["handle_status"],
                        }
                        for key in ("read_bytes","write_bytes","read_ops","write_ops"):
                            # Some platforms expose bytes without ops; each
                            # NULL field must keep its own unavailable status.
                            field_status[key] = ("OK" if x.get(key) is not None else
                                statuses["io_status"] if statuses["io_status"]!="OK" else "NOT_OBSERVED")
                        self.session_writer.submit("detail", {
                            **x, "field_status": field_status,
                            "thread_capture_status":statuses["threads_status"],
                            "child_capture_status":statuses["children_status"],
                            "requested_interval_ns": int(self.interval_s*1e9),
                            "correlation_key": f"detail-v2:{seq}"})
                except (DetailSensorError, KeyError, TypeError, ValueError) as exc:
                    # A generator or field validation may fail AFTER the
                    # parent process row was inserted. Never commit partial
                    # samples along with the diagnostic error.
                    conn.rollback()
                    code = (str(exc) if isinstance(exc, DetailSensorError)
                            else "SENSOR_DATA_INVALID")
                    conn.execute("INSERT INTO sensor_errors(time_monotonic_ns,code) VALUES (?,?)",
                                 (time.monotonic_ns(), code))
                    conn.commit()
                    self.error = code
                    if self.session_writer is not None:
                        self.session_writer.submit("error", {"time_ns":time.monotonic_ns(),
                            "sensor_id":"PSUTIL_DETAILED", "code":code})
                    if code in ("PID_REUSED", "PROCESS_EXITED", "INVALID_MONOTONIC_CLOCK"):
                        final = code
                        break
                self.stop_event.wait(self.interval_s)
        except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
            final = "STORAGE_OR_SENSOR_FAILURE"
            self.error = type(exc).__name__
        except Exception as exc:
            # An unexpected psutil/collector failure is not a clean Stop.
            final = "SENSOR_INTERNAL_FAILURE"
            self.error = type(exc).__name__
        finally:
            if conn is not None:
                # A failed thread/child insert can leave a process row in the
                # same uncommitted transaction. Never publish that partial row
                # while updating the final metadata state.
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                try:
                    conn.execute("UPDATE detail_metadata SET status=?", (final,))
                    conn.commit()
                except sqlite3.Error:
                    pass
                conn.close()
            self.status = final


def summarize_detail(folder: Path) -> dict | None:
    """Read-only, bounded sidecar summary; never counts missing as zero."""
    path = Path(folder) / "detail-v2.sqlite3"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro",
                                     uri=True, timeout=1)) as connection:
            connection.execute("PRAGMA query_only=ON")
            version, pid, status = connection.execute(
                "SELECT schema_version, pid, status FROM detail_metadata LIMIT 1").fetchone()
            if version != 2:
                return {"status": "UNSUPPORTED_DETAILED_SCHEMA"}
            samples, maxrss, max_private, max_handles = connection.execute(
                "SELECT count(*), max(rss_bytes), max(private_bytes), "
                "max(handles) FROM process_samples").fetchone()
            thread_records = connection.execute(
                "SELECT count(*) FROM thread_samples").fetchone()[0]
            child_records = connection.execute(
                "SELECT count(*) FROM child_samples").fetchone()[0]
            errors = connection.execute(
                "SELECT count(*) FROM sensor_errors").fetchone()[0]
            provenance = read_provenance(connection)
            provenance["quality_coverage"] = (
                "COMPLETE" if (provenance["contract_status"] == "OK" and
                               provenance["quality_samples"] == samples) else
                "LEGACY_NO_METADATA" if provenance["contract_status"] == (
                    "LEGACY_DETAIL_V2_NO_PROVENANCE") else "PARTIAL_OR_INVALID")
            return {"schema_version": 2, "status": status, "pid": pid,
                    "samples": samples, "peak_rss_bytes": maxrss,
                    "peak_private_bytes": max_private,
                    "peak_handles": max_handles,
                    "thread_records": thread_records,
                    "child_records": child_records, "sensor_errors": errors,
                    "provenance": provenance,
                    "source": "PSUTIL_EXTERNAL_READ_ONLY",
                    "root_cause_proven": False,
                    "tids_identity_attested": False}
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return {"status": "DETAILED_READ_UNAVAILABLE"}
