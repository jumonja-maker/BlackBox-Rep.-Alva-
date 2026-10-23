"""Standalone, opt-in application event client. Safe to copy into a project.

No debugger, injection, network or BLACK.BOX installation is needed by the
instrumented application. Events are untrusted application statements.
"""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading
import time
from uuid import uuid4


class EventWriter:
    def __init__(self, path, token, *, max_bytes=64 * 1024 * 1024):
        self.path = Path(path)
        self.token = str(token)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._seq = 0
        self.dropped = 0
        self.last_error = None
        if not 16 <= len(self.token) <= 128 or not 4096 <= max_bytes <= 4 * 1024**3:
            raise ValueError("INVALID_EVENT_WRITER_POLICY")

    def emit(self, kind, *, operation_id=None, parent_id=None, **attributes):
        """Returns False on failure; observation must not crash the target."""
        with self._lock:
            try:
                self._seq += 1
                record = {"schema_version": 1, "token": self.token,
                          "pid": os.getpid(), "tid": threading.get_native_id(),
                          "seq": self._seq, "kind": str(kind)[:80],
                          "source_clock": "PYTHON_MONOTONIC_NS",
                          "source_ns": time.monotonic_ns(),
                          "operation_id": operation_id, "parent_id": parent_id,
                          "attributes": attributes, "client_dropped": self.dropped}
                data = (json.dumps(record, ensure_ascii=True, allow_nan=False,
                                   separators=(",", ":")) + "\n").encode("ascii")
                if len(data) > 8192:
                    raise ValueError("EVENT_TOO_LARGE")
                if self.path.is_symlink():
                    raise ValueError("EVENT_PATH_SYMLINK")
                if self.path.exists() and self.path.stat().st_size + len(data) > self.max_bytes:
                    raise ValueError("EVENT_BUDGET_EXHAUSTED")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.path, flags, 0o600)
                try:
                    if os.write(fd, data) != len(data):
                        raise OSError("SHORT_EVENT_WRITE")
                finally:
                    os.close(fd)
                self.last_error = None
                return True
            except (OSError, ValueError, TypeError, RecursionError, OverflowError):
                self.dropped += 1
                self.last_error = "APPLICATION_EVENT_NOT_WRITTEN"
                return False

    @contextmanager
    def operation(self, name, *, parent_id=None, **attributes):
        operation_id = uuid4().hex
        self.emit("operation.begin", operation_id=operation_id,
                  parent_id=parent_id, name=name, **attributes)
        try:
            yield operation_id
        except BaseException as exc:
            self.emit("operation.error", operation_id=operation_id,
                      error_type=type(exc).__name__)
            raise
        finally:
            self.emit("operation.end", operation_id=operation_id)


class EventTail:
    """Bounded incremental reader; incomplete lines survive until next poll."""
    def __init__(self, path, token, pid):
        self.path, self.token, self.pid = Path(path), token, pid
        self.offset = 0
        self.pending = b""
        self.invalid = 0
        self.last_seq = {}
        self.ready = False
        self.client_dropped = None
        self.discontinuities = 0
        self.file_identity = None

    def poll(self, *, max_bytes=65536):
        if not self.path.exists():
            return []
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("INVALID_APPLICATION_EVENT_FILE")
        stat = self.path.stat();size=stat.st_size
        identity=(stat.st_dev,stat.st_ino)
        if size < self.offset or (self.file_identity is not None and self.file_identity!=identity):
            self.offset, self.pending = 0, b""
            self.last_seq.clear()
            self.discontinuities += 1
            self.ready = False
        self.file_identity=identity
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            raw = stream.read(max_bytes)
            self.offset += len(raw)
        parts = (self.pending + raw).split(b"\n")
        self.pending = parts.pop()
        if len(self.pending) > 8192:
            self.pending = b""
            self.invalid += 1
        result = []
        for line in parts:
            try:
                if len(line) > 8192:
                    raise ValueError("EVENT_TOO_LARGE")
                r = json.loads(line)
                if type(r) is dict and isinstance(r.get("source_ns"),str):
                    raw_ns=r["source_ns"]
                    if len(raw_ns)>19 or not raw_ns.isascii() or not raw_ns.isdecimal():
                        raise ValueError("INVALID_APP_CLOCK")
                    r["source_ns"]=int(raw_ns)
                if (type(r) is not dict or r.get("schema_version") != 1 or
                        r.get("token") != self.token or type(r.get("pid")) is not int or r.get("pid") != self.pid or
                        type(r.get("seq")) is not int or not 0 < r["seq"] <= 2**63-1 or
                        type(r.get("source_ns")) is not int or not 0 <= r["source_ns"] <= 2**63-1 or
                        type(r.get("source_clock")) is not str or not 1<=len(r["source_clock"])<=80 or
                        type(r.get("kind")) is not str or not 1 <= len(r["kind"]) <= 80 or
                        type(r.get("attributes")) is not dict):
                    raise ValueError("INVALID_APP_EVENT")
                # Re-encode to reject NaN/Infinity accepted by Python json.loads.
                json.dumps(r, allow_nan=False)
                tid = r.get("tid")
                tid_kind=r.get("tid_kind","OS_NATIVE")
                if tid_kind not in ("OS_NATIVE","RUNTIME_THREAD_ID"):
                    raise ValueError("INVALID_APP_THREAD_KIND")
                if type(tid) is not int or not (0 if tid_kind=="RUNTIME_THREAD_ID" else 1) <= tid <= 2**32-1:
                    raise ValueError("INVALID_APP_THREAD")
                for key in ("operation_id","parent_id"):
                    value=r.get(key)
                    if value is not None and (type(value) is not str or len(value)>128):
                        raise ValueError("INVALID_APP_OPERATION")
                key=(tid_kind,tid)
                previous = self.last_seq.get(key)
                if previous is not None and r["seq"] <= previous:
                    raise ValueError("REPLAYED_APP_EVENT")
                if key not in self.last_seq and len(self.last_seq) >= 4096:
                    raise ValueError("APP_THREAD_TRACKING_BUDGET")
                self.last_seq[key] = r["seq"]
                r.pop("token")
                dropped = r.get("client_dropped")
                if type(dropped) is int and dropped >= 0:
                    self.client_dropped = max(self.client_dropped or 0, dropped)
                if r["kind"] == "blackbox.ready":
                    self.ready = True
                result.append(r)
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
                self.invalid += 1
        return result
