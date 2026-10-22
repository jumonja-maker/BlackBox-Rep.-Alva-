"""Read-only system-process observation for the universal desktop shell.

This is *not* an Alva adapter. The future Alva platform will consume these
bounded, versioned observations. No injection, handles with write privileges,
network upload, file contents, ETW session or administrator requirement.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time

import psutil


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def available_processes(limit: int = 500) -> list[dict]:
    """Best-effort process picker; access-denied processes are harmless."""
    rows: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "memory_info", "status"]):
        try:
            d = proc.info
            name = (d.get("name") or "Unknown").strip()[:96]
            mem = d.get("memory_info")
            rows.append({
                "pid": int(d["pid"]),
                "name": name,
                "rss_mb": round(mem.rss / 1048576, 1) if mem else None,
                "status": (d.get("status") or "unknown")[:32],
            })
        except (psutil.Error, OSError, TypeError, ValueError, KeyError):
            continue
    rows.sort(key=lambda r: (r["name"].casefold(), r["pid"]))
    return rows[:limit]


class ReadOnlyProbe:
    """Single selected process + its visible children; 1-second cadence from UI."""

    def __init__(self) -> None:
        self.pid: int | None = None
        self.name = ""
        self.active = False
        self.started_at: str | None = None
        self._started_monotonic = 0.0
        self._proc: psutil.Process | None = None
        self._created: float | None = None
        self.history: deque[dict] = deque(maxlen=3600)
        self.events: deque[dict] = deque(maxlen=300)
        self._known_children: set[tuple[int, float]] = set()

    def _event(self, code: str, detail: str = "") -> None:
        self.events.append({
            "timestamp_utc": utc_stamp(),
            "code": code,
            "detail": detail[:120],
        })

    def attach(self, pid: int) -> None:
        """Requires an existing OS process, but does not start observation."""
        if self.active:
            raise RuntimeError("Stop the current observation before switching.")
        candidate = psutil.Process(int(pid))
        created = candidate.create_time()
        name = candidate.name()[:96]
        if not candidate.is_running():
            raise psutil.NoSuchProcess(pid)
        self.pid = int(pid)
        self.name = name
        self._created = created
        self._proc = candidate
        self.started_at = None
        self.history.clear()
        self.events.clear()
        self._known_children.clear()
        self._event("PROCESS_SELECTED", f"{name} · PID {pid}")

    def start(self) -> None:
        if self._proc is None:
            raise RuntimeError("Choose a process first.")
        if self.active:
            return
        if not self._identity_valid():
            raise RuntimeError("The selected process is no longer running.")
        self._proc.cpu_percent(interval=None)
        self.active = True
        self.started_at = utc_stamp()
        self._started_monotonic = time.monotonic()
        self._event("OBSERVATION_STARTED")

    def stop(self, reason: str = "USER_STOPPED") -> None:
        if self.active:
            self.active = False
            self._event(reason)

    def _identity_valid(self) -> bool:
        try:
            return bool(self._proc and self._proc.is_running() and
                        self._proc.create_time() == self._created and
                        self._proc.status() != psutil.STATUS_ZOMBIE)
        except (psutil.Error, OSError):
            return False

    def tick(self) -> dict | None:
        if not self.active or self._proc is None:
            return None
        if not self._identity_valid():
            self.stop("PROCESS_EXITED")
            return None
        try:
            root = self._proc
            children = root.children(recursive=True)
            nodes = [root, *children]
            rss = 0
            threads = 0
            count = 0
            for node in nodes:
                try:
                    info = node.memory_info()
                    rss += max(0, info.rss)
                    threads += max(0, node.num_threads())
                    count += 1
                except (psutil.NoSuchProcess, psutil.ZombieProcess,
                        psutil.AccessDenied, OSError):
                    continue
            cpu = root.cpu_percent(interval=None)
            current: set[tuple[int, float]] = set()
            for child in children:
                try:
                    current.add((child.pid, child.create_time()))
                except (psutil.Error, OSError):
                    continue
            for pid, _ in sorted(current - self._known_children):
                self._event("CHILD_STARTED", f"PID {pid}")
            for pid, _ in sorted(self._known_children - current):
                self._event("CHILD_EXITED", f"PID {pid}")
            self._known_children = current
            record = {
                "at": utc_stamp(),
                "seconds": round(time.monotonic() - self._started_monotonic, 2),
                "cpu_pct": round(max(0, cpu), 1),
                "rss_mb": round(rss / 1048576, 1),
                "process_count": count,
                "thread_count": threads,
            }
            self.history.append(record)
            return record
        except (psutil.NoSuchProcess, psutil.ZombieProcess,
                psutil.AccessDenied, OSError):
            self.stop("OBSERVATION_UNAVAILABLE")
            return None

    @property
    def last(self) -> dict:
        return self.history[-1] if self.history else {
            "seconds": 0.0, "cpu_pct": 0.0, "rss_mb": 0.0,
            "process_count": 0, "thread_count": 0,
        }

    def snapshot(self) -> dict:
        """Data is app-supplied and not independently attested."""
        return {
            "schema_version": 1,
            "product": "BLACK.BOX Universal",
            "source": "local_read_only_psutil",
            "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
            "root_cause_proven": False,
            "alva_status": "NOT_CONNECTED",
            "observed_process": {"name": self.name, "pid": self.pid},
            "started_at_utc": self.started_at,
            "exported_at_utc": utc_stamp(),
            "observation_active_at_export": self.active,
            "sample_count": len(self.history),
            "recent_samples": list(self.history),
            "recent_events": list(self.events),
            "limitations": [
                "No internal app events without cooperative instrumentation.",
                "Process memory growth alone does not prove a memory leak.",
                "CPU percent is sampled; no native root-cause proof.",
                "Sensitive process names/PIDs may be present; review before sharing.",
            ],
        }


def save_snapshot(path: Path, data: dict) -> None:
    """Explicit, user-selected export; publish complete JSON atomically."""
    destination = Path(path)
    stage: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8",
                dir=destination.parent, prefix=".blackbox-", suffix=".tmp",
                delete=False) as handle:
            stage = Path(handle.name)
            json.dump(data, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        os.replace(stage, destination)
    finally:
        if stage is not None:
            try:
                stage.unlink(missing_ok=True)
            except OSError:
                pass
