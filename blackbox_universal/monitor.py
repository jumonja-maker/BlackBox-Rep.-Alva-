"""Qt observer facade over Alva's public BLACK.BOX process-recording core.

The one authoritative process sampler is blackbox_rep_alva.probe.PsutilProbe.
Durable observations go to its SessionStore; stop produces its JSON, HTML and
AI Handoff. The visual shell never imports or distributes private Alva code.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from blackbox_rep_alva.contracts import ObserverError, event
from blackbox_rep_alva.handoff import build_handoff
from blackbox_rep_alva.probe import PsutilProbe, list_processes
from blackbox_rep_alva.report import write_report
from blackbox_rep_alva.storage import SessionStore


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def available_processes(limit: int = 500) -> list[dict]:
    """Core discovery plus best-effort RSS for the GUI process picker."""
    try:
        import psutil
    except ImportError:
        return []
    rows: list[dict] = []
    for item in list_processes():
        try:
            proc = psutil.Process(item["pid"])
            memory = proc.memory_info()
            status = proc.status()
            rss = round(memory.rss / 1048576, 1)
        except (psutil.Error, OSError):
            rss, status = None, "unknown"
        rows.append({
            "pid": item["pid"], "name": item["name"],
            "rss_mb": rss, "status": str(status)[:32],
        })
    rows.sort(key=lambda r: (r["name"].casefold(), r["pid"]))
    return rows[:limit]


def _default_sessions_root() -> Path:
    return Path.home() / "Documents" / "BLACK.BOX Universal" / "sessions"


def _write_handoff(path: Path, packet: dict) -> None:
    with path.open("x", encoding="utf-8") as out:
        json.dump(packet, out, ensure_ascii=False, indent=2, allow_nan=False)
        out.write("\n")


class ReadOnlyProbe:
    """A durable recording per explicit Start; all GUI views are read-only."""

    def __init__(self, output_root: Path | None = None) -> None:
        self.output_root = Path(output_root) if output_root else _default_sessions_root()
        self.pid: int | None = None
        self.name = ""
        self.active = False
        self.started_at: str | None = None
        self._core: PsutilProbe | None = None
        self._store: SessionStore | None = None
        self.session_folder: Path | None = None
        self.session_state = "NO_SESSION"
        self.report_result: dict | None = None
        self.handoff_result: dict | None = None
        self.last_error: str | None = None
        self.history: deque[dict] = deque(maxlen=3600)
        self.events: deque[dict] = deque(maxlen=300)

    def _event(self, code: str, detail: str = "") -> None:
        self.events.append({"timestamp_utc": utc_stamp(), "code": code,
                            "detail": detail[:120]})

    def attach(self, pid: int) -> None:
        if self.active:
            raise RuntimeError("Stop observation before switching targets.")
        core = PsutilProbe(pid)
        self._core = core
        self.pid = pid
        try:
            self.name = core.process.name()[:96]
        except Exception:
            self.name = "Unknown"
        self.started_at = None
        self.session_folder = None
        self.session_state = "NO_SESSION"
        self.report_result = None
        self.handoff_result = None
        self.last_error = None
        self.history.clear()
        self.events.clear()
        self._event("PROCESS_SELECTED", f"{self.name} · PID {pid}")

    def start(self) -> None:
        if self.pid is None:
            raise RuntimeError("Choose an accessible process first.")
        if self.active:
            return
        # Re-validate PID identity on every Start.
        core = PsutilProbe(self.pid)
        root = self.output_root
        if root.is_symlink():
            raise RuntimeError("Session root must not be a symlink.")
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir() or root.is_symlink():
            raise RuntimeError("Session root is unavailable.")
        store = SessionStore(root, self.pid)
        self._core = core
        self._store = store
        self.session_folder = store.folder
        self.session_state = "RECORDING"
        self.report_result = None
        self.handoff_result = None
        self.last_error = None
        self.history.clear()
        self.events.clear()
        self.active = True
        self.started_at = utc_stamp()
        self._event("OBSERVATION_STARTED")

    def stop(self, reason: str = "USER_STOPPED") -> None:
        if not self.active or self._store is None:
            return
        status = {
            "USER_STOPPED": "COMPLETED", "UI_CLOSED": "INTERRUPTED",
            "PROCESS_EXITED": "PROCESS_EXITED", "PID_REUSED": "PID_REUSED",
            "ACCESS_DENIED": "ACCESS_DENIED", "SAMPLE_UNAVAILABLE": "SAMPLE_UNAVAILABLE",
            "STORAGE_ERROR": "STORAGE_ERROR",
        }.get(reason, "INTERRUPTED")
        self.active = False
        store = self._store
        self._store = None
        self.session_state = status
        self._event(reason)
        try:
            store.finish(status)
        except ObserverError as exc:
            self.last_error = exc.code
            self._event("STORAGE_ERROR", exc.code)
        finally:
            store.close()
        if self.session_folder is None:
            return
        try:
            self.report_result = write_report(self.session_folder)
            self.handoff_result = build_handoff(self.session_folder)
            _write_handoff(self.session_folder / "ai-handoff.json", self.handoff_result)
            self._event("EVIDENCE_SAVED", "SQLite, HTML, JSON, AI Handoff")
        except (ObserverError, OSError, ValueError, TypeError):
            self.last_error = "REPORT_UNAVAILABLE"
            self._event("REPORT_UNAVAILABLE", "SQLite data retained")

    def tick(self) -> dict | None:
        if not self.active or self._core is None or self._store is None:
            return None
        try:
            sample = self._core.sample()
            self._store.write_sample(sample)
            record = {
                "at": utc_stamp(),
                "seconds": round(sample.elapsed_ms / 1000, 2),
                "cpu_pct": round(float(sample.cpu_percent or 0), 1),
                "rss_mb": round((sample.rss_bytes or 0) / 1048576, 1),
                "process_count": 1 + int(sample.children_count or 0),
                "thread_count": int(sample.num_threads or 0),
                "read_bytes": sample.read_bytes,
                "write_bytes": sample.write_bytes,
            }
            self.history.append(record)
            return record
        except ObserverError as exc:
            self.last_error = exc.code
            try:
                self._store.write_event(event("observer_error", exc.code, exc.stage, 0))
            except ObserverError:
                pass
            self.stop(exc.code)
            return None

    @property
    def last(self) -> dict:
        return self.history[-1] if self.history else {
            "seconds": 0.0, "cpu_pct": 0.0, "rss_mb": 0.0,
            "process_count": 0, "thread_count": 0,
        }

    def snapshot(self) -> dict:
        return {
            "schema_version": 1, "product": "BLACK.BOX Universal",
            "source": "local_read_only_psutil",
            "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
            "root_cause_proven": False,
            "alva_status": "NOT_CONNECTED",
            "observed_process": {"name": self.name, "pid": self.pid},
            "started_at_utc": self.started_at, "exported_at_utc": utc_stamp(),
            "observation_active_at_export": self.active,
            "session_state": self.session_state,
            "session_folder": str(self.session_folder) if self.session_folder else None,
            "sample_count": len(self.history), "recent_samples": list(self.history),
            "recent_events": list(self.events),
            "report_generated": self.report_result is not None,
            "handoff_generated": self.handoff_result is not None,
            "limitations": [
                "Only process/system sampling, not internal app tracing.",
                "Memory growth alone does not prove a memory leak.",
                "The recorded evidence is app-supplied and unauthenticated.",
                "Process names/PIDs are private; inspect before sharing.",
            ],
        }


def save_snapshot(path: Path, data: dict) -> None:
    """Explicit user-selected JSON snapshot with atomic publication."""
    destination = Path(path)
    stage: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=destination.parent,
                prefix=".blackbox-", suffix=".tmp", delete=False) as out:
            stage = Path(out.name)
            json.dump(data, out, ensure_ascii=False, indent=2, allow_nan=False)
            out.write("\n")
        os.replace(stage, destination)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)
