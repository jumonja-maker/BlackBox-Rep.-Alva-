"""Background, explicitly requested investigation of a completed BLACK.BOX session.

The core reads schema-1 SQLite read-only. Original session reports are never
changed; separate v2 investigation JSON and HTML are exclusive-created.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from uuid import uuid4

from PySide6.QtCore import QThread, Signal

from blackbox_investigation import InvestigationError, analyze_session, to_html
from blackbox_investigation.__main__ import _commit_export


def read_user_markers(folder: Path, *, start_ms: int | None = None,
                      end_ms: int | None = None) -> list[dict]:
    """Extract only locally recorded, unverified USER markers; bounded result."""
    db_path = folder / "session.sqlite3"
    if not db_path.is_file() or db_path.is_symlink():
        raise InvestigationError("SESSION_UNAVAILABLE")
    markers: list[dict] = []
    try:
        with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro",
                             uri=True, timeout=1) as connection:
            connection.execute("PRAGMA query_only=ON")
            for (blob,) in connection.execute(
                    "SELECT data FROM events ORDER BY seq LIMIT 10000"):
                try:
                    data = json.loads(blob)
                except (TypeError, ValueError):
                    continue
                if not isinstance(data, dict) or data.get("kind") != "user_problem":
                    continue
                when = data.get("elapsed_ms")
                if type(when) is not int or when < 0:
                    continue
                if ((start_ms is not None and when < start_ms) or
                        (end_ms is not None and when > end_ms)):
                    continue
                note = data.get("note", "")
                if type(note) is not str:
                    continue
                markers.append({"elapsed_ms": when, "kind": "user_problem",
                                "source": "USER", "note": note[:128]})
                if len(markers) >= 256:
                    break
    except sqlite3.Error:
        raise InvestigationError("INVALID_SESSION") from None
    return markers


def latest_bounded_interval(folder: Path) -> tuple[int, int, int]:
    """Return latest 4096 sample boundaries and total sample count."""
    path = folder / "session.sqlite3"
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro",
                             uri=True, timeout=1) as connection:
            connection.execute("PRAGMA query_only=ON")
            total = connection.execute("SELECT count(*) FROM samples").fetchone()[0]
            points = [r[0] for r in connection.execute(
                "SELECT elapsed_ms FROM samples ORDER BY seq DESC LIMIT 4096")]
    except (sqlite3.Error, OSError, ValueError):
        raise InvestigationError("INVALID_SESSION") from None
    if not points or type(points[0]) is not int:
        raise InvestigationError("INVALID_SESSION")
    return min(points), max(points), total


class InvestigationWorker(QThread):
    """Dedicated Qt worker; only signals touch the GUI."""
    result_ready = Signal(object, str)

    def __init__(self, folder: Path, language: str, *,
                 interval: tuple[int, int] | None = None, parent=None):
        super().__init__(parent)
        self.folder = Path(folder)
        self.language = language if language in ("RU", "EN") else "EN"
        self.interval = interval

    def run(self) -> None:
        try:
            lo, hi = self.interval if self.interval is not None else (None, None)
            markers = read_user_markers(self.folder, start_ms=lo, end_ms=hi)
            result = analyze_session(
                self.folder, user_markers=markers,
                interval_start_ms=lo, interval_end_ms=hi)
            # Do not mutate BLACK.BOX report.json/report.html. Use distinct,
            # collision-resistant names and fail if anything already exists.
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            prefix = f"investigation-{stamp}-{uuid4().hex[:8]}"
            json_path = self.folder / (prefix + ".json")
            html_path = self.folder / (prefix + ".html")
            contents = {
                "json": (json.dumps(result, ensure_ascii=False, indent=2,
                                    allow_nan=False) + "\n").encode("utf-8"),
                "html": to_html(result, lang=self.language).encode("utf-8"),
            }
            _commit_export({"json": json_path, "html": html_path}, contents)
            self.result_ready.emit({"result": result, "json": str(json_path),
                                    "html": str(html_path), "session": str(self.folder)}, "")
        except InvestigationError as exc:
            if exc.code == "SESSION_INTERVAL_REQUIRED":
                try:
                    lo, hi, total = latest_bounded_interval(self.folder)
                    self.result_ready.emit({"long_session": [lo, hi, total],
                                            "session": str(self.folder)}, "")
                except InvestigationError as err:
                    self.result_ready.emit(None, err.code)
            else:
                self.result_ready.emit(None, exc.code)
        except (OSError, TypeError, ValueError, OverflowError, sqlite3.Error):
            self.result_ready.emit(None, "INVESTIGATION_UNAVAILABLE")
