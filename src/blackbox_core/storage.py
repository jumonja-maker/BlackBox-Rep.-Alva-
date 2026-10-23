"""Append-only SQLite observations; existing sessions are never overwritten."""
from __future__ import annotations
from contextlib import closing
import sqlite3
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
from .contracts import ObserverError, Sample, bounded
from .event_journal import BoundedEventJournal


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _open_ro(folder: Path) -> sqlite3.Connection:
    path = Path(folder) / "session.sqlite3"
    if not path.is_file() or path.is_symlink():
        raise ObserverError("INVALID_DATA", "report")
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        return db
    except sqlite3.Error:
        raise ObserverError("INVALID_DATA", "report") from None


class SessionStore:
    def __init__(self, output: Path, pid: int, started_with: str = "psutil-read-only"):
        root = Path(output)
        if not root.is_dir() or root.is_symlink():
            raise ObserverError("STORAGE_ERROR", "storage")
        # Refuse a file/directory in place of a new session. Do not delete on error.
        self.folder = root / ("session-" + uuid4().hex)
        self.folder.mkdir(mode=0o700)
        self.db = sqlite3.connect(self.folder / "session.sqlite3")
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE metadata (
                    schema_version INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    started_utc TEXT NOT NULL,
                    ended_utc TEXT,
                    exit_code TEXT,
                    probe TEXT NOT NULL
                );
                CREATE TABLE samples (
                    seq INTEGER PRIMARY KEY,
                    elapsed_ms INTEGER NOT NULL,
                    rss_bytes INTEGER,
                    cpu_percent REAL,
                    num_threads INTEGER,
                    read_bytes INTEGER,
                    write_bytes INTEGER,
                    children_count INTEGER
                );
                CREATE TABLE events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    data TEXT NOT NULL
                );
            """)
            self.db.execute("INSERT INTO metadata VALUES (1, ?, ?, ?, NULL, NULL, ?)",
                            (self.folder.name, pid, _utc(), started_with))
            self.db.commit()
        except sqlite3.Error:
            self.db.close()
            raise ObserverError("STORAGE_ERROR", "storage") from None
        self.seq = 0
        self.finished = False
        self._journal: BoundedEventJournal | None = None

    def enable_background_events(self, *, queue_capacity: int = 64) -> None:
        """Delegate events to one bounded FIFO SQLite worker, opt-in only."""
        if self._journal is not None or self.finished:
            raise ObserverError("STORAGE_ERROR", "storage")
        self._journal = BoundedEventJournal(
            self.folder, capacity=queue_capacity)

    def write_lifecycle_event(self, record: dict) -> None:
        """Noncritical event: queue without a GUI wait; finish flushes it."""
        data = bounded(record).decode("ascii")
        if self._journal is not None:
            self._journal.enqueue(data, durable=False)
        else:
            self.write_event(record)

    def write_sample(self, sample: Sample) -> None:
        fields = sample.as_dict()
        self.seq += 1
        try:
            self.db.execute("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?)",
                            (self.seq, *(fields[k] for k in ("elapsed_ms", "rss_bytes", "cpu_percent",
                                "num_threads", "read_bytes", "write_bytes", "children_count"))))
            self.db.commit()
        except sqlite3.Error:
            raise ObserverError("STORAGE_ERROR", "storage") from None

    def write_event(self, record: dict) -> None:
        """Durability-acknowledged: action state MUST NOT advance before commit."""
        data = bounded(record).decode("ascii")
        if self._journal is not None:
            self._journal.enqueue(data, durable=True)
            return
        try:
            self.db.execute("INSERT INTO events(data) VALUES (?)", (data,))
            self.db.commit()
        except sqlite3.Error:
            raise ObserverError("STORAGE_ERROR", "storage") from None

    def finish(self, code: str) -> None:
        if self.finished:
            return
        if code not in ("COMPLETED", "PROCESS_EXITED", "ACCESS_DENIED", "PID_REUSED",
                        "SAMPLE_UNAVAILABLE", "STORAGE_ERROR", "INTERRUPTED"):
            raise ObserverError("INVALID_DATA", "storage")
        if self._journal is not None:
            self._journal.flush()
        try:
            self.db.execute("UPDATE metadata SET ended_utc=?, exit_code=?",
                            (_utc(), code))
            self.db.commit()
            self.finished = True
        except sqlite3.Error:
            raise ObserverError("STORAGE_ERROR", "storage") from None

    def close(self) -> None:
        try:
            if self._journal is not None:
                self._journal.close()
                self._journal = None
        finally:
            self.db.close()


def write_sample_from_worker(folder: Path, sample: Sample) -> int:
    """Append one schema-1 sample with an independent worker-owned connection.

    The original SessionStore connection remains in the Qt thread for user
    commands and lifecycle events. This single bounded transaction never
    changes schema 1, creates a new database or uses that GUI connection.
    """
    path = Path(folder) / "session.sqlite3"
    if (Path(folder).is_symlink() or path.is_symlink() or not path.is_file()):
        raise ObserverError("STORAGE_ERROR", "storage")
    values = sample.as_dict()
    fields = ("elapsed_ms", "rss_bytes", "cpu_percent", "num_threads",
              "read_bytes", "write_bytes", "children_count")
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=rw",
                                     uri=True, timeout=2)) as db:
            db.execute("BEGIN IMMEDIATE")
            metadata = db.execute(
                "SELECT schema_version, exit_code FROM metadata LIMIT 1"
            ).fetchone()
            if metadata != (1, None):
                raise ObserverError("STORAGE_ERROR", "storage")
            result = db.execute(
                "INSERT INTO samples VALUES "
                "((SELECT COALESCE(MAX(seq),0)+1 FROM samples),?,?,?,?,?,?,?)",
                tuple(values[key] for key in fields))
            seq = result.lastrowid
            db.commit()
            return seq
    except sqlite3.Error:
        raise ObserverError("STORAGE_ERROR", "storage") from None
