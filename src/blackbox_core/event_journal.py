"""Bounded, session-owned background writer for schema-1 SQLite event rows.

User-command callbacks require a durable result before advancing ActionCycle;
only noncritical lifecycle notes may be enqueued without waiting. A single
worker owns its independent SQLite connection. No GUI thread SQL event INSERT.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full, Queue
import sqlite3
from threading import Event, Thread

from .contracts import ObserverError


@dataclass
class _JournalTask:
    payload: str | None
    done: Event = field(default_factory=Event)
    failure: bool = False


class BoundedEventJournal:
    """FIFO journal with a finite queue; cannot claim durability before ack.

    An event payload is already bounded, validated JSON from contracts.bounded.
    A None payload represents a durability barrier (no synthetic event row).
    """

    def __init__(self, folder: Path, *, capacity: int = 64):
        if type(capacity) is not int or not 1 <= capacity <= 256:
            raise ValueError("INVALID_EVENT_QUEUE_CAPACITY")
        self.folder = Path(folder)
        path = self.folder / "session.sqlite3"
        if self.folder.is_symlink() or path.is_symlink() or not path.is_file():
            raise ObserverError("STORAGE_ERROR", "storage")
        self.path = path
        self._tasks: Queue[_JournalTask | None] = Queue(maxsize=capacity)
        self._ready = Event()
        self._failure = False
        self._closed = False
        self._worker = Thread(target=self._run, name="blackbox-event-journal",
                              daemon=True)
        self._worker.start()
        # Opening the owner connection is a bounded startup handshake. No
        # event can be accepted before the schema/connection is verified.
        self._ready.wait()
        if self._failure:
            self.close()
            raise ObserverError("STORAGE_ERROR", "storage")

    @property
    def failed(self) -> bool:
        return self._failure

    @property
    def pending(self) -> int:
        """An advisory queue-depth snapshot, excluding current in-flight IO."""
        return self._tasks.qsize()

    def _write_one(self, db: sqlite3.Connection, payload: str) -> None:
        db.execute("BEGIN IMMEDIATE")
        metadata = db.execute(
            "SELECT schema_version, exit_code FROM metadata LIMIT 1"
        ).fetchone()
        if metadata != (1, None):
            raise sqlite3.IntegrityError("NOT_ACTIVE_SCHEMA1_SESSION")
        db.execute("INSERT INTO events(data) VALUES (?)", (payload,))
        db.commit()

    def _run(self) -> None:
        try:
            with closing(sqlite3.connect(
                    self.path.resolve().as_uri() + "?mode=rw",
                    uri=True, timeout=2)) as db:
                row = db.execute(
                    "SELECT schema_version, exit_code FROM metadata LIMIT 1"
                ).fetchone()
                if row != (1, None):
                    raise sqlite3.IntegrityError("INVALID_SESSION")
                db.execute("PRAGMA synchronous=FULL")
                self._ready.set()
                while True:
                    task = self._tasks.get()
                    if task is None:
                        self._tasks.task_done()
                        return
                    try:
                        if self._failure:
                            task.failure = True
                        elif task.payload is not None:
                            try:
                                self._write_one(db, task.payload)
                            except Exception:
                                # Never acknowledge a runtime/storage error as
                                # a successfully persisted user command.
                                try:
                                    db.rollback()
                                except sqlite3.Error:
                                    pass
                                self._failure = True
                                task.failure = True
                    finally:
                        task.done.set()
                        self._tasks.task_done()
        except Exception:
            self._failure = True
        finally:
            self._ready.set()
            # Release every ack on startup/connection failure; none of these
            # events is ever reported as successfully committed.
            while True:
                try:
                    task = self._tasks.get_nowait()
                except Empty:
                    break
                if task is not None:
                    task.failure = True
                    task.done.set()
                self._tasks.task_done()

    def enqueue(self, payload: str, *, durable: bool) -> None:
        if self._closed or self._failure or not self._worker.is_alive():
            raise ObserverError("STORAGE_ERROR", "storage")
        task = _JournalTask(payload)
        try:
            self._tasks.put_nowait(task)
        except Full:
            raise ObserverError("STORAGE_ERROR", "storage") from None
        if durable:
            task.done.wait()  # never return a speculative ActionCycle commit
            if task.failure or self._failure:
                raise ObserverError("STORAGE_ERROR", "storage")

    def flush(self) -> None:
        """Wait for an ordered, durable barrier before SessionStore.finish."""
        self.enqueue_barrier()
        if self._failure:
            raise ObserverError("STORAGE_ERROR", "storage")

    def enqueue_barrier(self) -> None:
        if self._closed or self._failure or not self._worker.is_alive():
            raise ObserverError("STORAGE_ERROR", "storage")
        task = _JournalTask(None)
        # Finish must not skip accepted events if the bounded queue is full.
        self._tasks.put(task)
        task.done.wait()
        if task.failure or self._failure:
            raise ObserverError("STORAGE_ERROR", "storage")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Orderly termination after all accepted event records. This may
        # block on a stalled OS/filesystem write: do not falsely claim a
        # successful flush/close if the worker still owns a connection.
        if self._worker.is_alive():
            self._tasks.put(None)
            self._worker.join()
