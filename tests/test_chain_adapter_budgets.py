"""Real file/SQLite budget boundaries; no injected native evidence claims."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from blackbox_core.chain_adapters import _file, _snapshot_journal


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class ChainAdapterReadBudgetTests(unittest.TestCase):
    def context(self, root):
        ctx = SimpleNamespace(run_id="adapter-budget-fixture", output_dir=root,
                              cancel=threading.Event(), deadline=time.monotonic() + 30)
        def check():
            if ctx.cancel.is_set():
                raise InterruptedError("WORKFLOW_CANCELLED")
            if time.monotonic() >= ctx.deadline:
                raise TimeoutError("WORKFLOW_NODE_DEADLINE")
        ctx.check = check
        return ctx

    def test_initial_artifact_hash_stops_between_real_file_chunks_on_cancel(self):
        from blackbox_core import chain_io
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "saved-source.bin"
            source.write_bytes(b"a" * (3 * 1024**2))
            before = digest(source)
            ctx = self.context(root)
            actual_hash = hashlib.sha256
            updates = []
            class CancelAfterChunk:
                def __init__(self):
                    self.inner = actual_hash()
                def update(self, block):
                    updates.append(len(block))
                    self.inner.update(block)
                    ctx.cancel.set()
                def hexdigest(self):
                    return self.inner.hexdigest()
            with patch.object(chain_io.hashlib, "sha256", CancelAfterChunk):
                with self.assertRaisesRegex(InterruptedError, "WORKFLOW_CANCELLED"):
                    _file("TRACE", source, ctx=ctx)
            self.assertEqual(updates, [1024**2])
            self.assertEqual(digest(source), before)

    def test_expired_artifact_reference_deadline_prevents_source_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "saved-source.bin"
            source.write_bytes(b"actual saved bytes")
            ctx = self.context(root)
            ctx.deadline = time.monotonic() - 1
            with patch("blackbox_core.chain_io.hashlib.sha256", side_effect=AssertionError("must not hash")):
                with self.assertRaisesRegex(TimeoutError, "WORKFLOW_DEADLINE"):
                    _file("TRACE", source, ctx=ctx)

    def test_sqlite_snapshot_integrity_obeys_cancel_and_preserves_original_journal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "existing-deep-journal.sqlite3"
            with closing(sqlite3.connect(source)) as db:
                db.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY,value TEXT)")
                db.executemany("INSERT INTO evidence(value) VALUES(?)", (("fixture" * 100,) for _ in range(2000)))
                db.commit()
            before = digest(source)
            ctx = self.context(root)
            actual_connect = sqlite3.connect
            class Connection:
                def __init__(self, connection):
                    self.connection = connection
                def __getattr__(self, key):
                    return getattr(self.connection, key)
                def execute(self, sql, *args, **kwargs):
                    if sql == "PRAGMA integrity_check":
                        ctx.cancel.set()
                    return self.connection.execute(sql, *args, **kwargs)
            # backup() requires the actual sqlite3 destination connection.
            class Source(Connection):
                def backup(self, target, **kwargs):
                    return self.connection.backup(target.connection, **kwargs)
            def snapshot_connect(path, *args, **kwargs):
                connection = actual_connect(path, *args, **kwargs)
                return Source(connection) if kwargs.get("uri") else Connection(connection)
            with patch("blackbox_core.chain_adapters.sqlite3.connect", side_effect=snapshot_connect):
                with self.assertRaisesRegex(InterruptedError, "WORKFLOW_CANCELLED"):
                    _snapshot_journal(ctx, SimpleNamespace(inspector=None), {"_journal_path": str(source)})
            self.assertEqual(digest(source), before)


if __name__ == "__main__":
    unittest.main()
