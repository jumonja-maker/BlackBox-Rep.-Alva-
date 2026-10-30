"""Existing-index navigation contracts, executed on hosted CI only.

These synthetic indices test navigation/ownership, not native ETL collection.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from blackbox_core.decoder_index import PROTOCOL, build_index
from blackbox_universal.decoder_index_navigation import copy_navigation_index, navigation_filters
from blackbox_universal.decoder_panel import DecoderPanel

TRACE_HASH = "a" * 64


def make_index(folder):
    source, output = folder / "synthetic.protocol.jsonl", folder / "imported.sqlite3"
    rows = [{"type": "header", "protocol": PROTOCOL, "input_sha256": TRACE_HASH},
            {"type": "event", "ordinal": 1, "time_ms": 10.0, "pid": 123,
             "tid": 7, "process_instance": 17, "provider": "SYNTHETIC_ONLY",
             "name": "fixture.event", "payload": {}, "frames": []},
            {"type": "footer", "protocol": PROTOCOL, "rows": 1, "status": "DECODED"}]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    build_index(source, output, input_sha256=TRACE_HASH, format_name=".etl")
    return output


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class DecoderNavigationCopyContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = make_index(self.root)
        self.output = self.root / "private.sqlite3"
        self.original_hash = digest(self.source)

    def test_validated_copy_retains_source_and_distinguishes_trace_from_index_identity(self):
        result = copy_navigation_index(self.source, self.output,
            expected_trace_sha256=TRACE_HASH, expected_index_sha256=self.original_hash,
            filters={"process_instance": 17, "pid": 123, "tid": 7, "start_ms": 9.0, "end_ms": 11.0})
        self.assertNotEqual(result["path"], str(self.source))
        self.assertEqual(digest(self.output), self.original_hash)
        self.assertEqual(digest(self.source), self.original_hash)
        self.assertEqual(result["source_trace_sha256"], TRACE_HASH)
        self.assertEqual(result["navigation"]["process_instance"], 17)
        self.assertEqual(result["initial_page"]["rows"][0]["event"]["tid"], 7)
        self.assertEqual(result["live_identity_binding"], "NOT_ESTABLISHED")
        self.assertFalse(result["source_modified"])
        self.assertFalse(Path(str(self.source) + "-wal").exists())
        self.assertFalse(Path(str(self.source) + "-shm").exists())

    def test_wrong_trace_or_index_digest_never_publishes_a_copy(self):
        for key in ("expected_trace_sha256", "expected_index_sha256"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "HASH_MISMATCH"):
                copy_navigation_index(self.source, self.output, **{key: "b" * 64})
            self.assertFalse(self.output.exists())
            self.assertEqual(digest(self.source), self.original_hash)

    def test_cancellation_during_flush_removes_only_private_copy(self):
        cancellation = Event()
        native_fsync = os.fsync
        def cancel_at_flush(fd):
            native_fsync(fd)
            cancellation.set()
        with patch("blackbox_universal.decoder_index_navigation.os.fsync", side_effect=cancel_at_flush), \
                self.assertRaisesRegex(InterruptedError, "NAVIGATION_CANCELLED"):
            copy_navigation_index(self.source, self.output, cancel_event=cancellation)
        self.assertFalse(self.output.exists())
        self.assertEqual(digest(self.source), self.original_hash)

    def test_input_replacement_or_growth_during_copy_is_rejected(self):
        native_fsync = os.fsync
        def change_source(fd):
            native_fsync(fd)
            with self.source.open("ab") as stream:
                stream.write(b"changed")
        with patch("blackbox_universal.decoder_index_navigation.os.fsync", side_effect=change_source), \
                self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
            copy_navigation_index(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.source.exists())

    def test_preexisting_destination_is_not_overwritten_or_removed(self):
        self.output.write_bytes(b"owned by another export")
        with self.assertRaises(FileExistsError):
            copy_navigation_index(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b"owned by another export")
        self.assertEqual(digest(self.source), self.original_hash)

    def test_nonempty_wal_and_malformed_display_metadata_are_rejected(self):
        wal = Path(str(self.source) + "-wal")
        wal.write_bytes(b"uncheckpointed source")
        with self.assertRaisesRegex(ValueError, "SOURCE_NOT_CLOSED"):
            copy_navigation_index(self.source, self.output)
        wal.unlink()
        with sqlite3.connect(self.source) as connection:
            raw, = connection.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()
            summary = json.loads(raw)
            del summary["gc"]
            connection.execute("UPDATE metadata SET value=? WHERE key='summary'", (json.dumps(summary),))
        malformed_hash = digest(self.source)
        with self.assertRaisesRegex(ValueError, "DISPLAY_SUMMARY_INVALID"):
            copy_navigation_index(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(digest(self.source), malformed_hash)

    def test_limits_and_nonfinite_or_boolean_scope_are_rejected(self):
        for values in ({"pid": True}, {"process_instance": False}, {"tid": -1},
                       {"start_ms": float("nan")}, {"end_ms": float("inf")},
                       {"start_ms": 10.0, "end_ms": 10.0}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                navigation_filters(**values)
        with patch("blackbox_universal.decoder_index_navigation.MAX_INDEX_BYTES", 16), \
                self.assertRaisesRegex(ValueError, "SIZE_BUDGET"):
            copy_navigation_index(self.source, self.output)
        self.assertFalse(self.output.exists())
        with patch("blackbox_universal.decoder_index_navigation.time.monotonic", side_effect=[0.0, 2.0]), \
                self.assertRaisesRegex(TimeoutError, "NAVIGATION_TIMEOUT"):
            copy_navigation_index(self.source, self.output, timeout_seconds=1)
        self.assertFalse(self.output.exists())


class DecoderNavigationGuiContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.window = QWidget()
        self.window.language = "EN"
        self.window.probe = SimpleNamespace(active=False, session_folder=None)
        self.panel = DecoderPanel(self.window)
        self.source = make_index(self.root)
        self.original_hash = digest(self.source)
        self.panel.show()
        self.app.processEvents()

    def tearDown(self):
        self.panel.cancel()
        self.wait_idle()
        self.panel.cache.cleanup()
        self.panel.close()
        self.window.close()
        self.panel.deleteLater()
        self.window.deleteLater()
        self.app.processEvents()
        self.temp.cleanup()

    def wait_until(self, predicate):
        deadline = time.monotonic() + 10
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.assertTrue(predicate(), self.panel.error)

    def wait_idle(self):
        self.wait_until(lambda: self.panel.worker is None)

    def test_navigation_opens_private_index_presets_recorded_filters_and_preserves_source_after_decode(self):
        opened = []
        self.panel.index_interval_opened.connect(opened.append)
        self.assertTrue(self.panel.open_index_interval(self.source,
            expected_trace_sha256=TRACE_HASH, expected_index_sha256=self.original_hash,
            process_instance=17, pid=123, tid=7, start_ms=9.5, end_ms=11.0))
        self.assertIsNotNone(self.panel.worker)
        self.wait_idle()
        self.assertEqual(self.panel.state, "decoded", self.panel.error)
        self.assertEqual(self.panel.cpu_source.currentData(), "etw")
        self.assertEqual((self.panel.cpu_instance.text(), self.panel.cpu_tid.text()), ("17", "7"))
        self.assertEqual((self.panel.cpu_start.text(), self.panel.cpu_end.text()), ("9.5", "11.0"))
        self.assertEqual(self.panel.table.rowCount(), 1)
        self.assertEqual(len(opened), 1)
        self.assertNotEqual(self.panel.index, self.source)
        cached = self.panel.index
        new_source = self.root / "new-source.jsonl"
        new_source.write_text(json.dumps({"schema_version": 1, "pid": 5, "tid": 6,
            "seq": 1, "source_ns": 100, "source_clock": "SYNTHETIC_ONLY", "kind": "test"}) + "\n")
        self.panel.start_decode(new_source)
        self.wait_idle()
        self.assertFalse(cached.exists())
        self.assertTrue(self.source.exists())
        self.assertEqual(digest(self.source), self.original_hash)

    def test_late_result_after_cancel_cannot_install_index_or_emit_navigation(self):
        copied, release = Event(), Event()
        opened = []
        self.panel.index_interval_opened.connect(opened.append)
        real_copy = copy_navigation_index
        def hold_copy(*args, **kwargs):
            result = real_copy(*args, **kwargs)
            copied.set()
            if not release.wait(5):
                raise TimeoutError("TEST_RELEASE_NOT_RECEIVED")
            return result
        try:
            with patch("blackbox_universal.decoder_index_navigation.copy_navigation_index", side_effect=hold_copy):
                self.assertTrue(self.panel.open_index_interval(self.source, expected_trace_sha256=TRACE_HASH))
                self.wait_until(copied.is_set)
                self.panel.cancel_index_navigation()
                release.set()
                self.wait_idle()
            self.assertEqual(opened, [])
            self.assertIsNone(self.panel.index)
            self.assertEqual(list(Path(self.panel.cache.name).iterdir()), [])
            self.assertEqual(digest(self.source), self.original_hash)
        finally:
            release.set()

    def test_navigation_from_current_cache_keeps_its_own_graph_source(self):
        self.assertTrue(self.panel.open_index_interval(self.source, expected_trace_sha256=TRACE_HASH))
        self.wait_idle()
        graph_source = self.panel.index
        original = digest(graph_source)
        self.assertTrue(self.panel.open_index_interval(graph_source, expected_index_sha256=original,
                                                       process_instance=17, tid=7, start_ms=9.0, end_ms=11.0))
        self.wait_idle()
        self.assertEqual(self.panel.state, "decoded", self.panel.error)
        self.assertNotEqual(self.panel.index, graph_source)
        self.assertEqual(digest(graph_source), original)
        self.assertEqual(digest(self.panel.index), original)

    def test_failed_copy_keeps_previous_cached_source_bytes(self):
        self.assertTrue(self.panel.open_index_interval(self.source, expected_trace_sha256=TRACE_HASH))
        self.wait_idle()
        previous = self.panel.index
        original = digest(previous)
        self.assertTrue(self.panel.open_index_interval(previous, expected_trace_sha256="b" * 64))
        self.wait_idle()
        self.assertEqual(self.panel.state, "error")
        self.assertEqual(digest(previous), original)
        self.assertEqual([p for p in Path(self.panel.cache.name).glob("*.sqlite3")], [previous])

    def test_source_digest_refusal_is_visible_and_never_uses_stale_rows(self):
        self.assertTrue(self.panel.open_index_interval(self.source, expected_trace_sha256="b" * 64))
        self.wait_idle()
        self.assertEqual(self.panel.state, "error")
        self.assertIn("TRACE_HASH_MISMATCH", self.panel.error)
        self.assertIsNone(self.panel.index)
        self.assertEqual(self.panel.table.rowCount(), 0)
        self.assertEqual(digest(self.source), self.original_hash)

    def test_legacy_external_index_is_never_unlinked_by_later_decode(self):
        from blackbox_core.decoder_index import read_index
        self.panel.received({"path": str(self.source), "summary": read_index(self.source)["summary"]}, "")
        other = self.root / "other.jsonl"
        other.write_text(json.dumps({"schema_version": 1, "pid": 1, "tid": 2, "seq": 1,
                                     "source_ns": 100, "source_clock": "SYNTHETIC_ONLY", "kind": "test"}) + "\n")
        self.panel.start_decode(other)
        self.wait_idle()
        self.assertEqual(digest(self.source), self.original_hash)


if __name__ == "__main__":
    unittest.main()
