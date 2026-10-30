"""Own-index publication and import contracts; executed by hosted CI only."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbox_core.evidence_graph import build_graph
from blackbox_core.hypothesis_engine import generate_hypotheses
from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError, evidence_edge, evidence_node
from blackbox_core import investigation_graph_store as store


def graph(seed="a"):
    source = {"source_id": seed * 64, "source_type": "SESSION", "source_sha256": "f" * 64,
              "verification_class": "UNVERIFIED_IMPORT"}
    identity = {"kind": "SESSION_PROCESS", "instance_id": 1, "source_id": source["source_id"], "pid": 10}
    nodes = [evidence_node(source, "samples:1", "MEASUREMENT", process_identity=identity,
                          metadata={"metrics": {"rss_bytes": 100}}, time_domain="SESSION_MONOTONIC:" + source["source_id"],
                          time_bounds={"start": 10, "end": 10, "unit": "ns", "uncertainty": None})]
    return build_graph({"sources": [source], "nodes": nodes, "coverage": {}, "limitations": [], "selection": {}})


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class InvestigationStoreContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_roundtrip_is_read_only_and_identical_save_does_not_rewrite_file(self):
        target = self.root / "investigation-graph.sqlite3"
        value = graph()
        first = store.save_investigation(value, target)
        before = (digest(target), target.stat().st_mtime_ns, target.stat().st_ino)
        loaded = store.load_investigation(target)
        self.assertEqual(loaded, value)
        second = store.save_investigation(value, target)
        self.assertEqual(second["publication"], "IDENTICAL_EXISTING_INDEX")
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(before, (digest(target), target.stat().st_mtime_ns, target.stat().st_ino))
        page = store.query_graph(target, limit=1)
        self.assertEqual(page["records"], value["nodes"])
        self.assertFalse(page["has_more"])

    def test_existing_unrelated_source_is_never_overwritten(self):
        source = self.root / "session.sqlite3"
        with sqlite3.connect(source) as db:
            db.execute("CREATE TABLE source_events(id INTEGER PRIMARY KEY,value TEXT)")
            db.execute("INSERT INTO source_events VALUES(1,'preserve me')")
        before = digest(source)
        with self.assertRaises((InvestigationError, ValueError)):
            store.save_investigation(graph(), source)
        self.assertEqual(digest(source), before)
        self.assertFalse(list(self.root.glob(".blackbox-investigation-*")))

    def test_existing_other_case_is_not_overwritten(self):
        target = self.root / "case.sqlite3"
        store.save_investigation(graph(), target)
        before = digest(target)
        with self.assertRaises(FileExistsError):
            store.save_investigation(graph("b"), target)
        self.assertEqual(digest(target), before)

    def test_content_hash_and_parallel_graph_records_both_have_to_match(self):
        target = self.root / "case.sqlite3"
        store.save_investigation(graph(), target)
        with sqlite3.connect(target) as db:
            db.execute("UPDATE nodes SET record_json='{}'")
        with self.assertRaisesRegex(InvestigationError, "GRAPH_MISMATCH"):
            store.load_investigation(target)
        second = self.root / "second.sqlite3"
        store.save_investigation(graph(), second)
        with sqlite3.connect(second) as db:
            db.execute("UPDATE investigation SET content_json=content_json || ' '")
        with self.assertRaisesRegex(InvestigationError, "CONTENT_HASH"):
            store.load_investigation(second)

    def test_unsupported_schema_and_views_are_not_accepted_as_own_index(self):
        target = self.root / "case.sqlite3"
        store.save_investigation(graph(), target)
        with sqlite3.connect(target) as db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaisesRegex(InvestigationError, "SCHEMA"):
            store.load_investigation(target)
        second = self.root / "second.sqlite3"
        store.save_investigation(graph(), second)
        with sqlite3.connect(second) as db:
            db.execute("DROP TABLE edges")
            db.execute("CREATE VIEW edges AS SELECT 1 ordinal,'x' edge_id,'a' from_node,'b' to_node,'{}' record_json")
        with self.assertRaisesRegex(InvestigationError, "TABLES"):
            store.load_investigation(second)

    def test_dangling_references_never_publish_a_partially_valid_index(self):
        value = graph()
        value["edges"] = [evidence_edge(value["nodes"][0]["node_id"], "missing", "DIRECT_REFERENCE")]
        target = self.root / "invalid.sqlite3"
        with self.assertRaisesRegex(InvestigationError, "DANGLING"):
            store.save_investigation(value, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".blackbox-investigation-*")))

    def test_export_redacts_private_navigation_and_secrets_and_escapes_html(self):
        value = graph()
        source_id = value["sources"][0]["source_id"]
        value["_source_paths"] = {source_id: str(self.root / "private-user" / "events.sqlite3")}
        value["nodes"][0]["metadata"].update(password="SECRET_PASSWORD", token="SECRET_TOKEN",
            environment={"SECRET_KEY": "PRIVATE_ENVIRONMENT"}, value_hex="PRIVATE_MEMORY_BYTES")
        value["nodes"][0]["metadata"]["metrics"]["cpu_percent"] = 95
        value["hypotheses"] = generate_hypotheses(value)
        value["hypotheses"][0]["description"] = "<script>alert('untrusted')</script>"
        target = self.root / "case.html"
        receipt = store.export_investigation(value, target, format="html")
        text = target.read_text()
        for forbidden in ("SECRET_PASSWORD", "SECRET_TOKEN", "PRIVATE_ENVIRONMENT", "PRIVATE_MEMORY_BYTES", "private-user"):
            self.assertNotIn(forbidden, text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<script>", text)
        self.assertEqual(receipt["sha256"], digest(target))
        self.assertIn("SECRET_PASSWORD", json.dumps(value))  # Original facts were not mutated.

    def test_cancel_after_fsync_before_publication_removes_only_own_temporary_file(self):
        cancelled = threading.Event()
        target = self.root / "case.sqlite3"
        fsync = os.fsync
        def flush_then_cancel(descriptor):
            fsync(descriptor)
            cancelled.set()
        with patch.object(store.os, "fsync", side_effect=flush_then_cancel), patch.object(store.os, "link") as publish:
            with self.assertRaises(InterruptedError):
                store.save_investigation(graph(), target, budget=InvestigationBudget(cancel_event=cancelled))
        publish.assert_not_called()
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".blackbox-investigation-*")))

    def test_successful_atomic_publication_is_not_undone_by_later_cancellation(self):
        cancelled = threading.Event()
        target = self.root / "case.json"
        link = os.link
        def link_then_cancel(source, destination):
            link(source, destination)
            cancelled.set()
        with patch.object(store.os, "link", side_effect=link_then_cancel):
            receipt = store.export_investigation(graph(), target, budget=InvestigationBudget(cancel_event=cancelled))
        self.assertEqual(receipt["status"], "COMPLETED")
        self.assertTrue(target.exists())
        self.assertFalse(list(self.root.glob(".blackbox-investigation-export-*")))

    def test_sql_progress_interrupt_reports_cancellation_and_keeps_index_unchanged(self):
        target = self.root / "case.sqlite3"
        store.save_investigation(graph(), target)
        before = digest(target)
        cancelled = threading.Event()
        original_open = store._open_index
        def open_with_sql_cancellation(path, budget):
            actual_path, connection = original_open(path, budget)
            def interrupt_in_query():
                cancelled.set()
                return 1
            connection.set_progress_handler(interrupt_in_query, 1)
            return actual_path, connection
        with patch.object(store, "_open_index", side_effect=open_with_sql_cancellation):
            with self.assertRaises(InterruptedError):
                store.load_investigation(target, budget=InvestigationBudget(cancel_event=cancelled))
        self.assertTrue(cancelled.is_set())
        self.assertEqual(digest(target), before)

    @unittest.skipIf(os.name == "nt", "Windows disallows replacing this open SQLite file; exercise the real POSIX inode race")
    def test_path_replacement_after_open_is_rejected_instead_of_returning_old_inode_data(self):
        target, replacement = self.root / "old.sqlite3", self.root / "replacement.sqlite3"
        store.save_investigation(graph(), target)
        store.save_investigation(graph("b"), replacement)
        original_open = store._open_index
        def open_then_replace(path, budget):
            opened = original_open(path, budget)
            os.replace(replacement, target)
            return opened
        with patch.object(store, "_open_index", side_effect=open_then_replace):
            with self.assertRaisesRegex(InvestigationError, "CHANGED"):
                store.load_investigation(target)
