"""Additive facade invariants; format fixtures are not native test evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError
from blackbox_core.investigation_v3 import create_investigation, fork_for_experiment


TARGET = {"pid": 40, "created_100ns": 1234567, "image_path": r"C:\Apps\fixture.exe"}


def application_event(seq, kind, *, operation_id="operation-1", **attributes):
    return {"schema_version": 1, "token": "FORMAT_FIXTURE_TOKEN_ONLY", "pid": 40, "tid": 50,
            "seq": seq, "source_clock": "PYTHON_PERF_COUNTER_NS", "source_ns": seq * 1000,
            "kind": kind, "operation_id": operation_id, "parent_id": None,
            "client_dropped": 0, "attributes": attributes}


def write_events(path):
    rows = [application_event(1, "io.operation.begin", io_kind="READ"),
            application_event(2, "io.operation.end", io_kind="READ", status="ERROR", error_code=5, latency_ns=1000),
            application_event(3, "blackbox.completed", operation_id=None, status="COMPLETED", expected_operations=1)]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InvestigationFacadeContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "app-events.jsonl"
        write_events(self.source)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, path=None, **kwargs):
        return create_investigation([{"source_type": "EVENTS_JSONL", "path": str(path or self.source)}], **kwargs)

    def test_identical_file_at_new_path_has_same_case_and_node_identity(self):
        before = digest(self.source)
        first = self.build()
        moved = self.root / "different-name.jsonl"
        shutil.copyfile(self.source, moved)
        second = self.build(moved)
        self.assertEqual(first["case_id"], second["case_id"])
        self.assertEqual([node["node_id"] for node in first["nodes"]], [node["node_id"] for node in second["nodes"]])
        self.assertEqual(digest(self.source), before)
        self.assertEqual(digest(moved), before)
        self.assertTrue(any(hypothesis["category"] == "FILE_OPERATION_ERROR" for hypothesis in first["hypotheses"]))
        self.assertFalse(first["root_cause_proven"])

    def test_fork_requires_consent_and_preserves_original_source_facts_and_clocks(self):
        original = self.build(target_identity=TARGET)
        frozen = deepcopy(original)
        target = {**TARGET, "created_100ns": 7654321}
        with self.assertRaisesRegex(InvestigationError, "CONFIRMATION_REQUIRED"):
            fork_for_experiment(original, target)
        fork = fork_for_experiment(original, target, confirmed=True)
        self.assertEqual(original, frozen)
        self.assertNotEqual(fork["case_id"], original["case_id"])
        self.assertEqual(fork["origin_case_id"], original["case_id"])
        self.assertEqual(fork["original_target_identity"], TARGET)
        self.assertEqual(fork["target_identity"], target)
        self.assertEqual(fork["historical_target_relation"], "NOT_ESTABLISHED")
        self.assertEqual(fork["nodes"], original["nodes"])
        self.assertEqual(fork["edges"], original["edges"])
        self.assertEqual(fork["sources"], original["sources"])
        self.assertTrue(all(action["historical_target_relation"] == "NOT_ESTABLISHED" for action in fork["actions"]))

    def test_modified_source_during_analysis_cannot_publish_successful_index(self):
        from blackbox_core.critical_path import analyze_critical_path
        target = self.root / "investigation-graph.sqlite3"
        def alter_source_then_analyze(case, *, budget=None):
            with self.source.open("a") as stream:
                stream.write(json.dumps(application_event(4, "user.marker", note="changed during build")) + "\n")
            return analyze_critical_path(case, budget=budget)
        with patch("blackbox_core.critical_path.analyze_critical_path", side_effect=alter_source_then_analyze):
            with self.assertRaisesRegex((InvestigationError, ValueError), "CHANGED"):
                self.build(index_path=target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".blackbox-investigation-*")))

    def test_cancelled_build_cannot_publish_an_index(self):
        stop = threading.Event()
        stop.set()
        target = self.root / "case.sqlite3"
        with self.assertRaises(InterruptedError):
            self.build(index_path=target, budget=InvestigationBudget(cancel_event=stop))
        self.assertFalse(target.exists())
