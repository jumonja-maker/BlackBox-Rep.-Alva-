"""Reservation boundaries, distinct from native or whole-operation cleanup.

The JSONL/index/Inv3 paths use actual saved-file components. Explicit exception
injections below exercise failure policy and never establish Windows results.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.chain_adapters import build_catalog
from blackbox_core.chain_contracts import WorkflowDefinition
from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_store import WorkflowRunStore
from blackbox_core.investigation_graph_contracts import InvestigationError
from blackbox_core import chain_engine, issue_grouping


def edge(first, port, second, target):
    return {"edge_id": first + "." + port + "-" + second + "." + target,
            "source_node": first, "source_port": port, "target_node": second, "target_port": target}


class ReservationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trace = self.root / "source.jsonl"
        rows = [{"schema_version": 1, "token": "EXPLICIT_SAVED_FORMAT_FIXTURE", "pid": 42, "tid": 43,
            "seq": number, "source_ns": number * 1000, "source_clock": "FORMAT_FIXTURE_CLOCK",
            "kind": "user.marker", "client_dropped": 0, "attributes": {"name": "marker"}}
            for number in range(1, 4)]
        self.trace.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def run_graph(self, nodes, edges):
        definition = WorkflowDefinition.from_dict({"schema": "blackbox.workflow-definition/1",
            "workflow_id": "reservation-fixture", "title": "Explicit reservation fault fixture",
            "nodes": [{"budget_seconds": 15, **node} for node in nodes], "edges": edges,
            "budget": {"seconds": 180, "max_workers": 2, "max_owned_resources": 8,
                       "max_output_bytes": 16 * 1024**2}})
        store = WorkflowRunStore.create(self.root / "runs", definition)
        result = WorkflowEngine(definition, catalog=build_catalog(), store=store).run()
        return result, {row["node_id"]: row for row in result["nodes"]}, store

    def data_graph(self):
        return ([{"node_id": "source", "tool_id": "load_source",
                  "parameters": {"kind": "TRACE", "path": str(self.trace)}},
                 {"node_id": "decode", "tool_id": "decode_trace"},
                 {"node_id": "failed", "tool_id": "investigate", "allow_partial_inputs": True},
                 {"node_id": "next", "tool_id": "investigate", "allow_partial_inputs": True}],
                [edge("source", "source", "decode", "trace"),
                 edge("decode", "index", "failed", "evidence"),
                 edge("decode", "index", "next", "evidence")])

    def test_actual_data_failure_releases_only_unentered_native_reservation_and_keeps_failed_receipt(self):
        calls = []
        original = issue_grouping.group_recurrent_issues
        def fail_first(cases, *, budget=None):
            calls.append(True)
            if len(calls) == 1:
                raise InvestigationError("CONTROLLED_POSTNORMALIZATION_GRAPH_ERROR")
            return original(cases, budget=budget)
        nodes, edges = self.data_graph()
        with patch.object(issue_grouping, "group_recurrent_issues", fail_first), \
                patch("blackbox_core.deep_dump.inspect_dump") as native:
            result, records, store = self.run_graph(nodes, edges)
        native.assert_not_called()
        self.assertEqual(len(calls), 2, "the next independent Inv3 reservation must actually execute")
        self.assertEqual(records["failed"]["state"], "FAILED")
        self.assertEqual(records["failed"]["reason_code"], "CONTROLLED_POSTNORMALIZATION_GRAPH_ERROR")
        self.assertIn(records["next"]["state"], ("COMPLETED", "PARTIAL"))
        failed = records["failed"]
        self.assertEqual(failed["run_receipt"]["status"], "OPERATION_FAILED")
        self.assertFalse(failed["run_receipt"]["cleanup"]["confirmed"])
        self.assertEqual(failed["run_receipt"]["cleanup"]["status"], "NOT_COLLECTED")
        self.assertFalse(failed["cleanup"]["confirmed"])
        reserved = failed["resource_reservations"]["OFFLINE_DBGHELP_OWNER"]
        self.assertTrue(reserved["confirmed"])
        self.assertEqual(reserved["scope"], "DECLARED_RESERVATION_NOT_ENTERED")
        self.assertFalse(reserved["file_or_sqlite_cleanup_claimed"])
        self.assertEqual(result["state"], "PARTIAL")
        self.assertTrue(result["cleanup"]["confirmed"])
        saved = next(event["data"] for event in store.read_events()
                     if event["event"] == "node.result" and event["node_id"] == "failed")
        self.assertEqual(saved["run_receipt"], failed["run_receipt"])
        self.assertEqual(saved["resource_reservations"], failed["resource_reservations"])

    def test_explicit_unknown_owner_disables_even_previously_recorded_not_entered_proof(self):
        calls = []
        def fail_unknown(cases, *, budget=None):
            calls.append(True)
            error = InvestigationError("EXPLICIT_BOUNDARY_OWNER_UNCONFIRMED")
            error.offline_owner_retained = True
            raise error
        nodes, edges = self.data_graph()
        # Isolate a deliberately unreleasable unit-fixture lease. No Windows
        # owner exists in this injected test, and no actual QA lease is cleared.
        with patch.object(chain_engine, "_LEASES", {}), \
                patch.object(issue_grouping, "group_recurrent_issues", fail_unknown):
            result, records, _store = self.run_graph(nodes, edges)
            self.assertEqual(len(calls), 1)
            self.assertEqual(records["failed"]["state"], "RECOVERY_UNCONFIRMED")
            self.assertEqual(records["failed"]["resource_reservations"], {})
            self.assertEqual(records["next"]["state"], "RECOVERY_UNCONFIRMED")
            self.assertIn("OFFLINE_DBGHELP_OWNER", chain_engine._LEASES)
            self.assertFalse(result["cleanup"]["confirmed"])

    def test_dump_with_local_image_cannot_claim_its_native_reservation_was_not_entered(self):
        dump, image, pdb = (self.root / name for name in ("private-fixture.dmp", "fixture.exe", "fixture.pdb"))
        for path in (dump, image, pdb):
            path.write_bytes(b"EXPLICIT_BOUNDARY_FIXTURE_NO_NATIVE_CAPTURE")
        nodes = [{"node_id": "dump", "tool_id": "load_source",
                  "parameters": {"kind": "DUMP", "path": str(dump)}},
                 {"node_id": "first", "tool_id": "crash",
                  "parameters": {"image_path": str(image), "pdb_path": str(pdb)}},
                 {"node_id": "second", "tool_id": "crash",
                  "parameters": {"image_path": str(image), "pdb_path": str(pdb)}}]
        edges = [edge("dump", "source", "first", "dump"), edge("dump", "source", "second", "dump")]
        error = InvestigationError("INJECTED_OFFLINE_NATIVE_OWNER_UNCONFIRMED")
        error.cleanup_required = True
        with patch.object(chain_engine, "_LEASES", {}), \
                patch("blackbox_core.deep_dump.inspect_dump", side_effect=error) as native:
            result, records, _store = self.run_graph(nodes, edges)
            native.assert_called_once()
            self.assertEqual(native.call_args.kwargs["image_path"], str(image))
            self.assertEqual(records["first"]["resource_reservations"], {})
            self.assertEqual(records["first"]["state"], "RECOVERY_UNCONFIRMED")
            self.assertEqual(records["second"]["state"], "RECOVERY_UNCONFIRMED")
            self.assertFalse(records["first"]["run_receipt"]["cleanup"]["confirmed"])
            self.assertIn("OFFLINE_DBGHELP_OWNER", chain_engine._LEASES)
            self.assertFalse(result["cleanup"]["confirmed"])


if __name__ == "__main__":
    unittest.main()
