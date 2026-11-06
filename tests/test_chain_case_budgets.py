"""Explicit per-node case budgets over real saved JSONL/index files; hosted CI only."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from blackbox_core.chain_adapters import _budget, build_catalog
from blackbox_core.chain_contracts import WorkflowError
from blackbox_core.chain_validation import validate_parameters
from blackbox_core.investigation_graph_contracts import InvestigationError


CASE_TOOLS = ("load_graph", "investigate", "critical_path", "crash", "incident", "compare", "export_report")
DEFAULT_BYTES, EXPLICIT_BYTES, HARD_BYTES = 32 * 1024**2, 48 * 1024**2, 64 * 1024**2


class CaseContext:
    def __init__(self, folder, number):
        self.run_id, self.node_id, self.node_run_id = "case-budget-run", "case-node", "case-call-" + str(number)
        self.iteration, self.runtime = 0, None
        self.output_dir = Path(folder)
        self.output_dir.mkdir(parents=True)
        self.deadline, self.cancel = time.monotonic() + 60, threading.Event()

    def check(self):
        if self.cancel.is_set():
            raise InterruptedError("WORKFLOW_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WORKFLOW_NODE_DEADLINE")

    def remaining_seconds(self):
        return max(0, self.deadline - time.monotonic())


class CaseBudgetAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root, self.number = Path(self.temporary.name), 0
        self.catalog = build_catalog()

    def context(self):
        self.number += 1
        return CaseContext(self.root / ("output-" + str(self.number)), self.number)

    def call(self, name, inputs=None, parameters=None, *, ctx=None):
        return self.catalog[name].execute(ctx or self.context(), inputs or {}, parameters or {})

    def test_case_catalog_defaults_and_hard_limit_are_typed_and_scoped(self):
        for name in CASE_TOOLS:
            with self.subTest(tool=name):
                required = {"incident_id": 1} if name == "incident" else {}
                parsed = validate_parameters(self.catalog[name], required)
                self.assertEqual(parsed["max_result_bytes"], DEFAULT_BYTES)
                self.assertEqual(validate_parameters(self.catalog[name], {**required, "max_result_bytes": HARD_BYTES})[
                    "max_result_bytes"], HARD_BYTES)
                for invalid in (True, 1023, HARD_BYTES + 1, float(EXPLICIT_BYTES), "48 MiB"):
                    with self.subTest(invalid=invalid), self.assertRaises(WorkflowError):
                        validate_parameters(self.catalog[name], {**required, "max_result_bytes": invalid})
        for name in ("load_source", "decode_trace", "observe", "deep.modules"):
            self.assertNotIn("max_result_bytes", self.catalog[name].parameters)
        ctx = self.context()
        actual = _budget(ctx)
        self.assertEqual(actual.max_result_bytes, DEFAULT_BYTES)
        self.assertIs(actual.cancel_event, ctx.cancel)
        self.assertEqual(actual.deadline, ctx.deadline)

    def test_invalid_runtime_limit_is_refused_before_component_dispatch(self):
        with patch("blackbox_core.investigation_v3.create_investigation") as create, \
                patch("blackbox_core.investigation_v3.load_investigation") as load, \
                patch("blackbox_core.investigation_v3.export_investigation") as export:
            for name in CASE_TOOLS:
                for invalid in (True, 1023, HARD_BYTES + 1):
                    with self.subTest(tool=name, invalid=invalid):
                        ctx = self.context()
                        result = self.call(name, parameters={"max_result_bytes": invalid}, ctx=ctx)
                        self.assertEqual(result.reason_code, "WORKFLOW_ANALYSIS_RESULT_BYTE_LIMIT")
                        self.assertFalse(result.execution_started)
                        self.assertEqual(result.outputs, {})
                        self.assertFalse(hasattr(ctx, "_analysis_result_byte_limit"))
            create.assert_not_called()
            load.assert_not_called()
            export.assert_not_called()

    def test_explicit_limit_controls_actual_case_create_reopen_cp_and_export_without_source_authority(self):
        from blackbox_core.decoder_index import read_index
        from blackbox_core.investigation_v3 import load_investigation
        source = self.root / "case-budget-format-fixture.jsonl"
        rows = [{"schema_version": 1, "token": "CASE_BUDGET_FORMAT_FIXTURE_NOT_AUTHENTICATED", "pid": 42,
                 "tid": 43, "seq": number, "source_ns": number * 1000, "source_clock": "UNALIGNED_FIXTURE_CLOCK",
                 "kind": "user.marker", "client_dropped": 0,
                 "attributes": {"name": "fixture-" + str(number), "note": "bounded fixture detail " * 20}}
                for number in range(1, 13)]
        source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        artifact = self.call("load_source", parameters={"kind": "TRACE", "path": str(source)}).outputs["source"]
        index = self.call("decode_trace", {"trace": artifact}).outputs["index"]
        index_path = Path(index.value["_path"])
        index_before = hashlib.sha256(index_path.read_bytes()).hexdigest()
        limited_ctx = self.context()
        with self.assertRaisesRegex(InvestigationError, "INVESTIGATION_RESULT_BYTE_BUDGET") as caught:
            self.call("investigate", {"evidence": (index,)}, {"max_result_bytes": 4096}, ctx=limited_ctx)
        self.assertGreater(caught.exception.actual_result_bytes, 4096)
        self.assertEqual(caught.exception.result_byte_limit, 4096)
        self.assertEqual(caught.exception.run_context["parameters"]["max_result_bytes"], 4096)
        self.assertFalse(hasattr(limited_ctx, "_analysis_result_byte_limit"))
        high_ctx = self.context()
        deadline = high_ctx.deadline
        investigated = self.call("investigate", {"evidence": (index,)}, {"max_result_bytes": EXPLICIT_BYTES}, ctx=high_ctx)
        self.assertEqual(investigated.context["parameters"]["max_result_bytes"], EXPLICIT_BYTES)
        self.assertFalse(hasattr(high_ctx, "_analysis_result_byte_limit"))
        self.assertEqual(high_ctx.deadline, deadline)
        self.assertFalse(high_ctx.cancel.is_set())
        case = investigated.outputs["case"]
        saved = load_investigation(case.value["_path"])
        self.assertGreater(len(json.dumps(saved).encode("utf-8")), 4096)
        self.assertFalse(saved["root_cause_proven"])
        self.assertIsNone(saved["target_identity"])
        opened = self.call("load_graph", {"source": case}, {"max_result_bytes": EXPLICIT_BYTES})
        self.assertEqual(opened.context["limits"]["max_result_bytes"], EXPLICIT_BYTES)
        cp = self.call("critical_path", {"case": opened.outputs["case"]}, {"max_result_bytes": EXPLICIT_BYTES})
        self.assertEqual(cp.context["limits"]["max_result_bytes"], EXPLICIT_BYTES)
        self.assertTrue(Path(cp.outputs["report"].value["_path"]).is_file())
        exported = self.call("export_report", {"case": cp.outputs["case"]},
                             {"format": "json", "max_result_bytes": EXPLICIT_BYTES})
        self.assertEqual(exported.context["parameters"]["max_result_bytes"], EXPLICIT_BYTES)
        self.assertTrue(exported.outputs["report"].value["readback_verified"])
        public = json.loads(Path(exported.outputs["report"].value["_path"]).read_text(encoding="utf-8"))
        self.assertFalse(public["root_cause_proven"])
        self.assertEqual(public["sources"][0]["verification_class"], "UNVERIFIED_IMPORT")
        # An imported metadata claim does not configure the next node. Only
        # the next explicit node parameter can opt into a different limit.
        spoofed = replace(case, value={**deepcopy(case.value), "max_result_bytes": HARD_BYTES})
        ordinary = self.call("load_graph", {"source": spoofed})
        self.assertEqual(ordinary.context["limits"]["max_result_bytes"], DEFAULT_BYTES)
        self.assertEqual(_budget(high_ctx).max_result_bytes, DEFAULT_BYTES)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertEqual(hashlib.sha256(index_path.read_bytes()).hexdigest(), index_before)
        self.assertEqual(read_index(index_path)["summary"]["rows"], 12)
