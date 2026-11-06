"""Real offline adapters and explicit consent boundary contracts.

Fixtures exercise saved-file components. Mocked native boundaries below do not
claim Windows/UAC acceptance; that belongs to the hosted native R60 harness.
"""
from copy import deepcopy
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from blackbox_core.chain_adapters import ChainRuntime, build_catalog
from blackbox_core.chain_contracts import Artifact
from blackbox_core.deep_contracts import ActionRequest, DEEP_ACTIONS, ProcessIdentity
from blackbox_core.deep_tool_contracts import attach_run_receipt, begin_run, describe_tool


class AnalysisHTML(HTMLParser):
    """Independent parser; does not call the product's export readback code."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.active, self.parts, self.documents = False, [], []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("id") == "blackbox-analysis-data":
            if self.active or self.documents or values.get("type") != "application/json":
                raise AssertionError("INVALID_ANALYSIS_HTML_METADATA")
            self.active = True

    def handle_data(self, value):
        if self.active:
            self.parts.append(value)

    def handle_endtag(self, tag):
        if self.active and tag == "script":
            self.documents.append(json.loads("".join(self.parts)))
            self.active = False


class Context:
    def __init__(self, folder, runtime=None):
        self.run_id = "adapter-run"
        self.node_id = "adapter-node"
        self.node_run_id = "adapter-call"
        self.iteration = 1
        self.output_dir = Path(folder)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.deadline = time.monotonic() + 60
        self.cancel = threading.Event()
        self.runtime = runtime
        self.events = []

    def check(self):
        if self.cancel.is_set():
            raise InterruptedError("WORKFLOW_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WORKFLOW_DEADLINE")

    def remaining_seconds(self):
        return max(0, self.deadline - time.monotonic())

    def emit(self, phase, details=None):
        self.events.append((phase, details))

    def waiting_for_human(self, details):
        self.emit("WAITING_FOR_HUMAN", details)

    def running(self):
        self.emit("RUNNING")


class ChainAdapterOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = build_catalog()
        self.counter = 0
        self.trace = self.root / "source.jsonl"
        rows = [{"schema_version": 1, "token": "CONTRACT_FIXTURE_NOT_AUTHENTICATED",
            "pid": 42, "tid": 43, "seq": number, "source_ns": number * 1000,
            "source_clock": "FORMAT_FIXTURE_CLOCK", "kind": "user.marker", "client_dropped": 0,
            "attributes": {"name": "fixture-" + str(number)}} for number in range(1, 4)]
        self.trace.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def call(self, tool, inputs=None, parameters=None, runtime=None):
        self.counter += 1
        ctx = Context(self.root / ("output-" + str(self.counter)), runtime)
        return self.catalog[tool].execute(ctx, inputs or {}, parameters or {})

    def source(self):
        outcome = self.call("load_source", parameters={"kind": "TRACE", "path": str(self.trace)})
        self.assertEqual(outcome.status, "COMPLETED")
        self.assertTrue(outcome.cleanup["confirmed"])
        source = outcome.outputs["source"]
        self.assertEqual(source.sources[0]["source_id"], hashlib.sha256(self.trace.read_bytes()).hexdigest())
        self.assertEqual(source.sources[0]["verification"], "UNVERIFIED_IMPORT")
        return source

    def test_catalog_construction_does_not_construct_a_collector_or_inspector(self):
        with patch("blackbox_core.deep_service.InspectorService") as inspector, \
                patch("blackbox_core.research_worker.ResearchSession") as recorder:
            catalog = build_catalog()
        inspector.assert_not_called()
        recorder.assert_not_called()
        for operation in DEEP_ACTIONS:
            self.assertEqual(catalog["deep." + operation].descriptor, describe_tool(operation))
        self.assertNotIn("shell", catalog)
        self.assertEqual(catalog["decode_trace"].inputs["trace"].types, ("TRACE",))

    def test_real_saved_source_decoder_investigation_graph_and_reports(self):
        from blackbox_core.decoder_index import read_index
        from blackbox_core.investigation_v3 import load_investigation
        before = hashlib.sha256(self.trace.read_bytes()).hexdigest()
        source = self.source()
        decoded = self.call("decode_trace", {"trace": source})
        index = decoded.outputs["index"]
        actual = read_index(index.value["_path"], limit=1)["summary"]
        self.assertEqual(decoded.receipt, actual["run_receipt"])
        self.assertEqual(decoded.receipt["operation"], "decoder.decode")
        self.assertTrue(decoded.receipt["cleanup"]["confirmed"])
        investigated = self.call("investigate", {"evidence": (index,)})
        case = investigated.outputs["case"]
        saved = load_investigation(case.value["_path"])
        self.assertEqual(investigated.receipt["run_id"], saved["run_receipt"]["run_id"])
        self.assertFalse(saved["root_cause_proven"])
        self.assertEqual(saved["file_trust"], "UNVERIFIED_IMPORT")
        opened = self.call("load_graph", {"source": case})
        self.assertEqual(opened.outputs["case"].value["case_id"], case.value["case_id"])
        for format_name in ("json", "html"):
            exported = self.call("export_report", {"case": opened.outputs["case"]}, {"format": format_name})
            self.assertEqual(exported.receipt["operation"], "investigation.export")
            self.assertTrue(exported.outputs["report"].value["readback_verified"])
            text = Path(exported.outputs["report"].value["_path"]).read_text(encoding="utf-8")
            self.assertIn(saved["case_id"], text)
            self.assertNotIn("CONTRACT_FIXTURE_NOT_AUTHENTICATED", text)
        self.assertEqual(hashlib.sha256(self.trace.read_bytes()).hexdigest(), before)

    def test_source_changed_after_selection_cannot_be_decoded_as_same_evidence(self):
        source = self.source()
        self.trace.write_text(self.trace.read_text() + "{}\n", encoding="utf-8")
        result = self.call("decode_trace", {"trace": source})
        self.assertNotIn("index", result.outputs)
        self.assertNotEqual(result.status, "COMPLETED")
        self.assertFalse(result.receipt["execution_started"])

    def test_existing_analysis_does_not_claim_scheduler_or_root_cause_evidence(self):
        index = self.call("decode_trace", {"trace": self.source()}).outputs["index"]
        for tool, expected in (("waits", "NO_SCHEDULER_EVENTS"), ("file_io", "NO_FILE_IO_EVENTS"),
                               ("disk_io", "NO_DISK_REQUEST_EVENTS")):
            result = self.call(tool, {"index": index})
            self.assertEqual(result.status, expected)
            self.assertEqual(result.outputs["index"], index)
            report = json.loads(Path(result.outputs["report"].value["_path"]).read_text())
            self.assertEqual(report["status"], expected)
            self.assertEqual(result.receipt["status_adapter"], "WORKFLOW_LEGACY_STATUS_IDENTITY_V1")
        path = self.call("critical_path", {"case": index})
        self.assertEqual(path.status, "NOT_ESTABLISHED")
        report = json.loads(Path(path.outputs["report"].value["_path"]).read_text())
        self.assertFalse(report["end_to_end_established"])
        self.assertTrue(path.outputs["case"].value["case_id"])

    def test_actual_jsonl_analysis_reports_export_both_formats_with_same_semantics_and_bound_sources(self):
        trace_before = hashlib.sha256(self.trace.read_bytes()).hexdigest()
        index = self.call("decode_trace", {"trace": self.source()}).outputs["index"]
        index_path = Path(index.value["_path"])
        index_before = hashlib.sha256(index_path.read_bytes()).hexdigest()
        for tool, expected in (("waits", "NO_SCHEDULER_EVENTS"), ("file_io", "NO_FILE_IO_EVENTS"),
                               ("disk_io", "NO_DISK_REQUEST_EVENTS")):
            with self.subTest(tool=tool):
                analyzed = self.call(tool, {"index": index})
                source = analyzed.outputs["report"]
                report_path = Path(source.value["_path"])
                report_before = hashlib.sha256(report_path.read_bytes()).hexdigest()
                original = json.loads(report_path.read_text(encoding="utf-8"))
                documents = {}
                self.assertNotIn("_case_path", source.value)
                for format_name in ("json", "html"):
                    exported = self.call("export_report", {"case": source}, {"format": format_name})
                    self.assertEqual(exported.status, "COMPLETED")
                    self.assertEqual(exported.receipt["operation"], "workflow.export_report")
                    self.assertTrue(exported.receipt["execution_started"])
                    self.assertTrue(exported.receipt["cleanup"]["confirmed"])
                    reference = exported.outputs["report"]
                    self.assertTrue(reference.value["readback_verified"])
                    text = Path(reference.value["_path"]).read_text(encoding="utf-8")
                    if format_name == "json":
                        document = json.loads(text)
                    else:
                        reader = AnalysisHTML()
                        reader.feed(text)
                        reader.close()
                        self.assertFalse(reader.active)
                        self.assertEqual(len(reader.documents), 1)
                        document = reader.documents[0]
                    documents[format_name] = document
                    self.assertEqual(document["schema"], "blackbox.analysis-report/1")
                    self.assertEqual(document["analysis"], original)
                    self.assertEqual(document["analysis_status"], expected)
                    self.assertEqual(document["analysis"]["status"], expected)
                    self.assertEqual(document["root_cause"], "UNKNOWN")
                    self.assertEqual(document["source_trust"], "UNVERIFIED_IMPORT")
                    self.assertEqual(document["verification"]["source_report_sha256"], report_before)
                    self.assertEqual(document["verification"]["source_index_sha256"], index_before)
                    self.assertEqual(document["verification"]["source_index_artifact_id"], index.artifact_id)
                    self.assertNotIn(str(self.root), text)
                self.assertEqual(documents["json"], documents["html"])
                self.assertEqual(hashlib.sha256(report_path.read_bytes()).hexdigest(), report_before)
        self.assertEqual(hashlib.sha256(index_path.read_bytes()).hexdigest(), index_before)
        self.assertEqual(hashlib.sha256(self.trace.read_bytes()).hexdigest(), trace_before)

    def test_saved_analysis_export_refuses_existing_destination_and_cancel_after_real_stage_prepare(self):
        from blackbox_core.chain_reports import export_analysis_report
        from blackbox_core.export_recovery import ExportTransaction
        index = self.call("decode_trace", {"trace": self.source()}).outputs["index"]
        report = self.call("waits", {"index": index}).outputs["report"]
        source_path, index_path = Path(report.value["_path"]), Path(index.value["_path"])
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.trace, source_path, index_path)}
        destination = self.root / "existing-analysis.json"
        destination.write_bytes(b"existing owner document")
        with self.assertRaises(FileExistsError):
            export_analysis_report(report, destination)
        self.assertEqual(destination.read_bytes(), b"existing owner document")
        cancelled = threading.Event()
        original_prepare = ExportTransaction.prepare
        prepared = []
        def cancel_after_prepare(transaction, files):
            original_prepare(transaction, files)
            prepared.append(transaction.stage)
            cancelled.set()
        target = self.root / "cancelled-analysis.html"
        with patch.object(ExportTransaction, "prepare", cancel_after_prepare), \
                self.assertRaises(InterruptedError):
            export_analysis_report(report, target, format="html", cancel=cancelled)
        self.assertEqual(len(prepared), 1, "the actual saved analysis must reach real staged publication")
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".bb-export-*")))
        self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before}, before)

    def test_saved_analysis_export_rejects_unbound_index_locator_before_publication(self):
        from blackbox_core.chain_io import verify_artifact
        from blackbox_core.chain_reports import export_analysis_report
        index = self.call("decode_trace", {"trace": self.source()}).outputs["index"]
        report = self.call("file_io", {"index": index}).outputs["report"]
        unbound = Artifact("REPORT", {**report.value, "_index_path": str(self.root / "different-index.sqlite3")},
                           sources=report.sources, coverage=report.coverage, clock_domains=report.clock_domains)
        destination = self.root / "unbound-analysis.json"
        with self.assertRaisesRegex(ValueError, "WORKFLOW_UNBOUND_PRIVATE_SOURCE_LOCATOR"):
            verify_artifact(unbound)
        with self.assertRaisesRegex(ValueError, "WORKFLOW_UNBOUND_PRIVATE_SOURCE_LOCATOR"):
            export_analysis_report(unbound, destination)
        self.assertFalse(destination.exists())

    def test_comparison_reuses_actual_saved_case_analysis_and_existing_export(self):
        index = self.call("decode_trace", {"trace": self.source()}).outputs["index"]
        case = self.call("investigate", {"evidence": (index,)}).outputs["case"]
        comparison = self.call("compare", {"before": case, "after": case})
        self.assertEqual(comparison.status, "COMPLETED")
        artifact = comparison.outputs["comparison"]
        self.assertEqual(artifact.value["mode"], "INVESTIGATION_GRAPH")
        self.assertTrue(artifact.value["upstream_artifacts"])
        exported = self.call("export_report", {"case": artifact}, {"format": "json"})
        document = json.loads(Path(exported.outputs["report"].value["_path"]).read_text())
        self.assertIn("workflow_comparison", document)
        self.assertFalse(document["root_cause_proven"])

    def test_unsupported_source_kind_never_becomes_success(self):
        result = self.call("load_source", parameters={"kind": "REGISTRY", "path": str(self.trace)})
        self.assertNotEqual(result.status, "COMPLETED")
        self.assertEqual(result.outputs, {})
        self.assertIn("UNSUPPORTED_SOURCE_KIND", result.reason_code)


class ChainAdapterConsentBoundaryTests(unittest.TestCase):
    """Test doubles establish dispatch policy, never native execution evidence."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identity = ProcessIdentity(4242, 133000000000000001)
        self.process = Artifact("PROCESS", {"identity": self.identity.to_dict()})

    def execute(self, tool, runtime, parameters=None):
        ctx = Context(self.root / tool.replace(".", "-"), runtime)
        with patch("blackbox_core.chain_io.verify_artifact", return_value=None):
            return build_catalog(runtime)[tool].execute(ctx, {"process": self.process}, parameters or {}), ctx

    def result(self, operation="threads", *, cleanup=None):
        request = ActionRequest(operation, self.identity, confirmed=True)
        return attach_run_receipt(begin_run(request, run_id="boundary-fixture"),
            {"status": "COMPLETED", "data": {}, "operation_id": "boundary-fixture"},
            execution_started=True, cleanup=cleanup)

    def test_no_fresh_consent_never_dispatches_effectful_service_action(self):
        calls = []
        service = SimpleNamespace(execute=lambda *args, **kwargs: calls.append(args))
        runtime = ChainRuntime(inspector=service, authorize=lambda *args: False)
        result, ctx = self.execute("deep.memory.write", runtime)
        self.assertEqual(calls, [])
        self.assertEqual(result.status, "CONFIRMATION_REQUIRED")
        self.assertFalse(result.execution_started)
        self.assertEqual([event[0] for event in ctx.events], ["WAITING_FOR_HUMAN", "RUNNING"])

    def test_actual_receipt_and_unknown_cleanup_are_preserved(self):
        answer = self.result()
        expected = deepcopy(answer["run_receipt"])
        runtime = ChainRuntime(native_call=lambda *args: answer)
        result, _ = self.execute("deep.threads", runtime)
        self.assertEqual(result.receipt, expected)
        self.assertFalse(result.cleanup["confirmed"])
        self.assertNotIn("_path", result.outputs["result"].value)
        self.assertEqual(result.outputs["result"].value["source_unavailable_reason"],
                         "EXISTING_NATIVE_JOURNAL_REFERENCE_NOT_PROVIDED")

    def test_gui_native_callback_is_the_only_native_owner_and_receipt_is_required(self):
        calls = []
        runtime = ChainRuntime(native_call=lambda *args: calls.append(args) or {"status": "COMPLETED"})
        result, _ = self.execute("deep.threads", runtime)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "threads")
        self.assertEqual(calls[0][2], self.identity.to_dict())
        self.assertEqual(result.status, "OPERATION_FAILED")
        self.assertEqual(result.reason_code, "WORKFLOW_NATIVE_RECEIPT_REQUIRED")

    def test_completed_native_effect_receipt_survives_later_reference_failure(self):
        answer = self.result("memory.write", cleanup={"confirmed": True, "scope": "BOUNDARY_FIXTURE"})
        runtime = ChainRuntime(native_call=lambda *args: answer)
        with patch("blackbox_core.chain_adapters._snapshot_journal", side_effect=OSError("DISK_FULL_FIXTURE")):
            result, _ = self.execute("deep.memory.write", runtime)
        self.assertEqual(result.status, "OPERATION_FAILED")
        self.assertEqual(result.receipt, answer["run_receipt"])
        self.assertEqual(result.receipt["effects"], "REPORTED_COMPLETED")
        self.assertTrue(result.execution_started)
        self.assertIn("RESULT_REFERENCE_FAILED", result.reason_code)

    def test_headless_fresh_parameters_do_not_enter_persisted_context(self):
        calls = []
        answer = self.result("memory.write", cleanup={"confirmed": True, "scope": "BOUNDARY_FIXTURE"})
        service = SimpleNamespace(execute_owned=lambda request, **kwargs: calls.append(request) or answer)
        runtime = ChainRuntime(inspector=service, authorize=lambda *args: {
            "address": 4096, "expected_hex": "00", "value_hex": "01"})
        result, _ = self.execute("deep.memory.write", runtime)
        self.assertTrue(calls[0].confirmed)
        self.assertEqual(calls[0].parameters["value_hex"], "01")
        self.assertNotIn("value_hex", json.dumps(result.context))
        self.assertNotIn("expected_hex", json.dumps(result.outputs["result"].to_dict()))

    def test_headless_native_context_is_service_issued_runtime_only_and_exactly_released(self):
        calls = []
        reference = {"owner_run_id": "adapter-run", "context_id": "native-owned-fixture",
                     "generation": 7, "owns_session": True}
        answer = self.result()
        answer["native_context_ownership"] = deepcopy(reference)
        def execute_owned(request, **kwargs):
            calls.append(("execute", kwargs))
            return answer
        def release_native_context(owner_run_id, **kwargs):
            calls.append(("release", owner_run_id, kwargs))
            return {"status": "COMPLETED", "cleanup": {"confirmed": True,
                "scope": "EXACT_FIXTURE_NATIVE_CONTEXT"}, "native_context_ownership": None}
        service = SimpleNamespace(execute_owned=execute_owned, release_native_context=release_native_context)
        runtime = ChainRuntime(inspector=service)
        result, ctx = self.execute("deep.threads", runtime)
        self.assertEqual(calls[0][1]["owner_run_id"], ctx.run_id)
        self.assertIsNone(calls[0][1]["expected_context"])
        self.assertEqual(runtime.native_context_ref, reference)
        self.assertNotIn("native-owned-fixture", json.dumps(result.outputs["result"].to_dict()))
        finalized = build_catalog(runtime)["session_finalize"].execute(ctx, {}, {})
        self.assertEqual(calls[1], ("release", ctx.run_id, {"expected_context": reference}))
        self.assertTrue(finalized.cleanup["confirmed"])
        self.assertIsNone(runtime.native_context_ref)
        self.assertIsNone(runtime.owned_session_run_id)
        self.assertEqual(finalized.outputs["result"].value["source_unavailable_reason"],
                         "CONTROL_ONLY_NOT_DIAGNOSTIC_EVIDENCE")

    def test_cancellation_during_fresh_consent_cannot_dispatch_native_effect(self):
        calls = []
        service = SimpleNamespace(execute_owned=lambda *args, **kwargs: calls.append(args))
        def approve(operation, parameters, identity, ctx):
            ctx.cancel.set()
            return {"address": 4096, "expected_hex": "00", "value_hex": "01"}
        result, _ctx = self.execute("deep.memory.write", ChainRuntime(inspector=service, authorize=approve))
        self.assertEqual(calls, [])
        self.assertEqual(result.status, "CANCELLED")

    def test_session_finalizer_refuses_foreign_owner_and_requires_explicit_ack(self):
        calls = []
        runtime = ChainRuntime(session_finalize=lambda ctx: calls.append(ctx) or {"status": "COMPLETED"})
        ctx = Context(self.root / "finalizer", runtime)
        adapter = build_catalog(runtime)["session_finalize"]
        result = adapter.execute(ctx, {}, {})
        self.assertEqual(calls, [])
        self.assertNotEqual(result.status, "COMPLETED")
        runtime.owned_session_run_id = ctx.run_id
        result = adapter.execute(ctx, {}, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.status, "RECOVERY_UNCONFIRMED")
        self.assertEqual(runtime.owned_session_run_id, ctx.run_id)
        runtime.session_finalize = lambda ctx: {"status": "COMPLETED", "data": {"expiry_cleanup": {
            "confirmed": True, "scope": "R10_TERMINAL_HELPER_ACK", "journal_recorded": True}}}
        result = adapter.execute(ctx, {}, {})
        self.assertEqual(result.status, "COMPLETED")
        self.assertTrue(result.cleanup["confirmed"])
        self.assertIsNone(runtime.owned_session_run_id)


if __name__ == "__main__":
    unittest.main()
