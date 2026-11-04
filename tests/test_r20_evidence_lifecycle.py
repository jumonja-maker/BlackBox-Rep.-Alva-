"""R20 real local-file contracts; format fixtures are not native Windows proof.

All execution belongs to GitHub-hosted CI. These tests deliberately keep
producer authentication, complete capture and live identity unestablished.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbox_core.deep_contracts import ActionRequest
from blackbox_core.deep_tool_contracts import begin_evidence_run, attach_evidence_run_receipt, record_evidence_failure
from blackbox_core.decoder_service import decode_file, _private_decode_stage
from blackbox_core.decoder_index import read_index
from blackbox_core.evidence_graph import validate_case
from blackbox_core.evidence_normalization import source_coverage
from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError
from blackbox_core.investigation_v3 import create_investigation, export_investigation, load_investigation
from blackbox_core import investigation_graph_store as store
from blackbox_core.optional_jobs import OwnedProcessCleanupUnconfirmed
from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_core.deep_native import NativeError, ProcessInspector
from blackbox_core.deep_helper import DiagnosticActionEngine


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class EvidenceLifecycleContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "own-source.jsonl"
        events = [{"schema_version": 1, "token": "FORMAT_FIXTURE_R20_ONLY_NOT_AUTHENTICATED",
            "pid": 42, "tid": 43, "seq": n, "source_ns": n * 1000,
            "source_clock": "FORMAT_FIXTURE_CLOCK", "kind": kind, "client_dropped": 0,
            "attributes": attributes} for n, kind, attributes in
            ((1, "user.marker", {"note": "bounded local fixture"}),
             (2, "blackbox.completed", {"status": "COMPLETED", "expected_operations": 0}))]
        self.source.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")

    def build(self, **kwargs):
        return create_investigation([{"source_type": "EVENTS_JSONL", "path": str(self.source)}], **kwargs)

    def test_readonly_nullable_context_cannot_create_a_targetless_deep_action(self):
        context = begin_evidence_run("decoder.decode")
        self.assertIsNone(context.to_dict()["target"])
        with self.assertRaises(ValueError):
            ActionRequest("modules", None)
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_EVIDENCE_OPERATION"):
            begin_evidence_run("execute_shell")
        for timeout in (True, 0, float("nan"), float("inf"), 601):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                begin_evidence_run("decoder.decode", timeout_seconds=timeout)

    def test_success_does_not_manufacture_authentication_capture_or_cleanup(self):
        context = begin_evidence_run("investigation.create")
        result = attach_evidence_run_receipt(context, {"status": "COMPLETED"})
        receipt = result["run_receipt"]
        self.assertFalse(receipt["source"]["verified"])
        self.assertEqual(receipt["source"]["producer_authentication"], "NOT_ESTABLISHED")
        self.assertFalse(receipt["cleanup"]["confirmed"])
        self.assertFalse(receipt["target"]["verified"])
        self.assertEqual(receipt["coverage"]["completeness"], "UNKNOWN")

    def test_existing_native_failure_statuses_survive_the_readonly_adapter(self):
        for status in ("CANCELLED", "TIMED_OUT", "RECOVERY_UNCONFIRMED", "ACCESS_DENIED"):
            error = NativeError(status, "CONTROLLED_NATIVE_FAILURE_CONTRACT")
            record_evidence_failure(begin_evidence_run("investigation.create"), error)
            self.assertEqual(error.run_receipt["status"], status)
            self.assertFalse(error.run_receipt["cleanup"]["confirmed"])

    def test_decoder_persists_same_receipt_and_removes_only_private_input_stage(self):
        before = digest(self.source)
        index = self.root / "trace-index.sqlite3"
        result = decode_file(self.source, index)
        saved = read_index(index, limit=1)["summary"]
        self.assertEqual(saved, result)
        receipt = saved["run_receipt"]
        self.assertEqual(receipt["operation"], "decoder.decode")
        self.assertEqual(receipt["status"], "DECODED")
        self.assertEqual(receipt["source"]["sources"][0]["source_sha256"], before)
        self.assertEqual(receipt["source"]["sources"][0]["source_size_bytes"], self.source.stat().st_size)
        self.assertTrue(receipt["cleanup"]["confirmed"])
        self.assertEqual(receipt["cleanup"]["scope"], "DECODE_HELPER_AND_PRIVATE_INPUT_STAGING")
        self.assertEqual(receipt["coverage"]["completeness"], "UNKNOWN_CAPTURE_COMPLETENESS")
        self.assertEqual(digest(self.source), before)
        self.assertNotIn("FORMAT_FIXTURE_R20_ONLY", json.dumps(receipt))

    def test_cancelled_decoder_preserves_original_exception_and_no_partial_output(self):
        stop = threading.Event(); stop.set()
        destination = self.root / "cancelled.sqlite3"
        with self.assertRaises(InterruptedError) as caught:
            decode_file(self.source, destination, cancel=stop)
        self.assertEqual(caught.exception.run_receipt["status"], "CANCELLED")
        self.assertIsNone(caught.exception.run_receipt["execution_started"])
        self.assertFalse(caught.exception.run_receipt["cleanup"]["confirmed"])
        self.assertFalse(destination.exists())

    def test_unconfirmed_child_retains_actual_temporary_directory_for_explicit_retry(self):
        class RetainedOwner:
            cleanup_required = True
            def retain_cleanup_resource(self, resource):
                self.resource = resource
        owner = RetainedOwner()
        error = OwnedProcessCleanupUnconfirmed(owner, "CONTROLLED_UNCONFIRMED_OWNER_FIXTURE")
        with self.assertRaises(OwnedProcessCleanupUnconfirmed) as caught:
            with _private_decode_stage() as (name, release):
                (Path(name) / "keep-private-input").write_bytes(b"owned bytes")
                raise error
        record_evidence_failure(begin_evidence_run("decoder.decode"), caught.exception)
        self.assertEqual(caught.exception.run_receipt["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(caught.exception.run_receipt["cleanup"]["confirmed"])
        self.assertTrue(Path(name).is_dir())
        owner.resource.cleanup()
        self.assertFalse(Path(name).exists())

    def test_source_manifest_and_receipt_roundtrip_without_producer_promotion(self):
        before = digest(self.source)
        destination = self.root / "case.sqlite3"
        case = self.build(index_path=destination)
        source = case["sources"][0]
        self.assertEqual(source["source_sha256"], before)
        self.assertEqual(source["source_size_bytes"], self.source.stat().st_size)
        self.assertEqual(source["content_manifest"][0]["size_bytes"], self.source.stat().st_size)
        self.assertEqual(source["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(source["provenance"]["producer_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(case["coverage"]["evidence_completeness"], "UNKNOWN_CAPTURE_COMPLETENESS")
        loaded = load_investigation(destination)
        self.assertEqual(loaded["run_receipt"], case["run_receipt"])
        self.assertTrue(case["_index_receipt"]["readback_verified"])
        exported = self.root / "report.json"
        answer = export_investigation(case, exported)
        data = json.loads(exported.read_text())
        self.assertEqual(data["run_receipt"]["run_id"], case["run_receipt"]["run_id"])
        self.assertEqual(answer["sha256"], digest(exported))
        self.assertTrue(answer["readback_verified"])
        self.assertTrue(answer["run_receipt"]["cleanup"]["confirmed"])
        self.assertFalse(answer["run_receipt"]["source"]["verified"])
        self.assertEqual(digest(self.source), before)

    def test_imported_manifest_tampering_or_complete_promotion_is_rejected(self):
        case = self.build()
        for mutate in (
                lambda value: value["sources"][0].update(source_size_bytes=1),
                lambda value: value["sources"][0]["provenance"].update(producer_authentication="AUTHENTICATED"),
                lambda value: value["coverage"].update(evidence_completeness="COMPLETE")):
            value = deepcopy(case); mutate(value)
            with self.assertRaises(InvestigationError):
                validate_case(value)

    def test_known_loss_and_truncation_remain_incomplete_even_after_full_scan(self):
        for source in ({"decoded_status": "TRUNCATED"}, {"decoder_reported_lost_events": 1},
                       {"application_client_dropped_total": 1}, {"writer_dropped_commands": 1},
                       {"events_without_fields_or_schema": 1}, {"bounded_events": 1}):
            with self.subTest(source=source):
                self.assertEqual(source_coverage({"scan_complete": True, **source})["capture_status"],
                                 "INCOMPLETE_EVIDENCE")

    def test_existing_identical_index_replaced_in_callback_never_gets_success_receipt(self):
        case = self.build()
        target, replacement = self.root / "case.sqlite3", self.root / "foreign.tmp"
        store.save_investigation(case, target)
        replacement.write_bytes(b"FOREIGN_RESULT_MUST_REMAIN")
        with self.assertRaisesRegex(InvestigationError, "CHANGED_DURING_PUBLICATION"):
            store.save_investigation(case, target,
                before_publish=lambda: os.replace(replacement, target))
        self.assertEqual(target.read_bytes(), b"FOREIGN_RESULT_MUST_REMAIN")

    def test_replacement_after_create_new_export_is_uncertain_and_preserved(self):
        case = self.build()
        target = self.root / "export.json"
        original_link = os.link
        def replace_after_link(source, destination):
            original_link(source, destination)
            Path(destination).unlink()
            Path(destination).write_bytes(b"FOREIGN_PUBLICATION")
        with patch.object(store.os, "link", side_effect=replace_after_link):
            with self.assertRaises(InvestigationError) as caught:
                export_investigation(case, target)
        self.assertTrue(caught.exception.publication_unconfirmed)
        self.assertEqual(caught.exception.run_receipt["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(caught.exception.run_receipt["cleanup"]["confirmed"])
        self.assertEqual(target.read_bytes(), b"FOREIGN_PUBLICATION")

    def test_successful_index_publication_retains_readback_after_late_cancellation(self):
        case = self.build()
        cancelled = threading.Event()
        budget = InvestigationBudget(cancel_event=cancelled)
        deadline = budget.deadline
        target = self.root / "committed.sqlite3"
        original_link, original_load = os.link, store.load_investigation
        readback_budgets = []
        def publish_then_cancel(source, destination):
            original_link(source, destination)
            cancelled.set()
        def observe_readback(path, *, budget=None):
            readback_budgets.append(budget)
            return original_load(path, budget=budget)
        with patch.object(store.os, "link", side_effect=publish_then_cancel), \
                patch.object(store, "load_investigation", side_effect=observe_readback):
            receipt = store.save_investigation(case, target, budget=budget)
        self.assertEqual(receipt["status"], "COMPLETED")
        self.assertTrue(receipt["readback_verified"])
        self.assertEqual(receipt["sha256"], digest(target))
        self.assertTrue(cancelled.is_set())
        self.assertIs(budget.cancel_event, cancelled)
        self.assertTrue(readback_budgets)
        self.assertTrue(all(item.cancel_event is None and item.deadline == deadline and
                            item.max_source_bytes == budget.max_source_bytes and
                            item.max_result_bytes == budget.max_result_bytes
                            for item in readback_budgets))

    def test_late_cancel_cannot_certify_or_remove_a_replaced_publication(self):
        case = self.build()
        original_link = os.link
        for suffix, publish in (("sqlite3", store.save_investigation),
                                ("json", store.export_investigation)):
            with self.subTest(format=suffix):
                cancelled = threading.Event()
                target = self.root / ("replaced-after-commit." + suffix)
                foreign = self.root / ("foreign." + suffix)
                foreign.write_bytes(b"FOREIGN_RESULT_AFTER_COMMIT")
                def replace_then_cancel(source, destination):
                    original_link(source, destination)
                    os.replace(foreign, destination)
                    cancelled.set()
                with patch.object(store.os, "link", side_effect=replace_then_cancel):
                    with self.assertRaises(InvestigationError) as caught:
                        publish(case, target, budget=InvestigationBudget(cancel_event=cancelled))
                self.assertTrue(caught.exception.publication_unconfirmed)
                self.assertEqual(target.read_bytes(), b"FOREIGN_RESULT_AFTER_COMMIT")

    def test_late_cancellation_does_not_reset_the_publication_readback_deadline(self):
        case = self.build()
        cancelled = threading.Event()
        budget = InvestigationBudget(cancel_event=cancelled)
        target = self.root / "expired-after-commit.json"
        original_link = os.link
        def publish_then_expire(source, destination):
            original_link(source, destination)
            cancelled.set()
            # Simulate the original monotonic deadline expiring at commit;
            # postcommit verification must retain it rather than start afresh.
            budget.deadline = 1
        with patch.object(store.os, "link", side_effect=publish_then_expire):
            with self.assertRaises(TimeoutError) as caught:
                store.export_investigation(case, target, budget=budget)
        self.assertTrue(caught.exception.publication_unconfirmed)
        self.assertTrue(target.exists())
        self.assertFalse(list(self.root.glob(".blackbox-investigation-export-*")))

    def test_existing_source_cannot_be_selected_as_export_destination(self):
        case = self.build(); before = digest(self.source)
        with self.assertRaises(FileExistsError):
            export_investigation(case, self.source)
        self.assertEqual(digest(self.source), before)
        self.assertFalse(list(self.root.glob(".blackbox-investigation-export-*")))


class DeepQueryOwnershipContracts(unittest.TestCase):
    class Owner:
        cleanup_required = True
        cleanup_evidence = {"status": "RECOVERY_UNCONFIRMED"}
        def __init__(self):
            self.fail = True
            self.close_calls = 0
        def close(self, *, kill=False):
            self.close_calls += 1
            if self.fail:
                raise OwnedProcessCleanupUnconfirmed(self, "CONTROLLED_QUERY_OWNER")

    def test_handle_query_constructor_failure_preserves_exact_owner_without_automatic_retry(self):
        from blackbox_core.deep_native_handles import query_bounded
        owner = self.Owner(); owned = []
        error = OwnedProcessCleanupUnconfirmed(owner, "CONTROLLED_CONSTRUCTOR_FAILURE")
        with patch("blackbox_core.optional_jobs.OwnedProcess", side_effect=error):
            with self.assertRaises(OwnedProcessCleanupUnconfirmed):
                query_bounded(ProcessIdentity(42, 100), 7, owned_processes=owned)
        self.assertEqual(owned, [owner])
        self.assertEqual(owner.close_calls, 0)

    def test_poll_failure_still_reaches_the_authoritative_owned_close(self):
        from blackbox_core.deep_native_handles import query_bounded
        class Process:
            def poll(self):
                raise OSError("CONTROLLED_POLL_UNVERIFIABLE")
        class Child:
            cleanup_required = False
            process = Process()
            closed = False
            def close(self, *, kill=False):
                self.closed = kill
        child, owned = Child(), []
        with patch("blackbox_core.optional_jobs.OwnedProcess", return_value=child):
            result = query_bounded(ProcessIdentity(42, 100), 7, owned_processes=owned)
        self.assertEqual(result["name_status"], "INCOMPLETE_EVIDENCE")
        self.assertTrue(child.closed)
        self.assertEqual(owned, [])

    def test_inspector_retries_only_its_own_query_and_keeps_unconfirmed_owner(self):
        owner, foreign = self.Owner(), self.Owner()
        inspector = ProcessInspector(ProcessIdentity(42, 100))
        inspector._owned_query_processes.append(owner)
        answer = inspector.close()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(inspector.closed)
        self.assertEqual(inspector._owned_query_processes, [owner])
        self.assertEqual(foreign.close_calls, 0)
        owner.fail = False
        self.assertEqual(inspector.close()["status"], "COMPLETED")
        self.assertTrue(inspector.closed)
        self.assertEqual(inspector._owned_query_processes, [])
        self.assertEqual(foreign.close_calls, 0)

    def test_actual_typed_cleanup_error_cannot_become_generic_inspection_failure(self):
        inspector = ProcessInspector(ProcessIdentity(42, 100)); owner = self.Owner()
        with patch("blackbox_core.deep_native._windows"), patch.object(inspector, "_processes",
                side_effect=OwnedProcessCleanupUnconfirmed(owner, "CONTROLLED_QUERY_ERROR")):
            result = inspector.execute("processes")
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(result["data"]["owner_retained"])

    def test_helper_close_respects_inspector_owned_resource_ack(self):
        target = ProcessIdentity(42, 100)
        inspector = ProcessInspector(target); inspector._owned_query_processes.append(self.Owner())
        engine = DiagnosticActionEngine(target, ["processes"], inspector_factory=lambda identity: inspector)
        result = engine.close()
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(result["data"]["owner_retained"])
        self.assertTrue(result["retains_service"])


if __name__ == "__main__":
    unittest.main()
