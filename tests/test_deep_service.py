"""BB-DEEP-001 contracts and durable evidence; executed only by hosted CI."""
from __future__ import annotations

import json
from copy import deepcopy
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from blackbox_core.deep_contracts import ActionRequest, ProcessIdentity, canonical_operation, describe_actions
from blackbox_core.deep_helper import DiagnosticActionEngine, validate_parameters, _close_after_cancel
from blackbox_core.deep_elevation import ElevationCancelled
from blackbox_core.deep_ipc import IPCError, PipeServer, connect_pipe
from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core.deep_service import InspectorService, verify_helper_hello


class DeepContractsTests(unittest.TestCase):
    def test_exact_identity_and_typed_scope(self):
        identity = ProcessIdentity(42, 133000000000000001, "example.exe")
        self.assertEqual(ProcessIdentity.from_dict(identity.to_dict()), identity)
        self.assertEqual(canonical_operation("memory_restore"), "memory.rollback")
        for pid, created in ((True, 1), (0, 1), (42, True), (42, 0), (42, 2**64)):
            with self.subTest(pid=pid, created=created), self.assertRaises(ValueError):
                ProcessIdentity(pid, created)
        for timeout in (True, 0, -1, float("nan"), float("inf"), 121):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                ActionRequest("snapshot", identity, timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            ActionRequest("execute_shell", identity, {"command": "anything"})
        with self.assertRaises(ValueError):
            ActionRequest("memory.write", identity, {"_confirmed": True})

    def test_native_handles_and_arbitrary_commands_never_cross_public_boundary(self):
        for key in ("file_handle", "handle", "recovery_handle", "source_file_handle", "command", "shell", "argv"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_parameters({key: 123})

    def test_hello_requires_nonce_exact_instance_and_expected_image(self):
        executable = str(Path(__file__).resolve())
        identity = ProcessIdentity(42, 133000000000000001, executable)
        nonce = "ab" * 32
        hello = {"kind": "hello", "protocol": 1, "nonce": nonce, "identity": identity.to_dict()}
        verify_helper_hello(hello, nonce, identity, executable)
        invalid = [dict(hello, nonce="cd" * 32), dict(hello, protocol=2),
                   dict(hello, identity=ProcessIdentity(43, identity.created_100ns, executable).to_dict()),
                   dict(hello, identity=ProcessIdentity(42, identity.created_100ns + 1, executable).to_dict())]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises((PermissionError, ValueError)):
                verify_helper_hello(item, nonce, identity, executable)
        with self.assertRaises(PermissionError):
            verify_helper_hello(hello, nonce, identity, executable + ".different")

    def test_profile_command_accepts_only_bounded_explicit_systemwide_policy(self):
        identity = ProcessIdentity(42, 133000000000000001)
        valid = {"duration_seconds": 2, "profile": "BLACKBOX.Deep.Light", "systemwide_confirmed": True}
        self.assertEqual(ActionRequest("profile.etw", identity, valid, True).operation, "profile.etw")
        invalid = [dict(valid, duration_seconds=value) for value in (0, 31, True, 1.5)]
        invalid += [dict(valid, profile="custom.wprp"), dict(valid, systemwide_confirmed=False),
                    dict(valid, argv=["-cancel"]), dict(valid, destination="a.etl", output_path="b.etl")]
        for parameters in invalid:
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                ActionRequest("profile.etw", identity, parameters, True)

    def test_scenario_catalog_declares_lifecycle_cleanup_and_non_retry_policy(self):
        actions = {entry["operation"]: entry for entry in describe_actions()}
        for name, entry in actions.items():
            with self.subTest(operation=name):
                self.assertIsInstance(entry["preconditions"], list)
                self.assertTrue(entry["preconditions"])
                for field in ("required_rights", "impact", "stop_method", "cleanup", "failure_action", "output"):
                    self.assertIsInstance(entry[field], str)
                    self.assertTrue(entry[field].strip())
                self.assertGreater(entry["timeout_seconds"], 0)
                self.assertLessEqual(entry["timeout_seconds"], 120)
                self.assertIn("DESCRIPTIVE_ONLY", entry["authority"])
                if entry["mode"] == "INTERVENE":
                    self.assertTrue(entry["confirmation_required"])
                    self.assertIn("Never automatically retry", entry["failure_action"])
                    self.assertIn("RECOVERY_UNCONFIRMED", entry["failure_action"])
        step_conditions = " ".join(actions["debug.step"]["preconditions"])
        self.assertIn("ATTACHED", step_conditions)
        self.assertIn("PAUSED", step_conditions)
        self.assertIn("instruction-pointer", step_conditions)
        self.assertIn("thread_created_100ns", " ".join(actions["thread.suspend"]["preconditions"]))
        self.assertIn("suspension_id", actions["thread.suspend"]["output"])
        self.assertIn("expected_hex", " ".join(actions["memory.write"]["preconditions"]))
        self.assertIn("change_id", actions["memory.write"]["output"])
        self.assertIn("readback", actions["memory.rollback"]["output"])
        self.assertIn("debug.detach", actions["debug.breakpoint.add"]["stop_method"])
        self.assertIn("owned suspensions", actions["debug.detach"]["cleanup"])
        self.assertIn("snapshot_id", actions["snapshot"]["output"])
        self.assertIn("no live-process access", " ".join(actions["trace_evidence"]["preconditions"]))
        self.assertIn("saved_verified", actions["profile.etw"]["output"])


class DeepJournalTests(unittest.TestCase):
    def test_sensitive_payloads_removed_and_windows_connections_released(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            journal = EvidenceJournal(directory / "evidence")
            secret = "BB_DEEP_PRIVATE_MEMORY_SENTINEL_95a1"
            journal.append({"operation_id": "one", "parameters": {"value_hex": secret},
                            "data": {"payload": secret, "command_line": ["tool", secret]},
                            "before": {"original_bytes": secret}, "status": "COMPLETED"})
            path = journal.export(directory / "safe.jsonl")
            self.assertNotIn(secret, path.read_text())
            self.assertNotIn(secret.encode(), journal.path.read_bytes())
            self.assertEqual(journal.timeline()[0]["status"], "COMPLETED")
            renamed = journal.path.with_suffix(".closed")
            journal.path.rename(renamed)  # Windows catches any leaked SQLite connection here.
            renamed.unlink()

    def test_atomic_no_clobber_and_tampering_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = EvidenceJournal(root / "evidence")
            journal.append({"operation_id": "one", "status": "COMPLETED"})
            target = root / "existing.jsonl"
            target.write_text("unchanged")
            with self.assertRaises(FileExistsError):
                journal.export(target)
            self.assertEqual(target.read_text(), "unchanged")
            connection = sqlite3.connect(journal.path)
            try:
                connection.execute("UPDATE actions SET record_json='{}'")
                connection.commit()
            finally:
                connection.close()
            rejected = root / "tampered.jsonl"
            with self.assertRaisesRegex(ValueError, "HASH_CHAIN"):
                journal.export(rejected)
            self.assertFalse(rejected.exists())
            self.assertFalse(list(root.glob(".blackbox-deep-export-*")))

    def test_before_after_rejects_different_process_lifetimes(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = EvidenceJournal(temporary)
            first = ProcessIdentity(42, 100).to_dict()
            before = journal.snapshot(first, {"threads": 2})
            after = journal.snapshot(first, {"threads": 3})
            compared = journal.compare(before, after)
            self.assertEqual(compared["before"], {"threads": 2})
            self.assertEqual(compared["after"], {"threads": 3})
            self.assertEqual(compared["interpretation"], "OBSERVED_DIFFERENCE_NOT_CAUSAL_PROOF")
            reused = journal.snapshot(ProcessIdentity(42, 101).to_dict(), {"threads": 3})
            with self.assertRaisesRegex(ValueError, "IDENTITY_MISMATCH"):
                journal.compare(before, reused)

    def test_compare_separates_collection_cost_from_unchanged_observation_without_editing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = EvidenceJournal(temporary)
            identity = ProcessIdentity(42, 100).to_dict()
            old = {name: {"status": "COMPLETED", "source": "WINDOWS_LIVE_INSPECTION", "target": identity,
                          "data": {"rows": [{"address": 4096}], "duration_ns": 20},
                          "limitations": ["SEQUENTIAL_OBSERVATION"], "duration_ns": 1000}
                   for name in ("modules", "network", "memory_map")}
            newer = deepcopy(old)
            for value in newer.values():
                value["duration_ns"] = 9000
            before, after = journal.snapshot(identity, old), journal.snapshot(identity, newer)
            compared = journal.compare(before, after)
            self.assertEqual(compared["changed_sections"], [])
            self.assertEqual(compared["before"], old)
            self.assertEqual(compared["after"], newer)
            self.assertEqual(compared["acquisition_metadata_changes"], {
                name: {"before": {"duration_ns": 1000}, "after": {"duration_ns": 9000}} for name in old})
            self.assertEqual(journal.compare(before, before)["before"], old)
            self.assertEqual(journal.compare(after, after)["after"], newer)
            # Semantic differences remain visible even when collection timing
            # also varies, including a measured duration inside the payload.
            changes = {
                "measured_duration": lambda section: section["data"].update(duration_ns=21),
                "module_row": lambda section: section["data"]["rows"].append({"address": 8192}),
                "status": lambda section: section.update(status="INCOMPLETE_EVIDENCE"),
                "source": lambda section: section.update(source="OTHER_OBSERVATION_SOURCE"),
                "limitation": lambda section: section["limitations"].append("PARTIAL_DATA"),
            }
            for name, change in changes.items():
                with self.subTest(change=name):
                    different = deepcopy(newer)
                    change(different["modules"])
                    changed_id = journal.snapshot(identity, different)
                    self.assertEqual(journal.compare(before, changed_id)["changed_sections"], ["modules"])


class DeepEngineBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.identity = ProcessIdentity(42, 133000000000000001, "controlled.exe")
        self.inspector = Mock()
        self.engine = DiagnosticActionEngine(self.identity, ["profile.etw", "capabilities", "dump"],
                                             inspector_factory=lambda target: self.inspector)

    def test_profile_refuses_standard_token_even_with_an_attached_file_handle(self):
        request = ActionRequest("profile.etw", self.identity, {
            "duration_seconds": 1, "profile": "BLACKBOX.Deep.Light", "systemwide_confirmed": True}, True, 120)
        with patch("blackbox_core.deep_native.verify_identity", return_value=self.identity), \
                patch("blackbox_core.deep_helper.token_is_elevated", return_value=False), \
                patch("blackbox_core.deep_profiling.capture_etw") as capture:
            answer = self.engine.execute(request, file_handle=123)
        self.assertEqual(answer["status"], "ADMIN_REQUIRED")
        capture.assert_not_called()

    def test_unconfirmed_profile_cleanup_cannot_be_hidden_by_session_close(self):
        request = ActionRequest("profile.etw", self.identity, {
            "duration_seconds": 1, "profile": "BLACKBOX.Deep.Light", "systemwide_confirmed": True}, True, 120)
        unconfirmed = {"status": "RECOVERY_UNCONFIRMED", "error": "OWNED_ETW_STOP_UNCONFIRMED"}
        with patch("blackbox_core.deep_native.verify_identity", return_value=self.identity), \
                patch("blackbox_core.deep_helper.token_is_elevated", return_value=True), \
                patch("blackbox_core.deep_profiling.capture_etw", return_value=unconfirmed):
            answer = self.engine.execute(request, file_handle=123)
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        closed = self.engine.close()
        self.assertEqual(closed["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn(unconfirmed, closed["data"]["errors"])

    def test_capability_filter_cannot_probe_an_unapproved_operation(self):
        request = ActionRequest("capabilities", self.identity, {"operations": ["memory.write"]})
        with patch("blackbox_core.deep_native.verify_identity", return_value=self.identity), \
                patch("blackbox_core.deep_native.probe_access") as probe, \
                self.assertRaisesRegex(ValueError, "INVALID_CAPABILITY_OPERATION_FILTER"):
            self.engine.execute(request)
        probe.assert_not_called()

    def test_engine_keeps_inspector_and_owner_for_retryable_debug_cleanup(self):
        self.engine.debug = Mock()
        self.engine.debug.close.side_effect = [
            {"status": "RECOVERY_UNCONFIRMED", "data": {"owner_retained": True, "retry_cleanup_required": True}},
            {"status": "COMPLETED", "data": {"state": "DETACHED"}},
        ]
        retained = self.engine.close()
        self.assertTrue(retained["data"]["owner_retained"])
        self.assertTrue(retained["retains_service"])
        self.inspector.close.assert_not_called()
        denied = self.engine.execute(ActionRequest("dump", self.identity, {}, True), file_handle=123)
        self.assertEqual(denied["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(self.engine.close()["status"], "COMPLETED")
        self.inspector.close.assert_called_once()

    def test_active_operation_past_cancel_grace_retains_owner_instead_of_closing_engine(self):
        engine, active = Mock(), Mock()
        active.is_alive.return_value = True
        cancelled = threading.Event()
        response = _close_after_cancel(engine, active, cancelled)
        self.assertTrue(cancelled.is_set())
        active.join.assert_called_once_with(timeout=5)
        engine.close.assert_not_called()
        self.assertEqual(response["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(response["retains_service"])
        self.assertTrue(response["data"]["owner_retained"])
        self.assertTrue(response["data"]["operation_cancellation_pending"])
        active.is_alive.return_value = False
        engine.close.return_value = {"status": "COMPLETED"}
        self.assertEqual(_close_after_cancel(engine, active, cancelled)["status"], "COMPLETED")
        engine.close.assert_called_once()


class DeepServiceIntentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.service = InspectorService(Path(self.temporary.name) / "journal")
        self.identity = ProcessIdentity(42, 133000000000000001, "controlled.exe")

    def test_confirmation_required_without_launch(self):
        secret = "eac137d985b420ff" * 32
        with patch.object(self.service.broker, "launch") as launch, \
                patch.object(self.service, "_ensure_session") as ensure:
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": secret, "value_hex": secret}))
        self.assertEqual(answer["status"], "CONFIRMATION_REQUIRED")
        launch.assert_not_called()
        ensure.assert_not_called()
        latest, requested = self.service.journal.timeline()
        self.assertEqual((requested["phase"], latest["phase"]), ("REQUESTED", "RESULT"))
        self.assertEqual(latest["action_id"], answer["operation_id"])
        self.assertEqual(latest["status"], "CONFIRMATION_REQUIRED")
        self.assertFalse(latest["data"]["execution_started"])
        self.assertEqual(answer["journal"]["record_sha256"], latest["record_sha256"])
        self.assertNotIn(secret, json.dumps([requested, latest]))

    def test_confirmation_refusal_has_no_native_effect_when_its_audit_fails(self):
        request = ActionRequest("memory.write", self.identity,
                                {"address": 4096, "expected_hex": "01", "value_hex": "02"})
        for failure in ([OSError("full")], [{}, OSError("full")]):
            with self.subTest(failure=len(failure)), \
                    patch.object(self.service.journal, "append", side_effect=failure), \
                    patch.object(self.service, "_ensure_session") as ensure:
                answer = self.service.execute(request)
            self.assertEqual(answer["status"], "OPERATION_FAILED")
            ensure.assert_not_called()

    def test_failed_intent_prevents_any_helper_operation(self):
        with patch.object(self.service.journal, "append", side_effect=OSError("disk full")), \
                patch.object(self.service, "_ensure_session") as ensure:
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": "01", "value_hex": "02"}, True))
        self.assertEqual(answer["status"], "OPERATION_FAILED")
        self.assertIn("DURABLE_INTENT_FAILED", answer["error"])
        ensure.assert_not_called()

    def test_pre_cancelled_request_returns_typed_status_without_launch(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(self.service, "_ensure_session") as ensure:
            answer = self.service.execute(ActionRequest("snapshot", self.identity), cancel_event=cancelled)
        self.assertEqual(answer["status"], "CANCELLED")
        ensure.assert_not_called()
        self.assertEqual(self.service.journal.timeline()[0]["status"], "CANCELLED")

    def test_uac_cancel_and_refusal_preserve_ordinary_service(self):
        with patch.object(self.service, "_start_session", side_effect=ElevationCancelled(1223, "cancelled")):
            cancelled = self.service.elevate(self.identity, ["memory_read"], confirmed=True)
        self.assertEqual(cancelled["status"], "UAC_CANCELLED")
        self.assertFalse(self.service.admin_active)
        with patch.object(self.service, "_start_session", side_effect=PermissionError("token not elevated")):
            denied = self.service.elevate(self.identity, ["memory_read"], confirmed=True)
        self.assertEqual(denied["status"], "ACCESS_DENIED")
        self.assertFalse(self.service.admin_active)
        ordinary = self.service.execute(ActionRequest("timeline", self.identity))
        self.assertEqual(ordinary["status"], "COMPLETED")

    def test_uac_requires_durable_intent_and_closes_unrecorded_grant(self):
        with patch.object(self.service.journal, "append", side_effect=OSError("full")), \
                patch.object(self.service, "_start_session") as start:
            denied = self.service.elevate(self.identity, ["memory_read"], confirmed=True)
        self.assertEqual(denied["status"], "OPERATION_FAILED")
        self.assertEqual(denied["uac"]["requested"], False)
        start.assert_not_called()
        with patch.object(self.service.journal, "append", side_effect=[{}, OSError("full")]), \
                patch.object(self.service, "_start_session", return_value={"status": "COMPLETED", "limitations": []}), \
                patch.object(self.service, "end_admin_session", return_value={"status": "COMPLETED"}) as close:
            unrecorded = self.service.elevate(self.identity, ["memory_read"], confirmed=True)
        self.assertEqual(unrecorded["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(close.call_count, 2)  # Close old session, then the unrecorded new grant.

    def test_unconfirmed_and_invalid_typed_uac_scope_are_journaled_without_launch(self):
        for operations, confirmed, status in ((["memory_read"], False, "CONFIRMATION_REQUIRED"),
                                               (["timeline"], True, "OPERATION_FAILED"),
                                               ([], True, "OPERATION_FAILED")):
            with self.subTest(operations=operations, confirmed=confirmed), \
                    patch.object(self.service, "_start_session") as start, \
                    patch.object(self.service, "end_admin_session") as close:
                answer = self.service.elevate(self.identity, operations, confirmed=confirmed)
            self.assertEqual(answer["status"], status)
            self.assertEqual(answer["uac"], {"requested": False, "result": "NOT_STARTED"})
            start.assert_not_called()
            close.assert_not_called()
            latest, requested = self.service.journal.timeline(limit=2)
            self.assertEqual((requested["phase"], latest["phase"]), ("REQUESTED", "RESULT"))
            self.assertEqual(latest["status"], status)
            self.assertEqual(latest["action_id"], answer["operation_id"])
            self.assertFalse(latest["data"]["execution_started"])
        with patch.object(self.service.journal, "append", side_effect=OSError("full")), \
                patch.object(self.service, "_start_session") as start:
            failed = self.service.elevate(self.identity, ["memory_read"])
        self.assertEqual(failed["error"], "DURABLE_UAC_INTENT_FAILED")
        start.assert_not_called()

    def test_export_receipt_identifies_immutable_prefix_and_separate_durable_result(self):
        self.service.journal.append({"operation_id": "original", "status": "COMPLETED"})
        original = self.service.journal.timeline()[0]
        for number in range(2):
            destination = Path(self.temporary.name) / f"private-destination-{number}.jsonl"
            answer = self.service.export_journal(destination)
            self.assertEqual(answer["status"], "COMPLETED")
            exported = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines()]
            local = list(reversed(self.service.journal.timeline(limit=1000)))
            self.assertEqual(local[0], original)
            self.assertEqual(len(local), len(exported) + 1)
            self.assertEqual(answer["data"]["exported_records"], len(exported))
            self.assertEqual(answer["data"]["exported_last_sequence"], local[-2]["sequence"])
            self.assertEqual(answer["data"]["exported_chain_head_sha256"], exported[-1]["record_sha256"])
            self.assertEqual(exported[-1]["record"]["operation_id"], answer["operation_id"] + ":requested")
            self.assertEqual(local[-1]["operation_id"], answer["operation_id"] + ":result")
            self.assertEqual(answer["journal"]["record_sha256"], local[-1]["record_sha256"])
            self.assertEqual(local[-1]["data"]["export_scope"], "SNAPSHOT_THROUGH_EXPORT_REQUESTED")
            self.assertEqual(answer["data"]["path"], str(destination))
            self.assertNotIn("private-destination", json.dumps(local))
            self.assertNotIn("path", local[-1]["data"])
            self.assertNotIn("journal", local[-1])

    def test_export_failure_and_cancellation_are_audited_without_clobber_or_path_leak(self):
        destination = Path(self.temporary.name) / "private-existing.jsonl"
        destination.write_text("keep this original", encoding="utf-8")
        answer = self.service.export_journal(destination)
        self.assertEqual(answer["error"], "JOURNAL_EXPORT_DESTINATION_EXISTS")
        self.assertEqual(destination.read_text(encoding="utf-8"), "keep this original")
        latest = self.service.journal.timeline()[0]
        self.assertEqual(latest["status"], "OPERATION_FAILED")
        self.assertFalse(latest["data"]["export_published"])
        cancelled = threading.Event()
        cancelled.set()
        destination = destination.with_name("private-cancelled.jsonl")
        answer = self.service.export_journal(destination, cancel_event=cancelled)
        self.assertEqual(answer["status"], "CANCELLED")
        self.assertFalse(destination.exists())
        self.assertFalse(list(destination.parent.glob(".blackbox-deep-export-*")))
        self.assertEqual(self.service.journal.timeline()[0]["status"], "CANCELLED")
        self.assertNotIn("private-", json.dumps(self.service.journal.timeline()))

    def test_export_intent_failure_prevents_copy_and_result_failure_preserves_publication_uncertainty(self):
        destination = Path(self.temporary.name) / "private-output.jsonl"
        with patch.object(self.service.journal, "append", side_effect=OSError(str(destination))), \
                patch.object(self.service.journal, "export_snapshot") as export:
            denied = self.service.export_journal(destination)
        export.assert_not_called()
        self.assertEqual(denied["error"], "DURABLE_EXPORT_INTENT_FAILED")
        self.assertNotIn(str(destination), json.dumps(denied))
        append = self.service.journal.append
        def fail_result(record):
            if record.get("phase") == "RESULT":
                raise OSError(str(destination))
            return append(record)
        with patch.object(self.service.journal, "append", side_effect=fail_result):
            unconfirmed = self.service.export_journal(destination)
        self.assertEqual(unconfirmed["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(unconfirmed["error"], "EXPORT_RESULT_JOURNAL_COMMIT_FAILED")
        self.assertTrue(unconfirmed["data"]["export_published"])
        self.assertTrue(destination.is_file())
        self.assertEqual(self.service.journal.timeline()[0]["phase"], "REQUESTED")
        self.assertNotIn("private-output", json.dumps(self.service.journal.timeline()))

    def test_export_cancel_during_fsync_prevents_publication_and_is_audited(self):
        destination = Path(self.temporary.name) / "cancelled-before-link.jsonl"
        cancelled = threading.Event()
        fsync = os.fsync
        def flush_then_cancel(descriptor):
            fsync(descriptor)
            cancelled.set()
        with patch("blackbox_core.deep_journal.os.fsync", side_effect=flush_then_cancel), \
                patch("blackbox_core.deep_journal.os.link") as publish:
            answer = self.service.export_journal(destination, cancel_event=cancelled)
        publish.assert_not_called()
        self.assertEqual(answer["status"], "CANCELLED")
        self.assertFalse(answer["data"]["export_published"])
        self.assertFalse(destination.exists())
        self.assertFalse(list(destination.parent.glob(".blackbox-deep-export-*")))
        self.assertEqual(self.service.journal.timeline()[0]["status"], "CANCELLED")

    def test_export_cancel_after_atomic_publication_preserves_completed_file_and_receipt(self):
        destination = Path(self.temporary.name) / "already-published.jsonl"
        cancelled = threading.Event()
        link = os.link
        def publish_then_cancel(source, target):
            link(source, target)
            cancelled.set()
        with patch("blackbox_core.deep_journal.os.link", side_effect=publish_then_cancel):
            answer = self.service.export_journal(destination, cancel_event=cancelled)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertTrue(answer["data"]["export_published"])
        self.assertTrue(destination.is_file())
        self.assertEqual(self.service.journal.timeline()[0]["status"], "COMPLETED")
        self.assertEqual(answer["journal"]["record_sha256"], self.service.journal.timeline()[0]["record_sha256"])
        self.assertFalse(list(destination.parent.glob(".blackbox-deep-export-*")))

    def test_export_hash_failure_is_audited_without_repairing_or_publishing_corrupt_history(self):
        self.service.journal.append({"operation_id": "original", "status": "COMPLETED"})
        db = sqlite3.connect(self.service.journal.path)
        try:
            db.execute("UPDATE actions SET record_json='{}' WHERE operation_id='original'")
            db.commit()
        finally:
            db.close()
        destination = Path(self.temporary.name) / "rejected.jsonl"
        answer = self.service.export_journal(destination)
        self.assertEqual(answer["status"], "OPERATION_FAILED")
        self.assertEqual(answer["error"], "JOURNAL_HASH_CHAIN_MISMATCH")
        self.assertFalse(destination.exists())
        self.assertFalse(list(destination.parent.glob(".blackbox-deep-export-*")))
        latest = self.service.journal.timeline()[0]
        self.assertEqual(latest["phase"], "RESULT")
        self.assertEqual(latest["error"], answer["error"])
        db = sqlite3.connect(self.service.journal.path)
        try:
            self.assertEqual(db.execute("SELECT record_json FROM actions WHERE operation_id='original'").fetchone()[0], "{}")
        finally:
            db.close()

    def test_comparison_request_must_match_snapshot_target(self):
        before = self.service.journal.snapshot(self.identity.to_dict(), {"value": 1})
        after = self.service.journal.snapshot(self.identity.to_dict(), {"value": 2})
        other = ProcessIdentity(self.identity.pid, self.identity.created_100ns + 1, self.identity.image_path)
        answer = self.service.execute(ActionRequest("compare", other, {"before_id": before, "after_id": after}))
        self.assertEqual(answer["status"], "PROCESS_CHANGED")

    def test_profile_uac_retry_does_not_collide_with_own_unwritten_destination(self):
        destination = Path(self.temporary.name) / "explicit.etl"
        parameters = {"duration_seconds": 2, "profile": "BLACKBOX.Deep.Light",
                      "systemwide_confirmed": True, "destination": str(destination)}
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        sent = []
        class Channel:
            def send(inner, message, **kwargs):
                sent.append(message)
            def receive(inner, **kwargs):
                return {"kind": "result", "request_id": sent[-1]["request_id"],
                        "result": {"status": "COMPLETED", "data": {"saved_verified": True, "trace_bytes": 256}}}
        self.service._channel = Channel()
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch.object(self.service, "_ensure_session", return_value=None):
            denied = self.service.execute(ActionRequest("profile.etw", self.identity, parameters, True, 120))
            self.assertEqual(denied["status"], "ADMIN_REQUIRED")
            self.assertFalse(destination.exists())
            self.assertFalse(sent)
            self.service._permission = "ADMINISTRATOR"
            with patch.dict("sys.modules", {"msvcrt": types.SimpleNamespace(get_osfhandle=lambda fd: 456)}):
                accepted = self.service.execute(ActionRequest("profile.etw", self.identity, parameters, True, 120))
        self.assertEqual(accepted["status"], "COMPLETED")
        self.assertEqual(accepted["data"]["destination"], str(destination))
        self.assertFalse(accepted["data"]["automatic_share_export"])
        self.assertEqual(sent[-1]["attachment"], {"source_file_handle": 456})
        self.assertNotIn("destination", sent[-1]["request"]["parameters"])

    def test_dump_access_denial_preserves_destination_for_scoped_uac_retry(self):
        destination = Path(self.temporary.name) / "explicit.dmp"
        sent = []
        class Channel:
            def send(inner, message, **kwargs):
                sent.append(message)
            def receive(inner, **kwargs):
                return {"kind": "result", "request_id": sent[-1]["request_id"], "result": {
                    "status": "COMPLETED", "data": {"operations": [{"operation": "dump", "status": "ADMIN_REQUIRED"}]}}}
        self.service._channel = Channel()
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch.object(self.service, "_ensure_session", return_value=None):
            answer = self.service.execute(ActionRequest("dump", self.identity, {"destination": str(destination)}, True, 120))
        self.assertEqual(answer["status"], "ADMIN_REQUIRED")
        self.assertFalse(destination.exists())
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["request"]["operation"], "capabilities")
        self.assertEqual(sent[0]["request"]["parameters"], {"operations": ["dump"]})

    def test_timeline_results_do_not_recursively_embed_journal(self):
        for _ in range(20):
            answer = self.service.execute(ActionRequest("timeline", self.identity))
            self.assertEqual(answer["status"], "COMPLETED")
        latest = self.service.journal.timeline()[0]
        self.assertNotIn("entries", latest["data"])
        self.assertIn("returned_entries", latest["data"])

    def test_native_mutation_follows_durable_intent_and_result_failure_is_unconfirmed(self):
        sent = []
        class Channel:
            def send(inner, message, **kwargs):
                entries = self.service.journal.timeline()
                self.assertEqual(entries[0]["phase"], "REQUESTED")
                sent.append(message)

            def receive(inner, **kwargs):
                return {"kind": "result", "request_id": sent[-1]["request_id"],
                        "result": {"status": "COMPLETED", "data": {}, "limitations": []}}
        self.service._channel = Channel()
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        original = self.service.journal.append
        count = [0]
        def append(record):
            count[0] += 1
            if count[0] == 2:
                raise OSError("result disk full")
            return original(record)
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch.object(self.service, "_ensure_session", return_value=None), \
                patch.object(self.service.journal, "append", side_effect=append):
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": "01", "value_hex": "02"}, True))
        self.assertEqual(len(sent), 1)
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("RESULT_JOURNAL_COMMIT_FAILED", answer["error"])

    def _retained_helper_fixture(self, replies):
        helper = Mock(pid=456)
        helper.alive.return_value = True
        helper.terminate.side_effect = lambda: setattr(helper.alive, "return_value", False)
        channel = Mock()
        channel.receive.side_effect = replies
        self.service.helper = helper
        self.service._channel = channel
        self.service._target = self.identity
        self.service._scope = frozenset({"memory.write", "snapshot", "debug.detach"})
        self.service._expires = time.monotonic() + 60
        self.service._permission = "ADMINISTRATOR"
        self.service._interventions_started = True
        return helper, channel

    def test_lost_intervention_ack_is_unconfirmed_even_when_live_helper_cleans_up(self):
        helper, channel = self._retained_helper_fixture([
            OSError("reply pipe failed after native write"),
            {"kind": "closed", "result": {"status": "COMPLETED", "data": {}}},
        ])
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                {"address": 4096, "expected_hex": "01", "value_hex": "02"}, True))
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("ACKNOWLEDGEMENT_LOST", answer["error"])
        self.assertEqual(answer["data"]["cleanup"]["status"], "COMPLETED")
        self.assertEqual([call.args[0]["kind"] for call in channel.send.call_args_list], ["execute", "close"])
        self.assertEqual(self.service.journal.timeline()[0]["status"], "RECOVERY_UNCONFIRMED")
        helper.terminate.assert_called_once()

    def test_unsafe_cleanup_retains_owner_and_original_lease_until_explicit_retry(self):
        helper, channel = self._retained_helper_fixture([
            {"kind": "result", "request_id": "late-action", "result": {"status": "COMPLETED", "data": {"payload": "private"}}},
            {"kind": "closed", "result": {"status": "RECOVERY_UNCONFIRMED", "data": {
                "owner_retained": True, "retry_cleanup_required": True}}},
            {"kind": "closed", "result": {"status": "COMPLETED", "data": {}}},
        ])
        expires = self.service._expires
        failed = self.service.close()
        self.assertEqual(failed["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(failed["data"]["owner_retained"])
        self.assertTrue(failed["retains_service"])
        self.assertNotIn("private", json.dumps(failed))
        self.assertIs(self.service.helper, helper)
        self.assertIs(self.service._channel, channel)
        self.assertEqual(self.service._expires, expires)
        helper.terminate.assert_not_called()
        denied = self.service._ensure_session(ActionRequest("snapshot", self.identity))
        self.assertEqual(denied["status"], "RECOVERY_UNCONFIRMED")
        self.assertIsNone(self.service._ensure_session(ActionRequest("debug.detach", self.identity, confirmed=True)))
        succeeded = self.service.close()
        self.assertEqual(succeeded["status"], "COMPLETED")
        self.assertIsNone(self.service.helper)
        helper.terminate.assert_called_once()

    def test_retained_owner_has_finite_expiry_grace_and_failed_stop_keeps_identity(self):
        helper, channel = self._retained_helper_fixture([])
        self.service._expires = 100
        request = ActionRequest("snapshot", self.identity)
        with patch("blackbox_core.deep_service.time", types.SimpleNamespace(monotonic=lambda: 110)):
            grace = self.service._ensure_session(request)
        self.assertTrue(grace["data"]["owner_retained"])
        helper.terminate.assert_not_called()
        helper.terminate.side_effect = OSError("termination denied")
        with patch("blackbox_core.deep_service.time", types.SimpleNamespace(monotonic=lambda: 131)):
            failure = self.service._ensure_session(request)
        self.assertEqual(failure["status"], "RECOVERY_UNCONFIRMED")
        self.assertIs(self.service.helper, helper)
        self.assertEqual(self.service.helper_pid, 456)
        helper.close_handle.assert_not_called()

    def test_result_journal_failure_preserves_retained_owner_for_gui_retry(self):
        helper, channel = self._retained_helper_fixture([])
        def receive(**kwargs):
            request_id = channel.send.call_args.args[0]["request_id"]
            return {"kind": "result", "request_id": request_id, "result": {
                "status": "RECOVERY_UNCONFIRMED", "data": {
                    "owner_retained": True, "retry_cleanup_required": True}}}
        channel.receive.side_effect = receive
        append = self.service.journal.append
        def journal(record):
            if record.get("phase") == "RESULT":
                raise OSError("result storage unavailable")
            return append(record)
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch.object(self.service.journal, "append", side_effect=journal):
            answer = self.service.execute(ActionRequest("debug.detach", self.identity, {}, True))
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("RESULT_JOURNAL_COMMIT_FAILED", answer["error"])
        self.assertTrue(answer["data"]["owner_retained"])
        self.assertTrue(answer["data"]["retry_cleanup_required"])
        self.assertTrue(answer["retains_service"])
        self.assertIs(self.service.helper, helper)
        helper.terminate.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Actual Windows named-pipe peer identity requires Windows")
class DeepNamedPipePeerTests(unittest.TestCase):
    def test_foreign_peer_pid_is_rejected_and_pipe_is_closed(self):
        from uuid import uuid4
        server = PipeServer("\\\\.\\pipe\\BLACKBOX-DEEP-" + uuid4().hex)
        client = []
        errors = []
        def connect():
            try:
                client.append(connect_pipe(server.name, os.getpid(), deadline=time.monotonic() + 5))
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=connect, daemon=True)
        worker.start()
        try:
            with self.assertRaisesRegex(IPCError, "UNEXPECTED_DIAGNOSTIC_PIPE_CLIENT"):
                server.accept(os.getpid() + 1, deadline=time.monotonic() + 5)
        finally:
            worker.join(timeout=6)
            for channel in client:
                channel.close()
            server.close()
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, str(errors))

    def test_nonblocking_pipe_roundtrip_with_current_process_identity(self):
        from uuid import uuid4
        server = PipeServer("\\\\.\\pipe\\BLACKBOX-DEEP-" + uuid4().hex)
        errors = []
        payload = {"kind": "test", "text": "x" * 100000}
        def send():
            channel = None
            try:
                channel = connect_pipe(server.name, os.getpid(), deadline=time.monotonic() + 5)
                channel.send(payload, deadline=time.monotonic() + 5)
            except Exception as exc:
                errors.append(exc)
            finally:
                if channel is not None:
                    channel.close()
        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        try:
            server.accept(os.getpid(), deadline=time.monotonic() + 5)
            self.assertEqual(server.receive(deadline=time.monotonic() + 5), payload)
        finally:
            worker.join(timeout=6)
            server.close()
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, str(errors))


if __name__ == "__main__":
    unittest.main()
