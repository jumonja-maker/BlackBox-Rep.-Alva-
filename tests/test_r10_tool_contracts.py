"""R10 additive receipts and real local evidence; run only on hosted CI."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.deep_contracts import ActionRequest, DEEP_ACTIONS, ProcessIdentity
from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core.deep_service import InspectorService
from blackbox_core.deep_tool_contracts import (attach_run_receipt, begin_run,
                                               describe_tool)


class R10ToolContractTests(unittest.TestCase):
    def setUp(self):
        self.target = ProcessIdentity(42, 133000000000000001, "owned-target.exe")

    def test_allowlisted_descriptor_keeps_existing_operation_policy(self):
        for operation, spec in DEEP_ACTIONS.items():
            with self.subTest(operation=operation):
                descriptor = describe_tool(operation).to_dict()
                self.assertEqual(descriptor["version"], 1)
                self.assertEqual(descriptor["operations"], [operation])
                self.assertEqual(descriptor["required_rights"], spec.required_rights)
                self.assertEqual(descriptor["effects"], spec.impact)
                self.assertTrue(descriptor["cancellation"]["supported"])
                self.assertEqual(descriptor["cancellation"]["cleanup"], spec.cleanup)
                self.assertEqual(descriptor["budgets"]["max_admin_session_seconds"], 900)
        self.assertEqual(describe_tool("memory_write").operations, ("memory.write",))
        with self.assertRaisesRegex(ValueError, "OPERATION_NOT_ALLOWED"):
            describe_tool("execute_shell")

    def test_public_context_and_receipt_exclude_sensitive_payloads(self):
        secret = "PRIVATE_MEMORY_ENVIRONMENT_CREDENTIAL_SENTINEL_R10"
        request = ActionRequest("memory.write", self.target, {
            "address": 4096, "expected_hex": secret, "value_hex": secret,
            "environment": {"user_setting": secret}, "api_key": secret,
            "nested": {"authentication_token": secret, "client_secret": secret}}, True)
        context = begin_run(request, run_id="private-run", permission_level="ADMINISTRATOR")
        legacy = {"operation": "memory.write", "status": "COMPLETED", "operation_id": "private-run",
                  "data": {"memory": secret, "payload": secret, "readback_verified": True,
                           "change_id": "owned-change"}, "limitations": []}
        answer = attach_run_receipt(context, legacy, execution_started=True,
                                    source="WINDOWS_NATIVE_HELPER", source_verified=True,
                                    target_verified=True, helper_pid=43)
        public = json.dumps({key: answer[key] for key in ("tool_descriptor", "run_context", "run_receipt")})
        self.assertNotIn(secret, public)
        self.assertIs(answer["data"], legacy["data"])
        self.assertEqual(answer["run_context"]["target"], self.target.to_dict())
        self.assertTrue(answer["run_receipt"]["target"]["verified"])
        self.assertFalse(answer["run_receipt"]["cleanup"]["confirmed"])
        self.assertIn({"kind": "change_id", "reference": "owned-change"},
                      answer["run_receipt"]["result_references"])
        self.assertGreater(context.deadline_monotonic_ns, context.started_monotonic_ns)

    def test_every_required_legacy_status_survives_without_assumed_verification(self):
        context = begin_run(ActionRequest("modules", self.target), run_id="status-run")
        for status in ("COMPLETED", "ADMIN_REQUIRED", "NOT_COLLECTED", "INCOMPLETE_EVIDENCE",
                       "CANCELLED", "RECOVERY_UNCONFIRMED"):
            with self.subTest(status=status):
                legacy = {"status": status, "data": {"rows": []}, "limitations": ["SOURCE_LIMIT"]}
                answer = attach_run_receipt(context, legacy)
                receipt = answer["run_receipt"]
                self.assertEqual(answer["status"], status)
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["contract_version"], 1)
                self.assertFalse(receipt["source"]["verified"])
                self.assertFalse(receipt["target"]["verified"])
                self.assertFalse(receipt["cleanup"]["confirmed"])
                self.assertEqual(receipt["limitations"], ["SOURCE_LIMIT"])

    def test_cancellation_and_lost_result_do_not_hide_possible_effects(self):
        context = begin_run(ActionRequest("memory.write", self.target, {}, True), run_id="effect-run")
        committed = attach_run_receipt(context, {"status": "COMPLETED", "data": {"readback_verified": True}},
                                       execution_started=True, target_verified=True, source_verified=True)
        self.assertEqual(committed["run_receipt"]["effects"], "REPORTED_COMPLETED")
        for status in ("CANCELLED", "TIMED_OUT", "RECOVERY_UNCONFIRMED"):
            with self.subTest(status=status):
                answer = attach_run_receipt(context, {"status": status, "data": {
                    "reported_operation_status": "COMPLETED"}}, execution_started=True)
                self.assertEqual(answer["run_receipt"]["effects"], "MAY_HAVE_COMMITTED")
                self.assertEqual(answer["run_receipt"]["coverage"]["reported_operation_status"], "COMPLETED")
                self.assertFalse(answer["run_receipt"]["cleanup"]["confirmed"])
        refused = attach_run_receipt(context, {"status": "CONFIRMATION_REQUIRED"}, execution_started=False)
        self.assertEqual(refused["run_receipt"]["effects"], "NOT_STARTED")

    def test_cleanup_requires_explicit_ack_and_unconfirmed_status_wins(self):
        context = begin_run(ActionRequest("debug.detach", self.target, {}, True), run_id="cleanup-run")
        detached = {"status": "COMPLETED", "data": {"state": "DETACHED", "owned_resources_remaining": 0}}
        answer = attach_run_receipt(context, detached, execution_started=True)
        self.assertTrue(answer["run_receipt"]["cleanup"]["confirmed"])
        missing = attach_run_receipt(context, {"status": "COMPLETED", "data": {"state": "DETACHED"}})
        self.assertFalse(missing["run_receipt"]["cleanup"]["confirmed"])
        uncertain = attach_run_receipt(context, {**detached, "status": "RECOVERY_UNCONFIRMED"},
                                       cleanup={"status": "COMPLETED", "confirmed": True})
        self.assertFalse(uncertain["run_receipt"]["cleanup"]["confirmed"])
        self.assertEqual(uncertain["run_receipt"]["cleanup"]["status"], "RECOVERY_UNCONFIRMED")

    def test_sensitive_artifact_reference_never_copies_dump_or_destination(self):
        context = begin_run(ActionRequest("dump", self.target, {}, True), run_id="dump-run")
        answer = attach_run_receipt(context, {"status": "COMPLETED", "data": {
            "destination": "private-dump-destination.dmp", "payload": "private-dump-bytes",
            "sha256": "a" * 64, "saved_verified": True}}, execution_started=True)
        public = json.dumps(answer["run_receipt"])
        self.assertNotIn("private-dump", public)
        artifact = next(item for item in answer["run_receipt"]["result_references"]
                        if item["kind"] == "sensitive_artifact")
        self.assertFalse(artifact["automatic_share_export"])
        self.assertTrue(artifact["saved_verified"])


class R10RealJournalContractTests(unittest.TestCase):
    def test_real_read_only_service_result_receipt_is_retained_in_existing_journal_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = InspectorService(Path(temporary) / "journal")
            target = ProcessIdentity(42, 133000000000000001, "requested-history-target.exe")
            service.journal.append({"operation_id": "existing-observation", "status": "COMPLETED",
                                    "source": "TEST_OWNED_LOCAL_EVIDENCE", "target": target.to_dict()})
            answer = service.execute(ActionRequest("timeline", target, {"limit": 20}))
            self.assertEqual(answer["status"], "COMPLETED")
            receipt = answer["run_receipt"]
            self.assertEqual(receipt["status"], "COMPLETED")
            self.assertTrue(receipt["execution_started"])
            self.assertTrue(receipt["source"]["verified"])
            self.assertFalse(receipt["target"]["verified"])
            self.assertTrue(any(item["operation_id"] == "existing-observation"
                                for item in answer["data"]["entries"]))
            exported = service.journal.export(Path(temporary) / "receipt.jsonl")
            rows = [json.loads(line)["record"] for line in exported.read_text(encoding="utf-8").splitlines()]
            persisted = next(row for row in rows if row.get("operation_id") == answer["operation_id"] + ":result")
            self.assertEqual(persisted["run_receipt"]["run_id"], receipt["run_id"])
            self.assertEqual(persisted["run_receipt"]["status"], receipt["status"])

    def test_real_storage_failure_before_dispatch_has_not_started_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = InspectorService(temporary)
            request = ActionRequest("timeline", ProcessIdentity(42, 100), {"limit": 20})
            with patch.object(service.journal, "append", side_effect=OSError("storage unavailable")):
                answer = service.execute(request)
            self.assertEqual(answer["status"], "OPERATION_FAILED")
            self.assertFalse(answer["run_receipt"]["execution_started"])
            self.assertEqual(answer["run_receipt"]["coverage"]["completeness"], "NOT_COLLECTED")

    def test_journal_metadata_redacts_credentials_in_existing_sqlite_and_export(self):
        secret = "PRIVATE_R10_CREDENTIAL_JOURNAL_SENTINEL"
        with tempfile.TemporaryDirectory() as temporary:
            journal = EvidenceJournal(Path(temporary) / "journal")
            journal.append({"operation_id": "credentials", "api_key": secret,
                            "parameters": {"authentication_token": secret, "client_secret": secret,
                                           "environment": {"user_variable": secret}}})
            exported = journal.export(Path(temporary) / "metadata.jsonl")
            self.assertNotIn(secret, exported.read_text(encoding="utf-8"))
            self.assertNotIn(secret.encode(), journal.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
