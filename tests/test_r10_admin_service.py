"""R10 coordinator contracts; execution is restricted to GitHub-hosted CI."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

from blackbox_core.deep_contracts import ActionRequest, MAX_SESSION_SECONDS, ProcessIdentity
from blackbox_core.deep_elevation import ElevationCancelled
from blackbox_core.deep_service import InspectorService


class AdminLeaseServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.service = InspectorService(Path(self.temporary.name))
        self.a = ProcessIdentity(410, 133000000000000001, "A.exe")
        self.b = ProcessIdentity(420, 133000000000000002, "B.exe")
        self.helper_identity = ProcessIdentity(430, 133000000000000003, "helper.exe")
        self.messages = []

    def tearDown(self):
        # Fake helpers have no OS resources. Avoid adding cleanup replies to
        # assertions or masking a lost-ack contract with an automatic retry.
        self.service.helper = None
        self.service._channel = None
        self.temporary.cleanup()

    def lease(self, target=None, scope=()):
        self.service.helper = Mock(pid=self.helper_identity.pid)
        self.service.helper.alive.return_value = True
        self.service._helper_identity = self.helper_identity
        self.service._admin_session_managed = True
        self.service._session_nonce = "ab" * 32
        self.service._permission = "ADMINISTRATOR"
        self.service._elevated_verified = True
        self.service._admin_state = "ACTIVE"
        self.service._expires = time.monotonic() + 60
        self.service._target = target
        self.service._scope = frozenset(scope)
        self.service._session_catalog = frozenset({"capabilities", "memory_read", "snapshot", "memory.write"})
        service = self.service
        outer = self

        class Channel:
            def send(self, message, **kwargs):
                outer.messages.append(message)

            def receive(self, **kwargs):
                message = outer.messages[-1]
                kind = message["kind"]
                if kind == "target.bind":
                    return {"kind": "target.bound", "request_id": message["request_id"], "result": {
                        "status": "COMPLETED", "data": {"target": message["target"], "operations": message["operations"]}}}
                if kind == "target.release":
                    return {"kind": "target.released", "request_id": message["request_id"], "result": {
                        "status": "COMPLETED", "data": {"target": None, "operations": []}}}
                if kind == "session.status":
                    return {"kind": "session.status", "request_id": message["request_id"], "result": {
                        "status": "COMPLETED", "data": {"target": service._target.to_dict() if service._target else None,
                        "operations": sorted(service._scope), "permission_level": "ADMINISTRATOR", "elevated_verified": True,
                        "helper_identity": outer.helper_identity.to_dict(),
                        "token_authority": {"source": "WINDOWS_PROCESS_TOKEN", "elevated": True}}}}
                raise AssertionError(kind)

            def close(self):
                pass

        self.service._channel = Channel()
        return self.service.helper

    def test_preselection_launch_and_multiple_targets_keep_one_original_lease(self):
        def launch(target, operations, **kwargs):
            self.assertIsNone(target)
            self.assertTrue(kwargs["admin_lease"])
            self.assertTrue(kwargs["elevated"])
            self.assertEqual(kwargs["session_seconds"], MAX_SESSION_SECONDS)
            self.lease()
            return {"status": "COMPLETED", "data": self.service.session_status(), "limitations": []}

        with patch.object(self.service, "_start_session", side_effect=launch) as start:
            first = self.service.start_admin_session(confirmed=True)
            self.assertEqual(first["status"], "COMPLETED")
            original_deadline = self.service._expires
            original_helper = self.service.helper
            self.assertEqual(self.service.bind_target(self.a, ["memory_read"], confirmed=True)["status"], "COMPLETED")
            self.assertEqual(self.service.clear_target()["status"], "COMPLETED")
            self.assertEqual(self.service.bind_target(self.b, ["snapshot"], confirmed=True)["status"], "COMPLETED")
            status = self.service.session_status(refresh=True)
            reused = self.service.start_admin_session(confirmed=True)
        start.assert_called_once()
        self.assertIs(self.service.helper, original_helper)
        self.assertEqual(self.service._expires, original_deadline)
        self.assertEqual(status["state"], "ACTIVE")
        self.assertTrue(status["elevated_verified"])
        self.assertEqual(status["helper_identity"], self.helper_identity.to_dict())
        self.assertEqual(status["target"], self.b.to_dict())
        self.assertEqual(reused["uac"], {"requested": False, "result": "CURRENT_SESSION"})
        self.assertTrue(all(message["nonce"] == "ab" * 32 for message in self.messages))

    def test_missing_lease_or_target_consent_never_launches_or_dispatches(self):
        with patch.object(self.service, "_start_session") as launch:
            refusal = self.service.start_admin_session()
            self.assertEqual(refusal["status"], "CONFIRMATION_REQUIRED")
            launch.assert_not_called()
        self.lease()
        self.assertEqual(self.service.bind_target(self.a, ["memory_read"])["status"], "CONFIRMATION_REQUIRED")
        answer = self.service._ensure_session(ActionRequest("memory_read", self.a))
        self.assertEqual(answer["next_action"], "AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
        self.assertFalse(self.messages)
        self.service._target, self.service._scope = self.a, frozenset({"snapshot"})
        answer = self.service._ensure_session(ActionRequest("snapshot", self.b))
        self.assertEqual(answer["status"], "CONFIRMATION_REQUIRED")
        self.assertEqual(self.service._target, self.a)
        self.assertFalse(self.messages)

    def test_selection_clears_old_context_without_authorizing_new_identity(self):
        original_helper = self.lease(self.a, ["memory_read"])
        original_deadline = self.service._expires
        self.assertEqual(self.service.set_target(self.b)["status"], "COMPLETED")
        self.assertIsNone(self.service._target)
        self.assertFalse(self.service._scope)
        self.assertIs(self.service.helper, original_helper)
        self.assertEqual(self.service._expires, original_deadline)
        self.assertEqual([message["kind"] for message in self.messages], ["target.release"])

    def test_failed_cleanup_retains_owner_scope_and_never_silently_retries_bind(self):
        helper = self.lease(self.a, ["memory_read"])
        self.service._interventions_started = True
        expires = self.service._expires
        with patch.object(self.service, "_managed_exchange", return_value={"status": "RECOVERY_UNCONFIRMED",
                "data": {"owner_retained": True}}) as exchange:
            release = self.service.clear_target()
            refused = self.service.bind_target(self.b, ["snapshot"], confirmed=True)
            self.assertEqual(exchange.call_count, 1)
        self.assertEqual(release["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(refused["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(release["retains_service"])
        self.assertIs(self.service.helper, helper)
        self.assertEqual(self.service._target, self.a)
        self.assertEqual(self.service._scope, frozenset({"memory_read"}))
        self.assertEqual(self.service._expires, expires)
        self.assertEqual(self.service.session_status()["state"], "CLEANUP_REQUIRED")
        self.assertFalse(self.service.admin_active)
        helper.terminate.assert_not_called()
        self.assertEqual(self.service.clear_target()["status"], "COMPLETED")
        self.assertEqual(self.service.session_status()["state"], "ACTIVE")

    def test_lost_bind_ack_preserves_old_owner_until_explicit_cleanup(self):
        helper = self.lease(self.a, ["memory_read"])
        with patch.object(self.service, "_managed_exchange", side_effect=OSError("lost reply")):
            answer = self.service.bind_target(self.b, ["snapshot"], confirmed=True)
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(self.service._target, self.a)
        self.assertIs(self.service.helper, helper)
        self.assertEqual(self.service.session_status()["state"], "CLEANUP_REQUIRED")

    def test_new_target_exit_after_verified_previous_cleanup_clears_old_context(self):
        self.lease(self.a, ["memory_read"])
        with patch.object(self.service, "_managed_exchange", return_value={"status": "PROCESS_CHANGED",
                "data": {"target": None, "operations": [], "cleanup_required": False, "context_verified": True}}):
            answer = self.service.bind_target(self.b, ["snapshot"], confirmed=True)
        self.assertEqual(answer["status"], "PROCESS_CHANGED")
        self.assertIsNone(self.service._target)
        self.assertFalse(self.service._scope)
        self.assertEqual(self.service.session_status()["state"], "ACTIVE")

    def test_unsupported_parameters_refuse_before_helper_dispatch_with_not_started_receipt(self):
        self.lease(self.a, ["snapshot"])
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            answer = self.service.execute(ActionRequest("snapshot", self.a, {"unsupported_option": True}))
        self.assertEqual(answer["status"], "OPERATION_FAILED")
        self.assertEqual(answer["error"], "UNSUPPORTED_OPERATION_PARAMETER")
        self.assertFalse(answer["run_receipt"]["execution_started"])
        self.assertFalse(self.messages)

    def test_cancel_racing_success_retains_matching_real_execution_proof(self):
        self.lease(self.a, ["memory_read"])
        responses = [InterruptedError("cancellation raced operation completion")]

        def receive(**kwargs):
            if responses:
                raise responses.pop()
            return {"kind": "result", "request_id": self.messages[-1]["request_id"], "result": {
                "status": "COMPLETED", "data": {}, "diagnostic_execution": {
                    "source": "DIAGNOSTIC_HELPER", "source_verified": True,
                    "target_verified": True, "target": self.a.to_dict()}}}

        self.service._channel.receive = receive
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            answer = self.service.execute(ActionRequest("memory_read", self.a, {"address": 4096, "size": 1}))
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertTrue(answer["cancellation_requested"])
        self.assertTrue(answer["run_receipt"]["execution_started"])
        self.assertTrue(answer["run_receipt"]["source"]["verified"])
        self.assertTrue(answer["run_receipt"]["target"]["verified"])
        self.assertEqual([message["kind"] for message in self.messages], ["execute", "cancel"])

    def test_token_refusal_death_expiry_and_retained_cleanup_cannot_show_active(self):
        helper = self.lease()
        with patch.object(self.service, "_managed_exchange", return_value={"status": "ACCESS_DENIED", "data": {
                "elevated_verified": False, "permission_level": "STANDARD"}}):
            status = self.service.session_status(refresh=True)
        self.assertEqual(status["state"], "FAILED")
        self.assertFalse(status["admin_active"])
        self.assertFalse(status["elevated_verified"])
        self.lease()
        self.service._expires = time.monotonic() - 1
        self.assertEqual(self.service.session_status()["state"], "EXPIRED")
        helper = self.lease(self.a, ["snapshot"])
        helper.alive.return_value = False
        self.assertEqual(self.service.session_status()["state"], "FAILED")
        self.service._interventions_started = True
        self.assertEqual(self.service.session_status()["state"], "CLEANUP_REQUIRED")

    def test_denied_uac_has_no_false_active_or_startup_retry(self):
        with patch.object(self.service, "_start_session", side_effect=ElevationCancelled("denied")) as launch:
            answer = self.service.start_admin_session(confirmed=True)
        launch.assert_called_once()
        self.assertEqual(answer["status"], "UAC_CANCELLED")
        self.assertEqual(self.service.session_status()["state"], "DENIED")
        self.assertFalse(self.service.admin_active)

    def test_lease_input_is_finite_bounded_and_scope_is_allowlisted(self):
        for duration in (True, 0, MAX_SESSION_SECONDS + 1, float("nan"), float("inf")):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                self.service.start_admin_session(confirmed=True, session_seconds=duration)
        self.lease()
        for scope in (["shell"], ["timeline"], [], ["memory_read"] * 100):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.service.bind_target(self.a, scope, confirmed=True)
        self.assertFalse(self.messages)

    def test_result_receipt_uses_matching_helper_identity_evidence_only(self):
        self.lease(self.a, ["memory_read"])
        self.service._channel.receive = lambda **kwargs: {"kind": "result",
            "request_id": self.messages[-1]["request_id"], "result": {"status": "COMPLETED", "data": {},
            "diagnostic_execution": {"source": "DIAGNOSTIC_HELPER", "source_verified": True,
                                     "target_verified": True, "target": self.a.to_dict()}}}
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            answer = self.service.execute(ActionRequest("memory_read", self.a, {"address": 4096, "size": 1}))
        receipt = answer["run_receipt"]
        self.assertTrue(receipt["execution_started"])
        self.assertTrue(receipt["target"]["verified"])
        self.assertTrue(receipt["source"]["verified"])
        self.assertEqual(receipt["source"]["helper_pid"], self.helper_identity.pid)
        self.assertEqual(self.service.journal.timeline()[0]["run_receipt"]["run_id"], answer["operation_id"])


if __name__ == "__main__":
    unittest.main()
