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
from blackbox_core.deep_elevation import ElevationCancelled, HelperProcess
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

    def terminal_frame(self, *, completed=True):
        return {"kind": "expired", "reason": "LEASE_EXPIRED", "nonce": self.service._session_nonce,
                "identity": self.helper_identity.to_dict(),
                "context": {"target": self.service._target.to_dict() if self.service._target else None,
                            "operations": sorted(self.service._scope)},
                "context_released": completed,
                "result": {"status": "COMPLETED" if completed else "RECOVERY_UNCONFIRMED", "data": (
                    {"target": None, "operations": [], "cleanup": {"status": "COMPLETED", "data": {}}}
                    if completed else {"owner_retained": True, "target": self.a.to_dict(),
                                       "cleanup": {"status": "RECOVERY_UNCONFIRMED"}})}}

    def expired_owner(self):
        helper = self.lease(self.a, ["memory_read"])
        self.service._interventions_started = True
        self.service._expires = time.monotonic() - 1
        helper.alive.return_value = False
        return helper

    def test_effectful_expiry_accepts_only_authenticated_terminal_cleanup_after_helper_exit(self):
        helper = self.expired_owner()
        frame = self.terminal_frame()
        self.service._channel.receive = Mock(side_effect=[
            {"kind": "result", "request_id": "unobserved-action", "result": {"status": "COMPLETED",
             "data": {"private": "must-not-enter-terminal-proof"}}}, frame])
        status = self.service.session_status(refresh=True)
        self.assertEqual(status["state"], "EXPIRED")
        self.assertFalse(status["cleanup_required"])
        self.assertFalse(status["admin_active"])
        proof = status["expiry_cleanup"]
        self.assertTrue(proof["confirmed"])
        self.assertEqual(proof["helper_identity"], self.helper_identity.to_dict())
        self.assertEqual(proof["closed_context"]["target"], self.a.to_dict())
        self.assertEqual(proof["late_result_statuses"], [{"request_id": "unobserved-action", "status": "COMPLETED"}])
        self.assertNotIn("nonce", proof)
        self.assertIsNone(status["target"])
        proof["confirmed"] = False  # Public metadata cannot mutate the cached authorization evidence.
        self.assertTrue(self.service._expiry_cleanup["confirmed"])
        closed = self.service.end_admin_session()
        self.assertEqual(closed["status"], "COMPLETED")
        self.assertEqual(self.service.session_status()["state"], "INACTIVE")
        helper.terminate.assert_not_called()

    def test_expired_cleanup_without_ack_does_not_trust_guardian_recovery_file(self):
        self.expired_owner()
        self.service._channel.receive = Mock(side_effect=OSError("pipe closed without terminal ack"))
        with patch.object(self.service, "recovery_status", return_value={"status": "COMPLETED", "target": self.a.to_dict()}):
            status = self.service.session_status(refresh=True)
            closed = self.service.end_admin_session()
        self.assertEqual(status["state"], "CLEANUP_REQUIRED")
        self.assertIsNone(status["expiry_cleanup"])
        self.assertEqual(closed["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(self.service.session_status()["state"], "CLEANUP_REQUIRED")

    def test_wrong_nonce_helper_instance_context_or_release_claim_never_confirms_expiry(self):
        for field in ("nonce", "identity", "context", "scope", "context_released"):
            with self.subTest(field=field):
                self.expired_owner()
                self.service._owner_retained = self.service._cleanup_unconfirmed = False
                self.service._expiry_cleanup = None
                frame = self.terminal_frame()
                value = {"nonce": "cd" * 32, "identity": ProcessIdentity(430, 133000000000000004, "helper.exe").to_dict(),
                                "context": {"target": self.b.to_dict(), "operations": ["memory_read"]},
                                "scope": {"target": self.a.to_dict(), "operations": ["snapshot"]},
                                "context_released": False}[field]
                frame["context" if field == "scope" else field] = value
                self.service._channel.receive = Mock(return_value=frame)
                status = self.service.session_status(refresh=True)
                self.assertEqual(status["state"], "CLEANUP_REQUIRED")
                self.assertIsNone(status["expiry_cleanup"])
                self.assertEqual(status["target"], self.a.to_dict())

    def test_late_terminal_ack_remains_reachable_through_explicit_cleanup_retry(self):
        self.expired_owner()
        frame = self.terminal_frame()
        self.service._channel.receive = Mock(side_effect=[TimeoutError("cleanup not acknowledged yet"), frame])
        self.assertEqual(self.service.session_status(refresh=True)["state"], "CLEANUP_REQUIRED")
        self.assertEqual(self.service.end_admin_session()["status"], "COMPLETED")
        self.assertEqual(self.service.session_status()["state"], "INACTIVE")

    def test_explicit_close_ack_queued_across_expiry_remains_authenticated_and_reachable(self):
        helper = self.lease(self.a, ["memory_read"])
        self.service._interventions_started = True
        frame = self.terminal_frame()
        frame.update(kind="closed", reason="EXPLICIT_CLOSE")
        self.service._channel.receive = Mock(side_effect=[TimeoutError("close acknowledgement delayed"), frame])
        self.assertEqual(self.service.end_admin_session()["status"], "RECOVERY_UNCONFIRMED")
        self.assertIsNotNone(self.service._pending_close_context)
        self.service._expires = time.monotonic() - 1
        helper.alive.return_value = False
        closed = self.service.end_admin_session()
        self.assertEqual(closed["status"], "COMPLETED")
        self.assertEqual(closed["data"]["expiry_cleanup"]["reason"], "EXPLICIT_CLOSE")
        self.assertEqual(self.service.session_status()["state"], "INACTIVE")
        self.assertEqual([message["kind"] for message in self.messages], ["close"])

    def test_failed_terminal_cleanup_retains_exact_previous_target(self):
        self.expired_owner()
        self.service._channel.receive = Mock(return_value=self.terminal_frame(completed=False))
        status = self.service.session_status(refresh=True)
        self.assertEqual(status["state"], "CLEANUP_REQUIRED")
        self.assertFalse(status["expiry_cleanup"]["confirmed"])
        self.assertEqual(status["target"], self.a.to_dict())
        with patch.object(self.service, "_start_session") as start:
            refused = self.service.start_admin_session(confirmed=True)
        self.assertEqual(refused["status"], "RECOVERY_UNCONFIRMED")
        start.assert_not_called()

    def test_terminal_journal_failure_requires_explicit_durable_cleanup_retry(self):
        self.expired_owner()
        self.service._channel.receive = Mock(return_value=self.terminal_frame())
        with patch.object(self.service.journal, "append", side_effect=OSError("journal unavailable")):
            status = self.service.session_status(refresh=True)
            closed = self.service.end_admin_session()
        self.assertTrue(status["expiry_cleanup"]["confirmed"])
        self.assertFalse(status["expiry_cleanup"]["journal_recorded"])
        self.assertEqual(status["state"], "CLEANUP_REQUIRED")
        self.assertEqual(closed["status"], "RECOVERY_UNCONFIRMED")
        self.assertIsNone(self.service.helper)
        self.assertEqual(self.service.end_admin_session()["status"], "COMPLETED")
        self.assertFalse(self.service.session_status()["cleanup_required"])

    def test_unknown_action_outcome_stays_unknown_after_verified_cleanup_and_explicit_new_lease(self):
        helper = self.lease(self.a, ["memory.write"])
        helper.terminate.side_effect = lambda: setattr(helper.alive, "return_value", False)
        frame = self.terminal_frame()
        frame.update(kind="closed", reason="EXPLICIT_CLOSE")
        self.service._channel.receive = Mock(side_effect=[OSError("native action acknowledgement lost"), frame])
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            answer = self.service.execute(ActionRequest("memory.write", self.a,
                {"address": 4096, "expected_hex": "01", "value_hex": "02"}, confirmed=True))
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(answer["run_receipt"]["status"], "RECOVERY_UNCONFIRMED")

        self.assertIsNone(answer["run_receipt"]["execution_started"])
        self.assertEqual(answer["data"]["cleanup"]["status"], "COMPLETED")
        self.assertFalse(self.service.session_status()["cleanup_required"])
        self.assertEqual([message["kind"] for message in self.messages], ["execute", "close"])
        self.assertIsNone(self.service.helper)

        def authorized_launch(*args, **kwargs):
            self.lease()
            self.service._expiry_cleanup = None
            return {"status": "COMPLETED", "limitations": [], "data": self.service.session_status()}

        with patch.object(self.service, "_start_session", side_effect=authorized_launch) as launch:
            restarted = self.service.start_admin_session(confirmed=True)
        launch.assert_called_once()
        self.assertEqual(restarted["status"], "COMPLETED")
        self.assertEqual([message["kind"] for message in self.messages], ["execute", "close"])
        self.assertEqual(answer["run_receipt"]["status"], "RECOVERY_UNCONFIRMED")

    def test_confirmed_close_with_initial_unknown_exit_can_finish_on_later_exact_exit_proof(self):
        helper = self.lease(self.a, ["memory_read"])
        frame = self.terminal_frame()
        frame.update(kind="closed", reason="EXPLICIT_CLOSE")
        self.service._channel.receive = Mock(return_value=frame)
        helper.alive.side_effect = [True, OSError("WAIT_FAILED"), False, False, False]
        first = self.service.end_admin_session()
        self.assertEqual(first["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(self.service._expiry_cleanup["confirmed"])
        second = self.service.end_admin_session()
        self.assertEqual(second["status"], "COMPLETED")
        self.assertFalse(self.service.session_status()["cleanup_required"])
        self.assertEqual([message["kind"] for message in self.messages], ["close"])

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


class HelperProcessExitProofTests(unittest.TestCase):
    def native(self, waits, *, terminate=False):
        kernel = Mock()
        kernel.WaitForSingleObject.side_effect = waits
        kernel.TerminateProcess.return_value = terminate
        return HelperProcess(handle=123, pid=456), kernel

    def test_termination_denied_after_natural_exit_requires_same_handle_signal(self):
        helper, kernel = self.native([258, 0])
        with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                patch("blackbox_core.deep_elevation.C.get_last_error", return_value=5, create=True):
            helper.terminate()
        kernel.TerminateProcess.assert_called_once_with(123, 1)
        self.assertEqual([call.args for call in kernel.WaitForSingleObject.call_args_list], [(123, 0), (123, 0)])
        self.assertEqual(helper.handle, 123)

    def test_termination_denied_while_alive_remains_an_error(self):
        helper, kernel = self.native([258, 258])
        with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                patch("blackbox_core.deep_elevation.C.get_last_error", return_value=5, create=True):
            with self.assertRaisesRegex(OSError, "HELPER_TERMINATION_UNCONFIRMED") as raised:
                helper.terminate()
        self.assertEqual(raised.exception.errno, 5)
        self.assertEqual(helper.handle, 123)
        kernel.CloseHandle.assert_not_called()

    def test_failed_or_unrecognized_wait_is_neither_exit_nor_liveness_proof(self):
        for observed in (0xFFFFFFFF, 128, 12345):
            with self.subTest(observed=observed):
                helper, kernel = self.native([observed])
                with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                        patch("blackbox_core.deep_elevation.C.get_last_error", return_value=6, create=True):
                    with self.assertRaisesRegex(OSError, "HELPER_PROCESS_WAIT_UNCONFIRMED"):
                        helper.alive()
                self.assertEqual(helper.handle, 123)
                kernel.CloseHandle.assert_not_called()

    def test_discard_clears_termination_error_only_after_independent_exit_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = InspectorService(temporary)
            helper, kernel = self.native([258, 258, 258, 0])
            service.helper = helper
            with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                    patch("blackbox_core.deep_elevation.C.get_last_error", return_value=5, create=True):
                service._discard_helper(force=True)
            self.assertIsNone(service.helper)
            kernel.CloseHandle.assert_called_once_with(123)
            self.assertFalse(service._owner_retained)

    def test_discard_keeps_exact_owner_handle_for_denied_live_or_failed_wait(self):
        for observed in (258, 0xFFFFFFFF):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as temporary:
                service = InspectorService(temporary)
                helper, kernel = self.native(None)
                kernel.WaitForSingleObject.side_effect = None
                kernel.WaitForSingleObject.return_value = observed
                service.helper = helper
                with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                        patch("blackbox_core.deep_elevation.C.get_last_error", return_value=5, create=True):
                    with self.assertRaises(OSError):
                        service._discard_helper(force=True)
                self.assertIs(service.helper, helper)
                self.assertEqual(helper.handle, 123)
                self.assertTrue(service._owner_retained)
                self.assertTrue(service._cleanup_unconfirmed)
                kernel.CloseHandle.assert_not_called()

    def test_verified_cleanup_allows_bounded_graceful_exit_before_termination(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = InspectorService(temporary)
            helper, kernel = self.native([258, 0, 0])
            service.helper = helper
            with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True):
                service._discard_helper(force=True, cleanup_confirmed=True)
            self.assertEqual([call.args[1] for call in kernel.WaitForSingleObject.call_args_list], [0, 1000, 0])
            kernel.TerminateProcess.assert_not_called()
            kernel.CloseHandle.assert_called_once_with(123)
            self.assertIsNone(service.helper)

    def test_end_session_with_failed_wait_returns_typed_uncertainty_and_retains_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = InspectorService(temporary)
            helper, kernel = self.native(None)
            kernel.WaitForSingleObject.side_effect = None
            kernel.WaitForSingleObject.return_value = 0xFFFFFFFF
            service.helper = helper
            service._expires = time.monotonic() - 31
            with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                    patch("blackbox_core.deep_elevation.C.get_last_error", return_value=6, create=True):
                answer = service.end_admin_session()
                status = service.session_status()
            self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
            self.assertEqual(status["state"], "CLEANUP_REQUIRED")
            self.assertFalse(status["elevated_verified"])
            self.assertIs(service.helper, helper)
            kernel.CloseHandle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
