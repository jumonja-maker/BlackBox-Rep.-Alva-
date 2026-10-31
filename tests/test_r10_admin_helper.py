"""R10 helper ownership/authority contracts, executed only by hosted CI."""
from __future__ import annotations

import threading
import types
import unittest
from unittest.mock import Mock, patch

from blackbox_core.deep_contracts import ActionRequest, MAX_SESSION_SECONDS, ProcessIdentity
from blackbox_core.deep_helper import DiagnosticActionEngine, ManagedDiagnosticContext, run_helper
from blackbox_core.deep_native import NativeError


class AdminHelperLeaseTests(unittest.TestCase):
    def setUp(self):
        self.a = ProcessIdentity(42, 133000000000000001, "controlled-a.exe")
        self.b = ProcessIdentity(43, 133000000000000002, "controlled-b.exe")
        self.clock = [100.0]
        self.token = [True]
        self.engines = []
        self.live = {self.a.pid: self.a, self.b.pid: self.b}

        def verify(identity):
            if self.live.get(identity.pid) != identity:
                raise NativeError("PROCESS_CHANGED", "PROCESS_INSTANCE_CHANGED")
            return identity

        self.verify = Mock(side_effect=verify)

        def engine(target, operations, **kwargs):
            owner = Mock()
            owner.target = target
            owner.operations = frozenset(operations)
            owner.interventions_started = False
            owner.execute.return_value = {"operation": "threads", "status": "COMPLETED", "data": {"rows": []}}
            owner.close.return_value = {"status": "COMPLETED", "data": {}}
            self.engines.append(owner)
            return owner

        self.factory = Mock(side_effect=engine)
        self.context = ManagedDiagnosticContext(["threads", "debug.detach", "capabilities"],
                                                engine_factory=self.factory,
                                                identity_verifier=self.verify,
                                                token_verifier=lambda: self.token[0], clock=lambda: self.clock[0])

    def bind(self, target):
        return self.context.bind(target, ["threads", "debug.detach", "capabilities"], confirmed=True)

    def test_unbound_lease_requires_explicit_target_consent_then_reuses_exact_lease(self):
        expires = self.context.expires
        answer = self.context.execute(ActionRequest("threads", self.a))
        self.assertEqual(answer["status"], "CONFIRMATION_REQUIRED")
        self.factory.assert_not_called()
        self.assertEqual(self.bind(self.a)["status"], "COMPLETED")
        first = self.context.engine
        self.assertEqual(self.context.execute(ActionRequest("threads", self.a))["status"], "COMPLETED")
        first.execute.assert_called_once()
        self.assertEqual(self.context.execute(ActionRequest("threads", self.b))["status"], "CONFIRMATION_REQUIRED")
        first.execute.assert_called_once()
        self.clock[0] += 17
        self.assertEqual(self.bind(self.b)["status"], "COMPLETED")
        first.close.assert_called_once()
        self.assertEqual(self.context.engine.target, self.b)
        self.assertEqual(self.context.expires, expires)
        self.assertEqual(expires, 100 + MAX_SESSION_SECONDS)
        self.assertEqual(self.verify.call_count, 4)

    def test_missing_consent_does_not_clean_or_authorize_another_target(self):
        self.bind(self.a)
        owner = self.context.engine
        answer = self.context.bind(self.b, ["threads"], confirmed=False)
        self.assertEqual(answer["status"], "CONFIRMATION_REQUIRED")
        self.assertIs(self.context.engine, owner)
        owner.close.assert_not_called()
        self.assertEqual(len(self.engines), 1)

    def test_pid_reuse_is_rejected_before_old_owner_or_new_engine_changes(self):
        self.bind(self.a)
        owner = self.context.engine
        self.live[self.b.pid] = ProcessIdentity(self.b.pid, self.b.created_100ns + 1, self.b.image_path)
        with self.assertRaisesRegex(NativeError, "PROCESS_INSTANCE_CHANGED"):
            self.bind(self.b)
        self.assertIs(self.context.engine, owner)
        owner.close.assert_not_called()
        self.assertEqual(len(self.engines), 1)

    def test_target_is_reverified_after_cleanup_before_new_native_owner(self):
        self.bind(self.a)
        old = self.context.engine

        def exit_during_cleanup():
            self.live.pop(self.b.pid)
            return {"status": "COMPLETED", "data": {}}

        old.close.side_effect = exit_during_cleanup
        with self.assertRaisesRegex(NativeError, "PROCESS_INSTANCE_CHANGED"):
            self.bind(self.b)
        self.assertIsNone(self.context.engine)
        self.assertEqual(len(self.engines), 1)

    def test_cleanup_failure_retains_owner_and_requires_explicit_retry(self):
        self.bind(self.a)
        old = self.context.engine
        expires = self.context.expires
        old.close.side_effect = [{"status": "RECOVERY_UNCONFIRMED", "data": {"errors": ["restore failed"]}},
                                 {"status": "COMPLETED", "data": {}}]
        failed = self.bind(self.b)
        self.assertEqual(failed["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(failed["retains_service"])
        self.assertTrue(failed["data"]["owner_retained"])
        self.assertEqual(failed["data"]["target"], self.a.to_dict())
        self.assertIs(self.context.engine, old)
        self.assertEqual(self.bind(self.b)["status"], "RECOVERY_UNCONFIRMED")
        old.close.assert_called_once()  # A bind is never an implicit retry.
        blocked = self.context.execute(ActionRequest("threads", self.a))
        self.assertEqual(blocked["status"], "RECOVERY_UNCONFIRMED")
        old.execute.assert_not_called()
        self.assertEqual(self.context.release()["status"], "COMPLETED")
        self.assertEqual(self.bind(self.b)["status"], "COMPLETED")
        self.assertEqual(self.context.engine.target, self.b)
        self.assertEqual(self.context.expires, expires)

    def test_stuck_native_worker_retains_cancelled_owner_and_does_not_close_engine(self):
        self.bind(self.a)
        old = self.context.engine
        worker = Mock()
        worker.is_alive.return_value = True
        cancelled = threading.Event()
        answer = self.context.release(active=worker, active_cancel=cancelled)
        self.assertTrue(cancelled.is_set())
        worker.join.assert_called_once_with(timeout=5)
        old.close.assert_not_called()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIs(self.context.engine, old)
        self.assertEqual(self.bind(self.b)["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(len(self.engines), 1)

    def test_revoked_token_and_expiry_prevent_execution_but_allow_owned_cleanup(self):
        self.bind(self.a)
        old = self.context.engine
        self.token[0] = False
        self.assertEqual(self.bind(self.b)["status"], "ACCESS_DENIED")
        self.assertEqual(self.context.execute(ActionRequest("threads", self.a))["status"], "ACCESS_DENIED")
        old.execute.assert_not_called()
        self.token[0] = True
        self.clock[0] = self.context.expires
        self.assertEqual(self.bind(self.b)["status"], "SESSION_EXPIRED")
        self.assertEqual(self.context.execute(ActionRequest("threads", self.a))["status"], "SESSION_EXPIRED")
        self.assertEqual(self.context.release()["status"], "COMPLETED")
        old.close.assert_called_once()

    def test_status_requires_actual_admin_authority_and_reports_original_remaining_lease(self):
        authority = {"source": "WINDOWS_PROCESS_TOKEN", "elevation_flag": True,
                     "enabled_administrators": True, "integrity_rid": 0x3000, "elevated": True}
        self.clock[0] += 50
        with patch("blackbox_core.deep_helper.token_authority", return_value=authority):
            status = self.context.status()
        self.assertEqual(status["status"], "COMPLETED")
        self.assertTrue(status["data"]["elevated_verified"])
        self.assertIsNone(status["data"]["target"])
        self.assertEqual(status["data"]["expires_in_seconds"], 850)
        restricted = dict(authority, enabled_administrators=False, elevated=False)
        with patch("blackbox_core.deep_helper.token_authority", return_value=restricted):
            denied = self.context.status()
        self.assertEqual(denied["status"], "ACCESS_DENIED")
        self.assertFalse(denied["data"]["elevated_verified"])
        self.assertEqual(denied["data"]["permission_level"], "STANDARD")

    def test_unknown_intervention_exception_retains_cleanup_state(self):
        self.bind(self.a)
        owner = self.context.engine
        owner.interventions_started = True
        owner.execute.side_effect = OSError("native acknowledgement lost")
        with self.assertRaisesRegex(OSError, "acknowledgement lost"):
            self.context.execute(ActionRequest("threads", self.a))
        self.assertTrue(self.context.cleanup_required)
        self.assertEqual(self.bind(self.b)["status"], "RECOVERY_UNCONFIRMED")
        owner.close.assert_not_called()

    def test_unknown_local_duplicate_or_command_scope_and_unbounded_lease_are_rejected(self):
        for scope in (["execute_shell"], ["timeline"], ["threads", "threads"], [["threads"]], [True], []):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.context.bind(self.a, scope, confirmed=True)
        for duration in (True, 0, -1, MAX_SESSION_SECONDS + 1, float("nan"), float("inf")):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                ManagedDiagnosticContext(["threads"], duration=duration, token_verifier=lambda: True)
        with self.assertRaisesRegex(PermissionError, "ELEVATED_TOKEN_NOT_GRANTED"):
            ManagedDiagnosticContext(["threads"], token_verifier=lambda: False)
        self.factory.assert_not_called()


class AdminEngineExecutionEvidenceTests(unittest.TestCase):
    def test_capability_catalog_probe_does_not_authorize_execution_outside_target_scope(self):
        target = ProcessIdentity(42, 133000000000000001, "controlled.exe")
        inspector = Mock()
        engine = DiagnosticActionEngine(target, ["capabilities"], probe_operations=["capabilities", "threads"],
                                        inspector_factory=lambda target: inspector)
        with patch("blackbox_core.deep_native.verify_identity", return_value=target), \
                patch("blackbox_core.deep_native.probe_access", return_value={"status": "AVAILABLE"}):
            answer = engine.execute(ActionRequest("capabilities", target))
        self.assertEqual({row["operation"] for row in answer["data"]["operations"]}, {"capabilities", "threads"})
        refused = engine.execute(ActionRequest("threads", target))
        self.assertEqual(refused["status"], "ACCESS_DENIED")
        self.assertEqual(engine.operations, frozenset({"capabilities"}))
        inspector.execute.assert_not_called()

    def test_unsupported_options_and_ambiguous_aliases_cannot_execute_defaults(self):
        target = ProcessIdentity(42, 133000000000000001, "controlled.exe")
        inspector = Mock()
        engine = DiagnosticActionEngine(target, ["snapshot", "memory_read", "threads"], inspector_factory=lambda target: inspector)
        for operation, parameters in (("snapshot", {"unsupported_option": True}),
                                      ("threads", {"unsupported_option": True}),
                                      ("memory_read", {"address": 4096, "size": 1, "length": 2})):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                engine.execute(ActionRequest(operation, target, parameters))
        inspector.execute.assert_not_called()

    def test_collector_identity_failure_does_not_claim_verified_result_target(self):
        target = ProcessIdentity(42, 133000000000000001, "controlled.exe")
        inspector = Mock()
        inspector.execute.return_value = {"status": "PROCESS_CHANGED", "data": {}, "reason": "INSTANCE_CHANGED_AT_HANDLE_OPEN"}
        engine = DiagnosticActionEngine(target, ["threads"], inspector_factory=lambda target: inspector)
        with patch("blackbox_core.deep_native.verify_identity", return_value=target):
            answer = engine.execute(ActionRequest("threads", target))
        self.assertEqual(answer["status"], "PROCESS_CHANGED")
        self.assertFalse(answer["diagnostic_execution"]["target_verified"])

    def test_actual_native_dispatch_carries_exact_verified_identity_and_refusals_do_not(self):
        target = ProcessIdentity(42, 133000000000000001, "controlled.exe")
        inspector = Mock()
        inspector.execute.return_value = {"status": "COMPLETED", "data": {"rows": []}}
        engine = DiagnosticActionEngine(target, ["threads", "debug.attach"], inspector_factory=lambda target: inspector)
        with patch("blackbox_core.deep_native.verify_identity", return_value=target) as verify:
            answer = engine.execute(ActionRequest("threads", target))
        verify.assert_called_once_with(target)
        inspector.execute.assert_called_once()
        self.assertEqual(answer["diagnostic_execution"], {
            "source": "DIAGNOSTIC_HELPER", "source_verified": True,
            "target_verified": True, "target": target.to_dict()})
        refused = engine.execute(ActionRequest("debug.attach", target, confirmed=False))
        self.assertEqual(refused["status"], "CONFIRMATION_REQUIRED")
        self.assertNotIn("diagnostic_execution", refused)
        reused = ProcessIdentity(target.pid, target.created_100ns + 1, target.image_path)
        changed = engine.execute(ActionRequest("threads", reused))
        self.assertEqual(changed["status"], "PROCESS_CHANGED")
        self.assertNotIn("diagnostic_execution", changed)


class AdminHelperProtocolTests(unittest.TestCase):
    def test_unbound_authenticated_helper_responds_to_status_and_rejects_wrong_nonce(self):
        parent = ProcessIdentity(600, 133000000000000001, "gui.exe")
        own = ProcessIdentity(700, 133000000000000002, "helper.exe")
        nonce = "ab" * 32
        init = {"kind": "init", "nonce": nonce, "parent": parent.to_dict(), "target": None,
                "operations": ["threads", "capabilities"], "session_mode": "ADMIN_LEASE",
                "require_admin": True, "session_seconds": 60, "recovery_source_handle": 100}
        authority = {"source": "WINDOWS_PROCESS_TOKEN", "elevated": True,
                     "enabled_administrators": True, "elevation_flag": True, "integrity_rid": 0x3000}
        for wrong_nonce in (False, True):
            with self.subTest(wrong_nonce=wrong_nonce):
                channel, kernel = Mock(), Mock()
                kernel.WaitForSingleObject.return_value = 258
                channel.receive.side_effect = [init,
                    {"kind": "session.status", "request_id": "heartbeat", "nonce": "cd" * 32 if wrong_nonce else nonce},
                    {"kind": "close", "nonce": nonce}]
                with patch("blackbox_core.deep_helper.os", types.SimpleNamespace(name="nt", getpid=lambda: own.pid)), \
                        patch("blackbox_core.deep_helper.token_is_elevated", return_value=True), \
                        patch("blackbox_core.deep_helper.token_authority", return_value=authority), \
                        patch("blackbox_core.deep_helper._parent_handle", return_value=(kernel, 200)), \
                        patch("blackbox_core.deep_helper._duplicate_parent_file", return_value=300), \
                        patch("blackbox_core.deep_helper.connect_pipe", return_value=channel) as connect, \
                        patch("blackbox_core.deep_native.capture_identity", return_value=own), \
                        patch("blackbox_core.windows_research.enable_debug_privilege"):
                    if wrong_nonce:
                        with self.assertRaisesRegex(PermissionError, "INVALID_SESSION_MESSAGE_NONCE"):
                            run_helper("pipe", nonce, parent)
                    else:
                        self.assertEqual(run_helper("pipe", nonce, parent), 0)
                self.assertEqual(connect.call_args.args[:2], ("pipe", parent.pid))
                sent = [call.args[0] for call in channel.send.call_args_list]
                self.assertEqual(sent[0]["identity"], own.to_dict())
                self.assertEqual(sent[0]["nonce"], nonce)
                self.assertEqual(sent[1]["target"], None)
                self.assertEqual(sent[1]["session_mode"], "ADMIN_LEASE")
                if wrong_nonce:
                    self.assertEqual(len(sent), 2)
                else:
                    self.assertEqual(sent[2]["request_id"], "heartbeat")
                    self.assertTrue(sent[2]["result"]["data"]["elevated_verified"])
                    self.assertEqual(sent[2]["result"]["data"]["helper_identity"], own.to_dict())
                    self.assertEqual(sent[-1]["kind"], "closed")
                channel.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
