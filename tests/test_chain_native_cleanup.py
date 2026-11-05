"""R60 native ownership regressions; execute only on GitHub-hosted runners."""
from contextlib import ExitStack
from copy import deepcopy
import ctypes as C
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from blackbox_core import deep_native as native
from blackbox_core import windows_research
from blackbox_core.deep_contracts import ActionRequest, ProcessIdentity
from blackbox_core.deep_helper import DiagnosticActionEngine
from blackbox_core.deep_service import InspectorService
from blackbox_core.deep_debug import DebugSession
from blackbox_core.deep_elevation import HelperProcess
from blackbox_core.deep_ipc import IPCError, PipeChannel


class TransportCapabilityCleanupTests(unittest.TestCase):
    """Injected Win32/wrapper boundaries; real HANDLE closure is tested by Q21."""
    def native_helper(self, results):
        kernel = Mock()
        kernel.CloseHandle.side_effect = results
        helper = HelperProcess(handle=911, pid=123)
        return helper, kernel

    def test_helper_native_false_close_retains_exact_owner_until_successful_retry(self):
        helper, kernel = self.native_helper([False, True])
        with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                patch.object(C, "get_last_error", return_value=5, create=True):
            with self.assertRaisesRegex(OSError, "HELPER_PROCESS_HANDLE_CLOSE_UNCONFIRMED") as caught:
                helper.close_handle()
            self.assertIs(caught.exception.owner, helper)
            self.assertTrue(caught.exception.cleanup_unconfirmed)
            self.assertEqual(helper.handle, 911)
            self.assertFalse(helper.cleanup_evidence["confirmed"])
            self.assertTrue(helper.close_handle()["confirmed"])
            self.assertIsNone(helper.handle)
            self.assertTrue(helper.close_handle()["confirmed"])
        self.assertEqual([call.args for call in kernel.CloseHandle.call_args_list], [(911,), (911,)])

    def test_helper_invalid_handle_failure_never_closes_a_reused_numeric_slot(self):
        helper, kernel = self.native_helper([False])
        with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                patch.object(C, "get_last_error", return_value=6, create=True):
            with self.assertRaises(OSError):
                helper.close_handle()
            with self.assertRaisesRegex(OSError, "HELPER_HANDLE_OWNERSHIP_LOST"):
                helper.close_handle()
            with self.assertRaisesRegex(OSError, "HELPER_HANDLE_OWNERSHIP_LOST"):
                helper.alive()
        kernel.CloseHandle.assert_called_once_with(911)
        self.assertFalse(helper.cleanup_evidence["confirmed"])

    def test_popen_handle_uses_checked_wrapper_and_never_raw_close_or_gc_double_close(self):
        class Handle:
            # Models CPython Handle.Close: closed is set before _winapi raises.
            closed = False
            calls = 0
            fail = True
            def Close(self):
                if not self.closed:
                    self.closed = True
                    self.calls += 1
                    if self.fail:
                        raise OSError(5, "INJECTED_NATIVE_CLOSE_DENIAL")
        handle = Handle()
        process = types.SimpleNamespace(pid=123, _handle=handle, returncode=0)
        helper = HelperProcess(process=process)
        with patch("blackbox_core.deep_elevation.C.WinDLL", create=True) as native_dll:
            with self.assertRaisesRegex(OSError, "HELPER_POPEN_HANDLE_CLOSE_UNCONFIRMED"):
                helper.close_handle()
            self.assertFalse(handle.closed, "known failed native close must remain retryable")
            self.assertIs(helper.process._handle, handle)
            handle.fail = False
            self.assertTrue(helper.close_handle()["confirmed"])
            self.assertTrue(handle.closed)
            handle.Close()  # The same wrapper's later finalizer is now a no-op.
            helper.close_handle()
            native_dll.assert_not_called()
        self.assertEqual(handle.calls, 2)

    def test_pipe_false_close_retains_handle_then_consumes_only_successful_close(self):
        kernel = Mock()
        kernel.CloseHandle.side_effect = [False, True]
        with patch("blackbox_core.deep_ipc._kernel", return_value=kernel), \
                patch.object(C, "get_last_error", return_value=5, create=True):
            channel = PipeChannel(912)
            with self.assertRaisesRegex(IPCError, "DIAGNOSTIC_PIPE_CLOSE_UNCONFIRMED") as caught:
                channel.close()
            self.assertIs(caught.exception.owner, channel)
            self.assertEqual(channel.handle, 912)
            self.assertFalse(channel.cleanup_evidence["confirmed"])
            self.assertTrue(channel.close()["confirmed"])
            self.assertIsNone(channel.handle)
            channel.close()
        self.assertEqual([call.args for call in kernel.CloseHandle.call_args_list], [(912,), (912,)])

    def test_pipe_invalid_handle_does_not_retry_or_use_a_potentially_reused_slot(self):
        kernel = Mock()
        kernel.CloseHandle.return_value = False
        with patch("blackbox_core.deep_ipc._kernel", return_value=kernel), \
                patch.object(C, "get_last_error", return_value=6, create=True):
            channel = PipeChannel(913)
            with self.assertRaises(IPCError):
                channel.close()
            with self.assertRaisesRegex(IPCError, "OWNERSHIP_LOST"):
                channel.close()
            with self.assertRaisesRegex(IPCError, "OWNERSHIP_LOST"):
                channel.send({"kind": "fixture"}, deadline=time.monotonic() + 1)
        kernel.CloseHandle.assert_called_once_with(913)
        kernel.WriteFile.assert_not_called()


class QueryCleanupTests(unittest.TestCase):
    def setUp(self):
        self.target = ProcessIdentity(123, 456, "fixture.exe")
        self.inspector = native.ProcessInspector(self.target)
        self.kernel = Mock()
        self.kernel.open_process.return_value = 11
        self.kernel.open_thread.return_value = 21
        self.kernel.snapshot.return_value = 31
        self.kernel.close.return_value = True
        self.kernel.wait.return_value = 258
        self.kernel.thread_pid.return_value = self.target.pid
        self.kernel.thread_next.return_value = False
        self.kernel.module_first.return_value = False
        def first(handle, pointer):
            row = C.cast(pointer, C.POINTER(native.W.THREADENTRY32)).contents
            row.tid, row.pid, row.base_priority = 333, self.target.pid, 8
            return True
        self.kernel.thread_first.side_effect = first
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(native, "_windows"))
        self.stack.enter_context(patch.object(native.W, "Kernel", return_value=self.kernel))
        self.stack.enter_context(patch.object(native, "_identity", return_value=self.target))
        self.stack.enter_context(patch.object(native, "_times", return_value=(789, 1, 2)))
        self.stack.enter_context(patch.object(C, "get_last_error", return_value=18, create=True))

    def test_real_thread_collector_ack_counts_process_snapshot_and_thread_closes(self):
        answer = self.inspector.execute("threads")
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertEqual(answer["data"]["rows"][0]["created_100ns"], 789)
        cleanup = answer["native_query_cleanup"]
        self.assertTrue(cleanup["confirmed"])
        self.assertEqual((cleanup["opened"], cleanup["closed"], cleanup["retained"]), (3, 3, 0))
        self.assertEqual([call.args[0] for call in self.kernel.close.call_args_list], [21, 31, 11])
        self.assertFalse(self.inspector._owned_native_handles)

    def test_module_snapshot_close_failure_retains_only_exact_failed_capability(self):
        self.kernel.close.side_effect = lambda handle: handle != 31
        answer = self.inspector.execute("modules")
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(answer["data"]["reported_operation_status"], "COMPLETED")
        self.assertEqual(answer["native_query_cleanup"]["retained"], 1)
        self.assertEqual(self.inspector._owned_native_handles[0]["handle"], 31)
        self.assertEqual(self.inspector.close()["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(self.inspector.closed)
        self.kernel.close.reset_mock(side_effect=True)
        self.kernel.close.return_value = True
        closed = self.inspector.close()
        self.assertTrue(closed["data"]["cleanup"]["confirmed"])
        self.kernel.close.assert_called_once_with(31)
        self.assertFalse(self.inspector._owned_native_handles)

    def test_cancel_reason_survives_failed_finally_and_successful_handle_is_not_retried(self):
        self.kernel.thread_first.side_effect = native.NativeError("CANCELLED", "PRIMARY_CANCEL")
        self.kernel.close.side_effect = lambda handle: handle != 31
        answer = self.inspector.execute("threads")
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(answer["data"]["reported_operation_status"], "CANCELLED")
        self.assertEqual(answer["data"]["reported_operation_reason"], "PRIMARY_CANCEL")
        self.assertEqual([r["handle"] for r in self.inspector._owned_native_handles], [31])

    def test_invalid_handle_failure_never_retries_a_possibly_reused_numeric_slot(self):
        self.kernel.close.side_effect = lambda handle: handle != 31
        with patch.object(C, "get_last_error", return_value=6, create=True):
            answer = self.inspector.execute("modules")
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.kernel.close.reset_mock(side_effect=True)
        self.kernel.close.return_value = True
        self.assertEqual(self.inspector.close()["status"], "RECOVERY_UNCONFIRMED")
        self.kernel.close.assert_not_called()

    def test_identity_preflight_failure_is_in_actual_helper_operation_ack(self):
        self.kernel.open_process.side_effect = [71, 72]
        self.kernel.close.side_effect = lambda handle: handle != 71
        engine = DiagnosticActionEngine(self.target, ["threads"], inspector_factory=lambda _: self.inspector)
        engine.debug = Mock()
        answer = engine.execute(ActionRequest("threads", self.target))
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(answer["native_query_cleanup"]["opened"], 4)
        self.assertIn("IDENTITY_PROCESS_HANDLE", answer["native_query_cleanup"]["resource_kinds"])
        self.assertEqual([r["handle"] for r in self.inspector._owned_native_handles], [71])
        engine.debug.close.assert_not_called()

    def test_access_probe_covers_identity_and_both_process_handles(self):
        self.kernel.open_process.side_effect = [81, 82, 83]
        self.kernel.process_information.return_value = False
        with patch.object(native, "_times", return_value=(self.target.created_100ns, 0, 0)):
            with self.inspector.query_cleanup_scope("capabilities") as scope:
                probe = native.probe_access(self.target, "threads")
        self.assertEqual(probe["status"], "AVAILABLE")
        self.assertEqual(scope.evidence()["opened"], 3)
        self.assertTrue(scope.evidence()["confirmed"])
        self.assertEqual([call.args[0] for call in self.kernel.close.call_args_list], [81, 82, 83])

    def test_snapshot_aggregates_actual_child_cleanup_and_does_not_close_debug_owner(self):
        self.kernel.snapshot.side_effect = [31, 32]
        def small_section(*args):
            with self.inspector._open(0x1000):
                return {"rows": []}
        engine = DiagnosticActionEngine(self.target, ["snapshot"], inspector_factory=lambda _: self.inspector)
        engine.debug = Mock()
        with patch.object(self.inspector, "_memory_map", side_effect=small_section), \
                patch.object(self.inspector, "_network", side_effect=small_section), \
                patch.object(self.inspector, "_disk", side_effect=small_section):
            answer = engine.execute(ActionRequest("snapshot", self.target))
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertTrue(answer["native_query_cleanup"]["confirmed"])
        self.assertEqual(answer["native_query_cleanup"]["opened"], 9)
        self.assertTrue(all(section["native_query_cleanup"]["confirmed"] for section in answer["data"].values()))
        engine.debug.close.assert_not_called()

    def wct_api(self):
        api = Mock()
        api.OpenThreadWaitChainSession.return_value = 91
        api.CloseThreadWaitChainSession.return_value = None
        api.GetThreadWaitChain.return_value = False
        return api

    def wct_patches(self, api):
        stack = ExitStack()
        stack.enter_context(patch.object(windows_research, "os", types.SimpleNamespace(name="nt")))
        stack.enter_context(patch.object(C, "WinDLL", return_value=api, create=True))
        stack.enter_context(patch.object(C, "WINFUNCTYPE", side_effect=lambda *a: lambda f: f, create=True))
        stack.enter_context(patch.object(C, "get_last_error", return_value=5, create=True))
        stack.enter_context(patch.object(C, "set_last_error", create=True))
        return stack

    def test_wct_void_close_return_is_observed_even_when_query_fails(self):
        api, order = self.wct_api(), []
        api.CloseThreadWaitChainSession.side_effect = lambda h: order.append("closed")
        def observe(event, release):
            order.append(event)
            native._wct_cleanup_observer(event, release)
        with self.wct_patches(api), self.inspector.query_cleanup_scope("wait_chains") as scope:
            result = windows_research.wait_chain(333, cleanup_observer=observe)
        self.assertEqual(result["status"], "ACCESS_DENIED")
        self.assertEqual(order, ["OPENED", "closed", "CLOSED_CALLBACKS_DRAINED"])
        self.assertTrue(scope.evidence()["confirmed"])
        self.assertEqual(scope.evidence()["opened"], 1)

    def test_wct_close_exception_retains_callback_capability_until_explicit_retry(self):
        api = self.wct_api()
        api.CloseThreadWaitChainSession.side_effect = OSError("close boundary unavailable")
        with self.wct_patches(api), self.inspector.query_cleanup_scope("wait_chains") as scope:
            with self.assertRaisesRegex(OSError, "close boundary"):
                windows_research.wait_chain(333, cleanup_observer=native._wct_cleanup_observer)
        self.assertFalse(scope.evidence()["confirmed"])
        self.assertEqual(len(self.inspector._owned_native_handles), 1)
        api.CloseThreadWaitChainSession.side_effect = None
        self.assertTrue(self.inspector.close()["data"]["cleanup"]["confirmed"])
        self.assertFalse(self.inspector._owned_native_handles)


class HelperCleanupAcknowledgementTests(unittest.TestCase):
    def test_completed_inspector_without_cleanup_ack_retains_exact_owner(self):
        identity = ProcessIdentity(123, 456, "fixture.exe")
        inspector = Mock()
        inspector.close.return_value = {"status": "COMPLETED", "data": {}}
        engine = DiagnosticActionEngine(identity, ["threads"], inspector_factory=lambda _: inspector)
        answer = engine.close()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(answer["data"]["owner_retained"])
        self.assertTrue(answer["retains_service"])
        self.assertFalse(answer["data"]["cleanup"]["confirmed"])
        self.assertIs(engine.inspector, inspector)

    def test_completed_debug_without_worker_ack_retains_owner_even_if_inspector_closed(self):
        identity = ProcessIdentity(123, 456, "fixture.exe")
        inspector = Mock()
        inspector.close.return_value = {"status": "COMPLETED", "data": {"cleanup": {"confirmed": True}}}
        engine = DiagnosticActionEngine(identity, ["threads"], inspector_factory=lambda _: inspector)
        engine.debug = Mock()
        engine.debug.close.return_value = {"status": "COMPLETED", "data": {"state": "DETACHED"}}
        answer = engine.close()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(answer["data"]["owner_retained"])
        self.assertFalse(answer["data"]["cleanup"]["confirmed"])

    def test_debug_command_done_without_native_worker_cleanup_ack_is_not_completion(self):
        session = DebugSession(ProcessIdentity(123, 456, "fixture.exe"))
        session._worker = Mock()
        session._worker.is_alive.return_value = False
        done = threading.Event()
        done.set()
        session._closed = True
        session._close_command = types.SimpleNamespace(done=done, result={
            "status": "COMPLETED", "data": {"state": "DETACHED"}})
        answer = session.close()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIsNot(answer.get("native_owner_cleanup", {}).get("confirmed"), True)


class ServiceCleanupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.service = InspectorService(Path(self.folder.name))
        self.target = ProcessIdentity(123, 456, "fixture.exe")
        self.helper_identity = ProcessIdentity(124, 457, "helper.exe")
        self.messages = []

    def lease(self, *, target=True, managed=False):
        service = self.service
        service.helper = Mock(pid=self.helper_identity.pid)
        service.helper.alive.return_value = True
        service._helper_identity = self.helper_identity
        service._target = self.target if target else None
        service._scope = frozenset({"threads", "debug.attach"}) if target else frozenset()
        service._session_catalog = frozenset({"threads", "capabilities", "debug.attach"})
        service._expires = time.monotonic() + 300
        service._session_nonce = "a" * 64
        service._permission = "ADMINISTRATOR" if managed else "STANDARD"
        service._admin_session_managed = managed
        service._admin_state = "ACTIVE" if managed else "INACTIVE"
        service._elevated_verified = managed
        service._native_context_changed()
        service._channel = Mock()
        service._channel.send.side_effect = lambda message, **kwargs: self.messages.append(message)

    def reply(self, change=None, status="COMPLETED"):
        message = self.messages[-1]
        proof = {"status": "CONFIRMED", "confirmed": True, "ownership_known": True,
            "scope": "BLACKBOX_OWNED_NATIVE_QUERY_RESOURCES", "opened": 3, "closed": 3, "retained": 0,
            "operation": "threads", "target": self.target.to_dict(), "request_id": message["request_id"],
            "helper_identity": self.helper_identity.to_dict(), "session_nonce": self.service._session_nonce}
        proof.update(change or {})
        return {"kind": "result", "request_id": message["request_id"], "result": {
            "status": status, "data": {}, "native_query_cleanup": proof,
            "diagnostic_execution": {"source": "DIAGNOSTIC_HELPER", "source_verified": True,
                "target_verified": True, "target": self.target.to_dict()}}}

    def run_query(self, change=None):
        self.service._channel.receive.side_effect = lambda **kwargs: self.reply(change)
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os):
            return self.service.execute(ActionRequest("threads", self.target))

    def test_correlated_query_ack_reaches_original_receipt_and_journal_without_nonce(self):
        self.lease()
        with patch.object(self.service, "end_admin_session") as close:
            answer = self.run_query()
        close.assert_not_called()
        self.assertTrue(answer["run_receipt"]["cleanup"]["confirmed"])
        self.assertTrue(answer["run_receipt"]["cleanup"]["evidence"]["session_nonce_verified"])
        self.assertNotIn(self.service._session_nonce, json.dumps(answer))
        self.assertTrue(self.service.journal.timeline()[0]["run_receipt"]["cleanup"]["confirmed"])

    def test_wrong_nonce_operation_request_helper_or_target_cannot_become_ack(self):
        self.lease()
        for change in ({"session_nonce": "b" * 64}, {"operation": "modules"},
                       {"request_id": "foreign"}, {"helper_identity": self.target.to_dict()},
                       {"target": self.helper_identity.to_dict()}):
            with self.subTest(change=change):
                answer = self.run_query(change)
                self.assertEqual(answer["status"], "COMPLETED")
                self.assertFalse(answer["run_receipt"]["cleanup"]["confirmed"])

    def test_known_retained_scope_remains_distinct_from_unknown_cleanup(self):
        self.lease()
        answer = self.run_query({"status": "RETAINED", "confirmed": False,
            "scope": "TARGET_BOUND_DEBUG_CONTEXT", "resources": {"attached": True, "pending_memory_changes": 1}})
        cleanup = answer["run_receipt"]["cleanup"]
        self.assertEqual(cleanup["status"], "RETAINED")
        self.assertFalse(cleanup["confirmed"])
        self.assertTrue(cleanup["evidence"]["ownership_known"])
        self.assertNotIn("owner_retained", answer["data"])

    def test_result_journal_failure_keeps_cleanup_evidence_but_outcome_unconfirmed(self):
        self.lease()
        append = self.service.journal.append
        def write(row):
            if row.get("phase") == "RESULT":
                raise OSError("storage failure")
            return append(row)
        with patch.object(self.service.journal, "append", side_effect=write):
            answer = self.run_query()
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(answer["run_receipt"]["cleanup"]["confirmed"])
        self.assertTrue(answer["run_receipt"]["cleanup"]["evidence"]["confirmed"])

    def fresh_owned(self):
        def create(request, cancel_event=None):
            self.lease()
            return {"status": "COMPLETED", "data": {}}
        with patch.object(self.service, "execute", side_effect=create):
            return self.service.execute_owned(ActionRequest("threads", self.target), owner_run_id="run-A")

    def test_foreign_context_only_allows_readonly_borrow_without_close_or_ownership(self):
        self.lease()
        with patch.object(self.service, "execute", return_value={"status": "COMPLETED", "data": {}}) as execute, \
                patch.object(self.service, "clear_target") as clear, patch.object(self.service, "end_admin_session") as end:
            borrowed = self.service.execute_owned(ActionRequest("threads", self.target), owner_run_id="run-A")
            blocked = self.service.execute_owned(ActionRequest("debug.attach", self.target, confirmed=True), owner_run_id="run-A")
        self.assertIsNone(borrowed["native_context_ownership"])
        self.assertEqual(blocked["error"], "NATIVE_CONTEXT_OWNERSHIP_CONFLICT")
        execute.assert_called_once()
        clear.assert_not_called()
        end.assert_not_called()

    def test_fresh_session_ref_reenters_same_run_and_stale_generation_cannot_close(self):
        created = self.fresh_owned()
        reference = created["native_context_ownership"]
        self.assertTrue(reference["owns_session"])
        with patch.object(self.service, "execute", return_value={"status": "COMPLETED", "data": {}}):
            again = self.service.execute_owned(ActionRequest("threads", self.target),
                owner_run_id="run-A", expected_context=reference)
        self.assertEqual(again["native_context_ownership"], reference)
        self.service._native_context_changed()  # Actual legacy lifecycle invalidates this reference.
        with patch.object(self.service, "end_admin_session") as end:
            refused = self.service.release_native_context("run-A", expected_context=reference)
        self.assertEqual(refused["error"], "NATIVE_CONTEXT_OWNERSHIP_CONFLICT")
        end.assert_not_called()

    def test_callback_failure_after_new_native_context_keeps_owned_cleanup_reference(self):
        def create_then_fail(request, cancel_event=None):
            self.lease()
            raise OSError("PRIMARY_NATIVE_RESULT_STORAGE_FAILURE")
        with patch.object(self.service, "execute", side_effect=create_then_fail):
            answer = self.service.execute_owned(ActionRequest("threads", self.target), owner_run_id="run-A")
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("PRIMARY_NATIVE_RESULT_STORAGE_FAILURE", answer.get("error", ""))
        reference = answer["native_context_ownership"]
        self.assertEqual(reference["owner_run_id"], "run-A")
        self.assertTrue(reference["owns_session"])
        self.assertTrue(self.service._native_owner_matches("run-A", reference))
        self.assertIsNotNone(self.service.helper)

    def test_fresh_readonly_call_closed_inside_dispatch_keeps_cleanup_only_ack_without_rewriting_query(self):
        from io import BytesIO
        kernel = Mock()
        kernel.WaitForSingleObject.return_value = 0
        kernel.CloseHandle.return_value = True
        query = {"operation_id": "fixture-lost-query", "operation": "threads", "status": "OPERATION_FAILED",
                 "run_receipt": {"contract_version": 1, "run_id": "fixture-lost-query",
                    "execution_started": None, "cleanup": {"confirmed": False, "status": "NOT_COLLECTED"}}}
        stream = BytesIO()
        def dispatch_then_close(request, cancel_event=None):
            self.lease()
            self.service.helper = HelperProcess(handle=921, pid=self.helper_identity.pid)
            self.service._channel = PipeChannel(922)
            self.service._recovery_stream = stream
            self.service.journal.append(deepcopy(query))
            self.service._discard_helper(force=True)
            return deepcopy(query)
        with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                patch("blackbox_core.deep_ipc._kernel", return_value=kernel), \
                patch.object(self.service, "execute", side_effect=dispatch_then_close) as execute:
            answer = self.service.execute_owned(ActionRequest("threads", self.target), owner_run_id="run-A")
            ref = answer["native_context_ownership"]
            self.assertTrue(ref["cleanup_only"])
            self.assertTrue(self.service._native_owner_matches("run-A", ref))
            self.assertIsNone(ref["helper_identity"])
            self.assertEqual(ref["closed_context"]["helper_identity"], self.helper_identity.to_dict())
            before = deepcopy(self.service.journal.timeline()[0])
            refused = self.service.execute_owned(ActionRequest("threads", self.target),
                owner_run_id="run-A", expected_context=ref)
            self.assertEqual(refused["status"], "CONFIRMATION_REQUIRED")
            self.assertEqual(refused["next_action"], "RELEASE_CLOSED_NATIVE_CONTEXT_BEFORE_NEW_ACTION")
            execute.assert_called_once()
            released = self.service.release_native_context("run-A", expected_context=ref)
        self.assertTrue(released["cleanup"]["confirmed"])
        self.assertEqual(released["cleanup"]["scope"], "CHAIN_OWNED_NATIVE_CONTEXT")
        self.assertIsNone(self.service._native_context_owner)
        history = self.service.journal.timeline()
        self.assertEqual(next(row for row in history if row.get("operation_id") == "fixture-lost-query"), before)
        self.assertTrue(any(row.get("source") == "READ_ONLY_NATIVE_OWNER_CLEANUP_ACKNOWLEDGEMENT"
                            for row in history))
        self.assertEqual(answer["run_receipt"], query["run_receipt"])
        self.assertIsNone(answer["run_receipt"]["execution_started"])
        self.assertFalse(answer["run_receipt"]["cleanup"]["confirmed"])
        self.assertTrue(stream.closed)
        self.assertEqual([call.args for call in kernel.CloseHandle.call_args_list], [(922,), (921,)])

    def test_startup_primary_failure_survives_pipe_cleanup_failure_and_retains_actual_owner(self):
        primary = PermissionError("EXACT_HANDSHAKE_PRIMARY_FAILURE")
        pipe, helper = Mock(), Mock(pid=self.helper_identity.pid)
        pipe.name = "fixture-owned-pipe"
        pipe.accept.side_effect = primary
        pipe.close.side_effect = IPCError(5, "INJECTED_PIPE_CLOSE_DENIED")
        helper.alive.return_value = True
        helper.close_handle.return_value = {"confirmed": True, "scope": "EXPLICIT_FIXTURE_HANDLE_BOUNDARY"}
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch("blackbox_core.deep_service.PipeServer", return_value=pipe), \
                patch.object(self.service, "identity", return_value=self.target), \
                patch.object(self.service.broker, "launch", return_value=helper):
            try:
                with self.assertRaises(PermissionError) as caught:
                    self.service._start_session(self.target, ["threads"], elevated=False)
                self.assertIs(caught.exception, primary)
                self.assertIs(caught.exception.owner, self.service)
                self.assertTrue(caught.exception.cleanup_unconfirmed)
                self.assertTrue(any("INJECTED_PIPE_CLOSE_DENIED" in note
                                    for note in caught.exception.__notes__))
                self.assertIs(self.service.helper, helper)
                self.assertIs(self.service._channel, pipe)
                self.assertTrue(self.service._owner_retained)
                self.assertTrue(self.service._cleanup_unconfirmed)
                self.assertEqual(self.service._admin_state, "CLEANUP_REQUIRED")
            finally:
                # Explicit product retry closes its retained actual file stream;
                # the test never closes a product-owned resource on its behalf.
                pipe.close.side_effect = None
                pipe.close.return_value = {"confirmed": True, "scope": "EXPLICIT_FIXTURE_PIPE_BOUNDARY"}
                helper.alive.return_value = False
                self.service._discard_helper(force=True)
        self.assertIsNone(self.service.helper)
        self.assertIsNone(self.service._channel)
        self.assertIsNone(self.service._recovery_stream)
        helper.close_handle.assert_called_once()

    def test_fresh_closed_context_has_no_os_cleanup_ack_if_effects_or_close_proof_are_unknown(self):
        from io import BytesIO
        for effects, pipe_ack in ((True, True), (False, False)):
            with self.subTest(effects=effects, pipe_ack=pipe_ack):
                kernel = Mock()
                kernel.WaitForSingleObject.return_value = 0
                kernel.CloseHandle.return_value = True
                def dispatch_then_close(request, cancel_event=None):
                    self.lease()
                    self.service.helper = HelperProcess(handle=923, pid=self.helper_identity.pid)
                    channel = PipeChannel(924)
                    self.service._channel = channel
                    self.service._recovery_stream = BytesIO()
                    self.service._interventions_started = effects
                    if not pipe_ack:
                        # Boundary injection: a return without checked closure
                        # cannot produce a resource-release acknowledgement.
                        channel.close = lambda: None
                    self.service._discard_helper(force=True)
                    return {"status": "RECOVERY_UNCONFIRMED", "data": {}}
                with patch("blackbox_core.deep_elevation.C.WinDLL", return_value=kernel, create=True), \
                        patch("blackbox_core.deep_ipc._kernel", return_value=kernel), \
                        patch.object(self.service, "execute", side_effect=dispatch_then_close):
                    answer = self.service.execute_owned(ActionRequest("threads", self.target), owner_run_id="run-A")
                self.assertIsNone(answer["native_context_ownership"])
                self.assertIsNone(self.service._closed_native_cleanup)

    def test_new_target_in_borrowed_admin_lease_releases_only_owned_target_with_actual_ack(self):
        self.lease(target=False, managed=True)
        helper = self.service.helper
        def exchange(kind, **kwargs):
            if kind == "target.bind":
                return {"status": "COMPLETED", "data": {"target": self.target.to_dict(),
                    "operations": sorted({"threads", "capabilities"})}}
            return {"status": "COMPLETED", "data": {"target": None, "operations": [],
                "cleanup": {"status": "COMPLETED", "data": {"cleanup": {
                    "confirmed": True, "status": "CONFIRMED", "scope": "OWNED_DIAGNOSTIC_TARGET_CONTEXT"}}}}}
        with patch.object(self.service, "_managed_exchange", side_effect=exchange), \
                patch.object(self.service, "end_admin_session") as end:
            bound = self.service.bind_target_owned(self.target, ["threads"], owner_run_id="run-A", confirmed=True)
            reference = bound["native_context_ownership"]
            released = self.service.release_native_context("run-A", expected_context=reference)
        self.assertFalse(reference["owns_session"])
        self.assertTrue(released["cleanup"]["confirmed"])
        self.assertIs(self.service.helper, helper)
        self.assertIsNone(self.service._target)
        end.assert_not_called()

    def test_completed_without_explicit_context_cleanup_ack_stays_unconfirmed(self):
        reference = self.fresh_owned()["native_context_ownership"]
        def close():
            self.service.helper = None
            self.service._target, self.service._scope = None, frozenset()
            self.service._native_context_changed()
            return {"status": "COMPLETED", "data": {"active": False}}
        with patch.object(self.service, "end_admin_session", side_effect=close):
            answer = self.service.release_native_context("run-A", expected_context=reference)
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(answer["cleanup"]["confirmed"])
        refreshed = answer["native_context_ownership"]
        self.assertTrue(self.service._native_owner_matches("run-A", refreshed))
        self.assertEqual(refreshed["context_id"], reference["context_id"])
        self.assertIsNone(refreshed["helper_identity"])


if __name__ == "__main__":
    unittest.main()
