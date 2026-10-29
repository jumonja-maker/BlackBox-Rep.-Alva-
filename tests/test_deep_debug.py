"""Contract/ownership regression tests; executed only by GitHub-hosted CI."""
from __future__ import annotations

import ctypes
import queue
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_core.deep_debug import (
    DebugError, DebugSession, _Command, _Context, _DebugEvent, _WinAPI, _hex, _positive, _require_native_amd64,
)
from blackbox_core.deep_debug_guardian import encode_report, recover, validate_plan


class FakeKernel:
    def __init__(self):
        self.counts = {100: 2}
        self.closed = []
        self.before_suspend = None

    def SuspendThread(self, handle):
        if self.before_suspend:
            self.before_suspend()
        before = self.counts[handle]
        self.counts[handle] += 1
        return before

    def ResumeThread(self, handle):
        before = self.counts[handle]
        if before:
            self.counts[handle] -= 1
        return before

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


class FakeAPI:
    def __init__(self):
        self.identity = ProcessIdentity(88, 12345, "fixture.exe")
        self.memory = {0x1000: b"original", 0x2000: b"\x90"}
        self.k = FakeKernel()
        self.replacements = []
        self.alive = True
        self.before_replace = None
        self.protections = {0x2000: 0x20}
        self.debug_handle = None

    def verify(self):
        if not self.alive:
            raise DebugError("PROCESS_CHANGED", "FIXTURE_EXITED")

    def read(self, address, size):
        self.verify()
        value = self.memory[address]
        if len(value) != size:
            raise DebugError("INCOMPLETE_EVIDENCE", "SHORT_READ")
        return value

    def executable_address(self, address):
        return address == 0x2000

    def executable_protection(self, address):
        return self.protections[address]

    def restore_executable_protection(self, address, original):
        if self.protections[address] not in (original, 0x40):
            raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_PAGE_PROTECTION_CHANGED_EXTERNALLY")
        self.protections[address] = original

    def replace(self, address, expected, value, *, executable=False, original_protection=None):
        self.verify()
        if self.memory[address] != expected:
            raise DebugError("OPERATION_FAILED", "EXPECTED_BYTES_MISMATCH")
        if self.before_replace:
            self.before_replace()
        self.memory[address] = value
        self.replacements.append((address, expected, value, executable))
        if executable:
            self.restore_executable_protection(address, original_protection)

    def thread(self, tid, created=None, *, rights=0x0018):
        self.verify()
        if tid != 7 or created not in (None, 45678):
            raise DebugError("PROCESS_CHANGED", "THREAD_INSTANCE_CHANGED")
        return 100, 45678


class FakeGuardian:
    def __init__(self):
        self.pid = 999
        self.plans = []

    def update(self, plan):
        import copy
        validate_plan(plan)
        self.plans.append(copy.deepcopy(plan))

    def finish(self, *, clean):
        self.clean = clean


def session():
    result = DebugSession(ProcessIdentity(88, 12345, "fixture.exe"))
    result._api = FakeAPI()
    result._guard = FakeGuardian()
    return result


def plan(**updates):
    value = {"breakpoints": [], "changes": [], "suspensions": [], "stepping": None}
    value.update(updates)
    return value


class DeepDebugContracts(unittest.TestCase):
    def test_guardian_ack_cancellation_or_expiry_prevents_new_native_effects(self):
        cases = (
            ("memory.write", {"address": 0x1000, "expected_hex": b"original".hex(), "value_hex": b"modified".hex()}, "changes"),
            ("thread.suspend", {"tid": 7, "thread_created_100ns": 45678}, "suspensions"),
            ("debug.breakpoint.add", {"address": 0x2000}, "breakpoints"),
        )
        for operation, parameters, ledger in cases:
            for expired in (False, True):
                with self.subTest(operation=operation, expired=expired):
                    item = session()
                    if operation.startswith("debug."):
                        item._attached = True
                        item._event = _DebugEvent()
                        item._event.pid, item._event.tid = 88, 7
                    cancel = threading.Event()
                    command = _Command(operation, dict(parameters, _confirmed=True),
                                       time.monotonic() + 10, cancel, threading.Event())
                    acknowledge = item._guard.update
                    def ack(plan):
                        acknowledge(plan)
                        if plan[ledger]:
                            if expired:
                                command.deadline = 0
                            else:
                                cancel.set()
                    item._guard.update = ack
                    item._api.k.SuspendThread = Mock(wraps=item._api.k.SuspendThread)
                    item._check(command)
                    with self.assertRaises(DebugError) as caught:
                        item._dispatch(command)
                    self.assertEqual(caught.exception.status, "TIMED_OUT" if expired else "CANCELLED")
                    self.assertFalse(item._api.replacements)
                    item._api.k.SuspendThread.assert_not_called()
                    self.assertEqual(item._api.memory, {0x1000: b"original", 0x2000: b"\x90"})
                    self.assertFalse(item._guard.plans[-1][ledger])

    def test_unverified_int3_cleanup_retains_owner_until_rip_is_repaired(self):
        item = session()
        item._attached = True
        item._event = _DebugEvent()
        item._event.code, item._event.pid, item._event.tid = 1, 88, 7
        item._paused_breakpoint = "bp"
        item._breakpoints["bp"] = {"breakpoint_id": "bp", "address": 0x2000,
            "original_hex": "90", "installed": True, "enabled": True, "original_protection": 0x20,
            "hit_context": {"tid": 7, "created_100ns": 45678, "rip_before": 0x2001, "phase": "rewind_pending"}}
        item._api.memory[0x2000] = b"\xcc"
        item._api.context = Mock(side_effect=DebugError("ACCESS_DENIED", "CONTROLLED_CONTEXT_DENIAL", 5))
        item._api.k.ContinueDebugEvent = Mock(return_value=True)
        item._api.k.DebugActiveProcessStop = Mock(return_value=True)
        item._guard.finish = Mock()
        held = item._cleanup()
        self.assertEqual(held["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(held["data"]["owner_retained"])
        self.assertEqual(held["winerror"], 5)
        item._api.k.ContinueDebugEvent.assert_not_called()
        item._api.k.DebugActiveProcessStop.assert_not_called()
        item._guard.finish.assert_not_called()
        self.assertEqual(item.execute("memory.write", {})["error"], "UNRECOVERED_BREAKPOINT_CONTEXT_HELD")
        context = _Context()
        context.set64(248, 0x2001)
        item._api.context = Mock(return_value=context)
        item._api.set_context = Mock()
        completed = item._cleanup()
        self.assertEqual(completed["status"], "COMPLETED")
        self.assertEqual(context.get64(248), 0x2000)
        self.assertEqual(item._api.memory[0x2000], b"\x90")
        item._api.k.ContinueDebugEvent.assert_called_once()
        item._api.k.DebugActiveProcessStop.assert_called_once()
        self.assertFalse(item._owner_retained)

    def test_cleanup_never_resumes_after_failed_trap_byte_or_protection_restore(self):
        for failure in ("trap_flag", "code_byte", "page_protection", "guardian_shutdown"):
            with self.subTest(failure=failure):
                item = session()
                item._attached = True
                item._event = _DebugEvent()
                item._event.code, item._event.pid, item._event.tid = 1, 88, 7
                item._api.k.ContinueDebugEvent = Mock(return_value=True)
                item._api.k.DebugActiveProcessStop = Mock(return_value=True)
                item._guard.finish = Mock()
                denied = DebugError("ACCESS_DENIED", "CONTROLLED_RESTORE_FAILURE", 5)
                if failure == "trap_flag":
                    item._stepping = {"tid": 7, "created_100ns": 45678, "original_tf": False,
                                      "breakpoint_id": None, "pause_after": True}
                    item._api.context = Mock(side_effect=denied)
                else:
                    item._breakpoints["bp"] = {"breakpoint_id": "bp", "address": 0x2000,
                        "original_hex": "90", "installed": True, "enabled": True, "original_protection": 0x20}
                    if failure == "code_byte":
                        item._api.memory[0x2000] = b"\xcc"
                        item._api.replace = Mock(side_effect=denied)
                    elif failure == "page_protection":
                        item._api.restore_executable_protection = Mock(side_effect=denied)
                    else:
                        item._guard.update = Mock(side_effect=TimeoutError("NO_ACK"))
                        item._guard.abandon = Mock(side_effect=TimeoutError("STILL_RUNNING"))
                retained = item._cleanup()
                self.assertEqual(retained["status"], "RECOVERY_UNCONFIRMED")
                self.assertTrue(retained["data"]["owner_retained"])
                self.assertTrue(retained["data"]["retry_cleanup_required"])
                item._api.k.ContinueDebugEvent.assert_not_called()
                item._api.k.DebugActiveProcessStop.assert_not_called()
                item._guard.finish.assert_not_called()

    def test_cancellation_after_setting_trap_flag_restores_it_before_continuing(self):
        item = session()
        item._attached = True
        item._event = _DebugEvent()
        item._event.pid, item._event.tid = 88, 7
        context = _Context()
        context.set32(68, 0x202)
        item._api.context = Mock(return_value=context)
        cancel = threading.Event()
        item._api.set_context = Mock(side_effect=lambda handle, value: cancel.set())
        observed_flags = []
        def continue_event(*args):
            observed_flags.append(context.get32(68))
            return True
        item._api.k.ContinueDebugEvent = Mock(side_effect=continue_event)
        item._api.k.DebugActiveProcessStop = Mock(return_value=True)
        command = _Command("debug.step", {}, time.monotonic() + 10, cancel, threading.Event())
        with self.assertRaises(DebugError) as caught:
            item._continue(command, step=True)
        self.assertEqual(caught.exception.status, "CANCELLED")
        self.assertEqual(observed_flags, [0x202])
        self.assertIsNone(item._stepping)
        self.assertFalse(item._attached)

    def test_debug_owner_loop_stays_alive_after_retained_close_then_retries(self):
        item = session()
        api = item._api
        api.close = Mock()
        first = _Command("_close", {}, time.monotonic() + 10, None, threading.Event())
        retry = _Command("_close", {}, time.monotonic() + 10, None, threading.Event())
        item._queue.put(first)
        item._queue.put(retry)
        attempts = []
        def cleanup():
            attempts.append(True)
            self.assertFalse(item._stopping.is_set())
            api.close.assert_not_called()
            if len(attempts) == 1:
                return {"status": "RECOVERY_UNCONFIRMED", "data": {"owner_retained": True}}
            return {"status": "COMPLETED", "data": {"state": "DETACHED"}}
        item._cleanup = cleanup
        with patch("blackbox_core.deep_debug._WinAPI", return_value=api):
            item._run()
        self.assertTrue(first.done.is_set() and retry.done.is_set())
        self.assertEqual(first.result["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(retry.result["status"], "COMPLETED")
        api.close.assert_called_once()

    def test_background_int3_failure_retains_debug_thread_for_cleanup_request(self):
        item = session()
        api = item._api
        api.close = Mock()
        item._attached = True
        close = _Command("_close", {}, time.monotonic() + 10, None, threading.Event())
        item._queue.get = Mock(side_effect=[queue.Empty, close, queue.Empty])
        def failed_event(_):
            item._event = _DebugEvent()
            item._event.pid, item._event.tid = 88, 7
            item._paused_breakpoint = "bp"
            item._breakpoints["bp"] = {"breakpoint_id": "bp"}
            raise DebugError("ACCESS_DENIED", "GET_THREAD_CONTEXT", 5)
        item._pump = failed_event
        def cleanup():
            self.assertTrue(item._owner_retained)
            api.close.assert_not_called()
            item._attached = False
            return {"status": "COMPLETED", "data": {}}
        item._cleanup = cleanup
        with patch("blackbox_core.deep_debug._WinAPI", return_value=api):
            item._run()
        self.assertTrue(close.done.is_set())
        self.assertEqual(close.result["status"], "COMPLETED")
        api.close.assert_called_once()

    def test_suspend_failure_code_is_captured_before_handle_and_guardian_cleanup(self):
        item = session()
        observed = {"last_error": 0}
        def suspend(handle):
            observed["last_error"] = 5
            return 0xFFFFFFFF
        def fail(label):
            raise DebugError("ACCESS_DENIED", label, observed["last_error"])
        acknowledge = item._guard.update
        def ack(value):
            acknowledge(value)
            observed["last_error"] = 999
        item._guard.update = ack
        item._api.k.SuspendThread = suspend
        item._api.k.CloseHandle = lambda handle: observed.update(last_error=6)
        item._api.fail = fail
        with self.assertRaises(DebugError) as caught:
            item._suspend({"tid": 7, "thread_created_100ns": 45678})
        self.assertEqual(caught.exception.winerror, 5)
        self.assertEqual(observed["last_error"], 999)
        self.assertFalse(item._suspensions)

    def test_repeated_close_after_timeout_requires_actual_cleanup_acknowledgement(self):
        item = session()
        item._worker = Mock()
        completion = Mock()
        completion.wait.return_value = False
        completion.is_set.return_value = False
        with patch("blackbox_core.deep_debug.threading.Event", return_value=completion):
            first = item.close()
        self.assertEqual(first["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(first["data"]["owner_retained"])
        self.assertTrue(first["data"]["cleanup_acknowledgement_pending"])
        self.assertEqual(item.close(), first)
        self.assertEqual(item._queue.qsize(), 1)
        command = item._queue.get_nowait()
        # A result assignment alone is not the worker's publication barrier.
        command.result = {"status": "COMPLETED", "data": {"state": "DETACHED"}}
        self.assertEqual(item.close()["status"], "RECOVERY_UNCONFIRMED")
        completion.is_set.return_value = True
        self.assertEqual(item.close(), command.result)
        self.assertEqual(completion.wait.call_count, 1)

    def test_repeated_close_retains_acknowledged_failed_cleanup(self):
        item = session()
        item._closed = True
        completion = threading.Event()
        item._close_command = _Command("_close", {}, time.monotonic(), None, completion)
        item._close_command.result = {"status": "RECOVERY_UNCONFIRMED", "error": "OWNED_RESUME_NOT_CONFIRMED"}
        completion.set()
        self.assertEqual(item.close(), item._close_command.result)
        self.assertEqual(item.close()["status"], "RECOVERY_UNCONFIRMED")

    def test_wait_event_process_and_thread_handles_remain_system_owned(self):
        item = session()
        item._api.retain_debug_process_handle = Mock()
        item._api.k.ContinueDebugEvent = Mock(return_value=True)
        events = [(2, (400,)), (3, (401, 402, 403)), (6, (404,))]
        def wait(event_ref, milliseconds):
            code, handles = events.pop(0)
            event = event_ref._obj
            event.code, event.pid, event.tid = code, 88, 7
            raw = bytearray(160)
            for offset, handle in enumerate(handles):
                struct.pack_into("<Q", raw, offset * 8, handle)
            event.information[:] = raw
            return True
        item._api.k.WaitForDebugEvent = wait
        for _ in range(3):
            item._pump(1)
        # Windows retains 400/402/403 for later EXIT/detach cleanup. Closing
        # them here could later double-close a reused, unrelated HANDLE value.
        self.assertEqual(item._api.k.closed, [401, 404])
        item._api.retain_debug_process_handle.assert_called_once_with(402)
        self.assertIsNone(item._event)

    def test_debug_break_handle_is_an_independently_owned_duplicate(self):
        api = object.__new__(_WinAPI)
        api.k = FakeKernel()
        api.debug_handle = 901
        api.k.GetCurrentProcess = Mock(return_value=-1)
        def duplicate(source_process, source_handle, destination_process, destination, rights, inherit, options):
            self.assertEqual((source_process, source_handle, destination_process, rights, inherit, options),
                             (-1, 402, -1, 0, False, 2))
            destination._obj.value = 902
            return True
        api.k.DuplicateHandle = duplicate
        api.retain_debug_process_handle(402)
        self.assertEqual(api.debug_handle, 902)
        self.assertEqual(api.k.closed, [901])

    def test_cleanup_keeps_pending_event_and_native_error_when_continue_and_detach_fail(self):
        item = session()
        item._attached = True
        item._event = _DebugEvent()
        item._event.pid, item._event.tid = 88, 7
        item._api.k.ContinueDebugEvent = Mock(return_value=False)
        item._api.k.DebugActiveProcessStop = Mock(return_value=False)
        item._api.fail = Mock(side_effect=[
            DebugError("OPERATION_FAILED", "CONTINUE_BEFORE_DETACH_FAILED: controlled error", 6),
            DebugError("ACCESS_DENIED", "DEBUG_ACTIVE_PROCESS_STOP_FAILED: controlled error", 5)])
        result = item._cleanup()
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(result["winerror"], 6)
        self.assertEqual([failure["winerror"] for failure in result["data"]["native_cleanup_failures"]], [6, 5])
        self.assertTrue(item._attached)
        self.assertIsNotNone(item._event)

    def test_context_abi_requires_native_amd64_not_arm64_or_wow64(self):
        _require_native_amd64(0, 0x8664)
        for process, native in ((0, 0xAA64), (0x8664, 0xAA64), (0x014C, 0x8664), (0, 0)):
            with self.subTest(process=process, native=native), self.assertRaisesRegex(DebugError, "AMD64"):
                _require_native_amd64(process, native)

    def test_native_structures_have_x64_windows_layout_and_alignment(self):
        self.assertEqual(ctypes.sizeof(_DebugEvent), 176)
        context = _Context()
        self.assertEqual(context.address % 16, 0)
        context.set64(248, 0x123456789ABC)
        context.set32(68, 0x202)
        self.assertEqual(context.public()["rip"], 0x123456789ABC)
        self.assertEqual(context.public()["eflags"], 0x202)

    def test_memory_hex_parser_rejects_spaces_bools_and_oversized_input(self):
        for value in (None, True, "", "a", "aa bb", "GG", "aa" * 4097):
            with self.subTest(value=str(value)[:20]), self.assertRaises(DebugError):
                _hex(value, "expected")
        for value in (True, 0, -1, 1.1, "123"):
            with self.assertRaises(DebugError):
                _positive(value, "address")

    def test_mutation_requires_internal_confirmed_capability(self):
        item = session()
        command = _Command("memory.write", {"address": 0x1000, "expected_hex": b"original".hex(),
                                            "value_hex": b"modified".hex(), "confirmed": True},
                           time.monotonic() + 5, None, threading.Event())
        with self.assertRaisesRegex(DebugError, "EXPLICIT_CONFIRMATION_REQUIRED"):
            item._dispatch(command)
        self.assertEqual(item._api.memory[0x1000], b"original")
        self.assertFalse(item._changes)

    def test_cancellation_and_identity_are_checked_before_native_action(self):
        item = session()
        cancelled = threading.Event()
        cancelled.set()
        command = _Command("memory.write", {}, time.monotonic() + 5, cancelled, threading.Event())
        with self.assertRaisesRegex(DebugError, "CANCELLED_BEFORE"):
            item._check(command)
        command.cancel = None
        item._api.alive = False
        with self.assertRaisesRegex(DebugError, "FIXTURE_EXITED"):
            item._check(command)
        self.assertFalse(item._api.replacements)

    def test_memory_originals_never_enter_result_and_rollback_is_readback_verified(self):
        item = session()
        item._api.before_replace = lambda: self.assertEqual(
            item._guard.plans[-1]["changes"][0]["original_hex"], b"original".hex())
        output = item._write_memory({"address": 0x1000, "expected_hex": b"original".hex(),
                                     "value_hex": b"modified".hex()})
        self.assertEqual(output["status"], "COMPLETED")
        self.assertNotIn("original_hex", str(output))
        self.assertNotIn(b"original".hex(), str(output))
        identifier = output["data"]["change_id"]
        prepared = next(p for p in item._guard.plans if p["changes"])
        self.assertEqual(prepared["changes"][0]["original_hex"], b"original".hex())
        item._api.before_replace = None
        restored = item._rollback_memory({"change_id": identifier})
        self.assertTrue(restored["data"]["original_bytes_verified"])
        self.assertEqual(item._api.memory[0x1000], b"original")
        self.assertFalse(item._changes)

    def test_external_memory_mutation_refuses_restore_without_overwrite(self):
        item = session()
        output = item._write_memory({"address": 0x1000, "expected_hex": b"original".hex(),
                                     "value_hex": b"modified".hex()})
        item._api.memory[0x1000] = b"external"
        with self.assertRaisesRegex(DebugError, "EXPECTED_BYTES_MISMATCH"):
            item._rollback_memory({"change_id": output["data"]["change_id"]})
        self.assertEqual(item._api.memory[0x1000], b"external")
        self.assertEqual(len(item._changes), 1)

    def test_owned_suspend_resume_preserves_preexisting_suspend_counts(self):
        item = session()
        item._api.k.before_suspend = lambda: self.assertEqual(
            item._guard.plans[-1]["suspensions"][0]["phase"], "pending")
        output = item._suspend({"tid": 7, "thread_created_100ns": 45678})
        self.assertEqual(item._api.k.counts[100], 3)
        phases = [p["suspensions"][0]["phase"] for p in item._guard.plans if p["suspensions"]]
        self.assertEqual(phases, ["pending", "active"])
        restored = item._resume({"suspension_id": output["data"]["suspension_id"]})
        self.assertEqual(item._api.k.counts[100], 2)
        self.assertEqual(restored["data"]["owned_decrement"], 1)
        self.assertEqual(item._guard.plans[-2]["suspensions"][0]["phase"], "resuming")
        self.assertFalse(item._suspensions)
        with self.assertRaisesRegex(DebugError, "NO_OWNED_SUSPENSION"):
            item._resume({"tid": 7, "thread_created_100ns": 45678})
        self.assertEqual(item._api.k.counts[100], 2)

    def test_wrong_thread_lifetime_never_suspends_reused_tid(self):
        item = session()
        with self.assertRaisesRegex(DebugError, "THREAD_INSTANCE_CHANGED"):
            item._suspend({"tid": 7, "thread_created_100ns": 45679})
        self.assertEqual(item._api.k.counts[100], 2)
        self.assertFalse(item._suspensions)

    def test_original_int3_is_never_adopted_as_owned_breakpoint(self):
        item = session()
        item._attached = True
        item._event = Mock()
        item._api.memory[0x2000] = b"\xcc"
        with self.assertRaisesRegex(DebugError, "EXISTING_INT3_IS_NOT_OWNED"):
            item._add_breakpoint({"address": 0x2000})
        self.assertFalse(item._breakpoints)

    def test_breakpoint_protection_intent_precedes_native_page_change(self):
        item = session()
        item._attached = True
        item._event = Mock()
        item._api.before_replace = lambda: self.assertEqual(
            item._guard.plans[-1]["breakpoints"][0]["original_protection"], 0x20)
        result = item._add_breakpoint({"address": 0x2000})
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(item._api.protections[0x2000], 0x20)

    def test_uncertain_guardian_shutdown_never_duplicates_suspend_cleanup(self):
        item = session()
        item._suspensions["owned"] = {"tid": 7, "created_100ns": 45678,
                                      "handle": 100, "phase": "active", "previous_count": 2}
        item._api.k.counts[100] = 3
        item._guard.update = Mock(side_effect=TimeoutError("NO_ACK"))
        item._guard.abandon = Mock(side_effect=TimeoutError("STILL_RUNNING"))
        result = item._cleanup()
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(item._api.k.counts[100], 3)
        self.assertIn("owned", item._suspensions)

    def test_failed_kill_on_exit_setup_retains_unconfirmed_attachment_for_cleanup(self):
        item = session()
        item._api.ensure_rights = Mock()
        item._api.handle = 101
        item._api.k.CheckRemoteDebuggerPresent = Mock(return_value=True)
        item._api.k.DebugActiveProcess = Mock(return_value=True)
        item._api.k.DebugSetProcessKillOnExit = Mock(return_value=False)
        item._api.k.DebugActiveProcessStop = Mock(return_value=False)
        command = _Command("debug.attach", {}, time.monotonic() + 5, None, threading.Event())
        with self.assertRaisesRegex(DebugError, "KILL_ON_EXIT_CONFIGURATION_FAILED"):
            item._attach(command)
        self.assertTrue(item._attached)
        self.assertEqual(item.state, "RECOVERY_UNCONFIRMED")

    def test_breakpoint_context_failure_retains_pending_debug_event_and_blocks_continue(self):
        item = session()
        item._attached = True
        item._breakpoints["bp"] = {"breakpoint_id": "bp", "address": 0x2000,
                                    "original_hex": "90", "installed": True, "enabled": True,
                                    "original_protection": 0x20}
        item._api.memory[0x2000] = b"\xcc"
        def wait(event_ref, milliseconds):
            event = event_ref._obj
            event.code, event.pid, event.tid = 1, 88, 7
            raw = bytearray(160)
            struct.pack_into("<I", raw, 0, 0x80000003)
            struct.pack_into("<Q", raw, 16, 0x2000)
            struct.pack_into("<I", raw, 152, 1)
            event.information[:] = raw
            return True
        item._api.k.WaitForDebugEvent = wait
        item._api.context = Mock(side_effect=DebugError("ACCESS_DENIED", "CONTROLLED_CONTEXT_FAILURE"))
        with self.assertRaisesRegex(DebugError, "CONTROLLED_CONTEXT_FAILURE"):
            item._pump(1)
        self.assertIsNotNone(item._event)
        self.assertEqual(item._event.tid, 7)
        self.assertEqual(item._event_continue, 0x10002)
        self.assertEqual(item._breakpoints["bp"]["hit_context"]["phase"], "rewind_pending")
        command = _Command("debug.continue", {}, time.monotonic() + 5, None, threading.Event())
        with self.assertRaisesRegex(DebugError, "INSTRUCTION_POINTER_NOT_VERIFIED"):
            item._continue(command, step=False)


class DeepRecoveryContracts(unittest.TestCase):
    def test_oversize_recovery_report_stays_valid_json_and_never_claims_success(self):
        import json
        original = {"status": "COMPLETED", "reason": "HELPER_EXITED",
                    "target_identity": {"pid": 88, "created_100ns": 12345,
                                        "image_path": "Ж" * 32768}, "restored": {"memory_changes": 1}}
        encoded = encode_report(original)
        self.assertLessEqual(len(encoded), 32768)
        parsed = json.loads(encoded)
        self.assertEqual(parsed["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(parsed["details_truncated"])

    def test_immutable_identity_refuses_recovery_against_replaced_target(self):
        api = FakeAPI()
        api.alive = False
        result = recover(api, plan(), reason="HELPER_EXITED")
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(api.replacements)

    def test_prepared_memory_plan_without_effect_does_not_write(self):
        api = FakeAPI()
        result = recover(api, plan(changes=[{"address": 0x1000, "original_hex": b"original".hex(),
                                            "value_hex": b"modified".hex()}]), reason="HELPER_EXITED")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(api.replacements)

    def test_applied_memory_restores_only_exact_matching_replacement(self):
        api = FakeAPI()
        api.memory[0x1000] = b"modified"
        result = recover(api, plan(changes=[{"address": 0x1000, "original_hex": b"original".hex(),
                                            "value_hex": b"modified".hex()}]), reason="HELPER_EXITED")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(api.memory[0x1000], b"original")
        self.assertEqual(result["restored"]["memory_changes"], 1)
        self.assertNotIn("original_hex", str(result))

    def test_unknown_suspend_transition_never_decrements_someone_elses_count(self):
        for phase in ("pending", "resuming"):
            api = FakeAPI()
            result = recover(api, plan(suspensions=[{"tid": 7, "created_100ns": 45678,
                                                    "phase": phase}]), reason="HELPER_EXITED")
            self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
            self.assertEqual(api.k.counts[100], 2)

    def test_active_owned_suspend_recovery_decrements_exactly_once(self):
        api = FakeAPI()
        api.k.counts[100] = 3
        result = recover(api, plan(suspensions=[{"tid": 7, "created_100ns": 45678,
                                                "phase": "active", "previous_count": 2}]), reason="HELPER_EXITED")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(api.k.counts[100], 2)

    def test_breakpoint_byte_recovery_does_not_claim_instruction_pointer_recovery(self):
        api = FakeAPI()
        api.memory[0x2000] = b"\xcc"
        result = recover(api, plan(breakpoints=[{"address": 0x2000, "original_hex": "90",
                                               "original_protection": 0x20}]),
                         reason="HELPER_EXITED")
        self.assertEqual(api.memory[0x2000], b"\x90")
        self.assertEqual(result["restored"]["breakpoints"], 1)
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("BREAKPOINT_EXECUTION_CONTEXT_RECOVERY_NOT_ESTABLISHED", result["errors"])

    def test_guardian_restores_page_protection_when_crash_preceded_byte_write(self):
        api = FakeAPI()
        api.protections[0x2000] = 0x40
        result = recover(api, plan(breakpoints=[{"address": 0x2000, "original_hex": "90",
                                               "original_protection": 0x20}]), reason="HELPER_EXITED")
        self.assertEqual(api.protections[0x2000], 0x20)
        self.assertFalse(api.replacements)
        self.assertEqual(result["restored"]["breakpoints"], 1)

    def test_guardian_does_not_overwrite_external_protection_changes(self):
        api = FakeAPI()
        api.protections[0x2000] = 0x80
        result = recover(api, plan(breakpoints=[{"address": 0x2000, "original_hex": "90",
                                               "original_protection": 0x20}]), reason="HELPER_EXITED")
        self.assertEqual(api.protections[0x2000], 0x80)
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(result["restored"]["breakpoints"], 0)

    def test_guardian_rejects_breakpoint_without_protection_recovery_intent(self):
        with self.assertRaisesRegex(ValueError, "PROTECTION_INTENT"):
            validate_plan(plan(breakpoints=[{"address": 0x2000, "original_hex": "90"}]))

    def test_guardian_rejects_unbounded_or_extra_commands(self):
        with self.assertRaises(ValueError):
            validate_plan({**plan(), "shell": "anything"})
        with self.assertRaises(ValueError):
            validate_plan(plan(suspensions=[{}] * 129))
        with self.assertRaises((ValueError, DebugError)):
            validate_plan(plan(changes=[{"address": True, "original_hex": "00", "value_hex": "11"}]))


if __name__ == "__main__":
    unittest.main()
