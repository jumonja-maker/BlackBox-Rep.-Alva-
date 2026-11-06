"""Injected Win32 query-boundary checks, not evidence of Windows execution."""
from contextlib import ExitStack
import ctypes as C
import json
import os
import unittest
from unittest.mock import Mock, patch

from blackbox_core import chain_qa_native as native


class CurrentTokenFactsTests(unittest.TestCase):
    def setUp(self):
        self.kernel, self.adv = Mock(), Mock()
        self.kernel.GetCurrentProcess.return_value = -1
        self.remote_pid = os.getpid() + 100000
        self.kernel.OpenProcess.return_value = 901
        self.kernel.GetProcessId.side_effect = lambda process: os.getpid() if process == -1 else self.remote_pid
        self.kernel.GetProcessTimes.side_effect = self.process_times
        self.kernel.CloseHandle.return_value = True
        self.last_error = 0
        self.malformed = None
        self.query_failure = None
        self.elevation = 1
        self.restrictions_bytes = 1
        self.elevation_bytes = 4
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(native, "require_hosted_windows"))
        self.stack.enter_context(patch.object(C, "WinDLL", side_effect=lambda name, **_:
            self.kernel if name == "kernel32" else self.adv, create=True))
        self.stack.enter_context(patch.object(C, "set_last_error", side_effect=self.set_error, create=True))
        self.stack.enter_context(patch.object(C, "get_last_error", side_effect=lambda: self.last_error, create=True))
        self.stack.enter_context(patch.object(native, "_PENDING_TOKEN_HANDLES", []))

        def open_token(_process, access, output):
            self.assertEqual(access, 8 if _process == -1 else 10)
            C.cast(output, C.POINTER(C.c_void_p)).contents.value = 777
            return True

        self.adv.OpenProcessToken.side_effect = open_token
        self.adv.GetTokenInformation.side_effect = self.information
        self.adv.IsValidSid.return_value = True
        self.adv.GetLengthSid.side_effect = lambda pointer: 8 + 4 * C.c_ubyte.from_address(pointer + 1).value
        self.adv.LookupPrivilegeNameW.side_effect = self.lookup
        self.adv.IsTokenRestricted.return_value = False

        def membership(token, _sid, output):
            self.assertTrue(token is None or token.value == 888)
            C.cast(output, C.POINTER(C.c_int32)).contents.value = 0
            return True

        self.adv.CheckTokenMembership.side_effect = membership
        def duplicate(_token, level, output):
            self.assertEqual(level, 1)  # SecurityIdentification: query-only, never installed.
            C.cast(output, C.POINTER(C.c_void_p)).contents.value = 888
            return True
        self.adv.DuplicateToken.side_effect = duplicate

    def process_times(self, _process, created, *_):
        C.cast(created, C.POINTER(C.c_uint32))[0] = 456
        C.cast(created, C.POINTER(C.c_uint32))[1] = 1
        return True

    def set_error(self, value):
        self.last_error = value

    def information(self, _token, kind, buffer, _capacity, returned):
        sizes = {20: self.elevation_bytes, 18: 4, 21: self.restrictions_bytes, 25: 32, 2: 48, 3: 16}
        C.cast(returned, C.POINTER(C.c_uint32)).contents.value = sizes[kind]
        stage = "SIZE" if buffer is None else "SCALAR" if kind in (20, 18, 21) else "QUERY"
        if self.query_failure == (kind, stage):
            C.cast(returned, C.POINTER(C.c_uint32)).contents.value = 7
            self.last_error = 5
            return False
        if buffer is None:
            self.last_error = 122
            return False
        if kind in (20, 18, 21):
            self.assertEqual(_capacity, 4)
            if kind == 21 and self.restrictions_bytes == 1:
                C.cast(buffer, C.POINTER(C.c_ubyte)).contents.value = 1
            else:
                C.cast(buffer, C.POINTER(C.c_uint32)).contents.value = {20: self.elevation, 18: 2, 21: 1}[kind]
            return True
        address = C.addressof(buffer)
        if kind == 25:
            C.c_void_p.from_buffer(buffer).value = 1 if self.malformed == "sid_pointer" else address + 16
            C.c_uint32.from_buffer(buffer, 8).value = 0x60
            sid = b"\x01\x01\0\0\0\0\0\x10" + (8192).to_bytes(4, "little")
            C.memmove(address + 16, sid, len(sid))
        elif kind == 2:
            C.c_uint32.from_buffer(buffer).value = 1000 if self.malformed == "group_array" else 1
            C.c_void_p.from_buffer(buffer, 8).value = address + 24
            C.c_uint32.from_buffer(buffer, 16).value = 0x10
            sid = b"\x01\x02\0\0\0\0\0\x05" + (32).to_bytes(4, "little") + (544).to_bytes(4, "little")
            C.memmove(address + 24, sid, len(sid))
        else:
            C.c_uint32.from_buffer(buffer).value = 1
            C.c_uint32.from_buffer(buffer, 4).value = 23
            C.c_uint32.from_buffer(buffer, 12).value = 2
        return True

    def lookup(self, _system, _luid, buffer, returned):
        text = "SeChangeNotifyPrivilege"
        C.cast(returned, C.POINTER(C.c_uint32)).contents.value = len(text)
        if buffer is None:
            self.last_error = 122
            return False
        buffer.value = text
        return True

    def test_medium_integrity_deny_only_group_does_not_override_raw_elevation(self):
        facts = native.actual_current_token_facts()
        token = facts["process_token"]
        self.assertTrue(token["elevated"])
        self.assertEqual(token["elevation_raw"], 1)
        self.assertEqual(token["integrity"]["sid"], "S-1-16-8192")
        self.assertEqual(token["administrators_group"], {
            "present": True, "attributes": 0x10, "enabled": False, "deny_only": True})
        self.assertFalse(facts["effective_administrators_member"])
        self.assertEqual(token["privileges"][0]["name"], "SeChangeNotifyPrivilege")
        self.assertTrue(token["privileges"][0]["enabled"])
        self.assertEqual(token["has_restrictions_raw"], 1)
        self.assertEqual(facts["query_returned_bytes"], {"20": 4, "18": 4, "21": 1})
        self.assertEqual(facts["process_identity"], {"pid": os.getpid(), "created_100ns": (1 << 32) | 456})
        self.assertFalse(token["is_token_restricted"]["value"])
        self.assertTrue(facts["cleanup"]["confirmed"])
        self.assertNotIn('"handle":', json.dumps(facts))
        self.assertNotIn('"token_handle":', json.dumps(facts))
        self.assertNotIn("S-1-5-21-", json.dumps(facts))
        self.assertEqual(self.kernel.CloseHandle.call_count, 1)
        self.assertEqual(self.kernel.CloseHandle.call_args.args[0].value, 777)
        scalar_calls = [call for call in self.adv.GetTokenInformation.call_args_list if call.args[1] in (20, 18, 21)]
        self.assertEqual(len(scalar_calls), 3)
        self.assertTrue(all(call.args[2] is not None and call.args[3] == 4 for call in scalar_calls))

    def test_only_restriction_boolean_accepts_one_or_four_bytes(self):
        self.restrictions_bytes = 4
        facts = native.actual_current_token_facts()
        self.assertEqual(facts["query_returned_bytes"]["21"], 4)
        self.assertEqual(facts["process_token"]["has_restrictions_raw"], 1)
        self.elevation_bytes = 1
        with self.assertRaisesRegex(AssertionError, "SCALAR_QUERY:20") as caught:
            native.actual_current_token_facts()
        self.assertEqual(caught.exception.token_query_diagnostic["returned_bytes"], 1)
        self.elevation_bytes = 4
        self.restrictions_bytes = 2
        with self.assertRaisesRegex(AssertionError, "SCALAR_QUERY:21"):
            native.actual_current_token_facts()

    def test_remote_exact_borrowed_process_uses_own_membership_duplicate_and_keeps_process_handle(self):
        facts = native.actual_process_token_facts(self.remote_pid, process_handle=987)
        self.assertEqual(facts["schema"], "blackbox.r60.process-token-facts/1")
        self.assertEqual(facts["process_identity"], {"pid": self.remote_pid, "created_100ns": (1 << 32) | 456})
        self.assertEqual(facts["effective_membership_scope"],
                         "REQUESTED_PROCESS_PRIMARY_TOKEN_DUPLICATED_FOR_MEMBERSHIP_QUERY")
        self.adv.DuplicateToken.assert_called_once()
        self.assertEqual(self.adv.CheckTokenMembership.call_args.args[0].value, 888)
        self.assertEqual([call.args[0].value for call in self.kernel.CloseHandle.call_args_list], [888, 777])
        self.kernel.OpenProcess.assert_not_called()

    def test_remote_pid_mismatch_refuses_query_and_never_closes_borrowed_process(self):
        self.kernel.GetProcessId.side_effect = None
        self.kernel.GetProcessId.return_value = self.remote_pid + 1
        with self.assertRaisesRegex(AssertionError, "PROCESS_HANDLE_PID_MISMATCH"):
            native.actual_process_token_facts(self.remote_pid, process_handle=987)
        self.adv.OpenProcessToken.assert_not_called()
        self.kernel.CloseHandle.assert_not_called()

    def test_remote_query_closes_only_the_process_handle_it_opened(self):
        native.actual_process_token_facts(self.remote_pid)
        self.kernel.OpenProcess.assert_called_once_with(0x1000, False, self.remote_pid)
        capabilities = [call.args[0] for call in self.kernel.CloseHandle.call_args_list]
        self.assertEqual([value.value if isinstance(value, C.c_void_p) else value for value in capabilities],
                         [888, 777, 901])

    def test_remote_membership_duplicate_close_failure_is_retained_with_primary_token_closed(self):
        self.kernel.CloseHandle.side_effect = lambda capability: capability.value != 888
        with self.assertRaisesRegex(OSError, "TOKEN_QUERY_CLOSE_UNCONFIRMED"):
            native.actual_process_token_facts(self.remote_pid, process_handle=987)
        self.assertEqual([call.args[0].value for call in self.kernel.CloseHandle.call_args_list], [888, 777])
        failures = native._PENDING_TOKEN_HANDLES[0][1]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][0], "membership_impersonation_token")
        self.assertEqual(failures[0][1].value, 888)

    def test_remote_native_api_failures_keep_actual_error_and_close_only_acquired_query_handles(self):
        for api, closed in (("OpenProcessToken", []), ("DuplicateToken", [777]),
                            ("CheckTokenMembership", [888, 777])):
            with self.subTest(api=api):
                self.kernel.CloseHandle.reset_mock()
                def fail(*_):
                    self.last_error = 5
                    return False
                with patch.object(self.adv, api, side_effect=fail):
                    with self.assertRaises(AssertionError) as caught:
                        native.actual_process_token_facts(self.remote_pid, process_handle=987)
                self.assertEqual(caught.exception.native_call_diagnostic,
                                 {"api": api, "return_bool": False, "get_last_error": 5})
                self.assertIn(":api=" + api + ":return=0:error=5", str(caught.exception))
                self.assertEqual([call.args[0].value for call in self.kernel.CloseHandle.call_args_list], closed)

    def test_actual_query_return_error_length_and_capacity_survive_each_failed_stage(self):
        for kind, stage, capacity in ((20, "SCALAR", 4), (25, "SIZE", 0), (25, "QUERY", 32)):
            with self.subTest(kind=kind, stage=stage):
                self.query_failure = (kind, stage)
                self.kernel.CloseHandle.reset_mock()
                with self.assertRaises(AssertionError) as caught:
                    native.actual_current_token_facts()
                self.assertEqual(caught.exception.token_query_diagnostic, {
                    "information_class": kind, "stage": stage, "return_bool": False,
                    "get_last_error": 5, "returned_bytes": 7, "capacity": capacity})
                self.assertIn(":return=0:error=5:needed=7:capacity=" + str(capacity), str(caught.exception))
                self.kernel.CloseHandle.assert_called_once()

    def test_malformed_native_sid_and_group_ranges_fail_before_unsafe_read(self):
        for malformed, reason in (("sid_pointer", "SID_POINTER_BOUNDS"), ("group_array", "GROUP_ARRAY_BOUNDS")):
            with self.subTest(malformed=malformed):
                self.malformed = malformed
                self.kernel.CloseHandle.reset_mock()
                with self.assertRaisesRegex(AssertionError, reason):
                    native.actual_current_token_facts()
                self.kernel.CloseHandle.assert_called_once()

    def test_failed_close_retains_exact_query_token_and_does_not_certify_cleanup(self):
        self.kernel.CloseHandle.return_value = False
        with self.assertRaisesRegex(OSError, "TOKEN_QUERY_CLOSE_UNCONFIRMED") as caught:
            native.actual_current_token_facts()
        self.assertTrue(caught.exception.cleanup_required)
        self.assertEqual(len(native._PENDING_TOKEN_HANDLES), 1)
        retained_kernel, failures = native._PENDING_TOKEN_HANDLES[0]
        self.assertIs(retained_kernel, self.kernel)
        self.assertEqual(failures[0][0], "current_query_token")
        self.assertEqual(failures[0][1].value, 777)

    def test_primary_parse_failure_survives_simultaneous_close_failure(self):
        self.malformed = "sid_pointer"
        self.kernel.CloseHandle.return_value = False
        with self.assertRaisesRegex(AssertionError, "SID_POINTER_BOUNDS") as caught:
            native.actual_current_token_facts()
        self.assertTrue(any("TOKEN_QUERY_CLOSE_UNCONFIRMED" in note for note in caught.exception.__notes__))
        self.assertEqual(len(native._PENDING_TOKEN_HANDLES), 1)


if __name__ == "__main__":
    unittest.main()
