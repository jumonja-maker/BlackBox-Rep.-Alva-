"""Injected Win32 query-boundary checks, not evidence of Windows execution."""
from contextlib import ExitStack
import ctypes as C
import json
import unittest
from unittest.mock import Mock, patch

from blackbox_core import chain_qa_native as native


class CurrentTokenFactsTests(unittest.TestCase):
    def setUp(self):
        self.kernel, self.adv = Mock(), Mock()
        self.kernel.GetCurrentProcess.return_value = -1
        self.kernel.CloseHandle.return_value = True
        self.last_error = 0
        self.malformed = None
        self.elevation = 1
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(native, "require_hosted_windows"))
        self.stack.enter_context(patch.object(C, "WinDLL", side_effect=lambda name, **_:
            self.kernel if name == "kernel32" else self.adv, create=True))
        self.stack.enter_context(patch.object(C, "set_last_error", side_effect=self.set_error, create=True))
        self.stack.enter_context(patch.object(C, "get_last_error", side_effect=lambda: self.last_error, create=True))
        self.stack.enter_context(patch.object(native, "_PENDING_TOKEN_HANDLES", []))

        def open_token(_process, access, output):
            self.assertEqual(access, 8)
            C.cast(output, C.POINTER(C.c_void_p)).contents.value = 777
            return True

        self.adv.OpenProcessToken.side_effect = open_token
        self.adv.GetTokenInformation.side_effect = self.information
        self.adv.IsValidSid.return_value = True
        self.adv.GetLengthSid.side_effect = lambda pointer: 8 + 4 * C.c_ubyte.from_address(pointer + 1).value
        self.adv.LookupPrivilegeNameW.side_effect = self.lookup
        self.adv.IsTokenRestricted.return_value = False

        def membership(token, _sid, output):
            self.assertIsNone(token)
            C.cast(output, C.POINTER(C.c_int32)).contents.value = 0
            return True

        self.adv.CheckTokenMembership.side_effect = membership

    def set_error(self, value):
        self.last_error = value

    def information(self, _token, kind, buffer, _capacity, returned):
        sizes = {20: 4, 18: 4, 21: 4, 25: 32, 2: 48, 3: 16}
        C.cast(returned, C.POINTER(C.c_uint32)).contents.value = sizes[kind]
        if buffer is None:
            self.last_error = 122
            return False
        address = C.addressof(buffer)
        if kind in (20, 18, 21):
            C.c_uint32.from_buffer(buffer).value = {20: self.elevation, 18: 2, 21: 1}[kind]
        elif kind == 25:
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
        self.assertFalse(token["is_token_restricted"]["value"])
        self.assertTrue(facts["cleanup"]["confirmed"])
        self.assertNotIn("777", json.dumps(facts))
        self.assertNotIn("S-1-5-21-", json.dumps(facts))
        self.assertEqual(self.kernel.CloseHandle.call_count, 1)
        self.assertEqual(self.kernel.CloseHandle.call_args.args[0].value, 777)

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
