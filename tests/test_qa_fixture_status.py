"""Bounded QA status reads: real acknowledgement required, errors not hidden."""
import ctypes
import json
import os
from pathlib import Path
import tempfile
from threading import Thread
import time
import unittest
from unittest.mock import patch

from blackbox_core import qa_fixture_status as status


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def denied(code):
    error = PermissionError(13, "injected fixture open denial")
    error.winerror = code
    return error


class FixtureStatusTests(unittest.TestCase):
    def test_transient_native_denials_retry_and_require_matching_ack(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                clock = Clock()
                values = [denied(code), '{"ack":"older","error":null}',
                          '{"ack":"wanted","error":null,"cpu_enabled":1}']
                with patch.object(status, "monotonic", clock.monotonic), \
                        patch.object(status, "sleep", clock.sleep), \
                        patch.object(Path, "read_text", side_effect=values) as read:
                    result = status.wait_fixture_ack(Path("state.json"), "wanted")
                self.assertEqual(read.call_count, 3)
                self.assertEqual(result["cpu_enabled"], 1)
                self.assertIsNone(result["error"])
                self.assertAlmostEqual(clock.now, .04)

    def test_persistent_denial_fails_at_deadline_with_original_cause(self):
        clock = Clock()
        error = denied(5)
        with patch.object(status, "monotonic", clock.monotonic), \
                patch.object(status, "sleep", clock.sleep), \
                patch.object(Path, "read_text", side_effect=error) as read:
            with self.assertRaisesRegex(TimeoutError, "REAL_FIXTURE_COMMAND_TIMEOUT") as caught:
                status.wait_fixture_ack(Path("state.json"), "wanted", timeout=.1)
        self.assertIs(caught.exception.__cause__, error)
        self.assertAlmostEqual(clock.now, .1)
        self.assertLessEqual(read.call_count, 6)

    def test_unrelated_permission_error_is_not_retried(self):
        for error in (PermissionError(13, "POSIX denial"), denied(87)):
            with self.subTest(error=repr(error)), \
                    patch.object(status, "_IS_WINDOWS", False), \
                    patch.object(Path, "read_text", side_effect=error) as read, \
                    patch.object(status, "sleep") as sleep:
                with self.assertRaises(PermissionError):
                    status.wait_fixture_ack(Path("state.json"), "wanted")
                read.assert_called_once()
                sleep.assert_not_called()

    def test_windows_crt_errno_only_denial_retries_but_cannot_bypass_deadline(self):
        for transient in (True, False):
            with self.subTest(transient=transient):
                clock = Clock()
                error = PermissionError(13, "Windows CRT sharing denial")
                effects = ([error, '{"ack":"wanted","error":null}']
                           if transient else error)
                with patch.object(status, "_IS_WINDOWS", True), \
                        patch.object(status, "monotonic", clock.monotonic), \
                        patch.object(status, "sleep", clock.sleep), \
                        patch.object(Path, "read_text", side_effect=effects):
                    if transient:
                        result = status.wait_fixture_ack(Path("state.json"), "wanted", timeout=.1)
                        self.assertIsNone(result["error"])
                        self.assertAlmostEqual(clock.now, .02)
                    else:
                        with self.assertRaises(TimeoutError) as caught:
                            status.wait_fixture_ack(Path("state.json"), "wanted", timeout=.1)
                        self.assertIs(caught.exception.__cause__, error)
                        self.assertAlmostEqual(clock.now, .1)

    def test_invalid_json_or_non_object_is_not_retried(self):
        for text, exception in (("{", json.JSONDecodeError), ("[]", ValueError)):
            with self.subTest(text=text), \
                    patch.object(Path, "read_text", return_value=text) as read, \
                    patch.object(status, "sleep") as sleep:
                with self.assertRaises(exception):
                    status.wait_fixture_ack(Path("state.json"), "wanted")
                read.assert_called_once()
                sleep.assert_not_called()

    def test_missing_file_is_not_hidden(self):
        with patch.object(Path, "read_text", side_effect=FileNotFoundError), \
                patch.object(status, "sleep") as sleep:
            with self.assertRaises(FileNotFoundError):
                status.wait_fixture_ack(Path("state.json"), "wanted")
            sleep.assert_not_called()

    def test_stale_ack_expires_without_claiming_command_success(self):
        clock = Clock()
        with patch.object(status, "monotonic", clock.monotonic), \
                patch.object(status, "sleep", clock.sleep), \
                patch.object(Path, "read_text", return_value='{"ack":"old"}'):
            with self.assertRaises(TimeoutError):
                status.wait_fixture_ack(Path("state.json"), "wanted", timeout=.1)
        self.assertAlmostEqual(clock.now, .1)

    def test_matching_command_error_is_preserved_for_caller_assertion(self):
        text = '{"ack":"wanted","error":"UNSUPPORTED_QA_COMMAND"}'
        with patch.object(Path, "read_text", return_value=text):
            result = status.wait_fixture_ack(Path("state.json"), "wanted")
        self.assertEqual(result["error"], "UNSUPPORTED_QA_COMMAND")

    def test_invalid_wait_policy_is_rejected(self):
        for timeout in (0, -1, 31, float("nan"), float("inf"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                status.wait_fixture_ack(Path("state.json"), "wanted", timeout=timeout)
        with self.assertRaises(ValueError):
            status.wait_fixture_ack(Path("state.json"), "")

    @unittest.skipUnless(os.name == "nt", "Actual Windows share-denial fixture")
    def test_real_windows_exclusive_handle_is_retried_until_released(self):
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                      wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, wintypes.DWORD,
                                      wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "state.json"
            path.write_text('{"ack":"wanted","error":null}', encoding="utf-8")
            handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            released = False
            thread = None
            close_errors = []
            try:
                with self.assertRaises(PermissionError):
                    path.read_text(encoding="utf-8")

                def release():
                    nonlocal released
                    time.sleep(.1)
                    if kernel.CloseHandle(handle):
                        released = True
                    else:
                        close_errors.append(ctypes.get_last_error())

                thread = Thread(target=release, name="release-owned-fixture-handle")
                thread.start()
                result = status.wait_fixture_ack(path, "wanted")
                self.assertEqual(result, {"ack": "wanted", "error": None})
            finally:
                if thread is not None:
                    thread.join(5)
                if not released:
                    kernel.CloseHandle(handle)
            self.assertEqual(close_errors, [])



class FixtureReadyTests(unittest.TestCase):
    """Readiness is a verified real-process handoff, never file-exists alone."""

    @staticmethod
    def payload(**changes):
        row = {"fixture": "REAL_OS_QA_ONLY", "mode": "children",
               "pid": 4321, "created": 1234.5, "requested_count": 100}
        row.update(changes)
        return json.dumps(row)

    @staticmethod
    def read_ready(**kwargs):
        return status.wait_fixture_ready(
            Path("ready.json"), expected_pid=4321,
            expected_mode="children", expected_count=100,
            alive=lambda: True, timeout=.1, **kwargs)

    def test_native_windows_share_denials_recover_only_after_verified_payload(self):
        for code in (5, 32, 33):
            with self.subTest(code=code):
                clock = Clock()
                with patch.object(status, "_IS_WINDOWS", True), \
                        patch.object(status, "monotonic", clock.monotonic), \
                        patch.object(status, "sleep", clock.sleep), \
                        patch.object(Path, "read_text",
                                     side_effect=[denied(code), self.payload()]) as read:
                    result = self.read_ready()
                self.assertEqual(read.call_count, 2)
                self.assertEqual((result["pid"], result["requested_count"]), (4321, 100))
                self.assertAlmostEqual(clock.now, .02)

    def test_crt_errno_eacces_and_missing_file_are_only_transient(self):
        for transient in (PermissionError(13, "CRT denied"), FileNotFoundError()):
            with self.subTest(transient=type(transient).__name__):
                clock = Clock()
                with patch.object(status, "_IS_WINDOWS", True), \
                        patch.object(status, "monotonic", clock.monotonic), \
                        patch.object(status, "sleep", clock.sleep), \
                        patch.object(Path, "read_text",
                                     side_effect=[transient, self.payload()]):
                    result = self.read_ready()
                self.assertEqual(result["fixture"], "REAL_OS_QA_ONLY")
                self.assertAlmostEqual(clock.now, .02)

    def test_persistent_windows_denial_expires_preserving_original_error(self):
        clock = Clock()
        denied_open = denied(32)
        with patch.object(status, "_IS_WINDOWS", True), \
                patch.object(status, "monotonic", clock.monotonic), \
                patch.object(status, "sleep", clock.sleep), \
                patch.object(Path, "read_text", side_effect=denied_open) as read:
            with self.assertRaisesRegex(TimeoutError, "REAL_FIXTURE_READY_TIMEOUT") as caught:
                self.read_ready()
        self.assertIs(caught.exception.__cause__, denied_open)
        self.assertAlmostEqual(clock.now, .1)
        self.assertLessEqual(read.call_count, 6)

    def test_wrong_identity_or_malformed_ready_cannot_pass(self):
        for payload in (
            self.payload(pid=4322), self.payload(mode="threads"),
            self.payload(requested_count=99), self.payload(created="bad"),
            self.payload(fixture="SYNTHETIC"), "[]", "{",
        ):
            with self.subTest(payload=payload), \
                    patch.object(Path, "read_text", return_value=payload) as read, \
                    patch.object(status, "sleep") as sleep:
                with self.assertRaises(ValueError):
                    self.read_ready()
                read.assert_called_once()
                sleep.assert_not_called()

    def test_unrelated_error_and_worker_exit_cannot_pass(self):
        for is_windows, error in (
            (False, PermissionError(13, "POSIX denied")),
            (True, denied(87)),
        ):
            with self.subTest(windows=is_windows), \
                    patch.object(status, "_IS_WINDOWS", is_windows), \
                    patch.object(Path, "read_text", side_effect=error) as read, \
                    patch.object(status, "sleep") as sleep:
                with self.assertRaises(PermissionError):
                    self.read_ready()
                read.assert_called_once()
                sleep.assert_not_called()
        with patch.object(Path, "read_text") as read:
            with self.assertRaises(TimeoutError):
                status.wait_fixture_ready(
                    Path("ready.json"), expected_pid=4321,
                    expected_mode="children", expected_count=100,
                    alive=lambda: False, timeout=.1)
            read.assert_not_called()

    def test_ready_wait_policy_is_bounded(self):
        for timeout in (0, -1, 31, float("nan"), float("inf"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                status.wait_fixture_ready(
                    Path("ready.json"), expected_pid=4321,
                    expected_mode="children", expected_count=100,
                    alive=lambda: True, timeout=timeout)


if __name__ == "__main__":
    unittest.main()
