"""Profiling consent, privileged staging and exact output verification.

Run exclusively in GitHub-hosted CI. These bounded tests do not manufacture
ETW evidence; the native acceptance job separately captures the C fixture.
"""
import ctypes as C
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from blackbox_core import deep_profiling as profiling
from blackbox_core import deep_native_win as W
from blackbox_core.deep_native import NativeError


class OutputHandle:
    """Only models file HANDLE read/write; never models ETW availability."""
    dll = None

    def __init__(self, *, corrupt=False, initial=b""):
        self.data = bytearray(initial)
        self.offset = 0
        self.corrupt = corrupt
        self.writes = 0

    def file_type(self, handle):
        return 1

    def file_size(self, handle, output):
        C.cast(output, C.POINTER(W.I64))[0] = len(self.data)
        return True

    def file_pointer(self, handle, offset, output, origin):
        self.offset = offset
        return True

    def write_file(self, handle, pointer, size, count, overlapped):
        self.data[self.offset:self.offset + size] = C.string_at(pointer, size)
        self.offset += size
        self.writes += 1
        C.cast(count, C.POINTER(W.U32))[0] = size
        return True

    def flush_file(self, handle):
        return True

    def read_file(self, handle, pointer, size, count, overlapped):
        block = bytes(self.data[self.offset:self.offset + size])
        if self.corrupt and block:
            block = bytes([block[0] ^ 1]) + block[1:]
        C.memmove(pointer, block, len(block))
        self.offset += len(block)
        C.cast(count, C.POINTER(W.U32))[0] = len(block)
        return True


class ProfilingPolicyTests(unittest.TestCase):
    def test_bounded_duration_and_exact_consent(self):
        for value in (True, 0, 31, 5.0, "5"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                profiling.validate_policy({"duration_seconds": value, "systemwide_confirmed": True})
        for consent in (None, False, 1, "yes"):
            with self.subTest(consent=consent), self.assertRaises(NativeError) as error:
                profiling.validate_policy({"systemwide_confirmed": consent})
            self.assertEqual(error.exception.status, "CONFIRMATION_REQUIRED")

    def test_profile_and_arbitrary_tool_or_output_path_rejected(self):
        for extra in ({"profile": "CPU.Verbose"}, {"profile": "GeneralProfile.Light"},
                      {"profile": "GeneralProfile.Light+arbitrary.wprp!X"}, {"profile": "-cancel"},
                      {"executable": "other.exe"}, {"destination": "C:\\privileged.etl"},
                      {"file_handle": 123}, {"argv": []}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                profiling.validate_policy({"systemwide_confirmed": True, **extra})

    def test_reserved_policy_cannot_use_generic_unprotected_owner(self):
        from blackbox_core.trace_owner import TraceSupervisor
        from blackbox_core.windows_research import WprCapture
        with tempfile.TemporaryDirectory() as directory, \
                patch("blackbox_core.windows_research.wpr_tool", return_value="system-wpr.exe"):
            owner = TraceSupervisor(directory, profile=profiling.PROFILE)
            with self.assertRaisesRegex(ValueError, "INVALID_WPR_PROFILE"):
                WprCapture(directory, profile=profiling.PROFILE)
            with self.assertRaisesRegex(ValueError, "REQUIRES_PROTECTED_OWNER"):
                owner.start()
            self.assertFalse(owner.path.exists())
            self.assertEqual(owner.data["policy"]["profile"], profiling.PROFILE)
            self.assertEqual(TraceSupervisor(directory).data["policy"]["profile"], "GeneralProfile.Light")
            self.assertEqual(WprCapture(directory).profiles, ("GeneralProfile.Light",))

    def test_embedded_policy_explicitly_collects_classic_network_and_bounded_file_io(self):
        root = ET.fromstring(profiling.PROFILE_XML)
        self.assertEqual(hashlib.sha256(profiling.PROFILE_XML).hexdigest(), profiling.PROFILE_SHA256)
        self.assertEqual(profiling.PROFILE, "BLACKBOX.Deep.Light")
        keywords = {item.attrib["Value"] for item in root.findall("./Profiles/SystemProvider/Keywords/Keyword")}
        self.assertTrue({"FileIO", "FileIOInit", "DiskIO", "DiskIOInit", "ProcessThread",
                         "Loader", "CSwitch", "ReadyThread", "SampledProfile"} <= keywords)
        custom = root.findall("./Profiles/SystemProvider/Keywords/CustomKeyword")
        self.assertEqual([int(item.attrib["Value"], 16) for item in custom], [0x10000])
        collector = root.find("./Profiles/SystemCollector")
        self.assertEqual(int(collector.find("BufferSize").attrib["Value"]) *
                         int(collector.find("Buffers").attrib["Value"]), 64 * 1024)
        self.assertEqual(root.find("./Profiles/Profile").attrib["LoggingMode"], "Memory")
        self.assertEqual([item.attrib["Value"] for item in root.findall("./Profiles/SystemProvider/Stacks/Stack")],
                         ["SampledProfile"])
        self.assertIsNotNone(profiling._FILE_NAME.fullmatch(profiling.PROFILE_FILENAME))
        self.assertIsNone(profiling._FILE_NAME.fullmatch("caller-profile.wprp"))

    def _copy(self, data, output, *, budget=None, cancel=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observed.etl"
            path.write_bytes(data)
            with patch.object(W, "bind", return_value=output.read_file), \
                    patch.object(profiling, "MAX_TRACE_BYTES", budget or profiling.MAX_TRACE_BYTES):
                return profiling._copy_verified(output, 17, path,
                                                deadline=time.monotonic() + 10, cancel_event=cancel)

    def test_completed_save_requires_identical_handle_readback(self):
        data = b"controlled-file-copy-not-etw" * 16384
        output = OutputHandle()
        metadata = self._copy(data, output)
        self.assertEqual(bytes(output.data), data)
        self.assertEqual(metadata["trace_bytes"], len(data))
        self.assertEqual(metadata["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(metadata["saved_verified"])

    def test_successful_write_with_corrupt_readback_is_not_verified(self):
        with self.assertRaises(NativeError) as error:
            self._copy(b"controlled bytes", OutputHandle(corrupt=True))
        self.assertEqual(error.exception.status, "INCOMPLETE_EVIDENCE")

    def test_nonempty_destination_is_never_overwritten(self):
        output = OutputHandle(initial=b"existing user data")
        with self.assertRaises(ValueError):
            self._copy(b"new data", output)
        self.assertEqual(bytes(output.data), b"existing user data")
        self.assertEqual(output.writes, 0)

    def test_oversized_capture_is_not_partially_copied(self):
        output = OutputHandle()
        with self.assertRaises(NativeError) as error:
            self._copy(b"0123456789", output, budget=9)
        self.assertEqual(error.exception.status, "LIMIT_REACHED")
        self.assertEqual(output.writes, 0)

    def test_cancelled_copy_has_no_success_metadata_or_write(self):
        stop = threading.Event()
        stop.set()
        output = OutputHandle()
        with self.assertRaises(NativeError) as error:
            self._copy(b"controlled bytes", output, cancel=stop)
        self.assertEqual(error.exception.status, "CANCELLED")
        self.assertEqual(output.writes, 0)


@unittest.skipUnless(os.name == "nt", "Actual Windows filesystem security required")
class ProtectedStagingTests(unittest.TestCase):
    def setUp(self):
        from blackbox_core.deep_ipc import token_is_elevated
        if not token_is_elevated():
            self.skipTest("Elevated hosted-runner token required for protected staging")

    def test_two_owners_validate_acl_and_pin_until_both_close(self):
        first = profiling.ProtectedStaging()
        second = None
        moved = first.path.with_name(first.path.name + "-renamed")
        try:
            second = profiling.ProtectedStaging(first.path)
            self.assertEqual(first.path, second.path)
            # Independent Win32 oracle: DELETE access must be denied by the
            # retained reader's sharing policy, not merely by Path behavior.
            C.set_last_error(0)
            deletion = first._create_file(str(first.path), 0x10000, 1 | 2 | 4,
                                          None, 3, 0x02000000 | 0x00200000, None)
            error = C.get_last_error()
            if deletion and deletion != W.INVALID_HANDLE:
                first.kernel.close(deletion)
            self.assertEqual(deletion, W.INVALID_HANDLE)
            self.assertEqual(error, 32)  # ERROR_SHARING_VIOLATION.
            with self.assertRaises(OSError):
                first.path.rename(moved)
            self.assertTrue(first.path.is_dir())
            self.assertFalse(moved.exists())
            first.close()
            with self.assertRaises(OSError):
                first.path.rename(moved)
            with self.assertRaises(OSError):
                first.path.rmdir()
            second.close()
            # Once both pins close, rename becomes possible. This proves the
            # preceding denial came from retained handles rather than an ACL
            # that prevents this elevated test from renaming its own fixture.
            first.path.rename(moved)
            self.assertFalse(first.path.exists())
            moved.rename(first.path)
            self.assertEqual(first.cleanup(), [])
            self.assertFalse(first.path.exists())
        finally:
            if second is not None:
                second.close()
            first.close()
            if moved.exists() and not first.path.exists():
                moved.rename(first.path)
            first.cleanup()

    def test_fixed_profile_materialized_only_in_protected_staging_and_hash_reported(self):
        stage = profiling.ProtectedStaging()
        try:
            capture = profiling._capture_factory(stage.path, profile=profiling.PROFILE)
            definition = stage.path / profiling.PROFILE_FILENAME
            self.assertEqual(definition.read_bytes(), profiling.PROFILE_XML)
            with patch.object(capture, "_run") as command:
                metadata = capture.start()
            capture.active = False  # _run was mocked; no native recording occurred.
            command.assert_called_once_with(["-start", str(definition) + "!" + profiling.PROFILE_SELECTOR])
            self.assertEqual(metadata["profile_sha256"], profiling.PROFILE_SHA256)
            self.assertEqual(metadata["profile_components"], [profiling.PROFILE])
            self.assertEqual(metadata["collector_buffer_bytes"], 64 * 1024**2)
        finally:
            self.assertEqual(stage.cleanup(), [])

    def test_profile_definition_cannot_be_replaced_or_loaded_from_foreign_folder(self):
        stage = profiling.ProtectedStaging()
        try:
            capture = profiling._capture_factory(stage.path, profile=profiling.PROFILE)
            with self.assertRaises(FileExistsError):
                profiling._capture_factory(stage.path, profile=profiling.PROFILE)
            (stage.path / profiling.PROFILE_FILENAME).write_bytes(b"caller changed XML")
            with patch.object(capture, "_run") as command, self.assertRaises(NativeError):
                capture.start()
            command.assert_not_called()
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                profiling._capture_factory(directory, profile=profiling.PROFILE)
        finally:
            self.assertEqual(stage.cleanup(), [])

    def test_unpinned_directory_replacement_must_revalidate_acl(self):
        original = profiling.ProtectedStaging()
        moved = original.path.with_name(original.path.name + "-original")
        marker = original.path / "caller-controlled.txt"
        try:
            original.close()
            original.path.rename(moved)
            original.path.mkdir()
            marker.write_text("caller-controlled replacement")
            # A same-name directory alone does not establish trusted staging.
            # The new owner's inherited ProgramData DACL must be rejected.
            with self.assertRaises(NativeError) as refusal:
                profiling.ProtectedStaging(original.path)
            self.assertEqual(refusal.exception.status, "ACCESS_DENIED")
            self.assertEqual(marker.read_text(), "caller-controlled replacement")
        finally:
            original.close()
            marker.unlink(missing_ok=True)
            if moved.exists():
                if original.path.exists():
                    original.path.rmdir()
                moved.rename(original.path)
            original.cleanup()

    def test_foreign_directory_is_refused_without_changing_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "keep.txt"
            marker.write_text("unchanged")
            with self.assertRaises(ValueError):
                profiling.ProtectedStaging(directory)
            self.assertEqual(marker.read_text(), "unchanged")
