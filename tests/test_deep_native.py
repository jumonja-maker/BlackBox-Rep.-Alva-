"""Inspection policies and lifetime refusal paths; execute only in hosted CI."""
from contextlib import contextmanager
import ctypes as C
import hashlib
import os
import threading
import time
import unittest
from unittest.mock import Mock, patch

from blackbox_core import deep_native as native
from blackbox_core import deep_native_win as W
from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_core.deep_native_dump import CALLBACK_INPUT, IO_CALLBACK
from blackbox_core.deep_native_stacks import PSS_THREAD_ENTRY


@contextmanager
def opened(kernel=None, handle=7):
    yield kernel, handle


class NativePolicyTests(unittest.TestCase):
    def setUp(self):
        self.identity = ProcessIdentity(123, 456, "C:\\fixture.exe")
        self.inspector = native.ProcessInspector(self.identity)

    def test_exact_process_creation_required(self):
        with patch.object(native, "capture_identity", return_value=ProcessIdentity(123, 457, "C:\\fixture.exe")):
            with self.assertRaises(native.NativeError) as caught:
                native.verify_identity(self.identity)
        self.assertEqual(caught.exception.status, "PROCESS_CHANGED")

    def test_process_image_replacement_refused(self):
        with patch.object(native, "capture_identity", return_value=ProcessIdentity(123, 456, "C:\\other.exe")):
            with self.assertRaises(native.NativeError):
                native.verify_identity(self.identity)

    def test_memory_bounds_before_native_call(self):
        kernel = Mock()
        for address, length in ((True, 8), (0, 8), (1, 0), (1, 65537), (2**64 - 1, 2)):
            with self.subTest(address=address, length=length), self.assertRaises(ValueError):
                native.ProcessInspector._read(kernel, 7, address, length)
        kernel.read_memory.assert_not_called()

    def test_partial_memory_preserves_only_observed_bytes(self):
        kernel = Mock()
        def read(_, address, buffer, length, count):
            self.assertEqual((address, length), (4096, 8))
            C.memmove(buffer, b"ABC", 3)
            C.cast(count, C.POINTER(W.SIZE))[0] = 3
            return False
        kernel.read_memory.side_effect = read
        with patch.object(self.inspector, "_open", return_value=opened(kernel)):
            result = self.inspector._memory_read({"address": 4096, "length": 8}, None, None)
        self.assertEqual(result["hex"], "414243")
        self.assertEqual(result["bytes_read"], 3)
        self.assertEqual(result["sha256"], hashlib.sha256(b"ABC").hexdigest())
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")
        self.assertFalse(result["automatic_share_allowed"])

    def test_cancel_and_deadline_are_distinct(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(native.NativeError) as cancelled:
            native._check(time.monotonic() + 60, event)
        self.assertEqual(cancelled.exception.status, "CANCELLED")
        with self.assertRaises(native.NativeError) as timeout:
            native._check(time.monotonic() - 1)
        self.assertEqual(timeout.exception.status, "TIMED_OUT")

    def test_handle_name_timeout_not_reported_complete(self):
        with patch.object(self.inspector, "_open", return_value=opened()), \
                patch("blackbox_core.deep_native_handles.handle_rows", return_value=([{"handle": 12}], 0)), \
                patch("blackbox_core.deep_native_handles.query_bounded", return_value={"name_status": "TIMED_OUT", "name": None}):
            result = self.inspector._handles({"name_limit": 1}, None, None)
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")

    def test_selected_thread_reuse_refused_before_wct(self):
        rows = [{"tid": 33, "created_100ns": 99, "status": "COMPLETED"}]
        with patch.object(self.inspector, "_threads", return_value={"rows": rows}), \
                patch("blackbox_core.windows_research.wait_chain") as query:
            with self.assertRaises(native.NativeError) as changed:
                self.inspector._wait_chains({"tid": 33, "thread_created_100ns": 98}, None, None)
        self.assertEqual(changed.exception.status, "PROCESS_CHANGED")
        query.assert_not_called()

    def test_memory_map_has_continuation_on_budget(self):
        kernel = Mock()
        def query(_, address, pointer, size):
            info = C.cast(pointer, C.POINTER(W.MEMORY_BASIC_INFORMATION)).contents
            info.base, info.region_size, info.state = address, 4096, 0x1000
            return C.sizeof(info)
        kernel.virtual_query.side_effect = query
        with patch.object(self.inspector, "_open", return_value=opened(kernel)):
            result = self.inspector._memory_map({"limit": 1, "start_address": 4096}, None, None)
        self.assertEqual(result["next_address"], 8192)
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")
        self.assertFalse(result["complete_address_space"])

    @unittest.skipIf(os.name == "nt", "Non-Windows absence of native APIs")
    def test_linux_never_simulates_windows_observation(self):
        for operation in ("modules", "threads", "handles", "memory_map", "thread_stacks", "network", "disk"):
            with self.subTest(operation=operation):
                result = self.inspector.execute(operation)
                self.assertEqual(result["status"], "UNSUPPORTED_PLATFORM")
                self.assertEqual(result["data"], {})


@unittest.skipUnless(C.sizeof(C.c_void_p) == 8, "Native x64 ABI")
class NativeAbiTests(unittest.TestCase):
    def test_x64_context_alignment_and_register_layout(self):
        storage, context = W.aligned_context()
        self.assertEqual(C.sizeof(W.CONTEXT64), 1232)
        self.assertEqual(C.addressof(context) % 16, 0)
        self.assertEqual(W.CONTEXT64.rip.offset, 248)
        self.assertEqual(W.CONTEXT64.rsp.offset, 152)
        self.assertIsNotNone(storage)

    def test_minidump_callbacks_use_sdk_pack4(self):
        self.assertEqual(IO_CALLBACK.offset.offset, 8)
        self.assertEqual(IO_CALLBACK.size.offset, 24)
        self.assertEqual(C.sizeof(IO_CALLBACK), 28)
        self.assertEqual(CALLBACK_INPUT.type.offset, 12)
        self.assertEqual(CALLBACK_INPUT.data.offset, 16)

    def test_pss_thread_entry_native_alignment(self):
        self.assertEqual(PSS_THREAD_ENTRY.context.offset, 112)
        self.assertEqual(C.sizeof(PSS_THREAD_ENTRY), 120)


if __name__ == "__main__":
    unittest.main()

