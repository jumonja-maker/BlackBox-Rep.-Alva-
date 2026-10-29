"""Inspection policies and lifetime refusal paths; execute only in hosted CI."""
from contextlib import contextmanager
import ctypes as C
import hashlib
import os
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from blackbox_core import deep_native as native
from blackbox_core import deep_native_win as W
from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_core.deep_native_dump import CALLBACK_INPUT, IO_CALLBACK
from blackbox_core.deep_native_stacks import (PSS_THREAD_ENTRY, _same_unwind_image,
                                             _snapshot_module_identity, _stack_positions, collect_stacks)


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

    def test_missing_thread_identity_is_not_reported_as_reuse(self):
        rows = [{"tid": 33, "created_100ns": None, "status": "INCOMPLETE_EVIDENCE"}]
        with patch.object(self.inspector, "_threads", return_value={"rows": rows}), \
                patch("blackbox_core.windows_research.wait_chain") as query:
            with self.assertRaises(native.NativeError) as incomplete:
                self.inspector._wait_chains({"tid": 33, "thread_created_100ns": 98}, None, None)
        self.assertEqual(incomplete.exception.status, "INCOMPLETE_EVIDENCE")
        query.assert_not_called()

    def test_selected_thread_missing_from_partial_inventory_is_not_reported_as_reuse(self):
        rows = [{"tid": 33, "created_100ns": 99, "status": "COMPLETED"}]
        for truncated, status in ((True, "INCOMPLETE_EVIDENCE"), (False, "PROCESS_CHANGED")):
            with self.subTest(truncated=truncated), \
                    patch.object(self.inspector, "_threads", return_value={"rows": rows, "truncated": truncated}), \
                    patch("blackbox_core.windows_research.wait_chain") as query:
                with self.assertRaises(native.NativeError) as missing:
                    self.inspector._wait_chains({"tid": 34, "thread_created_100ns": 100}, None, None)
            self.assertEqual(missing.exception.status, status)
            query.assert_not_called()

    def test_wait_chain_inventory_gap_keeps_unknown_omissions_explicit(self):
        with patch.object(self.inspector, "_threads", return_value={"rows": [], "truncated": True}), \
                patch.object(self.inspector, "_open", return_value=opened()):
            result = self.inspector._wait_chains({}, None, None)
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")
        self.assertFalse(result["thread_inventory_complete"])
        self.assertTrue(result["omitted_is_lower_bound"])
        self.assertIn("THREAD_ENUMERATION_INCOMPLETE_OMITTED_COUNT_IS_LOWER_BOUND", result["_limitations"])

    def test_failed_thread_enumeration_is_not_a_complete_empty_inventory(self):
        kernel = Mock()
        kernel.snapshot.return_value = 7
        kernel.thread_first.return_value = False
        with patch.object(C, "get_last_error", return_value=5, create=True):
            with self.assertRaises(native.NativeError) as denied:
                self.inspector._thread_rows(kernel, None, None, 8)
        self.assertEqual(denied.exception.status, "ACCESS_DENIED")
        kernel.close.assert_called_once_with(7)

    def test_partial_process_inventory_retains_access_failure(self):
        process = Mock(pid=9)
        with patch.object(native, "verify_identity"), \
                patch("psutil.process_iter", return_value=iter([process])), \
                patch.object(native, "capture_identity", side_effect=native.NativeError("ACCESS_DENIED", "DENIED", 5)):
            result = self.inspector._processes({}, None, None)
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")
        self.assertEqual(result["rows"][0]["status"], "ACCESS_DENIED")

    def test_windows_idle_pid_does_not_abort_real_process_inventory(self):
        processes = [Mock(pid=0), Mock(pid=9)]
        with patch.object(native, "verify_identity"), \
                patch("psutil.process_iter", return_value=iter(processes)), \
                patch.object(native, "capture_identity", side_effect=native.NativeError("ACCESS_DENIED", "DENIED", 5)) as capture:
            result = self.inspector._processes({}, None, None)
        self.assertEqual([row["pid"] for row in result["rows"]], [0, 9])
        self.assertIsNone(result["rows"][0]["identity"])
        self.assertEqual(result["rows"][0]["kind"], "SYSTEM_IDLE_PROCESS")
        self.assertEqual(result["_status"], "INCOMPLETE_EVIDENCE")
        capture.assert_called_once_with(9)

    def test_32_bit_helper_refused_before_using_64_bit_structures(self):
        with patch.object(native.os, "name", "nt"), patch.object(C, "sizeof", return_value=4):
            with self.assertRaises(native.NativeError) as unsupported:
                native._windows()
        self.assertEqual(unsupported.exception.status, "INCOMPLETE_EVIDENCE")
        self.assertEqual(unsupported.exception.reason, "WINDOWS_64_BIT_INSPECTOR_REQUIRED")

    def test_unwind_metadata_requires_snapshot_identity_not_only_path_or_size(self):
        captured = {"guid": "fixture-guid", "age": 1, "machine": 0x8664,
                    "image_size": 0x10000, "image_timestamp": 1234}
        self.assertTrue(_same_unwind_image(captured, dict(captured)))
        for field in captured:
            replacement = {**captured, field: "other"}
            with self.subTest(field=field):
                self.assertFalse(_same_unwind_image(captured, replacement))
        self.assertFalse(_same_unwind_image({**captured, "guid": None}, {**captured, "guid": None}))

    def test_frame_module_navigation_requires_same_snapshot_binding(self):
        module = {"base": 0x10000, "size": 0x4000, "name": "fixture.dll",
                  "path": "C:\\fixture.dll", "loaded_pe": {"guid": "old-guid", "age": 1}}
        self.assertIsNone(_snapshot_module_identity(module))
        module.update(snapshot_binding="PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH",
                      snapshot_pe={"guid": "captured-guid", "age": 2})
        identity = _snapshot_module_identity(module)
        self.assertEqual(identity["source"], "SAME_PSS_CAPTURE")
        self.assertEqual(identity["snapshot_pe"], {"guid": "captured-guid", "age": 2})
        module["snapshot_pe"]["guid"] = "later-module-guid"
        self.assertEqual(identity["snapshot_pe"]["guid"], "captured-guid")
        self.assertIsNone(_snapshot_module_identity(None))

    def test_stackwalk_initialization_repeat_does_not_hide_real_callers(self):
        initial, caller, entry = (0x1100, 0x8000), (0x2200, 0x8040), (0x3300, 0x8100)
        advance = Mock(side_effect=[initial, caller, entry, None])
        self.assertEqual(list(_stack_positions(initial, advance, 16)), [initial, caller, entry])
        self.assertEqual(advance.call_count, 4)

    def test_stackwalk_true_cycle_still_stops_and_failed_walk_keeps_context(self):
        initial, caller = (0x1100, 0x8000), (0x2200, 0x8040)
        advance = Mock(side_effect=[initial, caller, initial])
        self.assertEqual(list(_stack_positions(initial, advance, 16)), [initial, caller])
        self.assertEqual(advance.call_count, 3)
        self.assertEqual(list(_stack_positions(initial, Mock(return_value=None), 16)), [initial])
        limited = Mock(side_effect=[initial, caller, (0x3300, 0x8100)])
        self.assertEqual(list(_stack_positions(initial, limited, 2)), [initial, caller])
        self.assertEqual(limited.call_count, 2)

    def test_cancel_during_stack_preparation_never_starts_native_snapshot(self):
        cancelled = threading.Event()
        kernel, capture = Mock(), Mock()
        def modules(*_):
            cancelled.set()
            return {"rows": []}
        def machine(handle, process, native_machine):
            C.cast(native_machine, C.POINTER(W.U16))[0] = 0x8664
            return True
        kernel.wow64.side_effect = machine
        with patch.object(self.inspector, "_modules", side_effect=modules), \
                patch.object(self.inspector, "_open", return_value=opened(kernel)), \
                patch.object(W, "bind", return_value=capture):
            with self.assertRaises(native.NativeError) as stopped:
                collect_stacks(self.inspector, {}, None, cancelled)
        self.assertEqual(stopped.exception.status, "CANCELLED")
        capture.assert_not_called()

    def test_stack_symbol_preparation_obeys_action_deadline(self):
        module = {"base": 0x10000, "path": "fixture.exe"}
        def load(binary, pdb, *, cancel):
            cancel.is_set()
            self.fail("Expired stack operation must stop symbol preparation")
        with patch.object(self.inspector, "_modules", return_value={"rows": [module]}), \
                patch("blackbox_core.decoder_native_symbols.load_native_symbols", side_effect=load), \
                patch.object(self.inspector, "_open") as opened_target:
            with self.assertRaises(native.NativeError) as expired:
                collect_stacks(self.inspector, {"module_base": 0x10000, "pdb_path": "fixture.pdb"}, 0, None)
        self.assertEqual(expired.exception.status, "TIMED_OUT")
        opened_target.assert_not_called()

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

    def test_loaded_pe_debug_identity_read_from_target_bytes(self):
        base = 0x100000
        dos = bytearray(64)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 60, 128)
        pe = bytearray(512)
        pe[:4] = b"PE\0\0"
        struct.pack_into("<H", pe, 4, 0x8664)
        struct.pack_into("<I", pe, 8, 12345)
        struct.pack_into("<H", pe, 24, 0x20B)
        struct.pack_into("<I", pe, 80, 0x4000)
        struct.pack_into("<I", pe, 132, 16)
        struct.pack_into("<II", pe, 184, 0x2000, 28)
        directory = bytearray(28)
        struct.pack_into("<III", directory, 12, 2, 24, 0x3000)
        rsds = b"RSDS" + bytes.fromhex("00112233445566778899aabbccddeeff") + struct.pack("<I", 7)
        expected = {(base, 64): bytes(dos), (base + 128, 512): bytes(pe),
                    (base + 0x2000, 28): bytes(directory), (base + 0x3000, 24): rsds}
        with patch.object(self.inspector, "_read", side_effect=lambda k, h, a, n: (expected[(a, n)], True)):
            result = self.inspector._loaded_pe(None, 7, base)
        self.assertEqual(result["guid"], "33221100-5544-7766-8899-aabbccddeeff")
        self.assertEqual(result["age"], 7)
        self.assertEqual(result["image_size"], 0x4000)

    def test_loaded_pe_refuses_debug_directory_outside_image(self):
        base = 0x100000
        dos, pe = bytearray(64), bytearray(512)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 60, 128)
        pe[:4] = b"PE\0\0"
        struct.pack_into("<H", pe, 24, 0x20B)
        struct.pack_into("<I", pe, 80, 0x4000)
        struct.pack_into("<I", pe, 132, 16)
        struct.pack_into("<II", pe, 184, 0x5000, 28)
        with patch.object(self.inspector, "_read", side_effect=[(bytes(dos), True), (bytes(pe), True)]) as reader:
            result = self.inspector._loaded_pe(None, 7, base)
        self.assertIsNone(result)
        self.assertEqual(reader.call_count, 2)

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

