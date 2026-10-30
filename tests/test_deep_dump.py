"""Minidump format fixtures, not evidence of a real Windows capture."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from threading import Event
import time
import unittest
from uuid import UUID

from blackbox_core.deep_dump import inspect_dump, read_dump_memory


def dump_bytes(*, overlap=False, memory64=False, unused_streams=0):
    """One AMD64 saved thread/module and four deliberately recognizable bytes."""
    stream_count = 5 + unused_streams
    data = bytearray(32 + stream_count * 12)
    entries = []

    def append(value):
        offset = len(data); data.extend(value); return offset

    system = append(struct.pack("<H", 9) + b"\0" * 30)
    entries.append((7, 32, system))
    name = "C:\\private-user\\native-probe.exe".encode("utf-16-le")
    name_rva = append(struct.pack("<I", len(name)) + name)
    cv = b"RSDS" + UUID(int=1).bytes_le + struct.pack("<I", 1) + b"probe.pdb\0"
    cv_rva = append(cv)
    module = bytearray(108)
    struct.pack_into("<QIIII", module, 0, 0x140000000, 4096, 0, 1234567890, name_rva)
    struct.pack_into("<II", module, 76, len(cv), cv_rva)
    modules = append(struct.pack("<I", 1) + module)
    entries.append((4, 112, modules))
    stack_rva = append(b"SAVED!!!")
    context = bytearray(256)
    struct.pack_into("<I", context, 48, 0x100001)
    struct.pack_into("<Q", context, 248, 0x140000120)
    struct.pack_into("<Q", context, 152, 0x70000000)
    struct.pack_into("<Q", context, 160, 0x70000008)
    context_rva = append(context)
    thread = struct.pack("<IIIIQQIIII", 77, 0, 0x20, 8, 0x60000000,
                         0x70000000, 8, stack_rva, len(context), context_rva)
    threads = append(struct.pack("<I", 1) + thread)
    entries.append((3, 52, threads))
    if memory64:
        memory_data_rva = len(data) + 32
        memory = append(struct.pack("<QQQQ", 1, memory_data_rva, 0x1000, 4))
        append(b"\xde\xad\xbe\xef")
        entries.append((9, 32, memory))
    else:
        memory_data_rva = append(b"\xde\xad\xbe\xef")
        descriptor = struct.pack("<QII", 0x1000, 4, memory_data_rva)
        memory = append(struct.pack("<I", 2 if overlap else 1) + descriptor * (2 if overlap else 1))
        entries.append((5, 36 if overlap else 20, memory))
    misc = append(struct.pack("<6I", 24, 3, 4321, 1700000000, 1, 2))
    entries.append((15, 24, misc))
    entries.extend([(0, 0, 0)] * unused_streams)
    struct.pack_into("<6IQ", data, 0, 0x504D444D, 0xA793, len(entries), 32, 0, 1700000100, 0)
    for i, entry in enumerate(entries):
        struct.pack_into("<III", data, 32 + 12 * i, *entry)
    return data


class DeepDumpInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "probe.dmp"

    def fixture(self, **kwargs):
        self.path.write_bytes(dump_bytes(**kwargs))
        return self.path

    def test_metadata_has_saved_context_modules_ranges_but_no_memory(self):
        path = self.fixture()
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        result = inspect_dump(path)
        data = result["data"]
        self.assertEqual(data["architecture"], "AMD64")
        self.assertEqual(data["modules"][0]["name"], "native-probe.exe")
        self.assertEqual(data["modules"][0]["pdb_identity"]["guid"], str(UUID(int=1)))
        self.assertEqual(data["threads"][0]["context"]["rip"], 0x140000120)
        self.assertEqual(data["threads"][0]["instruction_module"]["rva"], 0x120)
        self.assertEqual(data["memory_ranges"], [{"address": 0x1000, "size": 4}])
        self.assertEqual(data["recorded_pid"], 4321)
        self.assertEqual(data["recorded_creation_unix_seconds"], 1700000000)
        self.assertEqual(data["live_process_binding"], "NOT_ESTABLISHED")
        self.assertFalse(data["memory_contents_included"])
        self.assertNotIn("private-user", json.dumps(result))
        self.assertNotIn("deadbeef", json.dumps(result))
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_explicit_private_read_returns_only_requested_bytes(self):
        result = read_dump_memory(self.fixture(), 0x1001, 2)
        self.assertEqual(result["data"]["value_hex"], "adbe")
        self.assertEqual(result["data"]["privacy"], "SENSITIVE_MEMORY_DO_NOT_INCLUDE_IN_NORMAL_SHARE")

    def test_memory64_list_uses_file_offsets_not_virtual_addresses(self):
        path = self.fixture(memory64=True)
        self.assertEqual(read_dump_memory(path, 0x1000, 4)["data"]["value_hex"], "deadbeef")
        self.assertEqual(inspect_dump(path)["data"]["memory_ranges"][0]["address"], 0x1000)

    def test_ambiguous_overlap_refuses_arbitrary_first_match(self):
        with self.assertRaisesRegex(ValueError, "AMBIGUOUS"):
            read_dump_memory(self.fixture(overlap=True), 0x1000, 4)

    def test_read_does_not_join_missing_bytes_across_range(self):
        with self.assertRaisesRegex(ValueError, "CROSSES_RANGE"):
            read_dump_memory(self.fixture(), 0x1002, 4)

    def test_missing_memory_and_invalid_request_fail(self):
        p = self.fixture()
        with self.assertRaises(ValueError):
            read_dump_memory(p, 0x9999, 1)
        for address, size in ((True, 4), (-1, 4), (0x1000, 0), (0x1000, 4097), (2**64 - 2, 4)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                read_dump_memory(p, address, size)

    def test_truncated_header_and_directory_rejected(self):
        for value in (b"MDMP", dump_bytes()[:50]):
            self.path.write_bytes(value)
            with self.assertRaises(ValueError):
                inspect_dump(self.path)

    def test_duplicate_stream_and_out_of_bounds_rva_rejected(self):
        value = dump_bytes()
        struct.pack_into("<I", value, 32 + 12, 7)
        self.path.write_bytes(value)
        with self.assertRaisesRegex(ValueError, "DUPLICATE"):
            inspect_dump(self.path)
        value = dump_bytes()
        struct.pack_into("<I", value, 32 + 8, len(value) + 1)
        self.path.write_bytes(value)
        with self.assertRaisesRegex(ValueError, "OUTSIDE"):
            inspect_dump(self.path)

    def test_real_dbghelp_unused_directory_slots_are_not_duplicate_streams(self):
        path = self.fixture(memory64=True, unused_streams=4)
        metadata = inspect_dump(path)["data"]
        self.assertEqual(metadata["header"]["unused_stream_slots"], 4)
        self.assertEqual(metadata["header"]["stream_count"], 9)
        self.assertEqual(read_dump_memory(path, 0x1000, 4)["data"]["value_hex"], "deadbeef")

    def test_unused_slot_cannot_hide_nonempty_data(self):
        value = dump_bytes(unused_streams=1)
        struct.pack_into("<III", value, 32 + 5 * 12, 0, 1, 0)
        self.path.write_bytes(value)
        with self.assertRaisesRegex(ValueError, "NONEMPTY_UNUSED"):
            inspect_dump(self.path)

    def test_bad_signature_and_list_count_fail_without_allocation(self):
        value = dump_bytes(); value[:4] = b"BAD!"
        self.path.write_bytes(value)
        with self.assertRaisesRegex(ValueError, "HEADER"):
            inspect_dump(self.path)
        value = dump_bytes()
        module_rva, = struct.unpack_from("<I", value, 32 + 12 + 8)
        struct.pack_into("<I", value, module_rva, 0xFFFFFFFF)
        self.path.write_bytes(value)
        with self.assertRaisesRegex(ValueError, "LIST_LENGTH"):
            inspect_dump(self.path)

    def test_cancel_deadline_and_size_budget(self):
        p = self.fixture()
        cancel = Event(); cancel.set()
        with self.assertRaises(InterruptedError):
            inspect_dump(p, cancel_event=cancel)
        with self.assertRaises(TimeoutError):
            inspect_dump(p, deadline=time.monotonic() - 1)
        with self.assertRaises(ValueError):
            inspect_dump(p, max_bytes=64)

    def test_symlink_is_not_followed(self):
        p = self.fixture()
        link = self.root / "link.dmp"
        try:
            link.symlink_to(p)
        except OSError:
            self.skipTest("Symlink creation unavailable to this runner token")
        with self.assertRaisesRegex(ValueError, "UNSAFE"):
            inspect_dump(link)
