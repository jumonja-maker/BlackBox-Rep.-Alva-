"""Synthetic wire-format contracts, not evidence of native ETW decoding.

The real Windows native acceptance remains mandatory. These fixtures check that
compaction cannot change persisted observations or bypass import limits.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from blackbox_core import decoder_index as index
from blackbox_core import decoder_service as service
from blackbox_core.decoder_cpu import ETW_EVENT, ETW_PROVIDER, ETW_PROVIDER_GUID
from blackbox_core.decoder_profiles import SAMPLE_EVENT, SAMPLE_PROVIDER


SHA = "a" * 64
COMPACT = index.FRAME_MODULE_PER_EVENT
INLINE = index.FRAME_MODULE_INLINE
ABSENT = object()


def native_event(number=1, *, process_instance=2, load=0., unload=100., frames=8):
    module = dict(schema="blackbox.trace-module/1", source="TRACEEVENT_NATIVE_LOAD_WINDOW",
                  process_instance=process_instance, module_file_index=3,
                  image_base="0x140000000", image_size=65536, image_timestamp=123,
                  load_time_ms=load, unload_time_ms=unload,
                  pdb_guid=None, pdb_age=None, module_name="fixture.exe")
    return dict(type="event", ordinal=number, source_index=str(number), time_ms=float(number),
                source_ticks=str(number * 1000), utc_ticks="638000000000000000",
                cpu_sample=None, thread_schedule=None, io_observation=None,
                pid=42, tid=8, process_instance=process_instance,
                provider="SYNTHETIC_NATIVE_TRANSPORT_ONLY", provider_guid="00000000-0000-0000-0000-000000000000",
                event_id=1, version=0, name="fixture", opcode=0,
                activity_id="00000000-0000-0000-0000-000000000000",
                payload={"nullable": None, "custom": {"module_ref": 999, "frame_modules": "payload"}},
                payload_status="DECODED", raw_payload_bytes=0, bounded=False, errors=[], semantic=None,
                stack_status="RECORDED_ADDRESSES_OFFLINE_NAMES",
                frames=[dict(address=hex(0x140001000 + n), name="fixture!leaf" if n else "",
                             module_status="TRACE_NATIVE_MODULE_OBSERVED_UNVERIFIED",
                             module=deepcopy(module), rva=0x1000 + n, inline_note=None)
                        for n in range(frames)])


def compact_event(event):
    """Fixture encoder only; the actual C# writer is exercised by native CI."""
    row = deepcopy(event)
    table, identities = [], {}
    for frame in row["frames"]:
        if "module" not in frame or type(frame["module"]) is not dict:
            continue
        descriptor = frame["module"]
        key = json.dumps(descriptor, ensure_ascii=True, separators=(",", ":"))
        if key not in identities:
            identities[key] = len(table)
            table.append(descriptor)
        frame_copy = {("module_ref" if name == "module" else name):
                      (identities[key] if name == "module" else value)
                      for name, value in frame.items()}
        frame.clear()
        frame.update(frame_copy)
    row["frame_modules"] = table
    return row


class FrameModuleTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def stream(self, rows, name, *, encoding=COMPACT, footer=True):
        header = dict(type="header", protocol=index.PROTOCOL, input_sha256=SHA)
        if encoding is not ABSENT:
            header["frame_module_encoding"] = encoding
        records = [header, *rows]
        if footer:
            records.append(dict(type="footer", protocol=index.PROTOCOL,
                                rows=len(rows), status="DECODED", decoder_reported_lost_events=0))
        source = self.root / (name + ".jsonl")
        source.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in records),
                          encoding="utf-8")
        return source

    def build(self, rows, name, *, encoding=COMPACT):
        output = self.root / (name + ".sqlite3")
        meta = index.build_index(self.stream(rows, name, encoding=encoding), output,
                                 input_sha256=SHA, format_name=".etl")
        return output, meta

    def assert_rejected(self, row, name, *, encoding=COMPACT, reason=None):
        output = self.root / (name + ".sqlite3")
        with self.assertRaisesRegex(ValueError, reason or "."):
            index.build_index(self.stream([row], name, encoding=encoding), output,
                              input_sha256=SHA, format_name=".etl")
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob(".decoder-building-*")))

    @staticmethod
    def stored_events(path):
        with closing(sqlite3.connect(path)) as db:
            return list(db.execute("SELECT id,time_ms,pid,provider,name,has_stack,utc_time_ns,data "
                                   "FROM events ORDER BY id"))

    def test_compact_roundtrip_keeps_sql_text_api_nulls_and_catalog_identical(self):
        events = [native_event(1), native_event(2)]
        events[0].update(provider=SAMPLE_PROVIDER, name=SAMPLE_EVENT)
        events[1].update(provider=ETW_PROVIDER, name=ETW_EVENT,
                         provider_guid=ETW_PROVIDER_GUID, event_id=65535, opcode=46, version=1,
                         cpu_sample=dict(schema="blackbox.cpu-sample/1", source="ETW_KERNEL_PROFILE",
                                         parser="TRACEEVENT_SAMPLED_PROFILE",
                                         instruction_pointer="0x140001000", processor_index=0,
                                         executing_dpc=None, executing_isr=None))
        # An unavailable frame and explicit nullable/custom fields survive too.
        events[1]["frames"].append(dict(address="0x123", name="", module_status="UNKNOWN",
                                         module=None, rva=None, extra=None))
        compact = [compact_event(row) for row in events]
        before = deepcopy(compact)
        self.assertEqual(index._expand_native_frame_modules(compact[0], COMPACT), events[0])
        self.assertEqual(compact, before)
        inline_path, inline_meta = self.build(events, "legacy", encoding=ABSENT)
        compact_path, compact_meta = self.build(compact, "compact")
        explicit_path, _ = self.build(events, "explicit-inline", encoding=INLINE)
        self.assertEqual(self.stored_events(inline_path), self.stored_events(compact_path))
        self.assertEqual(self.stored_events(inline_path), self.stored_events(explicit_path))
        self.assertEqual(index.read_index(inline_path)["rows"], index.read_index(compact_path)["rows"])
        self.assertEqual(index.read_index(inline_path, mode="modules")["rows"],
                         index.read_index(compact_path, mode="modules")["rows"])
        self.assertEqual(index.read_index(inline_path, mode="cpu_stacks")["rows"],
                         index.read_index(compact_path, mode="cpu_stacks")["rows"])
        for key in ("rows", "status", "bounded_events", "events_with_errors", "native_modules",
                    "events_with_stacks", "profiles", "cpu_samples", "gc", "import_completeness"):
            self.assertEqual(inline_meta[key], compact_meta[key], key)
        self.assertEqual(compact_meta["profiles"]["cpu_profiler_samples_recorded"], 1)
        self.assertEqual(compact_meta["cpu_samples"]["etw_classification"]["ATTRIBUTION_UNKNOWN"], 1)
        self.assertEqual(compact, before)
        restored = index.read_index(compact_path)["rows"][0]["event"]
        self.assertNotIn("frame_modules", restored)
        self.assertNotIn("module_ref", restored["frames"][0])
        self.assertIsNone(restored["frames"][0]["module"]["pdb_guid"])
        self.assertIsNone(restored["frames"][0]["module"]["pdb_age"])
        for key in ("cpu_sample", "thread_schedule", "io_observation", "semantic"):
            self.assertIn(key, restored)
            self.assertIsNone(restored[key])
        self.assertEqual(restored["payload"]["custom"]["module_ref"], 999)
        self.assertEqual(restored["payload"]["custom"]["frame_modules"], "payload")

    def test_announced_compact_header_accepts_smaller_inline_fallback(self):
        row = native_event(frames=1)
        output, meta = self.build([row], "inline-fallback")
        baseline, _ = self.build([row], "inline-fallback-baseline", encoding=INLINE)
        self.assertEqual(self.stored_events(output), self.stored_events(baseline))
        self.assertEqual(meta["engine"]["frame_module_encoding"], COMPACT)

    def test_table_is_event_local_and_preserves_lifetime_and_process_identity(self):
        rows = [native_event(1, load=0., unload=1.5),
                native_event(2, load=1.5, unload=3.),
                native_event(3, process_instance=9, load=2.5, unload=10.)]
        output, meta = self.build([compact_event(row) for row in rows], "lifetimes")
        baseline, _ = self.build(rows, "lifetimes-baseline", encoding=INLINE)
        self.assertEqual(self.stored_events(output), self.stored_events(baseline))
        self.assertEqual(meta["native_modules"]["modules_observed_in_frames"], 3)
        # Reusing the preceding event's table cannot satisfy a later load window.
        stale = compact_event(rows[1])
        stale["ordinal"] = 1
        stale["frame_modules"] = compact_event(rows[0])["frame_modules"]
        self.assert_rejected(stale, "stale-window", reason="INVALID_TRACE_MODULE_FRAME")

    def test_distinct_descriptors_with_same_basename_are_not_collapsed(self):
        row = native_event(frames=4)
        for n, frame in enumerate(row["frames"][2:]):
            frame["module"]["module_file_index"] = 7
            frame["module"]["image_base"] = "0x180000000"
            frame["address"] = hex(0x180001000 + n)
            frame["rva"] = 0x1000 + n
        compact = compact_event(row)
        self.assertEqual(len(compact["frame_modules"]), 2)
        output, meta = self.build([compact], "same-basename")
        baseline, _ = self.build([row], "same-basename-baseline", encoding=INLINE)
        self.assertEqual(self.stored_events(output), self.stored_events(baseline))
        self.assertEqual(meta["native_modules"]["modules_observed_in_frames"], 2)

    def test_encoding_must_be_announced_and_known_even_for_empty_streams(self):
        for n, encoding in enumerate((ABSENT, INLINE, None, "PER_EVENT_MODULES_V2", 1, {}, [])):
            self.assert_rejected(compact_event(native_event()), f"encoding-{n}", encoding=encoding)
        source = self.stream([], "empty-unknown", encoding="future")
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_FRAME_MODULE_ENCODING"):
            index.build_index(source, self.root / "empty.sqlite3", input_sha256=SHA, format_name=".etl")
        self.assertFalse((self.root / "empty.sqlite3").exists())

    def test_invalid_reference_types_ranges_and_ambiguous_inline_are_rejected(self):
        for n, value in enumerate((True, False, -1, 1, 1.0, "0", None, [], {})):
            row = compact_event(native_event())
            row["frames"][0]["module_ref"] = value
            self.assert_rejected(row, f"reference-{n}", reason="INVALID_FRAME_MODULE_REFERENCE")
        row = compact_event(native_event())
        row["frames"][0]["module"] = None
        self.assert_rejected(row, "ambiguous-null", reason="INVALID_FRAME_MODULE_REFERENCE")
        row = compact_event(native_event())
        row.pop("frame_modules")
        self.assert_rejected(row, "missing-table", reason="MISSING_FRAME_MODULE_TABLE")
        row = compact_event(native_event())
        row["frames"][0].pop("address")
        self.assert_rejected(row, "missing-address", reason="INVALID_FRAME")

    def test_table_shape_unused_descriptors_and_exact_null_schema_are_rejected(self):
        for n, table in enumerate((None, {}, [], [None], ["module"], [dict()] * 129)):
            row = compact_event(native_event())
            row["frame_modules"] = table
            self.assert_rejected(row, f"table-{n}", reason="INVALID_FRAME_MODULE_TABLE")
        row = compact_event(native_event())
        row["frame_modules"].append(deepcopy(row["frame_modules"][0]))
        self.assert_rejected(row, "unused-descriptor", reason="UNUSED_FRAME_MODULE_DESCRIPTOR")
        for key in ("pdb_guid", "pdb_age", "load_time_ms", "process_instance"):
            row = compact_event(native_event())
            row["frame_modules"][0].pop(key)
            self.assert_rejected(row, "missing-" + key, reason="INVALID_TRACE_MODULE_FRAME")
        row = compact_event(native_event())
        row["frame_modules"][0]["pdb_guid"] = "12345678-1234-4321-8765-123456789abc"
        self.assert_rejected(row, "unpaired-null", reason="INCOMPLETE_TRACE_PDB_IDENTITY")
        row = compact_event(native_event())
        row["frame_modules"][0]["image_size"] = [1] * 100
        self.assert_rejected(row, "nested-descriptor", reason="INVALID_TRACE_MODULE_FRAME")

    def test_128_frames_are_preserved_and_129_are_rejected(self):
        row = native_event(frames=128)
        output, meta = self.build([compact_event(row)], "maximum-stack")
        self.assertEqual(len(index.read_index(output)["rows"][0]["event"]["frames"]), 128)
        self.assertEqual(meta["native_modules"]["frames_with_native_module"], 128)
        self.assert_rejected(compact_event(native_event(frames=129)), "oversized-stack",
                             reason="INVALID_FRAME_MODULE_TABLE")

    def test_references_cannot_bypass_expanded_event_byte_or_structure_limits(self):
        row = native_event(frames=128)
        row["payload"]["large"] = "x" * 225000
        compact = compact_event(row)
        self.assertLess(len(json.dumps(compact, separators=(",", ":")).encode("utf-8")), index.MAX_LINE)
        self.assertGreater(len(json.dumps(row, separators=(",", ":")).encode("utf-8")), index.MAX_LINE)
        self.assert_rejected(compact, "expanded-bytes", reason="EXPANDED_EVENT_OUTPUT_BUDGET")
        row = native_event(frames=128)
        row["payload"]["many"] = [None] * 18000
        self.assert_rejected(compact_event(row), "expanded-nodes", reason="JSON_STRUCTURE_BUDGET")

    def test_corrupt_tail_and_missing_footer_never_publish_compact_prefix(self):
        for suffix in ("", '{"unfinished":'):
            name = "missing-footer" if not suffix else "corrupt-tail"
            source = self.stream([compact_event(native_event())], name, footer=False)
            if suffix:
                with source.open("a", encoding="utf-8") as stream:
                    stream.write(suffix)
            output = self.root / (name + ".sqlite3")
            with self.assertRaises(ValueError):
                index.build_index(source, output, input_sha256=SHA, format_name=".etl")
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_service_adds_only_exact_explicit_inline_argv_and_retains_ownership(self):
        # Mock transport only: no native helper or OS process is launched here.
        source = self.root / "fixture.nettrace"
        source.write_bytes(b"SYNTHETIC_TRANSPORT_ONLY")
        helper = self.root / "decoder-tool"
        helper.write_bytes(b"NOT_EXECUTABLE_FIXTURE")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        for n, encoding in enumerate((None, COMPACT, INLINE)):
            seen = []
            owner = SimpleNamespace(process=SimpleNamespace(pid=123456789, returncode=0, poll=lambda: 0),
                                    close=Mock())

            def launch(command, **kwargs):
                seen.append(command)
                emitted_encoding = INLINE if command[-1] == "--inline-modules" else COMPACT
                records = [dict(type="header", protocol=index.PROTOCOL, input_sha256=digest,
                                frame_module_encoding=emitted_encoding),
                           dict(type="footer", protocol=index.PROTOCOL, rows=0, status="DECODED")]
                Path(command[2]).write_text("".join(json.dumps(row) + "\n" for row in records),
                                            encoding="utf-8")
                self.assertTrue(kwargs["detach_console"])
                return owner

            with self.subTest(encoding=encoding), patch.object(service, "helper_path", return_value=helper), \
                    patch("blackbox_core.optional_jobs.OwnedProcess", side_effect=launch), \
                    patch("psutil.Process"):
                meta = service.decode_file(source, self.root / f"service-{n}.sqlite3",
                                           native_module_encoding=encoding)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][0], str(helper))
            self.assertEqual(len(seen[0]), 4 if encoding == INLINE else 3)
            if encoding == INLINE:
                self.assertEqual(seen[0][-1], "--inline-modules")
            self.assertEqual(meta["engine"]["frame_module_encoding"], INLINE if encoding == INLINE else COMPACT)
            owner.close.assert_called_once_with(kill=True)

    def test_service_refuses_unknown_encoding_before_input_or_process_work(self):
        with patch("blackbox_core.optional_jobs.OwnedProcess") as owner:
            for value in ("future", "--inline-modules", 1, True, {}, []):
                with self.subTest(value=value), self.assertRaisesRegex(
                        ValueError, "UNSUPPORTED_FRAME_MODULE_ENCODING"):
                    service.decode_file(self.root / "absent.nettrace", self.root / "absent.sqlite3",
                                        native_module_encoding=value)
            owner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
