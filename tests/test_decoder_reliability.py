"""Failure/cancellation contracts; synthetic inputs do not certify native ETW."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import tracemalloc
import unittest
from unittest.mock import patch

from blackbox_core import decoder_index as index
from blackbox_core.decoder_limits import DecodeBudget, failure_details
from blackbox_core.decoder_service import decode_file

SHA = "a" * 64


def event(number, **extra):
    return {"type": "event", "ordinal": number, "time_ms": float(number),
            "pid": 12, "tid": 13, "process_instance": 0, "provider": "SYNTHETIC",
            "name": "fixture", "payload": {}, "frames": [], "semantic": None, **extra}


class DecoderReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "index.sqlite3"

    def app_trace(self, count=10):
        path = self.root / "app.jsonl"
        with path.open("w", encoding="utf-8") as stream:
            for n in range(1, count + 1):
                stream.write(json.dumps({"schema_version": 1, "pid": 12, "tid": 13,
                    "seq": n, "source_clock": "SYNTHETIC", "source_ns": n * 1000000,
                    "kind": "fixture"}) + "\n")
        return path

    def stream(self, records, **footer):
        path = self.root / "decoded.jsonl"
        rows = [{"type": "header", "protocol": index.PROTOCOL, "input_sha256": SHA},
                *records, {"type": "footer", "protocol": index.PROTOCOL,
                           "rows": len(records), "status": "DECODED", **footer}]
        path.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
        return path

    def assert_clean(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_jsonl_deadline_includes_parsing_and_indexing(self):
        source = self.app_trace()
        real_check = DecodeBudget.check

        def expire_during_index(budget, phase=None):
            if phase == "PARSE":
                budget.deadline = 0
            return real_check(budget, phase)

        with patch.object(DecodeBudget, "check", expire_during_index):
            with self.assertRaisesRegex(TimeoutError, "DECODER_TIMEOUT"):
                decode_file(source, self.output, timeout=1)
        self.assert_clean()
        self.assertEqual(decode_file(source, self.output)["rows"], 10)

    def test_original_changed_during_index_is_rejected_before_publication(self):
        source = self.app_trace()
        finish = index.ProfileBuilder.finish

        def change_after_records(builder):
            result = finish(builder)
            source.write_text(source.read_text() + "\n", encoding="utf-8")
            return result

        with patch.object(index.ProfileBuilder, "finish", change_after_records):
            with self.assertRaisesRegex(ValueError, "ORIGINAL_INPUT_CHANGED_DURING_DECODE"):
                decode_file(source, self.output)
        self.assert_clean()

    def test_cancel_during_aggregation_keeps_destination_unpublished_and_retry_works(self):
        source = self.app_trace()
        cancel = Event()
        finish = index.ProfileBuilder.finish

        def request_cancel(builder):
            result = finish(builder)
            cancel.set()
            return result

        with patch.object(index.ProfileBuilder, "finish", request_cancel):
            with self.assertRaises(InterruptedError):
                decode_file(source, self.output, cancel=cancel)
        self.assert_clean()
        cancel.clear()
        self.assertEqual(decode_file(source, self.output, cancel=cancel)["rows"], 10)

    def test_last_small_batch_cannot_exceed_index_disk_budget(self):
        source = self.stream([event(1, payload={"large": "x" * 180000})])
        with patch.object(index, "MAX_INDEX_BYTES", 128 * 1024):
            with self.assertRaisesRegex(ValueError, "INDEX_DISK_BUDGET"):
                index.build_index(source, self.output, input_sha256=SHA, format_name=".etl")
        self.assert_clean()

    def test_existing_destination_created_at_publish_race_is_not_overwritten(self):
        source = self.stream([event(1)])
        with self.assertRaises(FileExistsError):
            index.build_index(source, self.output, input_sha256=SHA, format_name=".etl",
                              before_publish=lambda: self.output.write_bytes(b"other owner's file"))
        self.assertEqual(self.output.read_bytes(), b"other owner's file")
        self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_pending_gc_pair_memory_does_not_grow_with_unrelated_payload_size(self):
        tracemalloc.start()
        try:
            adapter = index.GCAdapter()
            for n in range(1000):
                adapter.accept(event(n + 1, payload={"noise": str(n) + "x" * 64000},
                    semantic={"kind": "gc_start", "runtime": 1, "number": n}))
            retained, _peak = tracemalloc.get_traced_memory()
            self.assertLess(retained, 4 * 1024**2)
            self.assertEqual(adapter.health()["open_gc_starts"], 1000)
            pair = adapter.accept(event(1001, semantic={"kind": "gc_stop", "runtime": 1, "number": 0}))
            self.assertEqual(pair[0]["duration_ms"], 1000)
        finally:
            tracemalloc.stop()

    def test_deeply_nested_record_is_a_bounded_input_error(self):
        source = self.root / "nested.jsonl"
        source.write_text('{"v":' + '[' * 1500 + '0' + ']' * 1500 + '}\n')
        with self.assertRaisesRegex(ValueError, "JSON_STRUCTURE_BUDGET"):
            list(index.lines(source))
        self.assert_clean()

    def test_corrupt_tail_rejects_entire_import_and_preserves_original(self):
        source = self.app_trace()
        source.write_bytes(source.read_bytes() + b'{"unfinished":')
        before = source.read_bytes()
        with self.assertRaisesRegex(ValueError, "PARTIAL_JSONL"):
            decode_file(source, self.output)
        self.assert_clean()
        self.assertEqual(source.read_bytes(), before)

    def test_loss_count_and_footer_row_type_cannot_invent_completeness(self):
        for footer in ({"decoder_reported_lost_events": -1}, {"rows": True}):
            source = self.stream([event(1)], **footer)
            with self.assertRaises(ValueError):
                index.build_index(source, self.output, input_sha256=SHA, format_name=".etl")
            self.assert_clean()
        source = self.stream([event(1)], decoder_reported_lost_events=7)
        result = index.build_index(source, self.output, input_sha256=SHA, format_name=".etl")
        self.assertEqual(result["decoder_reported_lost_events"], 7)
        self.assertIsNone(result["capture_complete"])

    def test_native_event_budget_fails_but_application_prefix_is_explicit(self):
        with patch.object(index, "MAX_EVENTS", 2):
            native = self.stream([event(1), event(2), event(3)])
            with self.assertRaisesRegex(ValueError, "DECODER_EVENT_BUDGET"):
                index.build_index(native, self.output, input_sha256=SHA, format_name=".etl")
            self.assert_clean()
            result = decode_file(self.app_trace(3), self.output)
        self.assertEqual(result["rows"], 2)
        self.assertEqual(result["status"], "TRUNCATED")
        self.assertEqual(result["import_completeness"], "BOUNDED_PREFIX")
        self.assertIsNone(result["capture_complete"])

    def test_saved_index_summary_and_event_shape_are_validated(self):
        decode_file(self.app_trace(), self.output)
        with closing(sqlite3.connect(self.output)) as db:
            db.execute("UPDATE metadata SET value='[]' WHERE key='summary'")
            db.commit()
        with self.assertRaisesRegex(ValueError, "INVALID_INDEX_JSON_OBJECT"):
            index.read_index(self.output)
        self.output.unlink()
        decode_file(self.app_trace(), self.output)
        with closing(sqlite3.connect(self.output)) as db:
            db.execute("UPDATE events SET data='{}' WHERE id=1")
            db.commit()
        with self.assertRaisesRegex(ValueError, "INVALID_EVENT_ID_OR_TIME"):
            index.read_index(self.output)

    def test_saved_index_metadata_view_is_rejected(self):
        decode_file(self.app_trace(), self.output)
        with closing(sqlite3.connect(self.output)) as db:
            db.execute("ALTER TABLE metadata RENAME TO stored_metadata")
            db.execute("CREATE VIEW metadata AS SELECT * FROM stored_metadata")
            db.commit()
        with self.assertRaisesRegex(ValueError, "INVALID_INDEX_TABLES"):
            index.read_index(self.output)

    def test_large_saved_page_is_bounded_before_fetching_every_record(self):
        source = self.stream([event(i, payload={"text": "x" * 20000}) for i in range(1, 21)])
        index.build_index(source, self.output, input_sha256=SHA, format_name=".etl")
        with patch.object(index, "MAX_PAGE_BYTES", 80000):
            page = index.read_index(self.output, limit=20)
            self.assertLess(page["page_limit_used"], 20)
            self.assertTrue(page["has_more"])
            ids = [row["index_id"] for row in page["rows"]]
            while page["has_more"]:
                page = index.read_index(self.output, limit=20, after=page["next_cursor"])
                ids.extend(row["index_id"] for row in page["rows"])
            self.assertEqual(ids, list(range(1, 21)))
            self.assertEqual(len(index.read_index(self.output, limit=1)["rows"]), 1)

    def test_saved_index_filter_columns_must_match_event_payload(self):
        decode_file(self.app_trace(), self.output)
        with closing(sqlite3.connect(self.output)) as db:
            db.execute("UPDATE events SET pid=999 WHERE id=1")
            db.commit()
        with self.assertRaisesRegex(ValueError, "INDEX_EVENT_METADATA_MISMATCH"):
            index.read_index(self.output, pid=999)

    def test_failure_guidance_never_claims_partial_resume(self):
        for error, state in [(InterruptedError("DECODER_CANCELLED"), "CANCELLED"),
                             (TimeoutError("DECODER_TIMEOUT"), "TIMED_OUT"),
                             (ValueError("INDEX_DISK_BUDGET"), "LIMIT_REACHED")]:
            result = failure_details(error)
            self.assertEqual(result["state"], state)
            self.assertTrue(result["retry_from_original"])
            self.assertFalse(result["partial_index_reused"])


if __name__ == "__main__":
    unittest.main()
