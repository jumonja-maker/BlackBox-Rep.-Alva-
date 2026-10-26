"""Decoder contracts; synthetic rows are NOT proof of native trace decoding."""
import json
from pathlib import Path
import tempfile
from threading import Event
import unittest

from blackbox_core.decoder_index import (GCAdapter, PROTOCOL, build_index, read_index,
                                         own_events, lines)

HASH = "a" * 64


def event(n, kind=None, stamp=None, **semantic):
    return {"type": "event", "ordinal": n, "time_ms": n if stamp is None else stamp,
            "pid": 123, "tid": 7, "process_instance": 1, "provider": "SYNTHETIC_ONLY",
            "name": kind or "test", "payload": {}, "frames": [],
            "semantic": {"kind": kind, "runtime": 1, "number": 5, **semantic} if kind else None}


class DecoderIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def stream(self, events, footer=True, **summary):
        rows = [{"type": "header", "protocol": PROTOCOL, "input_sha256": HASH}, *events]
        if footer:
            rows.append({"type": "footer", "protocol": PROTOCOL, "rows": len(events),
                         "status": "DECODED", **summary})
        path = self.root / "events.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def build(self, events, **kwargs):
        path = self.stream(events, **kwargs)
        output = self.root / "trace.sqlite3"
        meta = build_index(path, output, input_sha256=HASH, format_name=".nettrace")
        return output, meta

    def test_full_index_not_500_row_preview_and_keyset_page(self):
        path, meta = self.build([event(i) for i in range(1, 602)])
        self.assertEqual(meta["rows"], 601)
        ids = []
        cursor = 0
        while True:
            page = read_index(path, after=cursor)
            ids.extend(row["index_id"] for row in page["rows"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        self.assertEqual(ids, list(range(1, 602)))
        self.assertIsNone(meta["loss"])
        self.assertIsNone(meta["capture_complete"])
        self.assertEqual(meta["verification_class"], "UNVERIFIED_IMPORT")

    def test_missing_footer_does_not_publish_partial_index(self):
        src = self.stream([event(1)], footer=False)
        out = self.root / "trace.sqlite3"
        with self.assertRaisesRegex(ValueError, "FOOTER"):
            build_index(src, out, input_sha256=HASH, format_name=".etl")
        self.assertFalse(out.exists())
        self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_gc_elapsed_not_mislabelled_pause(self):
        path, meta = self.build([event(1, "gc_start", stamp=1), event(2, "gc_stop", stamp=20)])
        rows = read_index(path, mode="gc")["rows"]
        self.assertEqual(rows[0]["event"]["duration_ms"], 19)
        self.assertEqual(rows[0]["event"]["kind"], "GC_ELAPSED_NOT_PAUSE")
        self.assertFalse(meta["gc"]["gc_elapsed_is_pause"])

    def test_gc_does_not_pair_across_process_instances_or_clr_instances(self):
        a = event(1, "gc_start")
        b = event(2, "gc_stop")
        b["process_instance"] = 2
        c = event(3, "gc_stop", runtime=2)
        _, meta = self.build([a, b, c])
        self.assertEqual(meta["gc"]["gc_pairs"], 0)
        self.assertEqual(meta["gc"]["open_gc_starts"], 1)
        self.assertEqual(meta["gc"]["unmatched_or_ambiguous"], 2)

    def test_duplicate_gc_start_is_ambiguous(self):
        _, meta = self.build([event(1, "gc_start"), event(2, "gc_start"), event(3, "gc_stop")])
        self.assertEqual(meta["gc"]["gc_pairs"], 0)

    def test_suspension_envelope_and_fully_suspended_are_distinct(self):
        path, _ = self.build([event(1, "suspend_begin", stamp=1),
                             event(2, "suspend_end", stamp=3),
                             event(3, "restart_begin", stamp=10),
                             event(4, "restart_end", stamp=12)])
        rows = [r["event"] for r in read_index(path, mode="gc")["rows"]]
        self.assertEqual([(x["kind"], x["duration_ms"]) for x in rows],
                         [("RUNTIME_SUSPENSION_ENVELOPE", 11), ("RUNTIME_FULLY_SUSPENDED", 7)])

    def test_truncated_trace_and_unmatched_events_remain_partial(self):
        _, meta = self.build([event(1, "gc_start")], status="TRUNCATED")
        self.assertEqual(meta["status"], "TRUNCATED")
        self.assertEqual(meta["gc"]["open_gc_starts"], 1)

    def test_cancellation_never_publishes_and_existing_destination_is_kept(self):
        cancel = Event(); cancel.set()
        path = self.stream([event(1)])
        out = self.root / "trace.sqlite3"
        with self.assertRaises(InterruptedError):
            build_index(path, out, input_sha256=HASH, format_name=".nettrace", cancel=cancel)
        self.assertFalse(out.exists())
        out.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            build_index(path, out, input_sha256=HASH, format_name=".nettrace")
        self.assertEqual(out.read_bytes(), b"keep")

    def test_invalid_sequences_nonfinite_and_changed_hash_rejected(self):
        out = self.root / "trace.sqlite3"
        for rows in ([event(2)], [event(1, stamp=float("nan"))]):
            with self.assertRaises(ValueError):
                build_index(self.stream(rows), out, input_sha256=HASH, format_name=".nettrace")
        with self.assertRaises(ValueError):
            build_index(self.stream([event(1)]), out, input_sha256="b" * 64, format_name=".nettrace")
        self.assertFalse(out.exists())

    def test_schema_one_adapter_removes_token_and_does_not_align_clocks(self):
        raw = {"schema_version": 1, "pid": 123, "tid": 7, "seq": 1, "kind": "stage.begin",
               "source_clock": "PYTHON_PERF_COUNTER_NS", "source_ns": 100, "token": "SECRET"}
        path = self.root / "own.jsonl"
        path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
        row = next(own_events(path))
        self.assertNotIn("SECRET", json.dumps(row))
        self.assertEqual(row["time_ms"], 0)
        self.assertIsNone(row["process_instance"])
        self.assertEqual(row["clock_alignment"], "SEPARATE_PER_PRODUCER_NOT_ALIGNED")
        out = self.root / "index.sqlite3"
        meta = build_index(path, out, input_sha256=HASH, format_name=".jsonl")
        self.assertEqual(meta["rows"], 1)

    def test_reject_duplicate_json_keys_and_partial_line(self):
        path = self.root / "bad.jsonl"
        for text in ('{"a":1,"a":2}\n', '{"a":1}'):
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                list(lines(path))

    def test_stack_fields_are_preserved_without_fabricated_symbols(self):
        row = event(1)
        row["frames"] = [{"address": "0x123", "name": ""}]
        path, meta = self.build([row])
        self.assertEqual(meta["events_with_stacks"], 1)
        self.assertEqual(read_index(path, mode="stacks")["rows"][0]["event"]["frames"], row["frames"])
        self.assertEqual(read_index(path, pid=999)["rows"], [])


if __name__ == "__main__":
    unittest.main()
