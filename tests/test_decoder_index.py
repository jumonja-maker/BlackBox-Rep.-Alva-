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

    def test_jsonl_writer_tokens_partition_reused_pid_and_are_never_exported(self):
        # Identical PID, clock and TID with independent writers must not be
        # merged into one timeline or rejected as a replayed sequence.
        base = {"schema_version": 1, "pid": 321, "tid": 77, "seq": 1,
                "source_clock": "PYTHON_PERF_COUNTER_NS", "kind": "test.event"}
        records = [dict(base, source_ns=1_000, token="secret-token-writer-A"),
                   dict(base, source_ns=999_000, token="secret-token-writer-B"),
                   dict(base, source_ns=2_000, token="secret-token-writer-A", seq=2)]
        path = self.root / "writers.jsonl"
        path.write_text("".join(json.dumps(x) + "\n" for x in records), encoding="utf-8")
        parsed = list(own_events(path))
        self.assertEqual([x["time_ms"] for x in parsed], [0, 0, .001])
        self.assertEqual([x["clock_scope"][-1] for x in parsed], [1, 2, 1])
        self.assertTrue(all(x["producer_identity_quality"] == "TOKEN_PARTITIONED_NOT_VERIFIED" for x in parsed))
        out = self.root / "index.sqlite3"
        build_index(path, out, input_sha256=HASH, format_name=".jsonl")
        saved = json.dumps(read_index(out), ensure_ascii=False)
        self.assertNotIn("secret-token", saved)

    def test_no_token_requires_ambiguous_producer_quality(self):
        path = self.root / "no-token.jsonl"
        path.write_text(json.dumps({"schema_version": 1, "pid": 22, "tid": 33,
                                    "seq": 1, "source_clock": "UNKNOWN_CLOCK",
                                    "source_ns": 200, "kind": "test.event"}) + "\n", encoding="utf-8")
        parsed = list(own_events(path))
        self.assertEqual(parsed[0]["producer_identity_quality"], "NO_TOKEN_WRITER_AMBIGUOUS")

    def test_index_filter_uses_literal_search_and_keyset_pagination(self):
        events = [event(1), event(2), event(3), event(4)]
        events[0]["name"] = "GC%Start"
        events[1]["name"] = "GC_Start"
        events[2]["name"] = "Other"
        events[3]["name"] = "GC%Start"
        path, _ = self.build(events)
        names = [r["event"]["name"] for r in read_index(path, search="GC%Start")["rows"]]
        self.assertEqual(names, ["GC%Start", "GC%Start"])
        self.assertEqual([r["event"]["name"] for r in read_index(path, search="GC_Start")["rows"]], ["GC_Start"])
        first = read_index(path, search="GC%Start", limit=1)
        self.assertTrue(first["has_more"])
        second = read_index(path, search="GC%Start", limit=1, after=first["next_cursor"])
        self.assertEqual(second["rows"][0]["index_id"], 4)
        self.assertEqual(len(read_index(path, search="SYNTHETIC_ONLY")["rows"]), 4)
        with self.assertRaises(ValueError):
            read_index(path, search="x" * 121)
        with self.assertRaises(ValueError):
            read_index(path, search=123)

    def test_stack_fields_are_preserved_without_fabricated_symbols(self):
        row = event(1)
        row["frames"] = [{"address": "0x123", "name": ""}]
        path, meta = self.build([row])
        self.assertEqual(meta["events_with_stacks"], 1)
        self.assertEqual(read_index(path, mode="stacks")["rows"][0]["event"]["frames"], row["frames"])
        self.assertEqual(read_index(path, pid=999)["rows"], [])

    def test_cpu_profile_uses_only_real_profiler_event_kind_and_preserves_unknown_frames(self):
        from blackbox_core.decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT
        frames = [{"address": "0x123", "name": "TEST_Leaf%_A"},
                  {"address": "0x456", "name": ""}]
        a = event(1)
        a["provider"], a["name"], a["frames"] = "Microsoft-Windows-DotNETRuntime", "GC/AllocationTick", frames
        b, c, d, e, f = (event(i) for i in range(2, 7))
        for row in (b, c, d, e, f):
            row["provider"], row["name"] = SAMPLE_PROVIDER, SAMPLE_EVENT
        b["frames"] = frames
        c["frames"] = frames
        d["frames"] = [{"address": "0xbeef", "name": "OtherFunction"}]
        e["frames"] = []
        f["frames"] = frames
        f["process_instance"] = 2  # same PID, different observed process instance
        path, meta = self.build([a, b, c, d, e, f])
        self.assertEqual(meta["events_with_stacks"], 5)
        profiles = meta["profiles"]
        self.assertEqual(profiles["cpu_profiler_samples_recorded"], 5)
        self.assertEqual(profiles["cpu_profiler_samples_with_stacks"], 4)
        self.assertEqual(profiles["cpu_profiler_samples_without_stacks"], 1)
        self.assertEqual(profiles["cpu_stack_groups_indexed"], 3)
        page = read_index(path, mode="cpu_stacks", limit=1)
        self.assertTrue(page["has_more"])
        first = page["rows"][0]["event"]
        self.assertEqual(first["recorded_sample_count"], 2)
        self.assertEqual(first["frames_without_names"], 1)
        self.assertEqual(first["frames"][1]["name"], "")
        self.assertEqual(first["measurement"], "EVENT_OCCURRENCES_NOT_CPU_TIME_OR_CPU_PERCENT")
        second = read_index(path, mode="cpu_stacks", after=page["next_cursor"], limit=2)
        self.assertEqual([r["event"]["recorded_sample_count"] for r in second["rows"]], [1, 1])
        exact = read_index(path, mode="cpu_stacks", search="Leaf%_A")
        self.assertEqual(len(exact["rows"]), 2)
        self.assertEqual(read_index(path, mode="cpu_stacks", search="LeafZ_A")["rows"], [])
        self.assertEqual(read_index(path, mode="cpu_stacks", pid=999)["rows"], [])
        self.assertIsNone(meta["capture_complete"])

    def test_unknown_process_instances_are_not_grouped_by_reused_pid(self):
        from blackbox_core.decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT
        rows = [event(1), event(2)]
        for row in rows:
            row["provider"], row["name"], row["process_instance"] = SAMPLE_PROVIDER, SAMPLE_EVENT, None
            row["frames"] = [{"address": "0x100", "name": ""}]
        path, meta = self.build(rows)
        self.assertEqual(meta["profiles"]["cpu_stack_groups_indexed"], 2)
        self.assertEqual(meta["profiles"]["cpu_profiler_samples_without_process_identity"], 2)
        values = read_index(path, mode="cpu_stacks")["rows"]
        self.assertTrue(all(r["event"]["recorded_sample_count"] == 1 for r in values))
        self.assertTrue(all(r["event"]["identity_quality"] ==
                            "UNKNOWN_PROCESS_INSTANCE_PID_REUSE_POSSIBLE" for r in values))

    def test_gc_statistics_keep_runtime_generation_and_pause_uncertainty(self):
        rows = [
            event(1, "gc_start", stamp=1, number=1, generation=2, gc_type="Blocking"),
            event(2, "gc_stop", stamp=4, number=1),
            event(3, "gc_start", stamp=6, number=2, generation=2, gc_type="Blocking"),
            event(4, "gc_stop", stamp=11, number=2),
            event(5, "suspend_begin", stamp=12),
            event(6, "suspend_end", stamp=13),
            event(7, "restart_begin", stamp=15),
            event(8, "restart_end", stamp=16)]
        path, meta = self.build(rows)
        profile = read_index(path, mode="gc_summary")
        self.assertEqual(meta["gc"]["gc_pairs"], 2)
        self.assertEqual(meta["profiles"]["gc_summary_groups"], 3)
        gc = next(x["event"] for x in profile["rows"] if x["event"]["kind"] == "GC_ELAPSED_NOT_PAUSE")
        self.assertEqual((gc["generation"], gc["runtime"], gc["interval_count"]), (2, 1, 2))
        self.assertEqual(gc["total_pair_duration_ms"], 8)
        self.assertEqual(gc["peak_pair_duration_ms"], 5)
        self.assertIs(gc["is_application_pause"], False)
        self.assertEqual(gc["measurement"], "SUM_OF_OBSERVED_PAIRS_NOT_WALL_TIME")
        self.assertEqual(len(read_index(path, mode="gc_summary", search="GC_ELAPSED")["rows"]), 1)
        self.assertEqual(read_index(path, mode="gc_summary", pid=999)["rows"], [])
        self.assertTrue(any(r["event"]["kind"] == "RUNTIME_FULLY_SUSPENDED" for r in profile["rows"]))

    def test_trace_utc_projection_is_queryable_but_never_called_session_aligned(self):
        from blackbox_core.decoder_clock import UNIX_EPOCH_DOTNET_TICKS
        base_ns = 1_700_000_000_000_000_000
        rows = [event(i) for i in range(1, 4)]
        for n, row in enumerate(rows, 1):
            row["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS + (base_ns+n*1_000_000)//100)
            row["source_ticks"] = str(100_000_000+n*1_000)
        path, meta = self.build(rows)
        self.assertEqual(meta["schema"], "blackbox.decoder-index/3")
        self.assertEqual(meta["calendar_clock"]["events_with_utc_projection"], 3)
        self.assertEqual(meta["calendar_clock"]["source_counter_events_observed"], 3)
        self.assertEqual(meta["calendar_clock"]["source_counter_events_missing"], 0)
        self.assertEqual(meta["calendar_clock"]["source_counter_min_ticks"], 100_001_000)
        self.assertEqual(meta["calendar_clock"]["source_counter_max_ticks"], 100_003_000)
        self.assertEqual(meta["calendar_clock"]["relative_vs_utc_offset_disagreements_over_10ms"], 0)
        self.assertEqual(meta["calendar_clock"]["trace_to_blackbox_session_clock_alignment"], "NOT_ESTABLISHED")
        self.assertEqual(meta["calendar_clock"]["same_boot_same_machine_and_time_sync"], "NOT_VERIFIED")
        first = read_index(path, mode="clock", limit=2)
        self.assertTrue(first["has_more"])
        self.assertEqual(len(first["rows"]), 2)
        self.assertEqual(first["rows"][0]["event"]["utc_time_ns"], base_ns+1_000_000)
        self.assertTrue(first["rows"][0]["event"]["utc_time_iso"].endswith("Z"))
        self.assertEqual(first["rows"][0]["event"]["utc_projection_quality"],
                         "TRACEEVENT_DERIVED_UTC_UNVERIFIED")
        last = read_index(path, mode="clock", limit=2, after=first["next_cursor"])
        self.assertEqual([r["index_id"] for r in last["rows"]], [3])
        self.assertEqual(len(read_index(path, mode="clock", pid=999)["rows"]), 0)

    def test_trace_utc_disagreement_is_reported_not_silently_aligned(self):
        from blackbox_core.decoder_clock import UNIX_EPOCH_DOTNET_TICKS
        base_ns = 1_700_000_000_000_000_000
        first, second = event(1), event(2)
        first["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS+(base_ns+1_000_000)//100)
        # The second event claims 100 ms more wall clock than trace elapsed.
        second["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS+(base_ns+102_000_000)//100)
        path, meta = self.build([first, second])
        health = meta["calendar_clock"]
        self.assertEqual(health["status"], "TRACE_RELATIVE_VS_UTC_DISAGREEMENT_UNCERTAIN")
        self.assertEqual(health["relative_vs_utc_offset_disagreements_over_10ms"], 1)
        self.assertGreaterEqual(health["max_relative_vs_utc_offset_disagreement_ns"], 90_000_000)
        self.assertEqual(len(read_index(path, mode="clock")["rows"]), 2)

    def test_untrusted_utc_malformed_ticks_never_publish_a_partial_index(self):
        invalid = [123, "１２３４５６７８９０１２３４５６７８", "bad", "-638355968000000000",
                   "9999999999999999999", "621355968000000000"]
        for bad in invalid:
            row = event(1)
            row["utc_ticks"] = bad
            path = self.stream([row])
            output = self.root / "bad-index.sqlite3"
            with self.assertRaisesRegex(ValueError, "TRACE_UTC"):
                build_index(path, output, input_sha256=HASH, format_name=".etl")
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_malformed_qpc_counter_refuses_untrusted_trace_projection(self):
        from blackbox_core.decoder_clock import UNIX_EPOCH_DOTNET_TICKS
        for bad in ("--123", "+123", "+-10", "", "１２３", "1.0",
                    str(2**63), str(-(2**63)-1), True, 123):
            item = event(1)
            item["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS+17_000_000_000_000_000)
            item["source_ticks"] = bad
            src = self.stream([item])
            output = self.root / "bad-qpc.sqlite3"
            with self.assertRaisesRegex(ValueError, "INVALID_TRACE_SOURCE_TICKS"):
                build_index(src,output,input_sha256=HASH,format_name=".etl")
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".decoder-building-*")))
        good = event(1)
        good["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS+17_000_000_000_000_000)
        good["source_ticks"] = "-123456"
        output, _ = self.build([good])
        self.assertEqual(read_index(output, mode="clock")["rows"][0]["event"]["source_ticks"],
                         "-123456")


    def test_malformed_source_counter_without_utc_never_publishes_index(self):
        for bad in ("1.5", "１２３", "--123", "", str(2**63), True):
            item = event(1)
            item["source_ticks"] = bad
            source = self.stream([item])
            output = self.root / "bad-counter-without-utc.sqlite3"
            with self.assertRaisesRegex(ValueError, "INVALID_TRACE_SOURCE_TICKS"):
                build_index(source, output, input_sha256=HASH, format_name=".etl")
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".decoder-building-*")))

    def test_jsonl_absence_of_utc_is_not_fabricated_and_v2_profile_reader_still_works(self):
        import sqlite3
        from contextlib import closing
        path = self.root / "own.jsonl"
        path.write_text(json.dumps({"schema_version": 1, "pid": 123, "tid": 7,
                  "seq": 1, "kind": "sample", "source_ns": 100,
                  "source_clock": "SOURCE_TEST"}) + "\n", encoding="utf-8")
        index = self.root / "own.sqlite3"
        meta = build_index(path,index,input_sha256=HASH,format_name=".jsonl")
        self.assertEqual(meta["calendar_clock"]["status"], "TRACE_UTC_NOT_RECORDED")
        self.assertEqual(meta["calendar_clock"]["events_with_utc_projection"], 0)
        self.assertEqual(read_index(index,mode="clock")["rows"], [])
        # A previously exported v2 index retains its existing CPU/GC readers
        # but cannot manufacture an absent v3 UTC column.
        with closing(sqlite3.connect(index)) as db:
            db.execute("PRAGMA user_version=2")
            db.commit()
        self.assertEqual(read_index(index,mode="cpu_stacks")["rows"], [])
        with self.assertRaisesRegex(ValueError, "REDECODE_REQUIRED_FOR_CLOCK_VIEW"):
            read_index(index,mode="clock")

    def test_cpu_profile_group_cap_and_saved_index_v1_compatibility(self):
        import sqlite3
        from unittest.mock import patch
        from blackbox_core.decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT
        rows = [event(1), event(2)]
        for i, row in enumerate(rows):
            row["provider"], row["name"] = SAMPLE_PROVIDER, SAMPLE_EVENT
            row["frames"] = [{"address": f"0x{i+1:x}", "name": ""}]
        with patch("blackbox_core.decoder_profiles.MAX_DISTINCT_STACKS", 1):
            path, meta = self.build(rows)
        self.assertEqual(meta["profiles"]["cpu_profiler_samples_recorded"], 2)
        self.assertEqual(meta["profiles"]["cpu_stack_groups_indexed"], 1)
        self.assertEqual(meta["profiles"]["cpu_profiler_samples_omitted_from_groups"], 1)
        self.assertEqual(len(read_index(path, mode="cpu_stacks")["rows"]), 1)
        from contextlib import closing
        # sqlite3.Connection.__exit__ commits/rolls back but DOES NOT close.
        # A dangling read/write handle blocks TemporaryDirectory cleanup
        # on Windows (WinError 32), even though Linux silently unlinks it.
        with closing(sqlite3.connect(path)) as db:
            # New development index has UTC provenance (v3). Legacy
            # readers still accept previously exported v1/v2 indexes.
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 3)
            db.execute("PRAGMA user_version=1")
            db.commit()
        self.assertEqual(len(read_index(path, mode="events")["rows"]), 2)
        with self.assertRaisesRegex(ValueError, "REDECODE_REQUIRED"):
            read_index(path, mode="cpu_stacks")


if __name__ == "__main__":
    unittest.main()
