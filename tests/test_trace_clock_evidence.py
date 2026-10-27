"""Truthful capture-side QPC clock evidence and offline journal review.

These tests use synthetic journals, never proof of Windows provenance. The
real kernel32 probe is also smoke-tested on Windows CI without a target.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from blackbox_core.decoder_index import PROTOCOL, build_index, read_index
from blackbox_core.trace_clock_evidence import (
    SCHEMA, assess_trace_capture_journal, bracket, capture_trace_clock_bracket)

SHA = "a" * 64


def fixture_index(folder):
    source = folder / "synthetic-decoder.jsonl"
    rows = [
        {"type": "header", "protocol": PROTOCOL, "input_sha256": SHA},
        {"type": "event", "ordinal": 1, "time_ms": 1., "pid": 123,
         "tid": 2, "process_instance": 1, "provider": "TEST",
         "name": "synthetic.clock", "payload": {}, "frames": [], "semantic": None},
        {"type": "footer", "protocol": PROTOCOL, "rows": 1, "status": "DECODED"}]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows),
                      encoding="utf-8")
    idx = folder / "index.sqlite3"
    build_index(source, idx, input_sha256=SHA, format_name=".etl")
    return idx


def anchor(qpc, mono, utc, *, pid=1234, hz=10_000_000):
    return bracket(qpc, qpc + 100, hz, mono, mono + 10_000,
                   utc, pid=pid)


def fixture_journal(folder, source="ETW_WPR"):
    if source == "ETW_WPR":
        begin, end = "before_tool_start", "after_tool_stop"
    else:
        begin, end = "before_tool_spawn", "after_tool_exit"
    data = {"source": source, "state": "COMPLETED",
            "result": {"sha256": SHA, "status": "CAPTURED"},
            "clock_anchors": {begin: anchor(10_000_000, 5_000_000_000, 1_800_000_000_000_000_000),
                              end: anchor(20_000_000, 6_000_000_000, 1_800_000_001_000_000_000)}}
    path = folder / "test.trace.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path, data


class TraceClockEvidenceTests(unittest.TestCase):
    def test_pure_qpc_bracket_rounding_and_quality(self):
        item = bracket(1000, 1100, 10_000_000,
                       100_000, 112_000, 1_800_000_000_000_000_000, pid=99)
        self.assertEqual(item["schema"], SCHEMA)
        self.assertEqual(item["status"], "BRACKET_OBSERVED_UNVERIFIED")
        self.assertEqual(item["qpc_bracket_width_ns"], 10_000)
        self.assertEqual(item["monotonic_bracket_width_ns"], 12_000)
        self.assertEqual(item["trace_to_session_alignment"], "NOT_ESTABLISHED")
        self.assertEqual(bracket(1000, 3_000_000, 10_000_000,
                                 100_000, 450_000_000, 1_800_000_000_000_000_000,
                                 pid=99)["status"], "WIDE_BRACKET_UNRELIABLE")

    def test_bad_clocks_and_boolean_as_counter_are_rejected(self):
        valid = [100, 200, 10_000_000, 1000, 1500, 1_800_000_000_000_000_000]
        for index, value in [(0, True), (1, 99), (2, 0), (3, -1),
                             (4, 999), (5, 0), (0, 2**65)]:
            invalid = valid.copy()
            invalid[index] = value
            with self.assertRaisesRegex(ValueError, "INVALID_CAPTURE_CLOCK_BRACKET"):
                bracket(*invalid, pid=88)
        with self.assertRaises(ValueError):
            bracket(*valid, pid=True)

    def test_platform_clock_capability_is_honest(self):
        item = capture_trace_clock_bracket()
        self.assertEqual(item["schema"], SCHEMA)
        self.assertEqual(item["trace_to_session_alignment"], "NOT_ESTABLISHED")
        if os.name == "nt":
            self.assertIn(item["status"], ("BRACKET_OBSERVED_UNVERIFIED",
                                           "WIDE_BRACKET_UNRELIABLE"), item)
            self.assertGreater(item["qpc_frequency_hz"], 0)
            self.assertLessEqual(item["qpc_before_ticks"], item["qpc_after_ticks"])
        else:
            self.assertEqual(item["status"], "WINDOWS_QPC_UNAVAILABLE")

    def test_matching_etw_journal_is_hash_linked_not_clock_certified(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            index = fixture_index(folder)
            journal, _ = fixture_journal(folder)
            digest_before = index.read_bytes()
            result = assess_trace_capture_journal(index, journal)
            self.assertEqual(result["status"], "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED")
            self.assertEqual(result["qpc_frequency_hz"], 10_000_000)
            self.assertEqual(result["trace_to_blackbox_session_clock_alignment"], "NOT_ESTABLISHED")
            self.assertEqual(result["same_boot_and_process_identity"], "NOT_INDEPENDENTLY_VERIFIED")
            self.assertEqual(index.read_bytes(), digest_before)
            self.assertEqual(read_index(index)["summary"]["capture_complete"], None)

    def test_hash_mismatch_and_missing_clock_anchors_never_align(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            idx = fixture_index(folder)
            journal, data = fixture_journal(folder)
            data["result"]["sha256"] = "b"*64
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "JOURNAL_TRACE_HASH_MISMATCH")
            data["result"]["sha256"] = SHA
            del data["clock_anchors"]
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "QPC_ANCHORS_NOT_RECORDED")
            data["state"] = "FAILED"
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "CAPTURE_NOT_COMPLETED")

    def test_modified_or_nonmonotonic_qpc_brackets_refused(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td); idx=fixture_index(folder)
            journal,data=fixture_journal(folder)
            data["clock_anchors"]["after_tool_stop"]["qpc_before_ticks"]=1
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "INVALID_QPC_ANCHOR_CONTRACT")
            data["clock_anchors"]["after_tool_stop"]=anchor(
                9_000_000, 4_000_000_000, 1_799_999_999_000_000_000)
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "NONMONOTONIC_CAPTURE_CLOCK_ANCHORS")
            data["clock_anchors"]["after_tool_stop"]=anchor(
                20_000_000, 6_000_000_000, 1_800_000_001_000_000_000, hz=5_000_000)
            journal.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(idx, journal)["status"],
                             "INCONSISTENT_CAPTURE_OWNER_OR_QPC_FREQUENCY")

    def test_eventpipe_source_requires_matching_decoder_format(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            index = fixture_index(folder)
            journal, data = fixture_journal(folder, source="EVENTPIPE_DOTNET_TRACE")
            self.assertEqual(assess_trace_capture_journal(index,journal)["status"],
                             "JOURNAL_AND_TRACE_SOURCE_MISMATCH")
            data["source"]="ETW_WPR"
            journal.write_text(json.dumps(data),encoding="utf-8")
            self.assertEqual(assess_trace_capture_journal(index,journal)["status"],
                             "QPC_ANCHORS_INCOMPLETE_OR_UNRELIABLE")


if __name__ == "__main__":
    unittest.main()
