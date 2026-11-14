"""The expert context identifies recorded evidence without borrowing live state."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from blackbox_universal.expert_context import format_analysis_context


SOURCE_A = Path("/recordings/A")
SOURCE_B = Path("/recordings/B")


def packet(folder=str(SOURCE_A), *, instance_id=1):
    return {
        "folder": folder,
        "interval": {
            "instance_id": instance_id,
            "metadata": {
                "pid": 4321,
                "creation_time": 0,
                "monotonic_origin_ns": 10_000_000_000,
                "file_trust": "UNVERIFIED_IMPORT",
                "clock_quality": "RECORDED_CLOCK_QUALITY",
                "recorded_status": "CLOSED",
            },
            "selected_interval_ns": [11_125_000_000, 13_000_000_001],
        },
    }


class ExpertAnalysisContextTests(unittest.TestCase):
    def assertNoPacketEvidence(self, text):
        for value in ("4321", "UNVERIFIED_IMPORT", "RECORDED_CLOCK_QUALITY", "CLOSED",
                      "11_125", "11125000000", "3.000000001", "Root PID"):
            self.assertNotIn(value, text)

    def test_ready_names_recorded_source_root_identity_and_precise_relative_range(self):
        result = format_analysis_context(SOURCE_A, packet())
        self.assertIn(f"Analysis source (recorded session): {SOURCE_A}", result)
        self.assertIn("Read: ready", result)
        self.assertIn("Root PID: 4321", result)
        self.assertIn("Root creation (Unix s): 0", result)
        self.assertIn("Selected recorded instance: 1", result)
        self.assertIn("1.125–3.000000001 s relative to recorded monotonic origin 10000000000 ns", result)
        self.assertIn("file_trust: UNVERIFIED_IMPORT", result)
        self.assertIn("clock_quality: RECORDED_CLOCK_QUALITY", result)
        self.assertIn("recorded_status: CLOSED", result)
        self.assertEqual(len(result.splitlines()), 4)

    def test_child_selection_keeps_root_pid_explicit_and_uses_selected_recorded_instance(self):
        value = packet(instance_id=7)
        value["threads"] = {"pid": 9999, "creation_time": 42}
        value["interval"]["pid"] = 9999
        result = format_analysis_context(SOURCE_A, value, instance_id=7)
        self.assertIn("Root PID: 4321", result)
        self.assertIn("Selected recorded instance: 7", result)
        self.assertNotIn("9999", result)
        self.assertNotIn("creation (Unix s): 42", result)

    def test_switch_from_a_to_b_never_shows_a_packet_during_loading_or_failure(self):
        for options, expected_state in (({"loading": True}, "loading"),
                                        ({"failed": True}, "unavailable"), ({}, "awaiting")):
            with self.subTest(options=options):
                result = format_analysis_context(SOURCE_B, packet(), **options)
                self.assertIn(str(SOURCE_B), result)
                self.assertIn(expected_state, result)
                self.assertNotIn(str(SOURCE_A), result)
                self.assertNoPacketEvidence(result)

    def test_loading_and_failure_also_suppress_matching_old_packet(self):
        for options in ({"loading": True}, {"failed": True}):
            with self.subTest(options=options):
                result = format_analysis_context(SOURCE_A, packet(), **options)
                self.assertIn(str(SOURCE_A), result)
                self.assertNoPacketEvidence(result)

    def test_stale_instance_packet_cannot_identify_current_child_selection(self):
        for old_instance in (1, None, True):
            with self.subTest(old_instance=old_instance):
                result = format_analysis_context(SOURCE_A,
                                                 packet(instance_id=old_instance), instance_id=7)
                self.assertIn("Selected recorded instance: 7", result)
                self.assertIn("awaiting", result)
                self.assertNoPacketEvidence(result)

    def test_boolean_instance_does_not_match_integer_one(self):
        result = format_analysis_context(SOURCE_A, packet(instance_id=True))
        self.assertIn("awaiting", result)
        self.assertNoPacketEvidence(result)

    def test_unselected_source_ignores_even_ready_packet(self):
        result = format_analysis_context(None, packet())
        self.assertIn("none selected", result)
        self.assertIn("Read: no source", result)
        self.assertNotIn(str(SOURCE_A), result)
        self.assertNoPacketEvidence(result)

    def test_no_packet_and_malformed_packets_keep_selected_source_and_wait(self):
        for value in (None, [], {}, {"folder": str(SOURCE_A), "interval": None}):
            with self.subTest(value=value):
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn(str(SOURCE_A), result)
                self.assertIn("awaiting", result)
                self.assertNoPacketEvidence(result)

    def test_epoch_zero_and_zero_clock_origin_are_known_not_missing(self):
        value = packet()
        value["interval"]["metadata"]["monotonic_origin_ns"] = 0
        value["interval"]["selected_interval_ns"] = [0, 1]
        result = format_analysis_context(SOURCE_A, value)
        self.assertIn("Root creation (Unix s): 0", result)
        self.assertIn("0–0.000000001 s relative to recorded monotonic origin 0 ns", result)

    def test_relative_range_preserves_ns_precision_at_large_origins_and_before_origin(self):
        value = packet()
        origin = 9_000_000_000_000_000_000
        value["interval"]["metadata"]["monotonic_origin_ns"] = origin
        value["interval"]["selected_interval_ns"] = [origin-1, origin+1]
        result = format_analysis_context(SOURCE_A, value)
        self.assertIn("-0.000000001–0.000000001 s relative to", result)
        self.assertIn(str(origin), result)

    def test_invalid_root_pid_does_not_borrow_child_identity(self):
        for missing in (None, False, True, float("nan"), 0, "4321"):
            with self.subTest(missing=missing):
                value = packet()
                value["interval"]["metadata"]["pid"] = missing
                value["threads"] = {"pid": 9999}
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn("Root PID: unknown", result)
                self.assertNotIn("9999", result)

    def test_invalid_or_missing_creation_identity_never_becomes_epoch_zero(self):
        for missing in (None, False, True, float("nan"), float("inf"), "0"):
            with self.subTest(missing=missing):
                value = packet()
                value["interval"]["metadata"]["creation_time"] = missing
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn("Root creation (Unix s): unknown", result)
                self.assertNotIn("Root creation (Unix s): 0", result)

    def test_missing_origin_preserves_raw_bounds_without_synthesizing_seconds(self):
        for origin in (None, False, True, float("nan"), float("inf"), 0.0, "0", -1):
            with self.subTest(origin=origin):
                value = packet()
                value["interval"]["metadata"]["monotonic_origin_ns"] = origin
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn("Selected range (raw ns): 11125000000–13000000001", result)
                self.assertIn("recorded monotonic origin (ns): unknown", result)
                self.assertNotIn("s relative to", result)

    def test_invalid_bound_is_unknown_and_valid_bound_stays_raw(self):
        for missing in (None, False, True, float("nan"), float("inf"), 0.0, "0", -1):
            with self.subTest(missing=missing):
                value = packet()
                value["interval"]["selected_interval_ns"] = [missing, 13_000_000_001]
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn("Selected range (raw ns): unknown–13000000001", result)
                self.assertNotIn("s relative to", result)

    def test_invalid_range_order_stays_raw_and_is_explicit(self):
        value = packet()
        value["interval"]["selected_interval_ns"] = [13_000_000_001, 11_125_000_000]
        result = format_analysis_context(SOURCE_A, value)
        self.assertIn("13000000001–11125000000", result)
        self.assertIn("invalid bound order", result)
        self.assertNotIn("s relative to", result)

    def test_missing_identity_clock_and_trust_remain_unknown_without_inference(self):
        value = packet()
        value["interval"]["metadata"] = {"schema_version": 2,
            "verification_class": "VERIFIED", "status": "CLOSED", "started_utc_ns": 0}
        result = format_analysis_context(SOURCE_A, value)
        for label in ("Root PID", "Root creation (Unix s)", "file_trust", "clock_quality", "recorded_status"):
            self.assertIn(label + ": unknown", result)
        self.assertNotIn("UNVERIFIED_IMPORT", result)
        self.assertNotIn("VERIFIED", result)
        self.assertNotIn("CLOSED", result)
        self.assertNotIn("0–0", result)

    def test_ru_en_keep_path_and_recorded_codes_verbatim(self):
        source = r"C:\Записи\case <alpha> & x.sqlite3"
        value = packet(source)
        for language, source_label in (("EN", "Analysis source"), ("RU", "Источник анализа")):
            with self.subTest(language=language):
                result = format_analysis_context(source, value, language=language)
                self.assertIn(source, result)
                self.assertIn(source_label, result)
                self.assertIn("file_trust: UNVERIFIED_IMPORT", result)
                self.assertIn("clock_quality: RECORDED_CLOCK_QUALITY", result)
                self.assertIn("recorded_status: CLOSED", result)
        self.assertIn("PID корневого процесса: 4321",
                      format_analysis_context(source, value, language="RU"))

    def test_formatter_does_not_inspect_filesystem_or_mutate_packet(self):
        value = packet()
        original = deepcopy(value)
        with patch.object(Path, "resolve", side_effect=AssertionError("must not resolve")), \
             patch.object(Path, "stat", side_effect=AssertionError("must not stat")), \
             patch.object(Path, "open", side_effect=AssertionError("must not read")):
            result = format_analysis_context(SOURCE_A, value)
        self.assertIn("Read: ready", result)
        self.assertEqual(value, original)

    def test_invalid_selected_instance_cannot_make_a_matching_malformed_packet_ready(self):
        for invalid in (True, False, 0, -1, 1.0, None, 2**63):
            with self.subTest(invalid=invalid):
                result = format_analysis_context(SOURCE_A, packet(instance_id=invalid), instance_id=invalid)
                self.assertIn("awaiting", result)
                self.assertIn("Selected recorded instance: unknown", result)
                self.assertNoPacketEvidence(result)

    def test_unknown_report_or_source_schema_suppresses_interpretation_and_preserves_selection(self):
        for key, invalid in (("schema_version", 1), ("schema_version", True),
                             ("schema_version", 99), ("source_schema_version", 99)):
            with self.subTest(key=key, invalid=invalid):
                value = packet()
                value["interval"][key] = invalid
                result = format_analysis_context(SOURCE_A, value)
                self.assertIn(str(SOURCE_A), result)
                self.assertIn("awaiting", result)
                self.assertNoPacketEvidence(result)
        legacy = packet()
        legacy["interval"].update(schema_version=2, source_schema_version=1)
        self.assertIn("Read: ready", format_analysis_context(SOURCE_A, legacy))
        legacy["interval"]["instance_id"] = 7
        self.assertIn("awaiting", format_analysis_context(SOURCE_A, legacy, instance_id=7))

    def test_huge_clock_is_unknown_and_unbounded_imported_status_has_an_explicit_preview(self):
        value = packet()
        value["interval"]["metadata"]["monotonic_origin_ns"] = 10**330
        value["interval"]["metadata"]["recorded_status"] = "status:" + "x" * 140000
        original = deepcopy(value)
        result = format_analysis_context(SOURCE_A, value)
        self.assertIn("recorded monotonic origin (ns): unknown", result)
        self.assertIn("recorded text truncated", result)
        self.assertLess(len(result), 2000)
        self.assertEqual(value, original)


if __name__ == "__main__":
    unittest.main()
