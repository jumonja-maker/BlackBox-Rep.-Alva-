"""Evidence wording preserves recorded values and limits in both languages."""
import copy
import json
import unittest

from blackbox_universal.evidence_presentation import detail_text, fact_lines, raw_json, time_text, title


def finding(number=1):
    return {
        "finding_id": f"finding-{number}", "schema_version": 2,
        "code": "DERIVED_RSS_GROWTH", "severity": "WARNING",
        "start_ns": 2_000_000_000 + number, "end_ns": None,
        "confidence_class": "DERIVED", "source_trust": "UNVERIFIED_IMPORT",
        "root_cause": "UNKNOWN", "root_cause_proven": False,
        "facts": [
            {"metric": "rss_bytes", "delta": 33_554_432, "threshold": 33_554_432},
            {"metric": "handle_count", "delta": 128, "threshold": 128},
            {"private_bytes": 0, "uss_bytes": None, "available": False,
             "vendor_unknown": {"future_bytes": 17, "text": "source-owned value"}},
        ],
        "alternative_explanations": ["RETAINED_CACHE", "FUTURE_ALTERNATIVE"],
        "limitations": ["COUNTERS_DO_NOT_ESTABLISH_ROOT_CAUSE", "BETWEEN_SAMPLE_ACTIVITY_UNKNOWN"],
        "hypotheses": [{"code": "INSPECT_COINCIDENT_WORK_AND_SOURCE_COVERAGE", "class": "CANDIDATE"}],
        "sources": [{"evidence_ref": "samples:DETAILED:17", "verification_class": "UNVERIFIED_IMPORT"}],
        "coverage": {"selected_samples": 5, "exact_missed_samples": None},
        "detail": {"incident_id": number}, "future_extension": {"empty": [], "zero": 0},
    }


class ExpertEvidencePresentationTests(unittest.TestCase):
    def test_facts_keep_null_zero_false_unknown_fields_and_metric_dependent_units(self):
        row = finding()
        before = copy.deepcopy(row)
        for language in ("EN", "RU"):
            with self.subTest(language=language):
                text = detail_text(row, language, origin=1_000_000_000)
                self.assertIn("33554432", text)
                self.assertIn("32.00 MiB", text)
                self.assertIn("0.00 MiB (0", text)
                self.assertIn("(null)", text)
                self.assertIn("(false)", text)
                self.assertIn("vendor_unknown", text)
                self.assertIn("future_bytes: 17", text)
                self.assertNotIn("future_bytes: 0.00 MiB", text)
                self.assertIn("source-owned value", text)
                self.assertIn("FUTURE_ALTERNATIVE", text)
                self.assertIn("samples:DETAILED:17", text)
                self.assertIn("DERIVED_RSS_GROWTH", text)
                self.assertIn("BETWEEN_SAMPLE_ACTIVITY_UNKNOWN", text)
                handle = "\n".join(fact_lines({"metric": "handle_count", "delta": 128}, language))
                self.assertIn("128", handle)
                self.assertNotIn("MiB", handle)
                unknown_nested = "\n".join(fact_lines({"metric": "rss_bytes", "vendor_unknown": {"threshold": 17, "max": 0}}, language))
                self.assertIn("17", unknown_nested)
                self.assertNotIn("MiB", unknown_nested, "Unknown nested fields must not inherit a guessed metric")
                self.assertEqual(json.loads(raw_json(row)), row)
        self.assertEqual(row, before, "Presentation must not mutate recorded evidence")

    def test_event_trust_and_unknown_source_are_not_inferred_from_detail_claims(self):
        event = {"code": "FUTURE_EVENT", "time_ns": 7, "source": "FUTURE_PROVIDER",
                 "severity": "INFO", "status": "FUTURE_STATUS", "instance_id": None,
                 "verification_class": "UNVERIFIED_IMPORT", "evidence_ref": "research.sqlite3:evidence:7",
                 "detail": {"verification_class": "OS_OBSERVED", "sensor_identity": None, "timestamp_precision": "UNKNOWN"}}
        for language in ("EN", "RU"):
            text = detail_text(event, language, origin=None, events=True)
            for literal in ("FUTURE_PROVIDER", "FUTURE_STATUS", "FUTURE_EVENT", "UNVERIFIED_IMPORT",
                            "OS_OBSERVED", "research.sqlite3:evidence:7", "(null)"):
                self.assertIn(literal, text)
            self.assertEqual(title("FUTURE_EVENT", language), "FUTURE_EVENT")
            self.assertNotIn("1970", text)
        self.assertIn("origin unknown", time_text(event, None, "EN", events=True))
        self.assertEqual(time_text({"time_ns": None}, 0, "EN", events=True), "Time not recorded")

    def test_incident_keeps_snapshot_gap_offsets_partial_context_and_complete_raw_packet(self):
        card = {"status": "OBSERVATION_ONLY", "root_cause": "UNKNOWN", "source_trust": "UNVERIFIED_IMPORT",
                "snapshots": {"before": {"status": "SAMPLED_GAP", "nearest_observed_ns": 17},
                              "at_end": {"status": "OBSERVED_NEAR_BOUNDARY_NOT_INTERPOLATED",
                                         "observed_ns": 21, "offset_ns": 3,
                                         "values": {"rss_bytes": 100, "private_bytes": 200, "uss_bytes": 50}}},
                "post_context_complete": False, "next_actions": ["INSPECT_AVAILABLE_WCT"],
                "limitations": ["PRE_POST_MAY_BE_PARTIAL"], "events": {"rows": [{"private_fixture": True}],
                                                                         "total_matching": 1, "has_more": False},
                "future_card_field": {"unknown_clock": None}}
        before = copy.deepcopy(card)
        for language in ("EN", "RU"):
            text = detail_text(card, language, card=True)
            for literal in ("SAMPLED_GAP", "OBSERVED_NEAR_BOUNDARY_NOT_INTERPOLATED", "21", "3",
                            "RSS", "Private Bytes", "USS", "PRE_POST_MAY_BE_PARTIAL", "(false)",
                            "INSPECT_AVAILABLE_WCT", "future_card_field", "(null)"):
                self.assertIn(literal, text)
            self.assertEqual(json.loads(raw_json(card)), card)
        self.assertEqual(card, before)

    def test_exit_and_app_crash_titles_retain_the_distinction(self):
        self.assertEqual(title("INCIDENT_PROCESS_EXIT_OBSERVED", "EN"), "Recorded incident: Process exit observed")
        self.assertIn("Application-reported", title("INCIDENT_APP_CRASH_MARKER", "EN"))
        self.assertIn("probe timeout", title("INCIDENT_UI_TIMEOUT", "EN"))
        self.assertIn("end not recorded", time_text(finding(), 0, "EN"))
        self.assertIn("end not recorded", time_text(finding(), None, "EN"))


if __name__ == "__main__":
    unittest.main()
