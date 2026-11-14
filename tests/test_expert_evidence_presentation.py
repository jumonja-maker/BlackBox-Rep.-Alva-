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

    def test_huge_integer_measurements_and_nonfinite_values_do_not_overflow_or_become_zero(self):
        huge = 10**330
        for language in ("EN", "RU"):
            text = "\n".join(fact_lines({"metric": "rss_bytes", "delta": huge}, language))
            self.assertIn(str(huge), text)
            self.assertIn("MiB", text)
            self.assertNotIn("inf", text)
            for value in (float("nan"), float("inf"), -float("inf")):
                invalid = "\n".join(fact_lines({"rss_bytes": value}, language))
                self.assertIn("non-finite" if language == "EN" else "неконечное", invalid)
                self.assertNotIn("0.00 MiB", invalid)

    def test_deep_and_wide_imports_have_bounded_default_views_and_complete_compact_raw_json(self):
        nested = {"leaf": "точное значение \"quoted\"\n"}
        for _ in range(600):
            nested = {"next": nested}
        text = "\n".join(fact_lines(nested, "EN"))
        self.assertIn("complete Raw JSON", text)
        self.assertLess(len(text), 20000)
        raw = raw_json(nested)
        self.assertLess(len(raw), 10000, "Indentation must not amplify a deeply nested import")
        decoded = json.loads(raw)
        for _ in range(600):
            decoded = decoded["next"]
        self.assertEqual(decoded, {"leaf": "точное значение \"quoted\"\n"})
        wide = {"rows": list(range(5000)), "long": "x" * 140000}
        self.assertEqual(json.loads(raw_json(wide)), wide)
        self.assertIn("complete Raw JSON", "\n".join(fact_lines(wide, "EN")))
        row = finding()
        row["facts"] = [{"unknown": "x" * 140000}]
        self.assertIn("complete Raw JSON", detail_text(row, "EN"))
        self.assertEqual(json.loads(raw_json(row)), row)

    def test_malformed_snapshot_containers_remain_literal_and_invalid_clocks_stay_explicit(self):
        for snapshots in (None, [], "provider-owned", False):
            card = {"snapshots": snapshots, "post_context_complete": None}
            self.assertIn("Incident observations", detail_text(card, "EN", card=True))
            self.assertEqual(json.loads(raw_json(card)), card)
        for invalid in (False, -1, 2**63, 10**330, float("nan"), "17"):
            self.assertIn("Invalid recorded timestamp", time_text({"time_ns": invalid}, 0, "EN", events=True))
        self.assertIn("origin unknown", time_text({"time_ns": 17}, -1, "EN", events=True))
        self.assertIn("Invalid recorded interval", time_text({"start_ns": 17, "end_ns": 0}, 0, "EN"))

    def test_long_unknown_codes_have_explicit_previews_and_raw_record_remains_complete(self):
        row = finding()
        row["code"] = "UNRECOGNIZED_" + "z" * 140000
        unknown_key = "vendor_key_" + "k" * 140000
        unknown_status = "VENDOR_STATUS_" + "s" * 140000
        row["facts"] = [{unknown_key: 42, "status": unknown_status}]
        text = detail_text(row, "EN")
        self.assertLess(len(text), 65536)
        self.assertIn("complete Raw JSON", text)
        self.assertIn("vendor_key_", text)
        self.assertIn("VENDOR_STATUS_", text)
        self.assertNotIn(unknown_key, text)
        self.assertNotIn(unknown_status, text)
        self.assertEqual(json.loads(raw_json(row)), row)

    def test_raw_json_preserves_json_types_escapes_and_rejects_non_json_values_without_replacement(self):
        values = {"integer": 0, "negative": -17, "float": 1.25, "true": True, "false": False,
                  "null": None, "empty_object": {}, "empty_array": [],
                  "text": "Русский / quoted \" slash \\ newline\ncontrol\x00\x1f",
                  "surrogate": "literal\ud800", "escaped_surrogate": r"literal\ud800"}
        for complex_record in (False, True):
            row = {**values, **({"force_compact": list(range(5000))} if complex_record else {})}
            raw = raw_json(row)
            raw.encode("utf-8", errors="strict")
            self.assertEqual(json.loads(raw), row)
            self.assertIn(r"\ud800", raw)
        for value in (float("nan"), float("inf"), -float("inf"), (1, 2), {1: "non-string key"}):
            for prefix in ({}, {"force_compact": list(range(5000))}):
                with self.subTest(value=value, compact=bool(prefix)):
                    with self.assertRaises((TypeError, ValueError)):
                        raw_json({**prefix, "invalid": value})
        cyclic = {}
        cyclic["next"] = cyclic
        with self.assertRaisesRegex(ValueError, "Circular"):
            raw_json(cyclic)
        text = detail_text({"code": "FUTURE", "detail": values}, "EN", events=True)
        text.encode("utf-8", errors="strict")


if __name__ == "__main__":
    unittest.main()
