"""Expert navigation and selected-recording context, with real Qt widgets.

Run only by hosted CI under the repository's application-test policy. Imported
data here is explicitly synthetic and establishes no physical Windows coverage.
"""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tools.qa_expert_workflow import (PAGES, SECTIONS, digest, observe_layout_readiness,
                                      synthetic_recording, validate_receipt)


class ExpertWorkflowQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.environ.get("GITHUB_ACTIONS") == "true" and
                os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
            raise AssertionError("EXPERT_QT_TESTS_REQUIRE_GITHUB_HOSTED_RUNNER")
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def pump(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if predicate():
                return
            time.sleep(.005)
        self.fail("EXPERT_QT_CONTRACT_DEADLINE")

    def close_window(self, window):
        from qt_test_support import close_and_drain
        close_and_drain(window, self.app, timeout=30)

    def test_pointer_keyboard_and_language_preserve_six_pages_and_five_page_embedding(self):
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest
        from blackbox_universal.decoder_window import DecoderWindow
        from blackbox_universal.window import UniversalWindow
        for kind, expected in ((UniversalWindow, PAGES[:5]), (DecoderWindow, PAGES)):
            with self.subTest(shell=kind.__name__), tempfile.TemporaryDirectory() as temp:
                window = kind(isolated=False, output_root=Path(temp), allow_update_check=False)
                window._timer.stop()
                window.show()
                window.activateWindow()
                try:
                    self.app.processEvents()
                    self.assertEqual(tuple(key for key, _ in window.PAGES), expected)
                    self.assertEqual(window.stack.count(), len(expected))
                    for language in ("RU", "EN"):
                        window._set_language(language)
                        for number, page in enumerate(expected, 1):
                            QTest.mouseClick(window._nav_buttons[page], Qt.MouseButton.LeftButton)
                            self.app.processEvents()
                            self.assertEqual(window.stack.currentIndex(), window._page_ids[page])
                            self.assertTrue(window._nav_buttons[page].property("active"))
                            # Start elsewhere, so a missing shortcut cannot
                            # pass merely because the pointer got here first.
                            window._navigate(expected[-1] if page != expected[-1] else expected[0])
                            window.setFocus()
                            QTest.keyClick(window, getattr(Qt.Key, "Key_" + str(number)),
                                           Qt.KeyboardModifier.ControlModifier)
                            self.app.processEvents()
                            self.assertEqual(window.stack.currentIndex(), window._page_ids[page])
                        QTest.keyClick(window, Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
                        self.app.processEvents()
                        self.assertEqual(window.stack.currentIndex(), window._page_ids["processes"])
                        self.assertTrue(window.process_search.hasFocus())
                    self.assertFalse(window.probe.active)
                    self.assertIsNone(window.probe.session_folder)
                    self.assertFalse(window.review_result_button.isEnabled())
                    self.assertFalse(window.deep_inspector_panel.bridge.has_session)
                finally:
                    self.close_window(window)

    def test_expert_anchors_keep_historic_selection_and_live_target_separate(self):
        from PySide6.QtCore import QPoint, QRect, Qt
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QPushButton
        from blackbox_universal.decoder_window import DecoderWindow
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture_path = synthetic_recording(root / "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE")
            before = digest(fixture_path)
            window = DecoderWindow(isolated=False, output_root=root / "sessions", allow_update_check=False)
            window._timer.stop()
            window.show()
            # An explicit live-selection sentinel: no attach/start call occurs.
            window.probe.pid = 98765
            try:
                window._load_session_interval(fixture_path.parent)
                self.pump(lambda: window._interval_worker is None)
                self.assertIsNotNone(window._interval_packet)
                self.assertEqual(window._interval_packet["folder"], str(fixture_path.parent))
                child = window.process_history_table.item_for_instance(2)
                self.assertIsNotNone(child)
                # Normal Qt selection triggers the original read-only worker.
                window.process_history_table.setCurrentItem(child)
                self.pump(lambda: window._interval_worker is None and window._interval_process == 2)
                self.assertEqual(window._interval_packet["interval"]["series"], "CHILD")
                selected_interval = tuple(window._interval_packet["interval"]["selected_interval_ns"])
                for language in ("RU", "EN"):
                    window._set_language(language)
                    window._navigate("reports")
                    for section in ("timeline", "findings", "library", "actions", "technical"):
                        button = window.findChild(QPushButton, "expertSection_" + section)
                        self.assertIsNotNone(button)
                        self.assertTrue(button.isEnabled())
                        window.stack.currentWidget().ensureWidgetVisible(button)
                        self.app.processEvents()
                        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                        self.app.processEvents()
                        target = window._expert_sections[section]
                        viewport = window.stack.currentWidget().viewport()
                        self.pump(lambda: target.isVisible() and not viewport.rect().intersected(
                            QRect(target.mapTo(viewport, QPoint()), target.size())).isEmpty(), timeout=5)
                        if section == "technical":
                            self.assertTrue(window.report_technical_toggle.isChecked())
                            self.assertTrue(window.report_snapshot_frame.isVisible())
                        self.assertEqual(window.stack.currentIndex(), window._page_ids["reports"])
                        self.assertEqual(window._interval_folder, fixture_path.parent)
                        self.assertEqual(window._interval_process, 2)
                        self.assertEqual(tuple(window._interval_packet["interval"]["selected_interval_ns"]), selected_interval)
                        self.assertEqual(window.probe.pid, 98765)
                        self.assertFalse(window.probe.active)
                        self.assertFalse(window.deep_inspector_panel.bridge.has_session)
                    self.assertIn(str(fixture_path.parent), window.report_context.text())
                    self.assertNotIn("98765", window.report_context.text())
                self.assertEqual(digest(fixture_path), before)
            finally:
                self.close_window(window)


def passed_receipt():
    """A minimal receipt shape used to exercise the independent gate's failures."""
    source_sha = "a" * 40
    proof = {"status": "PASS", "source_sha": source_sha,
        "source_identity": {"actual_source_sha": source_sha, "source_identity_status": "VERIFIED_EXPECTED_HEAD",
                            "tracked_worktree_clean": True},
        "frozen": False, "scale": "1", "gui_pid": 123, "dpi_scope": "QT_SCALE_FACTOR_SIMULATION",
        "physical_windows_10_11": "NOT_TESTED", "secure_desktop": "NOT_TESTED",
        "cleanup": {"owners_closed": True}, "callback_errors": [], "unexpected_dialogs": [],
        "navigation": [{"language": language, "page": page, "actual_qt_input": True}
                       for language in ("EN", "RU") for page in PAGES],
        "shortcuts": [{"language": language, "target": target, "actual_qt_input": True}
                      for language in ("EN", "RU") for target in (*PAGES, "process_search")],
        "sections": [{"language": language, "section": section, "actual_qt_input": True,
                      "context_unchanged": True, "target_visible_in_viewport": True}
                     for language in ("EN", "RU") for section in SECTIONS],
        "minimum_width": [{"language": language, "logical_window_client": [1020, 850],
                           "actual_qt_resize": True, "expanded_sections": ["library", "actions", "technical"],
                           "viewport_width": 788, "outer_horizontal_scroll_maximum": 0,
                           "research_panel_width": 752, "library_panel_width": 752}
                          for language in ("EN", "RU")],
        "anchor_geometry": [{"language": language, "stage": stage, "workspace_before_timeline": True,
            "caption": {"has_height_for_width": True, "policy_has_height_for_width": True,
                "actual_width": 600, "allocated_height": 48, "required_height_at_actual_width": 48,
                "rect": [0, 0, 600, 48], "visible_bounds": [0, 0, 600, 48],
                "workspace_contains": True, "no_button_overlap": True},
            "reveal_top": stage == "fixture-minimum-width",
            "geometry_view": "AT_REPORT_TOP_AFTER_SCREENSHOT" if stage == "fixture-minimum-width" else
                "SAME_VIEW_AFTER_SCREENSHOT",
            "scroll_before_probe": 300 if stage == "fixture-minimum-width" else 0, "scroll_at_probe": 0,
            "buttons": [{"name": name, "rect": [0, 0, 200, 32], "visible_bounds": [0, 0, 200, 32],
                "workspace_contains": True, "minimum_size_met": True, "siblings_disjoint": True,
                "ancestors_contain": True} for name in
                tuple("expertSection_" + section for section in SECTIONS) + ("copyAnalysisContext",)]}
            for language in ("EN", "RU") for stage in ("saved-report", "fixture-minimum-width")],
        "recordings": [], "screenshots": [],
        "fixture": {"scope": "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE", "source_unchanged": True,
                    "languages": ["EN", "RU"], "finding_selection_actual_qt_input": True,
                    "event_selection_actual_qt_input": True, "incident_card_actual_qt_input": True,
                    "copy_detail_roundtrip": True, "raw_json_roundtrip": True, "root_cause": "UNKNOWN"}}
    for row in proof["anchor_geometry"]:
        row["layout_diagnostics"] = {"height_timer_active": False, "height_metrics_dirty": False,
            "syncing_height": False, "workspace_minimum_height": 118, "workspace_layout_height_for_width": 118,
            "caption_exact_text": "Selected saved source: TEST_ONLY_SYNTHETIC\nRoot cause: UNKNOWN",
            "workspace_layout_rect": [0, 0, 600, 118], "parent_layout_rect": [0, 0, 650, 1000],
            "parent_contents_rect": [0, 0, 650, 1000]}
    proof["layout_readiness"] = [{"stage": row["stage"], "language": row["language"],
        "geometry_view": "AT_REPORT_TOP_AFTER_SCREENSHOT" if row["reveal_top"] else "SAME_VIEW_BEFORE_SCREENSHOT",
        "initial_observed_before_event_drain": True, "timeout_seconds": 2.0, "wait_step_seconds": .02,
        "settled": True, "samples": 2, "stable_valid_samples": 2, "elapsed_seconds": .02,
        "initial": deepcopy(row), "final": deepcopy(row)} for row in proof["anchor_geometry"]]
    for language in ("EN", "RU"):
        proof["recordings"].append({"language": language, "scope": "REAL_GUI_PROCESS_RECORDING",
            "samples": 3, "recorded_pid": 123, "research_helper_pid": 456, "recorded_status": "COMPLETED",
            "selected_session_matches": True, "handoff_actual_qt_input": True,
            "report_html_unknown_preserved": True, "source_files_unchanged_after_review": True,
            "files": {name: {"sha256": "b" * 64, "bytes": 128}
                      for name in ("session.sqlite3", "report.json", "report.html")},
            "recorded_sources": {name: {"sha256": "b" * 64, "bytes": 128}
                                 for name in ("session.sqlite3", "session-v2.sqlite3")}})
        for stage in ("saved-report", "fixture-findings", "fixture-minimum-width", "fixture-incident-card", "fixture-events"):
            proof["screenshots"].append({"id": stage + language, "source_sha": source_sha,
                "language": language, "scale": "1", "frozen": False, "bytes": 128, "sha256": "c" * 64,
                "stage": stage,
                "logical_window_client": [1020, 850] if stage == "fixture-minimum-width" else [1440, 1000],
                "scope": "REAL_GUI_PROCESS_RECORDING" if stage == "saved-report" else "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"})
    return proof


class ExpertReceiptGateTests(unittest.TestCase):
    def validate(self, proof):
        return validate_receipt(proof, source_sha="a" * 40, frozen=False, scale="1")

    def test_gate_accepts_complete_separately_labelled_evidence(self):
        proof = passed_receipt()
        self.assertIs(self.validate(proof), proof)

    def test_gate_refuses_unbound_source_form_scale_and_physical_claims(self):
        for path, value in ((("source_sha",), "d" * 40), (("source_identity", "actual_source_sha"), "d" * 40),
                            (("source_identity", "tracked_worktree_clean"), False), (("frozen",), True),
                            (("scale",), "2"), (("physical_windows_10_11",), "PASS"),
                            (("secure_desktop",), "PASS")):
            proof = deepcopy(passed_receipt())
            target = proof
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AssertionError):
                self.validate(proof)

    def test_gate_refuses_fixture_relabelled_as_real_or_incomplete_stop_and_selection(self):
        for path, value in ((("fixture", "scope"), "REAL_GUI_PROCESS_RECORDING"),
                            (("fixture", "source_unchanged"), False),
                            (("fixture", "raw_json_roundtrip"), False),
                            (("cleanup", "owners_closed"), False),
                            (("recordings", 0, "samples"), 0),
                            (("recordings", 0, "research_helper_pid"), 123),
                            (("recordings", 0, "handoff_actual_qt_input"), False),
                            (("recordings", 0, "recorded_status"), "RECORDING"),
                            (("recordings", 0, "source_files_unchanged_after_review"), False),
                            (("minimum_width", 0, "logical_window_client"), [1440, 1000]),
                            (("minimum_width", 0, "outer_horizontal_scroll_maximum"), 114),
                            (("minimum_width", 0, "research_panel_width"), 902),
                            (("minimum_width", 0, "library_panel_width"), 902),
                            (("screenshots", 0, "source_sha"), "d" * 40)):
            proof = deepcopy(passed_receipt())
            target = proof
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AssertionError):
                self.validate(proof)

    def test_clicked_anchor_cannot_substitute_for_unclipped_button_geometry(self):
        for path, value in ((("anchor_geometry",), []),
                            (("anchor_geometry", 0, "geometry_view"), "AT_REPORT_TOP_AFTER_SCREENSHOT"),
                            (("anchor_geometry", 1, "reveal_top"), False),
                            (("anchor_geometry", 1, "scroll_at_probe"), 300),
                            (("anchor_geometry", 0, "workspace_before_timeline"), False),
                            (("anchor_geometry", 0, "buttons", 3, "visible_bounds"), [0, 0, 200, 10]),
                            (("anchor_geometry", 0, "buttons", 3, "siblings_disjoint"), False),
                            (("anchor_geometry", 0, "buttons", 3, "ancestors_contain"), False),
                            (("anchor_geometry", 0, "buttons", 3, "minimum_size_met"), False)):
            proof = deepcopy(passed_receipt())
            target = proof
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AssertionError):
                self.validate(proof)

    def test_gate_refuses_wrapped_context_without_actual_caption_geometry(self):
        for key, value in (("has_height_for_width", False), ("policy_has_height_for_width", False),
                           ("allocated_height", 24), ("visible_bounds", [0, 0, 600, 13]),
                           ("workspace_contains", False), ("no_button_overlap", False)):
            proof = deepcopy(passed_receipt())
            proof["anchor_geometry"][0]["caption"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, 'WRAPPED_CAPTION_CLIPPED'):
                self.validate(proof)

    def test_gate_refuses_unbounded_unstable_or_relabelled_layout_readiness(self):
        for key, value in (("settled", False), ("samples", 1), ("stable_valid_samples", 1),
                           ("elapsed_seconds", 2.1), ("elapsed_seconds", float('inf')),
                           ("timeout_seconds", 20), ("initial_observed_before_event_drain", False),
                           ("geometry_view", "AT_REPORT_TOP_AFTER_SCREENSHOT")):
            proof = passed_receipt(); proof["layout_readiness"][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, 'NATURALLY_SETTLED'):
                self.validate(proof)
        for key, value in (("height_timer_active", True), ("height_metrics_dirty", True),
                           ("syncing_height", True), ("workspace_minimum_height", 0),
                           ("caption_exact_text", None)):
            proof = passed_receipt(); proof["layout_readiness"][0]["final"]["layout_diagnostics"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, 'NATURALLY_SETTLED'):
                self.validate(proof)
        proof = passed_receipt(); proof["layout_readiness"][0]["final"]["workspace_before_timeline"] = False
        with self.assertRaisesRegex(AssertionError, 'NATURALLY_SETTLED'):
            self.validate(proof)
        for key in ("height_timer_active", "workspace_minimum_height", "workspace_layout_height_for_width",
                    "height_metrics_dirty", "syncing_height", "parent_layout_rect", "caption_exact_text"):
            proof = passed_receipt(); del proof["layout_readiness"][0]["initial"]["layout_diagnostics"][key]
            with self.subTest(missing_initial_state=key), self.assertRaisesRegex(AssertionError, 'NATURALLY_SETTLED'):
                self.validate(proof)


class ExpertNaturalLayoutReadinessTests(unittest.TestCase):
    """Controlled clock/event witnesses for the exact bounded observation loop."""

    def observe(self, observations):
        clock = [0.0]
        drains = []
        samples = iter(observations)
        final = observations[-1]

        def read():
            return deepcopy(next(samples, final))

        def wait(seconds):
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, .02)
            clock[0] += seconds

        initial = deepcopy(observations[0])
        result = observe_layout_readiness(initial, read, lambda: drains.append(clock[0]), wait,
                                          clock=lambda: clock[0])
        self.assertEqual(len(drains), result["samples"])
        return result

    def test_pending_then_healthy_requires_two_identical_quiescent_strict_observations(self):
        good = deepcopy(passed_receipt()["anchor_geometry"][0])
        pending = deepcopy(good)
        pending["caption"]["allocated_height"] = 24
        pending["layout_diagnostics"]["height_timer_active"] = True
        changed = deepcopy(good); changed["layout_diagnostics"]["caption_exact_text"] += " updated"
        proof = self.observe([pending, good, changed, changed])
        self.assertTrue(proof["settled"])
        self.assertEqual(proof["initial"], pending)
        self.assertEqual(proof["final"], changed)
        self.assertEqual(proof["samples"], 4)
        self.assertEqual(proof["stable_valid_samples"], 2)
        self.assertLessEqual(proof["elapsed_seconds"], 2)

    def test_persistent_clipping_times_out_instead_of_certifying_or_repairing_geometry(self):
        bad = deepcopy(passed_receipt()["anchor_geometry"][0])
        bad["caption"]["allocated_height"] = 24
        original = deepcopy(bad)
        proof = self.observe([bad])
        self.assertFalse(proof["settled"])
        self.assertEqual(proof["stable_valid_samples"], 0)
        self.assertEqual(proof["initial"], original)
        self.assertEqual(proof["final"], original)
        self.assertLessEqual(proof["elapsed_seconds"], 2)
        self.assertLessEqual(proof["samples"], 101)
        self.assertEqual(bad, original)

    def test_valid_but_still_pending_or_dirty_cannot_claim_natural_readiness(self):
        for key in ("height_timer_active", "height_metrics_dirty", "syncing_height"):
            pending = deepcopy(passed_receipt()["anchor_geometry"][0])
            pending["layout_diagnostics"][key] = True
            with self.subTest(key=key):
                self.assertFalse(self.observe([pending])["settled"])


if __name__ == "__main__":
    unittest.main()
