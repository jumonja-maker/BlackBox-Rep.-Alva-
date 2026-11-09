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

from tools.qa_expert_workflow import PAGES, SECTIONS, digest, synthetic_recording, validate_receipt


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
        "recordings": [], "screenshots": [],
        "fixture": {"scope": "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE", "source_unchanged": True,
                    "languages": ["EN", "RU"], "finding_selection_actual_qt_input": True,
                    "event_selection_actual_qt_input": True, "incident_card_actual_qt_input": True,
                    "copy_detail_roundtrip": True, "raw_json_roundtrip": True, "root_cause": "UNKNOWN"}}
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


if __name__ == "__main__":
    unittest.main()
