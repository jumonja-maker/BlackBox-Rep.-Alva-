"""Hosted Qt state regressions for recorded analysis and expert navigation.

The interval reader is a controlled signal fixture: these tests exercise the
real widgets and callbacks without starting capture, workers or native tools.
Synthetic DTOs make no source-authenticity or physical Windows claims.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog

from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.timeline import SessionTimeline
from blackbox_universal.window import UniversalWindow
from qt_test_support import close_and_drain, dispose_closed_fixture


class ControlledIntervalReader(QObject):
    result_ready = Signal(object, str)
    finished = Signal()

    def __init__(self, folder, parent=None, **options):
        super().__init__(parent)
        self.folder = Path(folder)
        self.options = options
        self.started = False
        self.interrupted = False

    def start(self):
        self.started = True

    def requestInterruption(self):
        self.interrupted = True

    def complete(self, packet=None, error=""):
        self.result_ready.emit(packet, error)
        self.finished.emit()


def recorded_interval(folder, *, instance=1, pid=4321):
    """Small recorded DTO with recognizable, independently selectable evidence."""
    origin = 10_000_000_000
    lo, hi = origin+1_000_000_000, origin+2_000_000_000
    metrics = {key: {"max": None, "unit": "TEST_ONLY"} for key in SessionTimeline.TRACKS}
    metrics["cpu_interval_percent"]["max"] = 78.9
    metrics["rss_bytes"]["max"] = 23*1048576
    process = {"instance_id": instance, "pid": pid, "creation_time": 0,
               "executable_name": "TEST_ONLY_PROCESS_A", "first_observed_ns": lo,
               "last_observed_ns": hi, "resources": {}}
    event = {"event_time_ns": lo, "observed_ns": lo, "recorded_ns": lo,
             "event_type": "TEST_ONLY_EVENT_A", "source_kind": "OBSERVER",
             "verification_class": "UNVERIFIED_IMPORT", "recorded_verification_class": "OBSERVED",
             "detail": {"marker": "TEST_ONLY_EVENT_A"}}
    return {"folder": str(folder), "interval": {
        "instance_id": instance, "metadata": {"pid": pid, "creation_time": 0,
            "monotonic_origin_ns": origin, "recorded_status": "CLOSED",
            "file_trust": "UNVERIFIED_IMPORT", "clock_quality": "TEST_ONLY_CLOCK"},
        "selected_interval_ns": [lo, hi], "series": "STANDARD" if instance == 1 else "CHILD",
        "coverage": {"selected_samples": 2, "total_samples": 2,
                     "spacing_gap_pairs": 0, "sensor_error_records": 0},
        "metrics": metrics, "warnings": [],
        "process_tree_totals": {"root_rss_peak_bytes": 23*1048576,
                                "observed_tree_rss_peak_bytes": 31*1048576},
        "timeline": {"tracks": {key: [] for key in SessionTimeline.TRACKS},
                     "events": {"tracks": {}}}},
        "threads": {"instance_id": instance, "pid": pid, "status": "TEST_ONLY_THREADS_A", "top_threads": [
            {"tid": 2468, "segment_start_seq": 1, "cpu_percent": 2,
             "peak_cpu_percent": 3, "observed_pairs": 1}]},
        "processes": {"rows": [process], "has_more": False,
                      "root_instance_id": instance, "total_instances": 1},
        "events": {"rows": [event], "has_more": False, "next_cursor": None}}


class ExpertNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.environ.get("GITHUB_ACTIONS") == "true" and
                os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
            raise AssertionError("EXPERT_QT_TESTS_REQUIRE_GITHUB_HOSTED_RUNNER")
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source_a, self.source_b = self.root/"recorded-A", self.root/"recorded-B"
        self.windows = []
        self.callback_errors = []
        old_hook = sys.excepthook
        sys.excepthook = lambda kind, value, tb: self.callback_errors.append(
            "".join(traceback.format_exception(kind, value, tb)))
        self.addCleanup(setattr, sys, "excepthook", old_hook)
        for fixture in (
                patch("blackbox_universal.window.SessionIntervalWorker", ControlledIntervalReader),
                patch("blackbox_universal.window.available_processes", return_value=[]),
                patch("blackbox_universal.chain_bridge.ChainBuilderBridge.submit", return_value=None)):
            fixture.start()
            self.addCleanup(fixture.stop)
        self.window = self.make_window()

    def make_window(self, kind=UniversalWindow):
        window = kind(isolated=False, output_root=self.root/str(len(self.windows)), allow_update_check=False)
        self.windows.append(window)
        window._timer.stop()
        window._set_language("EN")
        return window

    def tearDown(self):
        for window in reversed(self.windows):
            # Controlled readers own no thread, files or sensor. Release their
            # signal lifecycle before draining the real widget owners.
            window._interval_pending = None
            if isinstance(window._interval_worker, ControlledIntervalReader):
                window._interval_worker.complete(None, "CANCELLED")
            close_and_drain(window, self.app, timeout=10)
        self.assertEqual(self.callback_errors, [], "Qt callback exceptions must fail this regression gate")

    def load_recorded_a(self, *, instance=1):
        window = self.window
        window._load_session_interval(self.source_a, instance_id=instance)
        value = recorded_interval(self.source_a, instance=instance)
        window._interval_worker.complete(value)
        self.assertIs(window._interval_packet, value)
        return value

    def add_evidence_panel_rows(self):
        """Populate each real panel from a synthetic DTO, without a query."""
        window = self.window
        lo, hi = window._interval_packet["interval"]["selected_interval_ns"]
        finding = {"finding_id": "TEST_ONLY_FINDING_A", "code": "CPU_SUSTAINED",
                   "start_ns": lo, "end_ns": hi, "confidence_class": "OBSERVATION_ONLY",
                   "severity": "WARNING"}
        analysis = window.analysis_panel
        analysis.raw.setChecked(True)
        analysis.packet = {"metadata": {"monotonic_origin_ns": lo}, "findings": [finding],
            "findings_total": 1, "has_more": False, "next_cursor": None,
            "coverage": {"selected_samples": 2, "spacing_gap_pairs": 0},
            "summary": {"support": {"metrics": window._interval_packet["interval"]["metrics"]}},
            "file_trust": "UNVERIFIED_IMPORT"}
        analysis.render()
        events = window.events_panel
        events.raw.setChecked(True)
        events.packet = {"monotonic_origin_ns": lo, "rows": [{"time_ns": lo,
            "code": "TEST_ONLY_UNIFIED_EVENT_A", "source": "OBSERVER", "severity": "INFO",
            "evidence_ref": "TEST_ONLY_EVENT_REF_A", "rank": 0, "id": 1}],
            "total_matching": 1, "has_more": False, "next_cursor": None,
            "source_trust": "UNVERIFIED_IMPORT"}
        events.render()
        self.assertIn("TEST_ONLY_FINDING_A", analysis.details.toPlainText())
        self.assertIn("TEST_ONLY_UNIFIED_EVENT_A", events.details.toPlainText())

    def assert_old_recording_not_visible(self):
        window = self.window
        self.assertIsNone(window._interval_packet)
        self.assertIsNone(window.session_timeline.payload)
        self.assertEqual(window.session_event_table.rowCount(), 0)
        self.assertEqual(window.process_history_table.topLevelItemCount(), 0)
        self.assertEqual(window.thread_detail_table.rowCount(), 0)
        self.assertEqual(window.session_event_details.toPlainText(), "")
        self.assertNotIn("TEST_ONLY_THREADS_A", window.thread_detail_status.text())
        self.assertNotIn("78.9", window.interval_summary.text())
        self.assertNotIn("31.00", window.process_history_summary.text())
        self.assertFalse(window.export_interval_btn.isEnabled())
        for panel in (window.analysis_panel, window.events_panel):
            self.assertIsNone(panel.packet)
            self.assertIsNone(panel.card_packet)
            self.assertEqual(panel.table.rowCount(), 0)
            self.assertEqual(panel.details.toPlainText(), "")
            self.assertFalse(panel.isEnabled())
            self.assertTrue(all("78.90" not in label.text() for label in panel.summaries))

    def test_review_blocks_active_finalizing_pending_and_missing_source(self):
        window = self.window
        window.probe.session_folder = self.source_a
        window._report_state = "saved"
        cases = (
            (window.probe, "active", True), (window.probe, "session_folder", None),
            (window, "_report_state", "saving"), (window, "_report_state", "recording"),
            (window, "_report_worker", object()), (window, "_pending_base_stop", "USER_STOPPED"),
            (window, "_pending_close", True),
        )
        for owner, attribute, value in cases:
            with self.subTest(attribute=attribute, value=value), patch.object(owner, attribute, value), \
                 patch.object(window, "_load_session_interval") as read:
                window._refresh_expert_context()
                self.assertFalse(window.review_result_button.isEnabled())
                self.assertFalse(window._expert_actions["review"].isEnabled())
                window._review_latest_recording()
                read.assert_not_called()
                self.assertEqual(window.stack.currentIndex(), window._page_ids["dashboard"])
        with patch.object(window, "_isolated", True), \
             patch.object(window.probe, "pending", True, create=True), \
             patch.object(window, "_load_session_interval") as read:
            window._refresh_expert_context()
            self.assertFalse(window.review_result_button.isEnabled())
            window._review_latest_recording()
            read.assert_not_called()

    def test_review_handoff_opens_recorded_evidence_without_changing_live_target(self):
        window = self.window
        window.probe.pid = 98765
        window.probe.session_folder = self.source_a
        window._set_report_status("saved")
        with patch.object(window.probe, "attach") as attach, patch.object(window.probe, "start") as start:
            window.review_result_button.click()
            reader = window._interval_worker
            self.assertIsInstance(reader, ControlledIntervalReader)
            self.assertTrue(reader.started)
            reader.complete(recorded_interval(self.source_a))
            attach.assert_not_called()
            start.assert_not_called()
        self.assertEqual(window.stack.currentIndex(), window._page_ids["reports"])
        self.assertEqual(window.probe.pid, 98765)
        self.assertFalse(window.probe.active)
        self.assertFalse(window.deep_inspector_panel.bridge.has_session)
        self.assertIn(str(self.source_a), window.report_context.text())
        context_values = "\n".join(window.report_context.text().splitlines()[1:])
        self.assertIn("4321", context_values)
        self.assertNotIn("98765", context_values)

    def test_queued_source_or_instance_switch_clears_old_visible_evidence_immediately(self):
        window = self.window
        for next_folder, next_instance in ((self.source_b, 1), (self.source_a, 7)):
            with self.subTest(folder=next_folder, instance=next_instance):
                self.load_recorded_a()
                self.add_evidence_panel_rows()
                window.session_event_details.setPlainText("TEST_ONLY_SELECTED_EVENT_A")
                # Hold A's refresh so the new selection must enter the queue.
                window._load_session_interval(self.source_a)
                old_reader = window._interval_worker
                window._load_session_interval(next_folder, instance_id=next_instance)
                self.assertTrue(old_reader.interrupted)
                self.assertEqual(window._interval_folder, next_folder)
                self.assertEqual(window._interval_process, next_instance)
                self.assertIn(str(next_folder), window.report_context.text())
                self.assertNotIn("4321", "\n".join(window.report_context.text().splitlines()[1:]))
                self.assert_old_recording_not_visible()
                # A's late success must not repopulate the selected B/child.
                old_reader.complete(recorded_interval(self.source_a))
                self.assert_old_recording_not_visible()
                window._interval_worker.complete(recorded_interval(next_folder, instance=next_instance, pid=6543))
                self.assertIn("6543", "\n".join(window.report_context.text().splitlines()[1:]))
                self.assertTrue(window.analysis_panel.isEnabled())
                self.assertTrue(window.events_panel.isEnabled())

    def test_failed_refresh_clears_prior_rows_details_summaries_and_export(self):
        window = self.window
        self.load_recorded_a()
        self.add_evidence_panel_rows()
        window.session_event_details.setPlainText("TEST_ONLY_SELECTED_EVENT_A")
        window._load_session_interval(self.source_a)
        window._interval_worker.complete(None, "SESSION_INTERVAL_UNAVAILABLE")
        self.assertTrue(window._interval_read_error)
        self.assert_old_recording_not_visible()
        self.assertIn(str(self.source_a), window.report_context.text())
        self.assertNotIn("4321", "\n".join(window.report_context.text().splitlines()[1:]))

    def test_late_standalone_thread_result_cannot_replace_another_recording_or_child(self):
        window = self.window
        window.probe.session_folder = self.source_a
        for selected_folder, selected_instance in ((self.source_b, 1), (self.source_a, 7)):
            with self.subTest(folder=selected_folder, instance=selected_instance):
                window._load_session_interval(selected_folder, instance_id=selected_instance)
                window._interval_worker.complete(recorded_interval(selected_folder, instance=selected_instance, pid=6543))
                current = window._thread_detail_payload
                old_threads = recorded_interval(self.source_a)["threads"]
                old_threads["status"] = "TEST_ONLY_STALE_THREADS"
                old_threads["top_threads"][0]["tid"] = 1122
                # Legacy standalone thread DTOs do not identify an instance.
                old_threads.pop("instance_id")
                window._thread_detail_ready({"folder": str(self.source_a), "analysis": old_threads}, "")
                self.assertIs(window._thread_detail_payload, current)
                self.assertNotIn("TEST_ONLY_STALE_THREADS", window.thread_detail_status.text())
                self.assertNotEqual(window.thread_detail_table.item(0, 0).text(), "1122")

    def test_late_export_receipt_or_error_does_not_replace_new_source_child_or_range_summary(self):
        window = self.window
        receipt = {"manifest": str(self.root/"TEST_ONLY_EXPORT_A.manifest.json")}
        for selection in ("folder", "child", "range"):
            for error in ("", "TEST_ONLY_EXPORT_ERROR_A"):
                with self.subTest(selection=selection, error=error):
                    exported = self.load_recorded_a()["interval"]
                    owner = SimpleNamespace(folder=self.source_a, options={
                        "instance_id": 1, "interval": tuple(exported["selected_interval_ns"])})
                    selected_folder = self.source_b if selection == "folder" else self.source_a
                    selected_instance = 7 if selection == "child" else 1
                    value = recorded_interval(selected_folder, instance=selected_instance)
                    if selection == "range":
                        value["interval"]["selected_interval_ns"] = [
                            bound+100_000_000 for bound in exported["selected_interval_ns"]]
                    with patch.object(window, "_interval_export_worker", owner):
                        window._load_session_interval(selected_folder,
                            value["interval"]["selected_interval_ns"], instance_id=selected_instance)
                        window._interval_worker.complete(value)
                        summary = window.interval_summary.text()
                        window._session_export_ready(receipt if not error else None, error)
                        self.assertEqual(window._interval_export_result,
                                         {"error": error} if error else receipt)
                        self.assertEqual(window.interval_summary.text(), summary)

    def test_export_receipts_stay_cached_without_overwriting_loading_or_queued_context(self):
        window = self.window
        exported = self.load_recorded_a()["interval"]
        owner = SimpleNamespace(folder=self.source_a, options={
            "instance_id": 1, "interval": tuple(exported["selected_interval_ns"])})
        receipt = {"manifest": str(self.root/"TEST_ONLY_EXPORT_A.manifest.json")}
        with patch.object(window, "_interval_export_worker", owner):
            window._load_session_interval(self.source_a)
            reader = window._interval_worker
            summary = window.interval_summary.text()
            window._session_export_ready(receipt, "")
            self.assertIs(window._interval_export_result, receipt)
            self.assertEqual(window.interval_summary.text(), summary)
            window._load_session_interval(self.source_b)
            queued_summary = window.interval_summary.text()
            window._session_export_ready(None, "TEST_ONLY_EXPORT_ERROR_A")
            self.assertEqual(window._interval_export_result, {"error": "TEST_ONLY_EXPORT_ERROR_A"})
            self.assertEqual(window.interval_summary.text(), queued_summary)
            reader.complete(recorded_interval(self.source_a))
            window._interval_worker.complete(recorded_interval(self.source_b))

    def test_matching_export_receipt_and_error_update_current_summary_and_remain_cached(self):
        window = self.window
        exported = self.load_recorded_a()["interval"]
        owner = SimpleNamespace(folder=self.source_a, options={
            "instance_id": 1, "interval": tuple(exported["selected_interval_ns"])})
        receipt = {"manifest": str(self.root/"TEST_ONLY_CURRENT_EXPORT.manifest.json")}
        with patch.object(window, "_interval_export_worker", owner):
            window._session_export_ready(receipt, "")
            self.assertIs(window._interval_export_result, receipt)
            self.assertIn(receipt["manifest"], window.interval_summary.text())
            window._session_export_ready(None, "TEST_ONLY_CURRENT_EXPORT_ERROR")
            self.assertEqual(window._interval_export_result, {"error": "TEST_ONLY_CURRENT_EXPORT_ERROR"})
            self.assertIn("TEST_ONLY_CURRENT_EXPORT_ERROR", window.interval_summary.text())

    def test_comparison_survives_navigation_language_and_explicit_live_switch(self):
        window = self.window
        comparison = {"TEST_ONLY_COMPARISON": {"zero": 0, "unknown": None, "false": False}}
        with patch("blackbox_universal.window.QFileDialog.getExistingDirectory",
                   side_effect=[str(self.source_a), str(self.source_b)]), \
             patch("blackbox_universal.window.compare_sessions", return_value=comparison) as compare:
            window._compare_sessions()
            self.assertEqual(json.loads(window.report_preview.toPlainText()), comparison)
            for language in ("RU", "EN"):
                window._navigate("dashboard")
                window._set_language(language)
                window._navigate("reports")
                self.assertEqual(json.loads(window.report_preview.toPlainText()), comparison)
                self.assertIn(str(self.source_a), window.report_preview_source.text())
                self.assertIn(str(self.source_b), window.report_preview_source.text())
            compare.assert_called_once_with(self.source_a, self.source_b)
            window.live_snapshot_button.click()
            self.assertNotIn("TEST_ONLY_COMPARISON", window.report_preview.toPlainText())
            window.last_comparison_button.click()
            self.assertEqual(json.loads(window.report_preview.toPlainText()), comparison)
            compare.assert_called_once()

    def test_late_async_comparison_is_cached_without_replacing_selected_live_snapshot(self):
        window = self.window
        window.probe.pid = 98765
        snapshot = {"pid": 98765, "recent_samples": [{"cpu_percent": None}],
                    "recent_events": [], "TEST_ONLY_LIVE": True}
        comparison = {"TEST_ONLY_LATE_COMPARISON": {"missing": None}}
        with patch.object(window, "_isolated", True), \
             patch.object(window.probe, "pending", False, create=True), \
             patch.object(window.probe, "send", create=True) as send, \
             patch.object(window.probe, "snapshot", side_effect=lambda: deepcopy(snapshot)), \
             patch("blackbox_universal.window.QFileDialog.getExistingDirectory",
                   side_effect=[str(self.source_a), str(self.source_b)]):
            window._compare_sessions()
            send.assert_called_once_with("compare", before=str(self.source_a), after=str(self.source_b))
            self.assertFalse(window.compare_sessions_button.isEnabled())
            window.live_snapshot_button.click()
            self.assertEqual(json.loads(window.report_preview.toPlainText()), snapshot)
            window._research_result("compare", comparison, "")
            self.assertEqual(json.loads(window.report_preview.toPlainText()), snapshot)
            self.assertNotIn("TEST_ONLY_LATE_COMPARISON", window.report_preview.toPlainText())
            window.last_comparison_button.click()
            self.assertEqual(json.loads(window.report_preview.toPlainText()), comparison)
            self.assertTrue(window.compare_sessions_button.isEnabled())
        self.assertEqual(window.probe.pid, 98765)
        self.assertFalse(window.probe.active)

    def test_helper_exit_releases_loading_comparison_without_replacing_selected_live_snapshot(self):
        window = self.window
        window.probe.pid = 98765
        snapshot = {"pid": 98765, "recent_samples": [], "recent_events": [],
                    "TEST_ONLY_LIVE_AFTER_HELPER_EXIT": {"unknown": None, "zero": 0}}
        for live_selected in (False, True):
            with self.subTest(live_selected=live_selected), \
                 patch.object(window, "_isolated", True), \
                 patch.object(window.probe, "pending", False, create=True), \
                 patch.object(window.probe, "send", create=True), \
                 patch.object(window.probe, "snapshot", side_effect=lambda: deepcopy(snapshot)), \
                 patch("blackbox_universal.window.QFileDialog.getExistingDirectory",
                       side_effect=[str(self.source_a), str(self.source_b)]):
                window._compare_sessions()
                loading_text = window.report_preview.toPlainText()
                self.assertFalse(window.compare_sessions_button.isEnabled())
                if live_selected:
                    window.live_snapshot_button.click()
                    self.assertEqual(json.loads(window.report_preview.toPlainText()), snapshot)
                window._research_terminated()
                self.assertEqual(window._comparison_state, "failed")
                self.assertIsNone(window._comparison_preview)
                self.assertTrue(window.compare_sessions_button.isEnabled())
                self.assertFalse(window.last_comparison_button.isEnabled())
                if live_selected:
                    self.assertEqual(json.loads(window.report_preview.toPlainText()), snapshot)
                else:
                    self.assertNotEqual(window.report_preview.toPlainText(), loading_text)
        self.assertEqual(window.probe.pid, 98765)
        self.assertFalse(window.probe.active)

    def test_modal_and_closing_shortcuts_cannot_change_page_or_review(self):
        window = self.window
        window.probe.session_folder = self.source_a
        window._set_report_status("saved")
        window.show()
        window.activateWindow()
        self.app.processEvents()
        dialog = QDialog(window)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        dialog.show()
        self.app.processEvents()
        try:
            self.assertIs(QApplication.activeModalWidget(), dialog)
            with patch.object(window, "_load_session_interval") as read:
                window._expert_actions["reports"].trigger()
                window._expert_actions["search"].trigger()
                window._expert_actions["review"].trigger()
                self.assertEqual(window.stack.currentIndex(), window._page_ids["dashboard"])
                read.assert_not_called()
        finally:
            dialog.close()
            dispose_closed_fixture(dialog, self.app)
        with patch.object(window, "_pending_close", True), \
             patch.object(window, "_load_session_interval") as read:
            window._expert_actions["reports"].trigger()
            window._expert_actions["search"].trigger()
            window._expert_actions["review"].trigger()
            self.assertEqual(window.stack.currentIndex(), window._page_ids["dashboard"])
            read.assert_not_called()

    def test_ctrl_six_preserves_five_page_embedding_and_opens_production_decoder(self):
        for window, decoder_expected in ((self.window, False), (self.make_window(DecoderWindow), True)):
            with self.subTest(shell=type(window).__name__):
                window.show()
                window.activateWindow()
                window._navigate("dashboard")
                window.setFocus()
                self.app.processEvents()
                QTest.keyClick(window, Qt.Key.Key_6, Qt.KeyboardModifier.ControlModifier)
                self.app.processEvents()
                self.assertEqual(window.stack.count(), 6 if decoder_expected else 5)
                self.assertEqual(window.stack.currentIndex(),
                                 window._page_ids["decoder" if decoder_expected else "dashboard"])
                self.assertEqual("decoder" in window._expert_actions, decoder_expected)
                self.assertFalse(window.probe.active)
                self.assertIsNone(window.probe.session_folder)
                window.hide()


if __name__ == "__main__":
    unittest.main()
