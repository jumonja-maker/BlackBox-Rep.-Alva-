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

from PySide6.QtCore import QObject, QProcess, Qt, Signal
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog

from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.research_bridge import ResearchBridge
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


class CommandReplies(QObject):
    command_result = Signal(str,str,object,str)


class ControlledResearchQueue(ResearchBridge):
    """Real send/shutdown protocol against a process-free writable Qt facade."""
    def __init__(self, parent=None):
        QObject.__init__(self, parent)
        self.sent = []
        self.process = SimpleNamespace(
            state=lambda: QProcess.ProcessState.Running, bytesToWrite=lambda: 0,
            write=self.write_packet)
        self._pending = {str(index): "TEST_ONLY_PENDING" for index in range(64)}
        self._queue = []
        self.closing = False
        self._stop_deadline = None
        self.active = True
        self.last_error = "RECOVERY_UNCONFIRMED"
        self.session_state = "INTERRUPTED_UNCONFIRMED"

    def write_packet(self, packet):
        self.sent.append(json.loads(packet))
        return len(packet)


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

    def test_report_comparison_cache_accepts_only_its_exact_command_reply(self):
        window = self.window
        replies = CommandReplies(window)
        replies.command_result.connect(window._research_command_result)
        own = {"TEST_ONLY_MAIN_COMPARE": {"unknown":None,"zero":0}}
        foreign = {"TEST_ONLY_RESEARCH_COMPARE": True}
        with patch.object(window,"_isolated",True), \
             patch.object(window.probe,"pending",False,create=True), \
             patch.object(window.probe,"command_result",replies.command_result,create=True), \
             patch.object(window.probe,"send",return_value="MAIN_REQUEST",create=True), \
             patch("blackbox_universal.window.QFileDialog.getExistingDirectory",side_effect=[str(self.source_a),str(self.source_b)]):
            window._compare_sessions()
            replies.command_result.emit("RESEARCH_REQUEST","compare",foreign,"")
            window._research_result("compare",foreign,"")
            self.assertEqual(window._comparison_state,"loading")
            self.assertIsNone(window._comparison_preview)
            replies.command_result.emit("MAIN_REQUEST","compare",own,"")
            self.assertEqual(window._comparison_preview,own)
            self.assertEqual(window._comparison_sources,(str(self.source_a),str(self.source_b)))
            replies.command_result.emit("RESEARCH_REQUEST","compare",foreign,"")
            window._research_result("compare",foreign,"")
            self.assertEqual(json.loads(window.report_preview.toPlainText()),own)

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

    def test_live_attach_and_start_preserve_selected_historic_thread_evidence(self):
        window = self.window
        self.load_recorded_a(instance=7)
        current = window._thread_detail_payload
        cells = [window.thread_detail_table.item(0, column).text()
                 for column in range(window.thread_detail_table.columnCount())]
        with patch.object(window.probe, "attach", side_effect=lambda pid: setattr(window.probe, "pid", pid)), \
             patch.object(window.probe, "start"), patch.object(window, "_update_all"):
            window._attach_pid(98765)
            window._start()
        self.assertEqual(window.probe.pid, 98765)
        self.assertEqual(window._interval_folder, self.source_a)
        self.assertEqual(window._interval_process, 7)
        self.assertIs(window._thread_detail_payload, current)
        self.assertEqual([window.thread_detail_table.item(0, column).text()
                          for column in range(window.thread_detail_table.columnCount())], cells)
        self.assertIn("4321", window.thread_detail_status.text())
        self.assertNotIn("98765", window.thread_detail_status.text())

    def test_bridge_dispatch_failures_do_not_claim_start_stop_or_change_interval(self):
        window = self.window
        with patch.object(window, "_isolated", True), \
             patch.object(window.probe, "pending", False, create=True), \
             patch.object(window.probe, "stopping", False, create=True), \
             patch("blackbox_universal.window.QMessageBox.warning") as warning:
            original = window._report_state
            with patch.object(window.probe, "start", side_effect=RuntimeError("RESEARCH_HELPER_UNAVAILABLE")):
                window._start()
            self.assertEqual(window._report_state, original)
            self.assertFalse(window.probe.active)
            with patch.object(window.probe, "active", True), \
                 patch.object(window.probe, "stop", side_effect=RuntimeError("RESEARCH_COMMAND_QUEUE_FULL")):
                window._stop()
                self.assertTrue(window.probe.active)
                self.assertEqual(window._report_state, original)
            milliseconds = window._timer.interval()
            with patch.object(window.probe, "send", side_effect=RuntimeError("RESEARCH_HELPER_UNAVAILABLE"), create=True):
                window._refresh_process_list()
                self.assertIn("unavailable", window.process_count.text())
                window.interval_combo.setCurrentIndex(1)
                self.assertEqual(window._timer.interval(), milliseconds)
                self.assertEqual(window.interval_combo.currentData(), milliseconds)
                self.assertIn("INTERVAL_CHANGE_UNAVAILABLE", window.recent_messages.toPlainText())
                with patch.object(window.probe, "pid", 98765), \
                     patch("blackbox_universal.window.QFileDialog.getSaveFileName",
                           return_value=(str(self.root/"TEST_ONLY_EXPORT.json"), "JSON")):
                    window._export()
            self.assertEqual(warning.call_count, 3)
        for handler, command in ((window._prepare_action, "prepare_action"),
                                 (window._begin_action, "begin_action"),
                                 (window._end_action, "finish_action")):
            with self.subTest(command=command), \
                 patch.object(window.probe, command, side_effect=RuntimeError("RESEARCH_COMMAND_QUEUE_FULL")), \
                 patch.object(window, "_update_all"), \
                 patch("blackbox_universal.window.QMessageBox.warning") as warning:
                handler()
                warning.assert_called_once()

    def test_async_start_and_stop_errors_restore_cached_state_without_claiming_success(self):
        window = self.window
        for operation, active, report, folder, research_state, expected in (
                ("start", False, None, None, "NO_SESSION", "unavailable"),
                ("start", False, {"saved":True}, self.source_a, "COMPLETED", "saved"),
                ("stop", True, None, self.source_a, "RECORDING", "recording"),
                ("stop", False, {"saved": True}, self.source_a, "FINALIZATION_UNCONFIRMED", "unavailable")):
            with self.subTest(operation=operation, active=active, research_state=research_state), \
                 patch.object(window.probe, "active", active), \
                 patch.object(window.probe, "report_result", report), \
                 patch.object(window.probe, "session_folder", folder), \
                 patch.object(window.probe, "data", {"research_state": research_state}, create=True), \
                 patch.object(window.probe, "start") as start, patch.object(window.probe, "stop") as stop, \
                 patch.object(window, "_update_all"):
                window._report_state = "recording" if operation == "start" else "saving"
                window._research_result(operation, None, "TEST_ONLY_ASYNC_RECORDING_FAILURE")
                self.assertEqual(window._report_state, expected)
                self.assertEqual(window.probe.active, active)
                self.assertIs(window.probe.report_result,report)
                start.assert_not_called();stop.assert_not_called()
                self.assertIn("TEST_ONLY_ASYNC_RECORDING_FAILURE", window.recent_messages.toPlainText())

    def test_language_switch_does_not_restore_empty_labels_over_controller_errors(self):
        window = self.window
        window.capture_settings.receive("capture_policy",None,"TEST_ONLY_POLICY_FAILURE")
        window.recovery_panel.busy = True
        window.recovery_panel.receive("export_recovery_scan",None,"TEST_ONLY_RECOVERY_FAILURE")
        window.marker_panel.receive("user_marker",None,"TEST_ONLY_MARKER_FAILURE")
        window.chain_builder_panel._received("validate",None,"TEST_ONLY_CHAIN_FAILURE")
        window.library_panel._busy.add("library_query")
        window.library_panel.receive("library_query",None,"TEST_ONLY_LIBRARY_FAILURE")
        for language in ("RU","EN"):
            window._set_language(language)
            for panel, marker in ((window.capture_settings,"POLICY"),(window.recovery_panel,"RECOVERY"),
                                  (window.marker_panel,"MARKER"),(window.chain_builder_panel,"CHAIN"),
                                  (window.library_panel,"LIBRARY")):
                self.assertIn("TEST_ONLY_"+marker+"_FAILURE",panel.status.text())

    def test_queue_full_quit_submission_preserves_unknown_owner_and_can_retry(self):
        bridge = ControlledResearchQueue(self.window)
        original = dict(bridge._pending)
        with self.assertRaisesRegex(RuntimeError, "RESEARCH_COMMAND_QUEUE_FULL"):
            bridge.shutdown()
        self.assertFalse(bridge.closing)
        self.assertTrue(bridge.active)
        self.assertEqual(bridge.session_state, "INTERRUPTED_UNCONFIRMED")
        self.assertEqual(bridge.last_error, "RECOVERY_UNCONFIRMED")
        self.assertEqual(bridge._pending, original)
        self.assertEqual(bridge.sent, [])
        self.assertIsNone(bridge._stop_deadline)
        bridge._pending.pop("0")
        bridge.shutdown()
        self.assertTrue(bridge.closing)
        self.assertEqual(bridge.sent[-1]["op"], "quit")
        self.assertIn("quit", bridge._pending.values())
        self.assertIsNotNone(bridge._stop_deadline)
        bridge.shutdown()
        self.assertEqual(len(bridge.sent), 1)
        self.assertTrue(bridge.active, "Submitting quit is not a cleanup acknowledgement")

    def test_rejected_window_selection_restores_the_cached_hwnd(self):
        class CachedWindowSelection:
            @property
            def selected_hwnd(self):
                return 10

            @selected_hwnd.setter
            def selected_hwnd(self, _value):
                raise RuntimeError("RESEARCH_COMMAND_QUEUE_FULL")

        window = self.window
        window.window_selector.addItem("TEST_ONLY_WINDOW_A", 10)
        window.window_selector.addItem("TEST_ONLY_WINDOW_B", 20)
        window.window_selector.setCurrentIndex(window.window_selector.findData(10))
        with patch.object(window.probe, "window_capture", CachedWindowSelection()):
            window.window_selector.setCurrentIndex(window.window_selector.findData(20))
            self.assertEqual(window.window_selector.currentData(), 10)
            self.assertEqual(window.probe.window_capture.selected_hwnd, 10)
            self.assertEqual(window.window_capture_status.text(), "WINDOW_SELECTION_UNAVAILABLE")

    def test_rejected_window_shutdown_stays_visible_and_retries_after_dispatch_recovers(self):
        window = self.window
        window._chain_close_complete = True
        window.show()
        self.app.processEvents()
        with patch.object(window, "_isolated", True), \
             patch.object(window.probe, "alive", True, create=True), \
             patch.object(window.probe, "pending", False, create=True), \
             patch.object(window.probe, "shutdown", side_effect=RuntimeError("RESEARCH_COMMAND_QUEUE_FULL"), create=True), \
             patch("blackbox_universal.window.QMessageBox.warning") as warning:
            self.assertFalse(window.close())
            self.assertTrue(window.isVisible())
            self.assertFalse(window._pending_close)
            self.assertTrue(window._timer.isActive())
            warning.assert_called_once()
        window._timer.stop()
        with patch.object(window, "_isolated", True), \
             patch.object(window.probe, "alive", True, create=True), \
             patch.object(window.probe, "shutdown", create=True) as shutdown:
            self.assertFalse(window.close())
            self.assertTrue(window._pending_close)
            self.assertTrue(window.isVisible())
            shutdown.assert_called_once()
            window.probe.alive = False
            window._research_terminated()
            self.app.processEvents()
            self.assertFalse(window.isVisible())
            self.assertFalse(window._pending_close)

    def test_each_window_owned_reader_completion_resumes_deferred_close(self):
        for field, callback in (("_thread_detail_worker", "_thread_detail_finished"),
                                ("_investigation_worker", "_investigation_finished"),
                                ("_update_worker", "_worker_finished")):
            with self.subTest(owner=field):
                window = self.make_window()
                window._chain_close_complete = True
                reader = ControlledIntervalReader(self.source_a, window)
                setattr(window, field, reader)
                reader.finished.connect(getattr(window, callback))
                window.show()
                self.app.processEvents()
                self.assertFalse(window.close())
                self.assertTrue(window.isVisible())
                self.assertTrue(window._pending_close)
                reader.finished.emit()
                self.app.processEvents()
                self.assertIsNone(getattr(window, field))
                self.assertFalse(window.isVisible())
                self.assertFalse(window._pending_close)

    def test_closing_suppresses_queued_update_investigation_and_recorded_reads(self):
        window = self.window
        window.probe.session_folder = self.source_a
        window.show()
        with patch("blackbox_universal.window._UpdateWorker") as update, \
             patch("blackbox_universal.window.InvestigationWorker") as investigation, \
             patch("blackbox_universal.window.SessionIntervalWorker") as interval, \
             patch("blackbox_universal.window.ThreadDetailWorker") as threads:
            window._investigation_retry = (self.source_a, (0, 1000))
            window._schedule_investigation_retry()
            with patch.object(window, "_pending_close", True):
                self.app.processEvents()  # Deliver the already-queued retry.
                window._automatic_update_check()
                window._check_updates()
                window._update_click()
                window._begin_investigation(folder=self.source_a)
                window._load_session_interval(self.source_a)
                window._load_thread_detail()
                window._investigation_retry = (self.source_a, (0, 1000))
                window._schedule_investigation_retry()
                self.assertIsNone(window._investigation_retry)
            for factory in (update, investigation, interval, threads):
                factory.assert_not_called()

    def test_export_modal_cannot_switch_the_consented_source_or_use_a_loading_packet(self):
        window = self.window
        for completed in (False, True):
            with self.subTest(completed=completed):
                self.load_recorded_a()
                def change_source_during_dialog():
                    window._load_session_interval(self.source_b)
                    if completed:
                        window._interval_worker.complete(recorded_interval(self.source_b))
                    return QDialog.DialogCode.Accepted
                with patch("blackbox_universal.window.QDialog.exec", side_effect=change_source_during_dialog), \
                     patch("blackbox_universal.window.QFileDialog.getExistingDirectory", return_value=str(self.root)), \
                     patch("blackbox_universal.window.SessionExportWorker") as export:
                    window._export_session_interval()
                    export.assert_not_called()
                if window._interval_worker is not None:
                    window._interval_worker.complete(recorded_interval(self.source_b))

    def test_reports_and_expert_buttons_fit_minimum_width_in_both_languages(self):
        from blackbox_universal.theme import set_retro_theme
        set_retro_theme(self.app)
        window = self.window
        window.show()
        window._navigate("reports")
        self.app.processEvents()
        # A selected source may wrap across several lines. The controlled
        # reader keeps this presentation test independent of path access.
        source = self.root / ("recorded-source-" * 12) / ("selected-source-" * 12)
        window._load_session_interval(source)
        window._interval_worker.complete(recorded_interval(source))
        self.assertTrue(window.report_context.wordWrap())
        self.assertTrue(window.report_context.hasHeightForWidth())
        self.assertTrue(window.report_context.sizePolicy().hasHeightForWidth())
        self.assertGreater(window.report_context.heightForWidth(350),
                           window.report_context.heightForWidth(1100))
        buttons = (*window.expert_section_buttons.values(), window.copy_context_button)
        workspace = window.report_context.parentWidget()
        timeline = window._expert_sections["timeline"]
        # The screenshot regression occurred with saved context and the
        # optional panels collapsed. Exercise expansion and both reflow
        # directions without manually assigning any child geometry.
        for expanded in (False, True):
            window.research_toggle.setChecked(expanded)
            window.library_toggle.setChecked(expanded)
            window.library_panel.storage_toggle.setChecked(expanded)
            for language in ("EN", "RU", "EN"):
                for width in (1440, 1020, 1280, 1440):
                    with self.subTest(expanded=expanded, language=language, width=width):
                        window._set_language(language)
                        window.resize(width, 850)
                        scroll = window.stack.currentWidget()
                        self.app.processEvents()
                        scroll.verticalScrollBar().setValue(0)
                        self.app.processEvents()
                        available = scroll.viewport().width()
                        for panel in (window.research_panel, window.library_panel):
                            if panel.isVisible():
                                self.assertLessEqual(panel.width(), available)
                        self.assertGreaterEqual(window.report_context.height(),
                                                window.report_context.heightForWidth(window.report_context.width()))
                        self.assertGreaterEqual(len({button.y() for button in buttons}), 2)
                        self.assertLessEqual(workspace.geometry().bottom(), timeline.geometry().top())
                        for index, button in enumerate(buttons):
                            self.assertGreaterEqual(button.width(), button.minimumSizeHint().width())
                            self.assertGreaterEqual(button.height(), button.minimumSizeHint().height())
                            self.assertTrue(workspace.rect().contains(button.geometry()),
                                            (button.text(), button.geometry(), workspace.rect()))
                            self.assertEqual(button.visibleRegion().boundingRect(), button.rect(),
                                             (button.text(), button.visibleRegion().boundingRect(), button.rect()))
                            for other in buttons[index + 1:]:
                                self.assertFalse(button.geometry().intersects(other.geometry()),
                                                 (button.text(), other.text()))

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
