"""Hosted Qt regressions for query identity and expert evidence navigation.

The bridge is an explicit asynchronous UI fixture; this does not claim native
collector, source authenticity or Windows acceptance.
"""
import copy
import json
import os
from pathlib import Path
import sys
import traceback
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

from blackbox_universal.evidence_panels import EvidencePanel
from qt_test_support import dispose_closed_fixture
from test_expert_evidence_presentation import finding


class FixtureBridge(QObject):
    result_ready = Signal(str, object, object)

    def __init__(self, parent):
        super().__init__(parent)
        self.session_folder = Path("/recording-fixture")
        self.calls = []

    def send(self, op, **args):
        self.calls.append((op, args))
        return len(self.calls)


class IdentifiedFixtureBridge(FixtureBridge):
    command_result = Signal(str, str, object, object)


def finding_page(key, *, rows=None, more=False, cursor=None):
    return {"request_key": key, "metadata": {"monotonic_origin_ns": 1_000_000_000},
            "findings": [finding(1), finding(2)] if rows is None else rows,
            "findings_total": 7, "has_more": more, "next_cursor": cursor,
            "coverage": {"selected_samples": 5, "spacing_gap_pairs": 1},
            "summary": {"support": {"metrics": {"cpu_interval_percent": {"max": 0}, "rss_bytes": {"max": 0}}}},
            "file_trust": "UNVERIFIED_IMPORT"}


class ExpertEvidencePanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.errors = []
        self.old_hook = sys.excepthook
        sys.excepthook = lambda kind, value, tb: self.errors.append("".join(traceback.format_exception(kind, value, tb)))
        self.host = QWidget()
        self.host.language = "EN"
        self.host.probe = FixtureBridge(self.host)
        self.layout = QVBoxLayout(self.host)
        self.panels = []

    def tearDown(self):
        try:
            for panel in self.panels:
                panel.timer.stop()
            self.host.close()
            dispose_closed_fixture(self.host, self.app)
            self.assertEqual(self.errors, [], "Qt callback errors must fail acceptance")
        finally:
            sys.excepthook = self.old_hook

    def panel(self, *, events=False):
        panel = EvidencePanel(self.host, events=events)
        self.layout.addWidget(panel)
        self.panels.append(panel)
        return panel

    def load_findings(self, panel):
        panel.refresh()
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation), None)

    def test_retranslation_preserves_selection_card_and_complete_raw_record(self):
        panel = self.panel()
        self.load_findings(panel)
        self.assertEqual(panel.selection()["finding_id"], "finding-1")
        panel.table.selectRow(1)
        selected = copy.deepcopy(panel.selection())
        calls = len(self.host.probe.calls)
        panel.raw.setChecked(True)
        self.assertEqual(json.loads(panel.details.toPlainText()), selected)
        panel.raw.setChecked(False)
        self.host.language = "RU"
        panel.retranslate()
        self.assertEqual(panel.selection(), selected)
        self.assertIn("Сохранённые факты", panel.details.toPlainText())
        self.assertEqual(panel.table.item(1, 1).toolTip(), selected["code"])
        panel.open_card()
        card = {"status": "OBSERVATION_ONLY", "root_cause": "UNKNOWN", "post_context_complete": False,
                "snapshots": {}, "next_actions": [], "limitations": [], "vendor": {"exact": [0, None, False]}}
        self.host.probe.result_ready.emit("incident_card", card, None)
        self.host.language = "EN"
        panel.retranslate()
        self.assertEqual(panel.selection(), selected)
        self.assertIs(panel.card_packet, card)
        panel.raw.setChecked(True)
        self.assertEqual(json.loads(panel.details.toPlainText()), card)
        panel.close_card()
        self.assertEqual(json.loads(panel.details.toPlainText()), selected)
        self.assertEqual(len(self.host.probe.calls), calls + 1, "Language and raw switches must not issue queries")

    def test_latest_filter_generation_wins_and_pagination_preserves_backend_cursors(self):
        panel = self.panel()
        panel.refresh()
        first_key = panel._generation
        panel.question.setCurrentIndex(panel.question.findData("CPU"))
        panel.refresh()
        self.host.probe.result_ready.emit(panel.op, finding_page(first_key), None)
        self.assertIsNone(panel.packet)
        self.app.processEvents()
        self.assertEqual(self.host.probe.calls[-1][1]["question"], "CPU")
        self.assertEqual(self.host.probe.calls[-1][1]["request_key"], panel._generation)
        cursor = [2_000_000_002, "fixture-cursor"]
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation, more=True, cursor=cursor), None)
        panel.forward()
        self.assertEqual(self.host.probe.calls[-1][1]["after"], cursor)
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation, rows=[finding(3)]), None)
        self.assertEqual(panel.selection()["finding_id"], "finding-3")
        panel.back()
        self.assertIsNone(self.host.probe.calls[-1][1]["after"])
        self.assertEqual(self.host.probe.calls[-1][1]["question"], "CPU")
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation, rows=[]), None)
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertFalse(panel.copy.isEnabled())

    def test_incident_card_cannot_replace_new_selection_or_new_recording(self):
        panel = self.panel()
        self.load_findings(panel)
        panel.open_card()
        panel.table.selectRow(1)
        self.host.probe.result_ready.emit("incident_card", {"status": "STALE_SELECTION_CARD"}, None)
        self.assertIsNone(panel.card_packet)
        self.assertNotIn("STALE_SELECTION_CARD", panel.details.toPlainText())
        self.assertIn("finding-2", panel.details.toPlainText())
        panel.open_card()
        panel.apply_interval(Path("/another-recording-fixture"), None)
        self.host.probe.result_ready.emit("incident_card", {"status": "STALE_FOLDER_CARD"}, None)
        self.assertIsNone(panel.card_packet)
        self.assertEqual(panel.details.toPlainText(), "")
        self.app.processEvents()
        self.assertEqual(self.host.probe.calls[-1][1]["folder"], str(Path("/another-recording-fixture")))

    def test_event_filters_keep_codes_unknown_time_disables_navigation_and_copy_is_explicit(self):
        panel = self.panel(events=True)
        panel.source.setCurrentIndex(panel.source.findData("WCT"))
        panel.severity.setCurrentIndex(panel.severity.findData("WARNING"))
        panel.search.setText("literal_%_Код")
        panel.start.setValue(1.25)
        panel.end.setValue(7.5)
        self.host.language = "RU"
        panel.retranslate()
        panel.refresh()
        args = self.host.probe.calls[-1][1]
        self.assertEqual((args["source"], args["severity"], args["search"], args["start_ms"], args["end_ms"]),
                         ("WCT", "WARNING", "literal_%_Код", 1250, 7500))
        row = {"time_ns": None, "code": "FUTURE_EVENT", "source": "WCT", "severity": "WARNING",
               "status": "UNAVAILABLE", "verification_class": "UNVERIFIED_IMPORT", "detail": {"unknown": False},
               "evidence_ref": "fixture:7", "instance_id": None, "rank": 1, "id": 7}
        QApplication.clipboard().setText("untouched before explicit copy")
        self.host.probe.result_ready.emit(panel.op, {"request_key": panel._generation, "rows": [row],
            "monotonic_origin_ns": None, "total_matching": 1, "has_more": False, "next_cursor": None,
            "source_trust": "UNVERIFIED_IMPORT"}, None)
        self.assertEqual(QApplication.clipboard().text(), "untouched before explicit copy")
        self.assertFalse(panel.navigate.isEnabled())
        self.assertFalse(panel.investigate.isEnabled())
        self.assertIn("UNVERIFIED_IMPORT", panel.details.toPlainText())
        panel.raw.setChecked(True)
        panel.copy.click()
        self.assertEqual(json.loads(QApplication.clipboard().text()), row)

    def test_imported_scalar_and_list_details_remain_navigable_without_incident_identity(self):
        panel = self.panel(events=True)
        selections = []
        panel.investigate_requested.connect(selections.append)
        for detail in (None, [], "provider-owned text", 0, False):
            with self.subTest(detail=detail):
                panel.refresh()
                row = {"time_ns": 2_000_000_000, "code": "FUTURE_EVENT", "source": "OBSERVER",
                       "severity": "INFO", "status": "RECORDED", "detail": detail,
                       "verification_class": "UNVERIFIED_IMPORT", "evidence_ref": "fixture:scalar",
                       "rank": 0, "id": 1}
                self.host.probe.result_ready.emit(panel.op, {"request_key": panel._generation, "rows": [row],
                    "monotonic_origin_ns": 1_000_000_000, "total_matching": 1,
                    "has_more": False, "next_cursor": None}, None)
                self.assertTrue(panel.investigate.isEnabled())
                panel.investigate.click()
                self.assertIsNone(selections[-1]["incident_id"])
                self.assertEqual(selections[-1]["selection"], {"start_ns": 2_000_000_000, "end_ns": 2_000_000_000})
                panel.raw.setChecked(True)
                self.assertEqual(json.loads(panel.details.toPlainText()), row)
                panel.raw.setChecked(False)

    def test_invalidation_clears_all_source_bound_views_and_does_not_revive_old_queries(self):
        for events in (False, True):
            with self.subTest(events=events):
                panel = self.panel(events=events)
                if not events:
                    self.load_findings(panel)
                    self.assertIn("5 / 7", panel.summaries[0].text())
                panel.refresh()
                old_key = panel._generation
                panel.refresh()  # A latest-query reload would normally follow this response.
                calls = len(self.host.probe.calls)
                panel.invalidate_interval(Path("/selected-recording-B"))
                self.assertIsNone(panel.packet)
                self.assertIsNone(panel.card_packet)
                self.assertIsNone(panel.selection())
                self.assertIsNone(panel.origin)
                self.assertIsNone(panel.instance_id)
                self.assertIsNone(panel._card_request)
                self.assertEqual(panel.details.toPlainText(), "")
                self.assertEqual(panel.table.rowCount(), 0)
                self.assertEqual([label.text() for label in panel.summaries], ["—"] * len(panel.summaries))
                self.assertIn(str(Path("/selected-recording-B")), panel.source_context.text())
                self.assertNotIn(str(self.host.probe.session_folder), panel.source_context.text())
                self.assertIn("Waiting", panel.status.text())
                self.assertEqual(panel.target.count(), 1)
                self.host.probe.result_ready.emit(panel.op, finding_page(old_key), None)
                self.app.processEvents()
                self.assertFalse(panel._busy)
                self.assertIsNone(panel.packet)
                self.assertEqual(len(self.host.probe.calls), calls, "Invalidation must not issue or revive a query")
                panel.apply_interval(Path("/selected-recording-B"), (11, 17), origin=5)
                self.app.processEvents()
                self.assertEqual(len(self.host.probe.calls), calls, "Applying context must not start evidence queries")
                panel.refresh()
                self.assertEqual(self.host.probe.calls[-1][1]["folder"], str(Path("/selected-recording-B")))

    def test_invalidation_drops_incident_bindings_and_source_label_keeps_literal_unknown_clock(self):
        panel = self.panel()
        self.load_findings(panel)
        panel.open_card()
        calls = len(self.host.probe.calls)
        folder = Path("/recording-fixture/<source claim>")
        panel.invalidate_interval(folder)
        self.host.probe.result_ready.emit("incident_card", {"status": "STALE_INCIDENT"}, None)
        self.app.processEvents()
        self.assertIsNone(panel.card_packet)
        self.assertIsNone(panel._card_request)
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertEqual(len(self.host.probe.calls), calls)
        panel.apply_interval(folder, (11, 17))
        self.assertEqual(panel.source_context.textFormat(), Qt.TextFormat.PlainText)
        self.assertIn("<source claim>", panel.source_context.text())
        self.assertIn("11–17 ns; recording origin unknown", panel.source_context.text())
        self.host.language = "RU"
        panel.retranslate()
        self.assertIn("Запись: ", panel.source_context.text())
        self.assertIn("11–17", panel.source_context.text())
        self.assertIsNone(panel.origin)
        self.assertEqual(len(self.host.probe.calls), calls)

    def test_recorded_child_scope_rejects_pending_root_results_and_legacy_callers_default_to_root(self):
        panel = self.panel()
        folder = Path("/recorded-process-scope")
        interval = (1_000_000_000, 4_000_000_000)
        panel.apply_interval(folder, interval, origin=1_000_000_000)
        panel.refresh()
        self.assertEqual(self.host.probe.calls[-1][1]["instance_id"], 1)
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation), None)
        panel.refresh()
        old_key = panel._generation
        panel.apply_interval(folder, interval, origin=1_000_000_000, instance_id=7)
        self.assertIsNone(panel.packet)
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertIn("Recorded instance ID 7", panel.source_context.text())
        self.assertIn("Counter/thread scope", panel.source_context.text())
        self.assertIn("Incidents, markers and source errors retain their source scope.", panel.source_context.text())
        panel.refresh()
        self.host.probe.result_ready.emit(panel.op, finding_page(old_key), None)
        self.assertIsNone(panel.packet, "A root-process reply must not become the selected child's evidence")
        self.app.processEvents()
        self.assertEqual(self.host.probe.calls[-1][1]["instance_id"], 7)
        child = finding(7)
        child["finding_id"] = "recorded-child-7"
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation, rows=[child]), None)
        self.assertEqual(panel.selection()["finding_id"], "recorded-child-7")
        self.assertIn("Recorded instance ID 7", panel.source_context.text())
        panel.apply_interval(folder, interval, origin=1_000_000_000)
        self.assertIsNone(panel.packet)
        panel.refresh()
        self.assertEqual(self.host.probe.calls[-1][1]["instance_id"], 1)

    def test_recorded_instance_validation_and_independent_event_target_filter(self):
        panel = self.panel()
        folder = Path("/recorded-process-scope")
        for invalid in (None, 0, -1, True, 1.0, 2**63):
            with self.subTest(invalid=invalid):
                generation = panel._generation
                with self.assertRaisesRegex(ValueError, "INVALID_PROCESS_INSTANCE"):
                    panel.apply_interval(folder, None, instance_id=invalid)
                self.assertEqual(panel._generation, generation)
                self.assertIsNone(panel.folder)
        panel.invalidate_interval(folder)
        panel.refresh()
        self.assertEqual(self.host.probe.calls, [], "An invalidated finding scope cannot silently query root instance 1")
        events = self.panel(events=True)
        events.apply_interval(folder, (1_000_000_000, 4_000_000_000), origin=1_000_000_000,
                              instance_id=7, processes=[{"instance_id": 7, "pid": 123, "creation_time": "fixture"}])
        self.assertEqual(events.target.currentData(), 0, "Report selection must not silently filter the event stream")
        events.refresh()
        self.assertEqual(self.host.probe.calls[-1][1]["instance_id"], 0)
        packet = {"request_key": events._generation, "rows": [], "monotonic_origin_ns": 1_000_000_000,
                  "total_matching": 0, "has_more": False, "next_cursor": None}
        self.host.probe.result_ready.emit(events.op, packet, None)
        self.assertIn("All process instances", events.source_context.text())
        events.target.setCurrentIndex(events.target.findData(7))
        events.refresh()
        self.assertEqual(self.host.probe.calls[-1][1]["instance_id"], 7)
        self.assertIn("All process instances", events.source_context.text(), "The visible old page retains its actual query scope while loading")
        self.host.probe.result_ready.emit(events.op, {**packet, "request_key": events._generation}, None)
        self.assertIn("Recorded instance ID 7", events.source_context.text())

    def test_page_failure_retains_the_accepted_cursor_and_changed_filter_failure_clears_old_evidence(self):
        panel = self.panel()
        panel.refresh()
        cursor = [2_000_000_002, "fixture-cursor"]
        first = finding_page(panel._generation, more=True, cursor=cursor)
        self.host.probe.result_ready.emit(panel.op, first, None)
        panel.forward()
        self.host.probe.result_ready.emit(panel.op, None, "PAGE_READ_FAILED")
        self.assertIs(panel.packet, first)
        self.assertEqual(panel._history, [])
        self.assertIsNone(panel._cursor)
        self.assertIn("Previous page retained", panel.status.text())
        panel.forward()
        self.assertEqual(self.host.probe.calls[-1][1]["after"], cursor)
        self.host.probe.result_ready.emit(panel.op, None, "PAGE_READ_FAILED")
        panel.question.setCurrentIndex(panel.question.findData("CPU"))
        panel.refresh()
        self.host.probe.result_ready.emit(panel.op, None, "<i>FILTER_READ_FAILED</i>")
        self.assertIsNone(panel.packet)
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertEqual([label.text() for label in panel.summaries], ["—"] * 3)
        self.assertFalse(panel.next.isEnabled())
        self.assertEqual(panel.status.textFormat(), Qt.TextFormat.PlainText)

    def test_send_failure_rolls_back_pagination_without_losing_the_accepted_page(self):
        panel = self.panel()
        panel.refresh()
        self.host.probe.result_ready.emit(panel.op, finding_page(panel._generation, more=True, cursor=[7, "fixture"]), None)
        accepted = panel.packet
        original_send = self.host.probe.send
        self.host.probe.send = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("QUEUE_FULL"))
        try:
            panel.forward()
            self.assertIs(panel.packet, accepted)
            self.assertEqual(panel._history, [])
            self.assertIsNone(panel._cursor)
            self.assertFalse(panel._busy)
            self.assertIn("QUEUE_FULL", panel.status.text())
        finally:
            self.host.probe.send = original_send

    def test_exact_command_ids_ignore_foreign_page_and_card_results_and_errors(self):
        self.host.probe = IdentifiedFixtureBridge(self.host)
        panel = self.panel()
        panel.refresh()
        page = finding_page(panel._generation)
        self.host.probe.command_result.emit("unrelated", panel.op, page, None)
        self.host.probe.result_ready.emit(panel.op, page, None)
        self.assertTrue(panel._busy)
        self.assertIsNone(panel.packet)
        self.host.probe.command_result.emit(str(panel._request_id), panel.op, page, None)
        self.assertIs(panel.packet, page)
        panel.open_card()
        card = {"status": "OBSERVATION_ONLY", "snapshots": []}
        self.host.probe.command_result.emit("unrelated", "incident_card", card, None)
        self.host.probe.command_result.emit("unrelated", "incident_card", None, "FOREIGN_FAILURE")
        self.assertTrue(panel._busy)
        self.assertIsNone(panel.card_packet)
        self.host.probe.command_result.emit(str(panel._request_id), "incident_card", card, None)
        self.assertIs(panel.card_packet, card)
        self.assertIn("unrecognized structure", panel.details.toPlainText())

    def test_malformed_page_envelopes_fail_once_without_retries_or_qt_callback_errors(self):
        panel = self.panel()
        for changes in ({"schema_version": 99}, {"findings": None}, {"findings": [None]},
                        {"findings": [finding()] * 101}, {"has_more": True, "next_cursor": None},
                        {"has_more": True, "next_cursor": []}, {"has_more": True, "next_cursor": [False, "id"]}):
            with self.subTest(changes=changes):
                panel.refresh()
                calls = len(self.host.probe.calls)
                result = {**finding_page(panel._generation), **changes}
                self.host.probe.result_ready.emit(panel.op, result, None)
                self.app.processEvents()
                self.assertFalse(panel._busy)
                self.assertIsNone(panel.packet)
                self.assertIn("Invalid evidence response", panel.status.text())
                self.assertEqual(len(self.host.probe.calls), calls)

    def test_missing_summary_and_invalid_time_are_explicit_while_raw_fields_remain_complete(self):
        panel = self.panel()
        panel.refresh()
        row = finding()
        row.update(start_ns=17, end_ns=0)
        row["facts"] = [{"metric": "rss_bytes", "delta": 10**330}]
        result = finding_page(panel._generation, rows=[row])
        result.update(metadata=None, summary=None, coverage=None, application_io_latency=None)
        self.host.probe.result_ready.emit(panel.op, result, None)
        self.assertIsNone(panel.origin)
        self.assertFalse(panel.investigate.isEnabled())
        self.assertFalse(panel.navigate.isEnabled())
        self.assertIn("Invalid recorded interval", panel.details.toPlainText())
        self.assertIn(str(10**330), panel.details.toPlainText())
        self.assertIn("not observed", panel.summaries[1].text())
        panel.raw.setChecked(True)
        self.assertEqual(json.loads(panel.details.toPlainText()), row)

    def test_invalid_raw_values_have_an_explicit_error_and_preserve_the_original_packet(self):
        import math
        panel = self.panel()
        panel.refresh()
        row = finding()
        row["facts"].append({"rss_bytes": float("nan")})
        result = finding_page(panel._generation, rows=[row])
        self.host.probe.result_ready.emit(panel.op, result, None)
        self.assertIn("Invalid non-finite value", panel.details.toPlainText())
        panel.raw.setChecked(True)
        self.assertIn("cannot be represented as JSON", panel.details.toPlainText())
        self.assertIn("not changed", panel.details.toPlainText())
        self.assertIs(panel.packet, result)
        self.assertTrue(math.isnan(row["facts"][-1]["rss_bytes"]))
        panel.raw.setChecked(False)
        self.assertIn("Invalid non-finite value", panel.details.toPlainText())
        row["facts"].pop()
        row["detail"]["cycle"] = row["detail"]
        panel.raw.setChecked(True)
        self.assertIn("Circular", panel.details.toPlainText())
        self.assertIs(row["detail"]["cycle"], row["detail"])


if __name__ == "__main__":
    unittest.main()
