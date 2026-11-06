"""Hosted Qt presentation contracts for explicitly omitted analysis models.

These are synthetic GUI records, not actual ETW or native acceptance evidence.
"""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication, QWidget

from blackbox_universal.investigation_graph_panel import InvestigationGraphPanel, PROJECTION_NAMES
from test_inv_gui import DeepPanelDouble, ReaderDouble, fixture_case


def omitted_case():
    case = fixture_case()
    for model in PROJECTION_NAMES:
        case.pop(model, None)
    case["coverage"].update(analysis_projection_completeness="PARTIAL",
        issue_analysis_status="NOT_INCLUDED_BYTE_BUDGET", omitted_models=[
            {"model": model, "reason": "AGGREGATE_CASE_RESULT_BYTE_BUDGET", "computed_bytes": 1_000_000}
            for model in PROJECTION_NAMES])
    return case


class OmittedProjectionGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = QWidget()
        self.window.language = "EN"
        self.window._investigation_root = Path(self.temp.name)
        self.window.probe = SimpleNamespace(session_folder=None)
        self.deep, self.reader = DeepPanelDouble(self.window), ReaderDouble()
        self.deep.bridge.setParent(self.deep)
        self.reader.setParent(self.window)
        self.panel = InvestigationGraphPanel(self.window, self.deep, bridge=self.reader)

    def tearDown(self):
        from qt_test_support import dispose_closed_fixture
        self.panel.shutdown()
        self.assertFalse(self.panel.bridge.busy)
        self.window.close()
        dispose_closed_fixture(self.window, self.app)
        self.temp.cleanup()

    def test_omitted_views_show_unknown_counts_in_both_languages_without_reanalysis(self):
        case = omitted_case()
        original = deepcopy(case)
        self.panel.load_case(case)
        self.assertEqual(self.panel.nodes_model.rows, case["nodes"])
        self.assertIn("Counts for these views are unknown", self.panel.projection_summary.text())
        notices = (self.panel.hypothesis_summary, self.panel.actions_summary, self.panel.recurrence_summary,
                   self.panel.critical_summary, self.panel.delay_summary, self.panel.crash_summary)
        for notice in notices:
            self.assertIn("unavailable", notice.text())
            self.assertIn("Missing rows do not establish an absence", notice.text())
        self.assertNotIn("findings: 0", self.panel.delay_summary.text())
        for model in ("hypotheses", "recurrences", "critical", "delays", "crash"):
            self.assertEqual(self.panel._models[model].rowCount(), 0)
        self.assertEqual(self.panel.action_combo.count(), 0)
        for index in range(self.panel.section.count()):
            self.panel.section.setCurrentIndex(index)
        self.window.language = "RU"
        self.panel.retranslate()
        self.assertIn("Количество результатов этих представлений неизвестно", self.panel.projection_summary.text())
        for notice in notices:
            self.assertIn("недоступно", notice.text())
            self.assertIn("не доказывает отсутствие проблем", notice.text())
        self.assertNotIn("наблюдений: 0", self.panel.delay_summary.text())
        self.assertEqual(case, original)
        self.assertEqual(self.reader.calls, [])
        self.assertEqual(self.deep.calls, [])

    def test_loading_normal_models_clears_omission_notices_and_keeps_saved_rows(self):
        self.panel.load_case(omitted_case())
        case = fixture_case()
        case["issues"] = [{"group_id": "saved-issue", "status": "CANDIDATE"}]
        case["delay_investigation"] = {"status": "OBSERVATIONS_AVAILABLE", "findings": [
            {"category": "FILE_IO", "description": "Recorded synthetic interval", "status": "RECORDED",
             "details": {"observed_request_ms": 4}, "source_nodes": []}]}
        case["crash_investigation"] = {"status": "INCOMPLETE_EVIDENCE", "summary": {
            "failure_events": 1, "saved_dumps": 0, "threads": 0, "frames": 0}, "events": [
            {"provider": "SYNTHETIC_GUI", "event_id": 1}]}
        case["critical_path"] = {"status": "NOT_ESTABLISHED", "segments": [], "totals": {}}
        original = deepcopy(case)
        self.panel.load_case(case)
        for label in (self.panel.projection_summary, self.panel.hypothesis_summary,
                      self.panel.actions_summary, self.panel.recurrence_summary):
            self.assertEqual(label.text(), "")
        self.assertEqual(self.panel._models["hypotheses"].rows, case["hypotheses"])
        self.assertEqual(self.panel._models["recurrences"].rows, case["issues"])
        self.assertEqual(self.panel._models["delays"].rowCount(), 1)
        self.assertEqual(self.panel._models["crash"].rowCount(), 1)
        self.assertEqual(self.panel.action_combo.count(), 1)
        self.assertIn("findings: 1", self.panel.delay_summary.text())
        self.assertNotIn("unavailable", self.panel.critical_summary.text())
        self.assertNotIn("unavailable", self.panel.crash_summary.text())
        self.assertEqual(case, original)
        self.assertEqual(self.reader.calls, [])

    def test_saved_recurrence_groups_remain_visible_when_issue_projection_is_omitted(self):
        case = omitted_case()
        grouping = {"groups": [{"group_id": "actual-saved-group", "status": "CANDIDATE"}], "candidates": []}
        case["issue_grouping"] = grouping
        self.panel.load_case(case)
        self.assertEqual(self.panel._models["recurrences"].rows, grouping["groups"])
        self.assertIn("issue analysis", self.panel.recurrence_summary.text())
        self.assertEqual(self.reader.calls, [])


if __name__ == "__main__":
    unittest.main()
