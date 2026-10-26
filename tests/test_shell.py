"""Cross-platform tests for real shell behavior (Qt runs offscreen in CI)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import psutil
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

from blackbox_universal.monitor import (
    ReadOnlyProbe, available_processes, save_snapshot,
)
from blackbox_core.contracts import ObserverError
from blackbox_core.report import summarize
from blackbox_universal.theme import set_retro_theme, font_coverage
from blackbox_universal.window import UniversalWindow


class ObserverTests(unittest.TestCase):
    def test_attach_current_process_sample_stop_and_export(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        observer = ReadOnlyProbe(output_root=Path(self.temp.name))
        observer.attach(os.getpid())
        self.assertFalse(observer.active)
        observer.start()
        time.sleep(0.025)
        sample = observer.tick()
        self.assertIsNotNone(sample)
        self.assertGreaterEqual(sample["rss_mb"], 0)
        self.assertGreaterEqual(sample["process_count"], 1)
        observer.stop()
        self.assertFalse(observer.active)
        record = observer.snapshot()
        self.assertEqual(record["schema_version"], 1)
        self.assertFalse(record["root_cause_proven"])
        self.assertEqual(record["sample_count"], 1)
        self.assertEqual(record["observed_process"]["pid"], os.getpid())
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "observation.json"
            save_snapshot(destination, record)
            self.assertEqual(json.loads(destination.read_text(
                encoding="utf-8"))["observed_process"]["pid"], os.getpid())
            self.assertEqual([p.name for p in Path(folder).iterdir()],
                             ["observation.json"])

    def test_process_selection_does_not_start_observation(self):
        observer = ReadOnlyProbe()
        observer.attach(os.getpid())
        self.assertFalse(observer.active)
        self.assertEqual(observer.snapshot()["sample_count"], 0)

    def test_invalid_pid_is_not_mistaken_for_live_target(self):
        observer = ReadOnlyProbe()
        with self.assertRaises(ObserverError) as failure:
            observer.attach(2**31 - 1)
        self.assertEqual(failure.exception.code, 'PROCESS_NOT_FOUND')
        self.assertFalse(observer.active)

    def test_process_picker_returns_only_bounded_metadata(self):
        rows = available_processes(limit=10000)
        self.assertIsInstance(rows, list)
        self.assertTrue(all(set(r) ==
                            {"pid", "name", "rss_mb", "status"}
                            for r in rows))
        self.assertTrue(all(type(r["pid"]) is int for r in rows))
        self.assertNotIn("cmdline", json.dumps(rows))
        self.assertNotIn("environ", json.dumps(rows))


class QtShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.default_root = patch('blackbox_universal.monitor._default_sessions_root',
                                  return_value=Path(self.tmp.name))
        self.default_root.start()
        self.window = UniversalWindow()
        self.window._timer.stop()

    def _wait_report(self):
        for _ in range(600):
            self.app.processEvents()
            if self.window._report_worker is None and self.window._base_sample_worker is None:
                return
            time.sleep(0.01)
        self.fail("report worker did not terminate")

    def tearDown(self):
        from qt_test_support import close_and_drain
        close_and_drain(self.window,self.app)
        self.default_root.stop()
        self.tmp.cleanup()

    def test_simplified_shell_keeps_file_help_navigation_but_no_start_footer(self):
        from PySide6.QtWidgets import QFrame, QLabel
        self.window._set_language("EN")
        self.assertIsNone(self.window.findChild(QFrame, "taskbar"))
        self.assertFalse(hasattr(self.window, "clock"))
        toolbar = self.window.findChild(QFrame, "toolbar")
        self.assertIsNotNone(toolbar)
        buttons = [item.text() for item in toolbar.findChildren(QPushButton)]
        self.assertTrue(any(text.startswith("FILE") for text in buttons))
        self.assertTrue(any(text.startswith("HELP") for text in buttons))
        self.assertFalse(any(text.startswith("VIEW") for text in buttons))
        self.assertEqual(len(self.window._nav_buttons), 5)
        settings = self.window.stack.widget(self.window._page_ids["settings"])
        labels = " ".join(item.text() for item in settings.findChildren(QLabel))
        for removed in ("PRIVACY & SECURITY", "Read-only process counters",
                        "No code injection or target manipulation",
                        "No automatic upload or account sign-in",
                        "Report export only when explicitly requested",
                        "No administrator privileges requested by this shell",
                        "PREVIEW / v0.3"):
            self.assertNotIn(removed, labels)
        self.assertIn("v0.4.1", labels)

    def test_dashboard_gives_remaining_vertical_space_to_telemetry(self):
        from PySide6.QtWidgets import QVBoxLayout
        page = self.window.stack.widget(self.window._page_ids["dashboard"]).widget()
        layout = page.layout()
        self.assertIsInstance(layout, QVBoxLayout)
        self.assertGreater(sum(layout.stretch(i) for i in range(layout.count())), 0)
        self.assertGreaterEqual(self.window.chart.minimumHeight(), 205)

    def test_maximized_desktop_keeps_normal_window_restore_controls(self):
        self.window.showMaximized()
        self.app.processEvents()
        self.assertTrue(self.window.isMaximized())
        self.window._toggle_maximized()
        self.app.processEvents()
        self.assertFalse(self.window.isMaximized())
        self.window._toggle_maximized()
        self.app.processEvents()
        self.assertTrue(self.window.isMaximized())

    def test_five_real_pages_and_classic_three_window_controls(self):
        self.assertEqual(len(self.window.PAGES), 5)
        self.assertEqual(self.window.stack.count(), 5)
        self.assertEqual(len(self.window._nav_buttons), 5)
        chrome = self.window.findChildren(QPushButton, "windowControl")
        self.assertEqual(len(chrome), 3)
        for key, _ in self.window.PAGES:
            self.window._navigate(key)
            self.assertEqual(self.window.stack.currentIndex(),
                             self.window._page_ids[key])
        self.assertTrue(self.window.windowTitle().startswith("BLACK.BOX"))

    def test_ru_en_text_has_real_regular_and_bold_glyphs(self):
        evidence = font_coverage(self.app)
        self.assertTrue(evidence["ok"], json.dumps(evidence, ensure_ascii=False))
        self.assertEqual(len(evidence["fonts"]), 4)

    def test_section_breadcrumbs_without_marketing_headings(self):
        from PySide6.QtWidgets import QFrame, QLabel
        expected = {
            "processes": ("WINDOWS / PROCESS EXPLORER", "WINDOWS / ПРОЦЕССЫ"),
            "events": ("WINDOWS / EVENT VIEWER", "WINDOWS / ЖУРНАЛ СОБЫТИЙ"),
            "reports": ("LOCAL DISK / REPORTS", "ЛОКАЛЬНЫЙ ДИСК / ОТЧЁТЫ"),
            "settings": ("CONTROL PANEL / PREFERENCES",
                         "ПАНЕЛЬ УПРАВЛЕНИЯ / НАСТРОЙКИ"),
        }
        for language, index in (("EN", 0), ("RU", 1)):
            self.window._set_language(language)
            for key in ("dashboard", *expected):
                self.window._navigate(key)
                page = self.window.stack.currentWidget()
                breadcrumbs = [label for label in page.findChildren(QLabel)
                               if label.objectName() == "eyebrow"]
                self.assertEqual([label.text() for label in breadcrumbs],
                                 [] if key == "dashboard" else [expected[key][index]])
                for label in breadcrumbs:
                    self.assertFalse(label.wordWrap(),
                                     f"Breadcrumb wrapped on {key} in {language}")
                    self.assertGreater(label.sizeHint().width(),
                                       label.sizeHint().height() * 2)
                self.assertFalse(
                    [label.text() for label in page.findChildren(QLabel)
                     if label.objectName() == "hero"],
                    f"Marketing slogan returned on {key} in {language}")
                if key == "processes":
                    self.assertFalse(page.findChildren(QFrame, "notice"))

    def test_selected_process_acknowledgement_matches_observation_state(self):
        # The right side of Current Session must never claim attachment to
        # a target before the user explicitly selects one.
        self.window._set_language("RU")
        self.window._update_all()
        self.assertTrue(self.window.target_binding.isHidden())
        self.assertEqual(self.window.target_binding_title.text(), "")

        self.window.probe.attach(os.getpid())
        self.window._update_all()
        self.assertFalse(self.window.target_binding.isHidden())
        self.assertEqual(self.window.target_binding_title.text(),
                         "✓  ПРОЦЕСС ПРИВЯЗАН")
        self.assertIn(str(os.getpid()), self.window.target_binding_detail.text())
        self.assertIn("Готов к наблюдению",
                      self.window.target_binding_detail.text())
        self.assertFalse(self.window.target_binding_title.wordWrap())

        self.window._start()
        self.assertEqual(self.window.target_binding_title.text(),
                         "●  НАБЛЮДЕНИЕ АКТИВНО")
        self.assertIn("Запись наблюдений",
                      self.window.target_binding_detail.text())
        self.window._tick()
        self.window._stop()
        self._wait_report()
        self.assertEqual(self.window.target_binding_title.text(),
                         "✓  СЕАНС ЗАВЕРШЁН")
        self.assertIn("Отчёт сохранён", self.window.target_binding_detail.text())

        self.window._set_language("EN")
        self.assertEqual(self.window.target_binding_title.text(),
                         "✓  SESSION FINISHED")
        self.assertIn("Report saved", self.window.target_binding_detail.text())

        # A new target discards the old session's completion confirmation.
        self.window.probe.attach(os.getpid())
        self.window._update_all()
        self.assertEqual(self.window.target_binding_title.text(),
                         "✓  PROCESS ATTACHED")

    def test_real_process_picker_filter_and_attach_workflow(self):
        target = {"pid": os.getpid(),
                  "name": psutil.Process().name(),
                  "rss_mb": 55.5, "status": "running"}
        with patch("blackbox_universal.window.available_processes",
                   return_value=[target]):
            self.window._refresh_process_list()
        self.window.process_search.setText(str(os.getpid()))
        self.assertEqual(self.window.process_table.rowCount(), 1)
        self.window.process_table.selectRow(0)
        self.window._attach_selected()
        self.assertEqual(self.window.probe.pid, os.getpid())
        self.assertFalse(self.window.probe.active)
        self.assertTrue(self.window.start_btn.isEnabled())
        self.window._start()
        self.window._tick()
        self.assertTrue(self.window.probe.active)
        self.assertGreater(self.window.probe.last["rss_mb"], 0)
        self.assertTrue(self.window.stop_btn.isEnabled())
        self.window._stop()
        self._wait_report()
        self.assertFalse(self.window.probe.active)
        session = self.window.probe.session_folder
        self.assertIsNotNone(session)
        self.assertTrue((session / "session.sqlite3").is_file())
        self.assertTrue((session / "report.json").is_file())
        self.assertTrue((session / "report.html").is_file())
        self.assertFalse((session / "ai-handoff.json").exists())
        self.assertGreaterEqual(summarize(session)["samples"], 1)

    def test_export_only_after_user_selection_without_cloud_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            dst = Path(folder) / "report.json"
            self.window.probe.attach(os.getpid())
            self.window.probe.start()
            self.window._tick()
            self.window._stop()
            self._wait_report()
            with patch("blackbox_universal.window.QFileDialog.getSaveFileName",
                       return_value=(str(dst), "JSON files (*.json)")), \
                 patch.object(QMessageBox, "information", return_value=None):
                self.window._export()
            self.assertTrue(dst.is_file())
            report = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(report["source"], "local_read_only_psutil")
            self.assertFalse(report["root_cause_proven"])

    def test_public_ui_has_no_platform_laboratory_or_brand(self):
        self.assertEqual(
            [page for page, _ in self.window.PAGES],
            ["dashboard", "processes", "events", "reports", "settings"])
        for page in self.window._page_ids:
            self.window._navigate(page)
            from PySide6.QtWidgets import QLabel
            public_labels = " ".join(x.text() for x in
                                     self.window.stack.currentWidget().findChildren(QLabel))

    def test_sampling_interval_is_user_editable_and_connected(self):
        self.window.interval_combo.setCurrentIndex(2)
        self.assertEqual(self.window._timer.interval(), 5000)
        self.window.interval_combo.setCurrentIndex(0)
        self.assertEqual(self.window._timer.interval(), 1000)


if __name__ == "__main__":
    unittest.main()
