"""Acceptance tests for the unified public observer + original Qt desktop."""
from __future__ import annotations
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from blackbox_rep_alva.report import compare, summarize
from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow


class DurableDesktopIntegration(unittest.TestCase):
    def test_two_full_session_lifecycles_have_isolated_human_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            observer = ReadOnlyProbe(output_root=root)
            observer.attach(os.getpid())
            self.assertFalse(list(root.iterdir()), "Attach must never create session data")
            folders = []
            for _ in range(2):
                observer.start()
                for _ in range(3):
                    self.assertIsNotNone(observer.tick())
                observer.stop()
                folder = observer.session_folder
                self.assertIsNotNone(folder)
                self.assertFalse(observer.active)
                self.assertEqual(observer.session_state, "COMPLETED")
                self.assertFalse(observer.last_error)
                self.assertEqual(observer.report_result["sample_count"], 3)
                for name in ("session.sqlite3", "report.json", "report.html"):
                    self.assertTrue((folder / name).is_file(), name)
                self.assertFalse((folder / "ai-handoff.json").exists())
                with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                    self.assertEqual(
                        db.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 3)
                html = (folder / "report.html").read_text(encoding="utf-8")
                self.assertIn("BlackBox Process Observation", html)
                self.assertIn("Application root cause not determined", html)
                report = summarize(folder)
                self.assertEqual(report["state"], "closed")
                self.assertEqual(report["samples"], 3)
                folders.append(folder)
            self.assertNotEqual(folders[0], folders[1])
            self.assertEqual(len(list(root.iterdir())), 2)
            comparison = compare(*folders)
            self.assertFalse(comparison["regression_proven"])
            self.assertIn("peak_rss_bytes", comparison["metrics"])

    def test_pid_reuse_between_attach_and_start_is_rejected_without_disk_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            observer = ReadOnlyProbe(output_root=root)
            observer.attach(os.getpid())
            with patch("blackbox_universal.monitor.PsutilProbe") as probe:
                probe.return_value.created = observer._core.created + 10
                from blackbox_rep_alva.contracts import ObserverError
                with self.assertRaises(ObserverError) as error:
                    observer.start()
                self.assertEqual(error.exception.code, "PID_REUSED")
            self.assertFalse(observer.active)
            self.assertFalse(list(root.iterdir()))

    def test_exit_closes_and_preserves_durable_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            observer = ReadOnlyProbe(Path(temp))
            observer.attach(os.getpid())
            observer.start()
            observer.tick()
            observer.stop("UI_CLOSED")
            self.assertEqual(observer.session_state, "INTERRUPTED")
            self.assertEqual(summarize(observer.session_folder)["exit_code"], "INTERRUPTED")
            self.assertEqual(summarize(observer.session_folder)["samples"], 1)
            self.assertFalse((observer.session_folder / "ai-handoff.json").exists())

    def test_export_has_no_pretend_platform_attestation(self):
        with tempfile.TemporaryDirectory() as temp:
            observer = ReadOnlyProbe(Path(temp))
            observer.attach(os.getpid())
            observer.start()
            observer.tick()
            observer.stop()
            packet = observer.snapshot()
            self.assertFalse(packet["root_cause_proven"])
            self.assertNotIn("alva_status", packet)
            self.assertEqual(packet["evidence_origin"], "APP_SUPPLIED_NOT_AUTHENTICATED")


class InternalDiagnosticsWindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def test_default_without_runtime_keeps_diagnostics_internal(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    window._alva_interpreter = ""
                    with patch.object(window, "_start_alva_worker") as start:
                        window._finalize_alva_if_configured()
                        start.assert_not_called()
                    self.assertNotIn("alva", window._page_ids)
                    self.assertFalse(hasattr(window, "alva_check"))
                finally:
                    window.close()

    def test_bundled_alva_runs_automatically_without_python_or_tab(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    session = Path(temp) / "session"
                    session.mkdir()
                    (session / "report.json").write_text("{}", encoding="utf-8")
                    window.probe.session_folder = session
                    window._alva_interpreter = ""
                    with patch("blackbox_universal.window.bundled_runtime_available",
                               return_value=True), \
                         patch.object(window, "_start_alva_worker") as launch:
                        window._finalize_alva_if_configured()
                        launch.assert_called_once_with(None, session, persist=True)
                        window._finalize_alva_if_configured()
                        launch.assert_called_once()
                    self.assertNotIn("alva", window._page_ids)
                    self.assertFalse(hasattr(window, "alva_connect"))
                finally:
                    window.close()

    def test_previously_authorized_runtime_runs_after_session_without_ui(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    session = Path(temp) / "session"; session.mkdir()
                    (session / "report.json").write_text("{}", encoding="utf-8")
                    window.probe.session_folder = session
                    window._alva_interpreter = str(Path(temp) / "authorized" / "python.exe")
                    with patch.object(window, "_start_alva_worker") as start:
                        window._finalize_alva_if_configured()
                        start.assert_called_once_with(
                            Path(window._alva_interpreter), session, persist=True)
                        window._finalize_alva_if_configured()
                        start.assert_called_once()
                    self.assertNotIn("alva", window._page_ids)
                finally:
                    window.close()

    def test_review_outcome_lives_on_reports_without_platform_tab(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    self.assertNotIn("alva", window._page_ids)
                    window._private_diagnostics_result({
                        "status": "ok", "reviewed_checks": 4,
                        "declared_checks": 4, "evidence_status": "ok"}, "")
                    self.assertIn("4/4", window.evidence_status.text())
                    self.assertNotIn("Alva", window.evidence_status.text())
                    window._set_language("RU")
                    self.assertIn("4/4", window.evidence_status.text())
                    self.assertIn("свидетельств", window.evidence_status.text())
                    window._private_diagnostics_result({
                        "status": "ok", "reviewed_checks": 1,
                        "declared_checks": 4, "evidence_status": "error"}, "")
                    self.assertIn("1/4", window.evidence_status.text())
                finally:
                    window.close()

    def test_bundled_check_failure_is_visible_without_platform_brand(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    window.probe.report_result = {"status": "ok"}
                    with patch("blackbox_universal.window.bundled_runtime_available",
                               return_value=True):
                        window._private_diagnostics_result({
                            "status": "error",
                            "error_code": "BUNDLED_RUNTIME_CHECK_FAILED"}, "")
                    self.assertIn("did not complete", window.evidence_status.text())
                    self.assertNotIn("Alva", window.evidence_status.text())
                    window._set_language("RU")
                    self.assertIn("не завершена", window.evidence_status.text())
                finally:
                    window.close()

    def test_background_runtime_result_does_not_create_platform_ui(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(temp)):
                window = UniversalWindow()
                window._timer.stop()
                try:
                    window._private_diagnostics_result(
                        {"status": "error", "error_code": "ALVA_NOT_INSTALLED"}, "")
                    self.assertEqual(window._diagnostics_last_result["status"], "error")
                    self.assertFalse(hasattr(window, "alva_output"))
                finally:
                    window.close()


if __name__ == "__main__":
    unittest.main()
