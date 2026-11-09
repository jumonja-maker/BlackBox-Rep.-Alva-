"""Owner uncertainty stays visible and cannot authorize export recovery."""
import os
import unittest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget
from blackbox_universal.recovery_panel import RecoveryPanel
from blackbox_universal.research_messages import explain
from qt_test_support import dispose_closed_fixture


class RecoveryProbe(QObject):
    result_ready = Signal(str, object, str)

    def send(self, *args, **kwargs):
        raise AssertionError("Presentation must not issue recovery commands")


class ExpertRecoveryContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.environ.get("GITHUB_ACTIONS") == "true" and
                os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
            raise AssertionError("EXPERT_QT_TESTS_REQUIRE_GITHUB_HOSTED_RUNNER")
        cls.app = QApplication.instance() or QApplication([])

    def test_uncertain_owner_blocks_recovery_and_retranslation_keeps_its_meaning(self):
        host = QWidget()
        host.language = "EN"
        host.probe = RecoveryProbe(host)
        panel = RecoveryPanel(host)
        QVBoxLayout(host).addWidget(panel)
        try:
            for active in (True, None, False):
                panel.rows = [{"journal": "TEST_ONLY_JOURNAL", "state": "PREPARED",
                               "owner_active": active, "can_finish": True}]
                panel.selection.clear()
                panel.selection.addItem("TEST_ONLY_JOURNAL")
                for language in ("EN", "RU"):
                    host.language = language
                    panel.retranslate()
                    self.assertEqual(panel.finish.isEnabled(), active is False)
                    self.assertEqual(panel.discard.isEnabled(), active is False)
                    expected = (("Exit verified" if language == "EN" else "Завершение подтверждено")
                                if active is False else
                                ("Active or exit not verified" if language == "EN" else
                                 "Активен или завершение не подтверждено"))
                    self.assertIn(expected, panel.detail.toPlainText())
            panel.rows = []
            panel.selection.clear()
            panel.controls()
            self.assertEqual(panel.detail.toPlainText(), "")
            for code in ("EXPORT_RECOVERY_OWNER_ACTIVE", "PURGE_OWNER_STILL_ACTIVE"):
                self.assertIn("cannot be verified", explain(code, "EN"))
                self.assertIn("не подтверждено", explain(code, "RU"))
        finally:
            host.close()
            dispose_closed_fixture(host, self.app)
