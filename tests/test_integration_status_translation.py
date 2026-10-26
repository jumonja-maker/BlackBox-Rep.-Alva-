"""A language switch must not need another source snapshot to update status."""
import os
import unittest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QWidget
from blackbox_universal.research_panel import ResearchPanel


class StatusBridge(QObject):
    updated = Signal()
    result_ready = Signal(str, object, str)
    data = {}
    last_error = None

    def send(self, *args, **kwargs):
        raise AssertionError("Translation must not send a source command")


class CachedStatusTranslationTest(unittest.TestCase):
    def test_status_changes_language_without_waiting_for_helper(self):
        app = QApplication.instance() or QApplication([])
        host = QWidget(); host.language = "EN"; host.probe = StatusBridge()
        panel = ResearchPanel(host)
        panel.scenario.setText("Unchanged scenario")
        try:
            self.assertIn("Checking", panel.status.text())
            host.language = "RU"; panel.retranslate()
            self.assertIn("Проверяем", panel.status.text())
            self.assertIn("Ожидается событие приложения", panel.status.text())
            self.assertNotIn("Checking", panel.status.text())
            host.probe.data = {"app_ready": True,
                              "capabilities": {"privilege": {"mode": "ADMINISTRATOR"}}}
            panel.retranslate()
            self.assertIn("Администратор", panel.status.text())
            self.assertIn("Проверочное событие получено", panel.status.text())
            host.language = "EN"; panel.retranslate()
            self.assertIn("Administrator", panel.status.text())
            self.assertIn("Control event received", panel.status.text())
            self.assertEqual(panel.scenario.text(), "Unchanged scenario")
            app.processEvents()
        finally:
            host.close()


if __name__ == "__main__":
    unittest.main()
