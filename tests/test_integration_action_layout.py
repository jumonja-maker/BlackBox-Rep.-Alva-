"""PR17+18 action retention and nonoverlap in real Qt layout, no OS commands."""
import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QObject, QRect, Signal
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QWidget

from blackbox_universal.action_grid import ActionGrid
from blackbox_universal.marker_panel import MarkerPanel
from blackbox_universal.research_panel import ResearchPanel


class BridgeFixture(QObject):
    updated = Signal()
    result_ready = Signal(str, object, str)

    def __init__(self):
        super().__init__()
        self.data = {}
        self.last_error = None
        self.active = True
        self.pending = False
        self.sent = []

    def snapshot(self):
        return {"active_stages": [{"stage_id": "qa-stage", "name": "QA stage"}]}

    def send(self, op, **args):
        self.sent.append((op, args))
        return "test-command-id"


class ActionLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def assert_nonoverlap(self, buttons, boundary):
        for i, button in enumerate(buttons):
            rect = button.geometry()
            self.assertFalse(button.isHidden())
            self.assertGreater(rect.width(), 0)
            self.assertGreaterEqual(rect.width(), button.minimumSizeHint().width())
            self.assertTrue(boundary.contains(rect), (button.text(), rect, boundary))
            for other in buttons[i + 1:]:
                self.assertFalse(rect.intersects(other.geometry()),
                                 (button.text(), other.text()))

    def test_reflow_retains_widgets_order_clicks_and_translation(self):
        host = QWidget()
        grid = ActionGrid(host, max_columns=4)
        buttons = [QPushButton("Test action " + str(i)) for i in range(9)]
        clicked = []
        for i, button in enumerate(buttons):
            button.clicked.connect(lambda checked=False, n=i: clicked.append(n))
            grid.addWidget(button)
        try:
            host.show()
            for lang in ("EN", "RU", "EN"):
                for i, button in enumerate(buttons):
                    button.setText(("Проверить сохранённые данные " if lang == "RU" else
                                    "Verify saved evidence ") + str(i))
                for size in (9, 14, 18):
                    font = host.font(); font.setPointSize(size); host.setFont(font)
                    grid.invalidate(); self.app.processEvents()
                    widest = max(button.sizeHint().width() for button in buttons)
                    narrow = widest + 10
                    wide = widest * 4 + 30
                    self.assertGreater(grid.heightForWidth(narrow), grid.heightForWidth(wide))
                    for width in (narrow, wide, narrow):
                        height = grid.heightForWidth(width)
                        grid.setGeometry(QRect(0, 0, width, height))
                        self.assert_nonoverlap(buttons, QRect(0, 0, width, height))
                        self.assertEqual([grid.itemAt(i).widget() for i in range(9)], buttons)
            buttons[5].click()
            self.assertEqual(clicked, [5])
        finally:
            host.close()

    def test_all_seventeen_research_commands_survive_reflow(self):
        host = QWidget(); host.language = "EN"; host.probe = BridgeFixture()
        layout = QVBoxLayout(host); panel = ResearchPanel(host); layout.addWidget(panel)
        expected = (
            "Context / capabilities", "Apply context", "Prepare my application",
            "Verify native PDB…", "Inspect dump stacks…", "Windows snapshot",
            "ETW recording", "EventPipe 10 s", "System failure events",
            "Read saved ETL…", "Capture minidump", "Administrator mode…",
            "Export investigation…", "Compare investigations…", "Verify package…",
            "Recover interrupted session…", "Open saved session…")
        original = list(panel.buttons)
        panel.scenario.setText("Keep my experiment")
        panel.begin.setValue(1.25); panel.end.setValue(4.75)
        try:
            host.show()
            for language in ("RU", "EN", "RU"):
                host.language = language; panel.retranslate()
                self.assertEqual(tuple(panel.by_action), expected)
                self.assertEqual(panel.buttons, original)
                self.assertEqual(panel.scenario.text(), "Keep my experiment")
                for width in (620, 900, 720):
                    host.resize(width, 1100); self.app.processEvents()
                    # Place the real action group at the width available on the
                    # page; all handlers and hidden optional sources are retained.
                    w = max(width - 40, panel.action_grid.minimumSize().width())
                    h = panel.action_grid.heightForWidth(w)
                    panel.action_grid.setGeometry(QRect(0, 0, w, h))
                    self.assert_nonoverlap(original, QRect(0, 0, w, h))
            panel.by_action["Context / capabilities"].click()
            panel.load.click()
            self.assertEqual(host.probe.sent, [
                ("inspect", {}),
                ("episode", {"folder": None, "start_ms": 1250, "end_ms": 4750})])
        finally:
            host.close()

    def test_user_markers_keep_fields_stage_and_exact_command_binding(self):
        host = QWidget(); host.language = "EN"; host.probe = BridgeFixture()
        layout = QVBoxLayout(host); panel = MarkerPanel(host); layout.addWidget(panel)
        panel.name.setText("Original stage"); panel.note.setText("Original note")
        panel.refresh()
        try:
            host.show()
            for language in ("RU", "EN"):
                host.language = language; panel.retranslate(); self.app.processEvents()
                width = panel.action_grid.minimumSize().width() + 20
                height = panel.action_grid.heightForWidth(width)
                panel.action_grid.setGeometry(QRect(0, 0, width, height))
                self.assert_nonoverlap([b for _, b in panel.buttons], QRect(0, 0, width, height))
            for kind, button in panel.buttons:
                button.click()
                self.assertEqual(host.probe.sent[-1], ("user_marker", {
                    "kind": kind, "name": "Original stage", "note": "Original note",
                    "stage_id": "qa-stage"}))
            self.assertEqual(len(host.probe.sent), 4)
        finally:
            host.close()


if __name__ == "__main__":
    unittest.main()
