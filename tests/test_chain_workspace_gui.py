"""Hosted Qt workspace cases, each in a fresh owned child with its real theme.

The parent test process never creates/rethemes QApplication. Child assertions
exercise layout and actual input, with bounded output and explicit result proof.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

_CASE_NAMES = ('test_six_column_toolbar_reflows_without_overlap_or_losing_click_handlers', 'test_canvas_dominates_supported_ru_en_workspace_without_oversized_actions', 'test_middle_and_space_panning_and_plain_wheel_preserve_saved_nodes_and_cursor_anchor', 'test_lost_mouse_grab_or_focus_cancels_pan_and_space_in_text_stays_text')
_MAX_CHILD_OUTPUT = 128 * 1024


def _run_workspace_child(case_name):
    if case_name not in _CASE_NAMES:
        raise AssertionError("UNKNOWN_WORKSPACE_CASE")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from copy import deepcopy
    import time
    from PySide6.QtCore import QEvent, QPoint, QPointF, QRect, Qt
    from PySide6.QtGui import QWheelEvent
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QPushButton, QScrollArea, QWidget
    from blackbox_universal.action_grid import ActionGrid
    from blackbox_universal.theme import set_retro_theme
    from blackbox_universal.window import UniversalWindow
    from qt_test_support import close_and_drain, dispose_closed_fixture

    class WorkspaceChildTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.app = QApplication.instance() or QApplication([])
            set_retro_theme(cls.app)

        def setUp(self):
            self.temp = tempfile.TemporaryDirectory()
            self.window = UniversalWindow(output_root=Path(self.temp.name), allow_update_check=False)
            self.window._timer.stop()
            self.window.showNormal()
            self.window.resize(1600, 1000)
            self.panel = self.window.chain_builder_panel
            self.window.overview_tabs.setCurrentWidget(self.panel)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                self.app.processEvents()
                if self.panel.catalog and not self.panel.bridge.busy:
                    break
                time.sleep(.005)
            self.assertTrue(self.panel.catalog)

        def tearDown(self):
            close_and_drain(self.window, self.app, timeout=15)
            self.temp.cleanup()

        def visible_rect(self, widget):
            result = QRect(widget.mapTo(self.window, QPoint()), widget.size())
            ancestor = widget.parentWidget()
            while ancestor is not None:
                result = result.intersected(QRect(ancestor.mapTo(self.window, QPoint()), ancestor.size()))
                ancestor = ancestor.parentWidget()
            return result

        def scroll_to_top(self):
            ancestor = self.panel.parentWidget()
            while ancestor is not None:
                if isinstance(ancestor, QScrollArea):
                    ancestor.horizontalScrollBar().setValue(ancestor.horizontalScrollBar().minimum())
                    ancestor.verticalScrollBar().setValue(ancestor.verticalScrollBar().minimum())
                ancestor = ancestor.parentWidget()
            self.app.processEvents()

        def populate_graph(self):
            for index in range(6):
                self.panel.add_tool("process_select", [40 + index % 3 * 420, 40 + index // 3 * 400])
            self.app.processEvents()

        def test_six_column_toolbar_reflows_without_overlap_or_losing_click_handlers(self):
            host = QWidget()
            grid = ActionGrid(host, max_columns=6, spacing=4)
            buttons = [QPushButton("Action " + str(index)) for index in range(12)]
            clicked = []
            for index, button in enumerate(buttons):
                button.clicked.connect(lambda checked=False, current=index: clicked.append(current))
                grid.addWidget(button)
            try:
                host.show()
                self.app.processEvents()
                widest = max(button.sizeHint().expandedTo(button.minimumSizeHint()).width() for button in buttons)
                for columns in (6, 2, 6):
                    width = widest * columns + 4 * (columns - 1)
                    height = grid.heightForWidth(width)
                    host.resize(width, height)
                    grid.setGeometry(QRect(0, 0, width, height))
                    self.app.processEvents()
                    self.assertEqual(len({button.y() for button in buttons}), 12 // columns)
                    for index, button in enumerate(buttons):
                        self.assertIs(button.parentWidget(), host)
                        self.assertTrue(host.rect().contains(button.geometry()))
                        for other in buttons[index + 1:]:
                            self.assertFalse(button.geometry().intersects(other.geometry()))
                    self.assertEqual([grid.itemAt(index).widget() for index in range(12)], buttons)
                QTest.mouseClick(buttons[-1], Qt.MouseButton.LeftButton, pos=buttons[-1].rect().center())
                self.assertEqual(clicked, [11])
            finally:
                host.close()
                dispose_closed_fixture(host, self.app)

        def test_canvas_dominates_supported_ru_en_workspace_without_oversized_actions(self):
            self.populate_graph()
            for width, height in ((1600, 1000), (1280, 800)):
                for language in ("RU", "EN"):
                    with self.subTest(width=width, height=height, language=language):
                        self.window.resize(width, height)
                        self.window._set_language(language)
                        self.window.overview_tabs.setCurrentWidget(self.panel)
                        self.app.processEvents()
                        self.scroll_to_top()
                        pane, canvas = self.visible_rect(self.panel), self.visible_rect(self.panel.canvas)
                        ratio = canvas.height() / max(1, pane.height())
                        measured = {"window": [width, height], "language": language,
                            "visible_panel": list(pane.getRect()), "visible_canvas": list(canvas.getRect()),
                            "canvas_height_fraction": ratio, "action_bar_height": self.panel.action_bar.height()}
                        print("R60_COMPACT_WORKSPACE_GEOMETRY " + json.dumps(measured, sort_keys=True), flush=True)
                        self.assertGreaterEqual(ratio, .55, measured)
                        self.assertGreaterEqual(canvas.width(), 350, measured)
                        self.assertLessEqual(self.panel.action_bar.height(), 90, measured)
                        for button in (self.panel.open_button, self.panel.save_button, self.panel.validate_button,
                                       self.panel.start_button, self.panel.cancel_button):
                            self.assertEqual(self.visible_rect(button).size(), button.size(), button.objectName())
                        self.assertIn("chainNavigationHint", self.panel.navigation_hint.objectName())
                        self.assertEqual(self.panel.inspector_tabs.count(), 4)
                        self.panel.inspector_tabs.setCurrentIndex(3)
                        self.app.processEvents()
                        self.assertTrue(self.panel.budget_seconds.isVisible())
                        self.assertTrue(self.panel.override_tools.isVisible())
                        self.panel.inspector_tabs.setCurrentIndex(0)

        def test_middle_and_space_panning_and_plain_wheel_preserve_saved_nodes_and_cursor_anchor(self):
            self.populate_graph()
            canvas = self.panel.canvas
            canvas.resetTransform()
            canvas.zoom(2)
            canvas.centerOn(canvas.sceneRect().center())
            canvas.setFocus()
            self.app.processEvents()
            original = deepcopy(self.panel.document)
            positions = {key: item.pos() for key, item in canvas.items_by_id.items()}
            point = canvas.viewport().rect().center()
            for button, use_space in ((Qt.MouseButton.MiddleButton, False), (Qt.MouseButton.LeftButton, True)):
                for bar, movement in ((canvas.horizontalScrollBar(), 40), (canvas.verticalScrollBar(), 25)):
                    self.assertLessEqual(bar.minimum(), bar.value() - movement)
                    self.assertLessEqual(bar.value() - movement, bar.maximum())
                before = canvas.mapToScene(point)
                if use_space:
                    QTest.keyPress(canvas, Qt.Key.Key_Space)
                QTest.mousePress(canvas.viewport(), button, pos=point)
                QTest.mouseMove(canvas.viewport(), point + QPoint(40, 25), delay=30)
                QTest.mouseRelease(canvas.viewport(), button, pos=point + QPoint(40, 25))
                if use_space:
                    QTest.keyRelease(canvas, Qt.Key.Key_Space)
                self.app.processEvents()
                actual_delta = canvas.mapToScene(point) - before
                self.assertAlmostEqual(actual_delta.x(), -40 / canvas.transform().m11(), delta=2)
                self.assertAlmostEqual(actual_delta.y(), -25 / canvas.transform().m11(), delta=2)
            point = QPoint(canvas.viewport().width() // 3, canvas.viewport().height() // 3)
            QTest.mouseMove(canvas.viewport(), point)
            self.app.processEvents()
            before, scale = canvas.mapToScene(point), canvas.transform().m11()
            wheel = QWheelEvent(QPointF(point), QPointF(canvas.viewport().mapToGlobal(point)), QPoint(), QPoint(0, 120),
                                Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
            self.app.sendEvent(canvas.viewport(), wheel)
            self.app.processEvents()
            self.assertGreater(canvas.transform().m11(), scale)
            self.assertLessEqual((canvas.mapToScene(point) - before).manhattanLength(), 3)
            canvas.zoom(1e6)
            self.assertLessEqual(canvas.transform().m11(), 3.5 + 1e-9)
            canvas.zoom(1e-6)
            self.assertGreaterEqual(canvas.transform().m11(), .15 - 1e-9)
            self.assertEqual(self.panel.document, original)
            self.assertEqual({key: item.pos() for key, item in canvas.items_by_id.items()}, positions)

        def test_lost_mouse_grab_or_focus_cancels_pan_and_space_in_text_stays_text(self):
            self.populate_graph()
            canvas = self.panel.canvas
            canvas.setFocus()
            self.app.processEvents()
            original = deepcopy(self.panel.document)
            point = canvas.viewport().rect().center()
            QTest.keyPress(canvas, Qt.Key.Key_Space)
            QTest.mousePress(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
            self.app.sendEvent(canvas.viewport(), QEvent(QEvent.Type.UngrabMouse))
            self.assertIsNone(canvas._pan_origin)
            self.assertFalse(canvas._space_down)
            self.assertEqual(canvas.viewport().cursor().shape(), Qt.CursorShape.ArrowCursor)
            QTest.mouseRelease(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
            QTest.keyRelease(canvas, Qt.Key.Key_Space)
            self.assertEqual(self.panel.document, original)
            QTest.keyPress(canvas, Qt.Key.Key_Space)
            self.panel.title.setFocus()
            self.app.processEvents()
            self.assertFalse(canvas._space_down)
            QTest.keyClick(self.panel.title, Qt.Key.Key_Space)
            self.assertFalse(canvas._space_down)


    callback_errors = []
    previous_hook = sys.excepthook
    def record_callback(kind, value, tb):
        callback_errors.append(kind.__name__[:64])
        previous_hook(kind, value, tb)
    sys.excepthook = record_callback
    try:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([WorkspaceChildTests(case_name)]))
    finally:
        sys.excepthook = previous_hook
    passed = result.wasSuccessful() and result.testsRun == 1 and not result.skipped and not callback_errors
    print("R60_WORKSPACE_CHILD_RESULT " + json.dumps({"case": case_name, "passed": passed,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "callback_errors": callback_errors}, sort_keys=True), flush=True)
    return 0 if passed else 1


class CanvasWorkspaceTests(unittest.TestCase):
    def run_child(self, case_name):
        root = Path(__file__).resolve().parents[1]
        paths = [str(root / "src"), str(root), str(root / "tests")]
        inherited = os.environ.get("PYTHONPATH")
        if inherited:
            paths.append(inherited)
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONUTF8="1", PYTHONPATH=os.pathsep.join(paths))
        # A file prevents an unbounded stdout allocation in the parent. The
        # controlled child output is capped before it is read or forwarded.
        with tempfile.TemporaryFile() as transcript:
            completed = subprocess.run([sys.executable, "-X", "faulthandler", str(Path(__file__).resolve()),
                "--workspace-child", case_name], cwd=root, env=env, stdout=transcript, stderr=subprocess.STDOUT,
                timeout=60)
            size = transcript.seek(0, os.SEEK_END)
            self.assertLessEqual(size, _MAX_CHILD_OUTPUT, "WORKSPACE_CHILD_OUTPUT_BUDGET_EXCEEDED:" + str(size))
            transcript.seek(0)
            output = transcript.read(_MAX_CHILD_OUTPUT + 1).decode("utf-8", errors="replace")
        for line in output.splitlines():
            if line.startswith(("R60_COMPACT_WORKSPACE_GEOMETRY ", "R60_WORKSPACE_CHILD_RESULT ")):
                print(line, flush=True)
        self.assertEqual(completed.returncode, 0, output[-12000:])
        markers = [line.partition("R60_WORKSPACE_CHILD_RESULT ")[2] for line in output.splitlines()
                   if line.startswith("R60_WORKSPACE_CHILD_RESULT ")]
        self.assertEqual(len(markers), 1, output[-12000:])
        self.assertEqual(json.loads(markers[0]), {"case": case_name, "passed": True,
            "tests_run": 1, "failures": 0, "errors": 0, "skipped": 0, "callback_errors": []})

    def test_six_column_toolbar_reflows_without_overlap_or_losing_click_handlers(self):
        self.run_child('test_six_column_toolbar_reflows_without_overlap_or_losing_click_handlers')

    def test_canvas_dominates_supported_ru_en_workspace_without_oversized_actions(self):
        self.run_child('test_canvas_dominates_supported_ru_en_workspace_without_oversized_actions')

    def test_middle_and_space_panning_and_plain_wheel_preserve_saved_nodes_and_cursor_anchor(self):
        self.run_child('test_middle_and_space_panning_and_plain_wheel_preserve_saved_nodes_and_cursor_anchor')

    def test_lost_mouse_grab_or_focus_cancels_pan_and_space_in_text_stays_text(self):
        self.run_child('test_lost_mouse_grab_or_focus_cancels_pan_and_space_in_text_stays_text')


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--workspace-child":
        raise SystemExit(_run_workspace_child(sys.argv[2]))
    unittest.main()
