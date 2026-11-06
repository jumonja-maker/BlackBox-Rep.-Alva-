"""Real Qt pointer delivery for the R60 acceptance route; hosted CI only.

These widget fixtures verify mouse geometry, not native diagnostic operations.
"""
import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QPushButton, QScrollArea, QVBoxLayout, QWidget

from blackbox_universal.chain_qa import _assert_visible_hit_point, _ensure_visible_hit_point, _real_button_click


class AcceptanceMouseGeometryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget()
        self.layout = QVBoxLayout(self.window)

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def show_control(self, control):
        self.layout.addWidget(control)
        control.setFixedSize(480, 48)
        self.window.show()
        self.app.processEvents()
        return control

    def test_wide_blank_checkbox_uses_indicator_and_emits_actual_clicked_and_toggled(self):
        checkbox = self.show_control(QCheckBox(""))
        clicked, toggled = QSignalSpy(checkbox.clicked), QSignalSpy(checkbox.toggled)
        # Reproduce the original QA miss: the row's empty middle is outside
        # this checkbox's indicator/text hit area, although it is visible.
        QTest.mouseClick(checkbox, Qt.MouseButton.LeftButton, pos=checkbox.rect().center())
        self.assertEqual(clicked.count(), 0)
        self.assertEqual(toggled.count(), 0)
        self.assertFalse(checkbox.isChecked())
        _real_button_click(checkbox)
        self.assertEqual(clicked.count(), 1)
        self.assertEqual(toggled.count(), 1)
        self.assertTrue(checkbox.isChecked())
        _real_button_click(checkbox)
        self.assertEqual(clicked.count(), 2)
        self.assertEqual(toggled.count(), 2)
        self.assertFalse(checkbox.isChecked())

    def test_blank_rtl_checkbox_with_changed_indicator_size_retains_actual_mouse_hit(self):
        checkbox = QCheckBox("")
        checkbox.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        checkbox.setStyleSheet("QCheckBox::indicator { width: 30px; height: 26px; }")
        self.show_control(checkbox)
        clicked, toggled = QSignalSpy(checkbox.clicked), QSignalSpy(checkbox.toggled)
        _real_button_click(checkbox)
        self.assertEqual(clicked.count(), 1)
        self.assertEqual(toggled.count(), 1)
        self.assertTrue(checkbox.isChecked())

    def test_normal_push_button_still_receives_a_real_center_click(self):
        button = self.show_control(QPushButton("Run explicit GUI action"))
        clicked = QSignalSpy(button.clicked)
        _real_button_click(button)
        self.assertEqual(clicked.count(), 1)
        self.assertFalse(button.isCheckable())

    def test_clipped_direct_widget_click_is_refused_then_actual_scroll_makes_it_reachable(self):
        scroll = QScrollArea()
        scroll.setFixedSize(480, 180)
        content = QWidget()
        content.resize(900, 600)
        button = QPushButton("Scroll to explicit action", content)
        button.setObjectName("scrollAction")
        button.setGeometry(700, 400, 160, 42)
        scroll.setWidget(content)
        self.layout.addWidget(scroll)
        self.window.show()
        self.app.processEvents()
        clicked = QSignalSpy(button.clicked)
        self.assertTrue(button.isVisible(), "Qt visibility alone must not stand in for viewport clipping")
        with self.assertRaisesRegex(AssertionError, "R60_GUI_POINTER_OUTSIDE_VISIBLE_ANCESTOR"):
            _real_button_click(button)
        self.assertEqual(clicked.count(), 0)
        scroll.ensureWidgetVisible(button)
        self.app.processEvents()
        _real_button_click(button)
        self.assertEqual(clicked.count(), 1)

    def test_nested_scroll_hit_point_settles_again_after_outer_viewport_resize(self):
        outer = QScrollArea()
        outer.setFixedSize(620, 230)
        outer_content = QWidget()
        outer_content.resize(1300, 900)
        inner = QScrollArea(outer_content)
        inner.setGeometry(650, 500, 500, 230)
        inner_content = QWidget()
        inner_content.resize(900, 600)
        button = QPushButton("Nested explicit action", inner_content)
        button.setObjectName("nestedScrollAction")
        button.setGeometry(700, 400, 160, 42)
        inner.setWidget(inner_content)
        outer.setWidget(outer_content)
        self.layout.addWidget(outer)
        self.window.show()
        self.app.processEvents()
        clicked = QSignalSpy(button.clicked)
        with self.assertRaisesRegex(AssertionError, "R60_GUI_POINTER_OUTSIDE_VISIBLE_ANCESTOR"):
            _real_button_click(button)
        self.assertEqual(clicked.count(), 0)
        _ensure_visible_hit_point(self.app, button)
        _assert_visible_hit_point(button, button.rect().center())
        _real_button_click(button)
        self.assertEqual(clicked.count(), 1)
        self.assertGreater(inner.horizontalScrollBar().value(), 0)
        self.assertGreater(inner.verticalScrollBar().value(), 0)
        self.assertGreater(outer.horizontalScrollBar().value(), 0)
        self.assertGreater(outer.verticalScrollBar().value(), 0)
        outer.setFixedSize(420, 130)
        self.app.processEvents()
        _ensure_visible_hit_point(self.app, button)
        _assert_visible_hit_point(button, button.rect().center())
        _real_button_click(button)
        self.assertEqual(clicked.count(), 2)


if __name__ == "__main__":
    unittest.main()
