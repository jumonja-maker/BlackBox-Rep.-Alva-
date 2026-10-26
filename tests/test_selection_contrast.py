"""Painted selection regression: a correct palette alone is not sufficient."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QPushButton, QScrollArea, QVBoxLayout, QWidget

from blackbox_universal.theme import COLORS, set_retro_theme
from blackbox_universal.widgets import WindowPanel
from blackbox_universal.window import _page
from tools.qa_popup_contrast import assert_readable, capture_combo, row_pixels, reveal_combo


def luminance(color):
    values = [v / 255 for v in (color.red(), color.green(), color.blue())]
    values = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in values]
    return sum(a * b for a, b in zip(values, (.2126, .7152, .0722)))


class SelectionContrastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        set_retro_theme(cls.app)

    def setUp(self):
        self.page, layout = _page()
        self.panel = WindowPanel('Selection QA', 'TEST FIXTURE')
        layout.addWidget(self.panel)
        self.combo = QComboBox()
        for value in ('STANDARD', 'DETAILED', 'INCIDENT_BURST'):
            self.combo.addItem(value, value)
        self.panel.content.addWidget(self.combo)
        self.page.resize(620, 400)
        self.page.show()
        self.page.activateWindow()
        self.app.processEvents()

    def tearDown(self):
        self.combo.hidePopup()
        self.page.close()
        self.page.deleteLater()
        self.app.processEvents()

    def test_active_inactive_and_disabled_highlight_roles_are_paired(self):
        for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive,
                      QPalette.ColorGroup.Disabled):
            with self.subTest(group=group):
                fg = self.app.palette().color(group, QPalette.ColorRole.HighlightedText)
                bg = self.app.palette().color(group, QPalette.ColorRole.Highlight)
                self.assertEqual(fg.name(), COLORS['navy'])
                self.assertEqual(bg.name(), COLORS['selection'])
                dark, light = sorted((luminance(fg), luminance(bg)))
                self.assertGreater((light + .05) / (dark + .05), 7)

    def test_actual_nested_popup_mouse_and_keyboard_keep_text_and_values(self):
        with tempfile.TemporaryDirectory() as folder:
            try:
                for lang, labels in (
                        ('EN', ('STANDARD', 'DETAILED', 'INCIDENT_BURST')),
                        ('RU', ('СТАНДАРТНЫЙ', 'ПОДРОБНЫЙ', 'ЗАПИСЬ ИНЦИДЕНТА'))):
                    for index, label in enumerate(labels):
                        self.combo.setItemText(index, label)
                    records = capture_combo(self.app, self.combo, Path(folder), lang)
                    self.assertEqual(len(records), 6)
                    self.assertEqual(self.combo.currentData(), 'INCIDENT_BURST')
                    self.assertEqual(tuple(self.combo.itemData(i) for i in range(3)),
                                     ('STANDARD', 'DETAILED', 'INCIDENT_BURST'))
            except AssertionError:
                view = self.combo.view()
                image = view.viewport().grab().toImage()
                counts = Counter(image.pixelColor(x, y).name()
                                 for y in range(3, image.height() - 3, 3)
                                 for x in range(3, image.width() - 3, 3))
                print('POPUP_RENDER_FAILURE ' + json.dumps({
                    'row': view.currentIndex().row(),
                    'pixels': row_pixels(view, view.currentIndex()),
                    'dominant': counts.most_common(8)}), flush=True)
                raise
            finally:
                if os.environ.get('GITHUB_ACTIONS') == 'true':
                    shutil.copytree(folder, Path('popup-qa') / 'unit', dirs_exist_ok=True)

    def test_pixel_gate_detects_regression_even_with_correct_palette(self):
        # Deliberately broken local styles test the detector, not production.
        # The separate Windows workflow runs the unmodified original checkout
        # to reproduce the real defect. A repaired list delegate can correctly
        # resist the old parent-only leak, so that alone is no longer a valid
        # negative fixture.
        view = self.combo.view()
        for background, foreground, error in (
                ('#fffaf0', '#fffaf0', 'POPUP_SELECTION_BACKGROUND_LOST'),
                ('#ffddaa', '#ffddaa', 'POPUP_SELECTED_TEXT_UNREADABLE')):
            with self.subTest(error=error):
                view.setStyleSheet(
                    'QAbstractItemView { selection-background-color: ' + background +
                    '; selection-color: ' + foreground + '; } '
                    'QAbstractItemView::item:selected, QAbstractItemView::item:hover {'
                    'background: ' + background + '; color: ' + foreground + '; }')
                self.combo.showPopup()
                self.app.processEvents()
                QTest.keyClick(view, Qt.Key.Key_Home)
                QTest.qWait(80)
                self.app.processEvents()
                index = self.combo.model().index(0, 0)
                self.assertEqual(view.currentIndex().row(), 0)
                stats = row_pixels(view, index)
                with self.assertRaisesRegex(AssertionError, error):
                    assert_readable(stats)
                self.combo.hidePopup()
                self.app.processEvents()

    def test_reveal_uses_bounded_page_scroll_without_selecting_or_starting_anything(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addSpacing(1200)
        combo = QComboBox()
        combo.addItem('STANDARD', 'STANDARD')
        combo.addItem('DETAILED', 'DETAILED')
        layout.addWidget(combo)
        layout.addSpacing(1200)
        scroll.setWidget(page)
        scroll.resize(500, 360)
        scroll.show()
        scroll.activateWindow()
        self.app.processEvents()
        original = combo.currentData()
        try:
            reveal_combo(self.app, scroll, combo)
            bar = scroll.verticalScrollBar()
            self.assertGreater(bar.value(), 0)
            self.assertLessEqual(bar.value(), bar.maximum())
            centre = scroll.viewport().mapFromGlobal(combo.mapToGlobal(combo.rect().center()))
            self.assertTrue(scroll.viewport().rect().contains(centre))
            self.assertEqual(combo.currentData(), original)
            self.assertFalse(combo.view().isVisible())
        finally:
            scroll.close()
            scroll.deleteLater()
            self.app.processEvents()

    def test_disabled_primary_and_accent_do_not_look_actionable(self):
        for kind in ('primary', 'accent'):
            button = QPushButton('QA action')
            button.setObjectName(kind)
            self.panel.content.addWidget(button)
            button.setEnabled(False)
            self.app.processEvents()
            image = button.grab().toImage()
            dpr = image.devicePixelRatio()
            color = image.pixelColor(round(8 * dpr), image.height() // 2)
            self.assertEqual(color.name(), '#ded8ce')
            self.assertFalse(button.isEnabled())


if __name__ == '__main__':
    unittest.main()
