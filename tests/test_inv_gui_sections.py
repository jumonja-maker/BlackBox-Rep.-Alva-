"""Exact Qt Investigation section contract for hosted Windows/Linux CI.

This runs the REAL workspace (not a mock or screenshot-only approximation)
and independently checks the required 10 section identifiers and page mapping.
Actual native measurements and the packaged helper are checked separately.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from blackbox_universal.window import UniversalWindow
from tools.qa_inv_gui import REQUIRED_SECTION_KEYS, verify_workspace_sections


class InvestigationWorkspaceSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_real_workspace_all_ten_sections_ru_en_page_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            window = UniversalWindow(output_root=Path(temp), allow_update_check=False)
            try:
                window._timer.stop()
                window.show()
                self.app.processEvents()
                panel = window.investigation_graph_panel
                self.assertEqual(len(REQUIRED_SECTION_KEYS), 10)
                for language in ("RU", "EN"):
                    window._set_language(language)
                    self.assertEqual(verify_workspace_sections(panel), REQUIRED_SECTION_KEYS)
                    for index, key in enumerate(REQUIRED_SECTION_KEYS):
                        self.assertEqual(panel.section.itemData(index), key)
                        self.assertTrue(panel.section.itemText(index).strip())
                        panel.section.setCurrentIndex(index)
                        self.app.processEvents()
                        self.assertEqual(panel.section.currentData(), key)
                        self.assertIs(panel.pages.currentWidget(), panel.pages.widget(index))
                self.assertEqual(len(window._nav_buttons), 6)
            finally:
                from qt_test_support import close_and_drain
                close_and_drain(window, self.app, timeout=15)

    def test_missing_reordered_and_unmapped_pages_fail_closed(self):
        class Combo:
            def __init__(self, keys):
                self.keys = keys
            def count(self):
                return len(self.keys)
            def itemData(self, index):
                return self.keys[index]

        class Pages:
            def __init__(self, count):
                self.page_count = count
            def count(self):
                return self.page_count
            def widget(self, index):
                return object() if index < self.page_count else None

        def panel(keys, page_count):
            return SimpleNamespace(section=Combo(keys), pages=Pages(page_count))

        self.assertEqual(verify_workspace_sections(panel(REQUIRED_SECTION_KEYS, 10)),
                         REQUIRED_SECTION_KEYS)
        for keys in (REQUIRED_SECTION_KEYS[:-1],
                     REQUIRED_SECTION_KEYS[:-2] + tuple(reversed(REQUIRED_SECTION_KEYS[-2:])),
                     REQUIRED_SECTION_KEYS[:-1] + ("invented",)):
            with self.subTest(keys=keys), self.assertRaisesRegex(
                    AssertionError, "INV_TEN_WORKSPACE_SECTIONS_REQUIRED"):
                verify_workspace_sections(panel(keys, len(keys)))
        with self.assertRaisesRegex(AssertionError, "INV_WORKSPACE_SELECTOR_PAGE_MAPPING_INCOMPLETE"):
            verify_workspace_sections(panel(REQUIRED_SECTION_KEYS, 9))


if __name__ == "__main__":
    unittest.main()
