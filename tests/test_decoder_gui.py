"""Production sixth page and cancellable worker lifecycle (offscreen)."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.theme import set_retro_theme


class DecoderGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = DecoderWindow(output_root=Path(self.temp.name), allow_update_check=False)
        self.window._timer.stop()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        from qt_test_support import close_and_drain
        self.window.decoder_panel.cancel()
        self.wait_idle()
        close_and_drain(self.window, self.app)
        self.temp.cleanup()

    def wait_idle(self):
        deadline = time.monotonic() + 8
        while self.window.decoder_panel.worker is not None and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.01)
        self.assertIsNone(self.window.decoder_panel.worker)

    def test_six_pages_and_real_jsonl_index_without_recording(self):
        self.assertEqual(self.window.stack.count(), 6)
        self.assertEqual(self.window.PAGES[-1][0], "decoder")
        self.assertEqual(len(self.window._nav_buttons), 6)
        panel = self.window.decoder_panel
        self.window._navigate("decoder")
        self.app.processEvents()
        for language in ("RU", "EN"):
            self.window._set_language(language)
            self.assertTrue(panel.isVisible())
            self.assertTrue(panel.open_button.isVisible())
        source = Path(self.temp.name) / "own.jsonl"
        source.write_text(json.dumps({"schema_version": 1, "pid": 1, "tid": 2, "seq": 1,
            "source_ns": 100, "source_clock": "TEST_ONLY", "kind": "test.event", "token": "PRIVATE"}) + "\n",
            encoding="utf-8")
        panel.start_decode(source)
        self.wait_idle()
        self.assertEqual(panel.state, "decoded", panel.error)
        self.assertEqual(panel.table.rowCount(), 1)
        panel.table.selectRow(0)
        self.app.processEvents()
        self.assertNotIn("PRIVATE", panel.details.toPlainText())
        self.assertFalse(self.window.probe.active)

    def test_research_roundtrip_page_contract_accepts_six_and_legacy_five(self):
        from types import SimpleNamespace
        from blackbox_universal.research_e2e import _pages_match_build
        from blackbox_universal.window import UniversalWindow
        self.assertTrue(_pages_match_build(self.window))
        original = UniversalWindow.PAGES
        legacy = SimpleNamespace(PAGES=original,
            stack=SimpleNamespace(count=lambda: len(original)),
            _page_ids={name: i for i, (name, _) in enumerate(original)})
        self.assertTrue(_pages_match_build(legacy))
        legacy.stack = SimpleNamespace(count=lambda: 6)
        self.assertFalse(_pages_match_build(legacy))
        legacy.stack = SimpleNamespace(count=lambda: 5)
        legacy.PAGES = original + (("wrong", "SYNTHETIC"),)
        self.assertFalse(_pages_match_build(legacy))

    def test_decoder_navigation_uses_standard_scroll_page_at_two_window_sizes(self):
        from PySide6.QtWidgets import QScrollArea
        for width, height in ((1330, 850), (1020, 690)):
            self.window.resize(width, height)
            for lang in ("EN", "RU"):
                self.window._set_language(lang)
                self.window._navigate("reports")
                self.window._navigate("decoder")
                self.app.processEvents()
                current = self.window.stack.currentWidget()
                self.assertIsInstance(current, QScrollArea)
                self.assertIs(current.widget(), self.window.decoder_panel)
                self.assertTrue(current.widgetResizable())
                self.assertTrue(self.window.decoder_panel.open_button.isVisible())
                self.window._navigate("dashboard")
                self.window._navigate("decoder")
                self.assertEqual(current.verticalScrollBar().value(), 0)

    def test_close_cancels_and_drains_worker_without_qthread_destruction(self):
        def blocked(*args, cancel, **kwargs):
            if not cancel.wait(5):
                raise RuntimeError("TEST_DID_NOT_CANCEL")
            raise InterruptedError("DECODER_CANCELLED")
        with patch("blackbox_universal.decoder_panel.decode_file", side_effect=blocked):
            self.window.decoder_panel.start_decode(Path(self.temp.name) / "synthetic.nettrace")
            self.window.close()
            self.wait_idle()
        self.assertIn("DECODER_CANCELLED", self.window.decoder_panel.error)
        self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
