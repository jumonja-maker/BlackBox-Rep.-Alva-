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

    def test_new_decode_clears_old_trace_and_failed_input_does_not_show_stale_rows(self):
        panel = self.window.decoder_panel
        valid = Path(self.temp.name) / "first.jsonl"
        valid.write_text(json.dumps({"schema_version": 1, "pid": 5, "tid": 6,
            "seq": 1, "source_ns": 100, "source_clock": "TEST",
            "kind": "first.event"}) + "\n", encoding="utf-8")
        panel.start_decode(valid)
        self.wait_idle()
        self.assertEqual(panel.state, "decoded", panel.error)
        self.assertEqual(panel.table.rowCount(), 1)
        self.assertTrue(panel.export_button.isEnabled())
        broken = Path(self.temp.name) / "broken.jsonl"
        broken.write_text('{"incomplete":true}', encoding="utf-8")
        panel.start_decode(broken)
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertFalse(panel.export_button.isEnabled())
        self.assertFalse(panel.review_clock_button.isEnabled())
        self.assertIsNone(panel.index)
        self.wait_idle()
        self.assertEqual(panel.state, "error")
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertFalse(panel.export_button.isEnabled())

    def test_search_filter_is_applied_to_index(self):
        panel = self.window.decoder_panel
        source = Path(self.temp.name) / "search.jsonl"
        rows = [{"schema_version": 1, "pid": 5, "tid": 6, "seq": i+1,
                 "source_ns": (i+1)*1000000, "source_clock": "TEST",
                 "kind": name} for i, name in enumerate(("alpha.event", "beta.event"))]
        source.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
        panel.start_decode(source)
        self.wait_idle()
        panel.search.setText("beta")
        panel.apply_button.click()
        self.assertEqual(panel.table.rowCount(), 1)
        self.assertIn("beta", panel.table.item(0, 4).text())

    def test_cpu_profiler_and_gc_generation_views_keep_semantic_units_and_language(self):
        from blackbox_core.decoder_index import PROTOCOL, build_index
        from blackbox_core.decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT

        rows = [
            {"type": "header", "protocol": PROTOCOL, "input_sha256": "a"*64},
            {"type": "event", "ordinal": 1, "time_ms": 1., "pid": 87, "tid": 42,
             "process_instance": 2, "provider": SAMPLE_PROVIDER, "name": SAMPLE_EVENT,
             "payload": {}, "frames": [{"address": "0x1234", "name": "TEST_Leaf"}],
             "stack_status": "RECORDED_ADDRESSES_OFFLINE_NAMES", "semantic": None},
            {"type": "event", "ordinal": 2, "time_ms": 2., "pid": 87, "tid": 42,
             "process_instance": 2, "provider": "Microsoft-Windows-DotNETRuntime", "name": "GC/Start",
             "payload": {}, "frames": [],
             "semantic": {"kind": "gc_start", "runtime": 1, "number": 3,
                          "generation": 2, "gc_type": "Blocking"}},
            {"type": "event", "ordinal": 3, "time_ms": 4., "pid": 87, "tid": 42,
             "process_instance": 2, "provider": "Microsoft-Windows-DotNETRuntime", "name": "GC/Stop",
             "payload": {}, "frames": [],
             "semantic": {"kind": "gc_stop", "runtime": 1, "number": 3}},
            {"type": "footer", "protocol": PROTOCOL, "rows": 3, "status": "DECODED"}]
        from blackbox_core.decoder_clock import UNIX_EPOCH_DOTNET_TICKS
        rows[1]["utc_ticks"] = str(UNIX_EPOCH_DOTNET_TICKS+17_000_000_000_000_000+10_000)
        rows[1]["source_ticks"] = "1234567"
        source = Path(self.temp.name) / "audit-typed.jsonl"
        source.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
        target = Path(self.temp.name) / "audit-typed.sqlite3"
        panel = self.window.decoder_panel
        panel.index = target
        panel.summary = build_index(source, target, input_sha256="a"*64, format_name=".nettrace")
        panel.state = "decoded"
        self.window._navigate("decoder")
        for language in ("EN", "RU"):
            self.window._set_language(language)
            index = panel.mode.findData("cpu_stacks")
            self.assertGreaterEqual(index, 0)
            panel.mode.setCurrentIndex(index)
            panel.pid.setValue(87)
            panel.apply_button.click()
            self.assertEqual(panel.table.rowCount(), 1)
            self.assertEqual(panel.table.horizontalHeaderItem(1).text(), "SAMPLES")
            self.assertEqual(panel.table.item(0, 1).text(), "1")
            self.assertIn("TEST_Leaf", panel.table.item(0, 4).text())
            panel.table.selectRow(0)
            self.assertIn("EVENT_OCCURRENCES_NOT_CPU_TIME_OR_CPU_PERCENT",
                          panel.details.toPlainText())
            panel.mode.setCurrentIndex(panel.mode.findData("gc_summary"))
            panel.apply_button.click()
            self.assertEqual(panel.table.rowCount(), 1)
            self.assertEqual(panel.table.horizontalHeaderItem(1).text(), "PAIRS")
            self.assertIn("Gen2", panel.table.item(0, 4).text())
            self.assertIn("NOT_PAUSE", panel.table.item(0, 4).text())
            panel.mode.setCurrentIndex(panel.mode.findData("clock"))
            panel.apply_button.click()
            self.assertEqual(panel.table.rowCount(), 1)
            self.assertEqual(panel.table.horizontalHeaderItem(1).text(), "UTC")
            self.assertTrue(panel.table.item(0, 1).text().endswith("Z"))
            panel.table.selectRow(0)
            self.assertIn("TRACEEVENT_DERIVED_UTC_UNVERIFIED",panel.details.toPlainText())
            self.assertIn("NOT_ESTABLISHED",panel.status.text())

    def test_capture_clock_journal_manual_review_is_hash_linked_not_aligned(self):
        from blackbox_core.decoder_index import PROTOCOL, build_index
        from blackbox_core.trace_clock_evidence import bracket
        panel = self.window.decoder_panel
        source = Path(self.temp.name) / "synthetic-etl-events.jsonl"
        rows = [
            {"type": "header", "protocol": PROTOCOL, "input_sha256": "a"*64},
            {"type": "event", "ordinal": 1, "time_ms": 1., "pid": 123,
             "tid": 2, "process_instance": 1, "provider": "TEST",
             "name": "synthetic", "payload": {}, "frames": [],
             "semantic": None},
            {"type": "footer", "protocol": PROTOCOL, "rows": 1, "status": "DECODED"}]
        source.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
        index = Path(self.temp.name) / "captured.sqlite3"
        meta = build_index(source, index, input_sha256="a"*64, format_name=".etl")
        panel.received({"path": str(index), "summary": meta}, "")
        self.assertTrue(panel.review_clock_button.isEnabled())
        self.window._navigate("decoder")
        before = bracket(10_000_000, 10_000_100, 10_000_000,
                         5_000_000_000, 5_000_010_000,
                         1_800_000_000_000_000_000, pid=1234)
        after = bracket(20_000_000, 20_000_100, 10_000_000,
                        6_000_000_000, 6_000_010_000,
                        1_800_000_001_000_000_000, pid=1234)
        journal = Path(self.temp.name) / "synthetic.trace.json"
        document = {"source": "ETW_WPR", "state": "COMPLETED",
                    "result": {"sha256": "a"*64},
                    "clock_anchors": {"before_tool_start": before,
                                      "after_tool_stop": after}}
        journal.write_text(json.dumps(document), encoding="utf-8")
        for lang in ("EN", "RU"):
            self.window._set_language(lang)
            report = panel.review_clock_journal_path(journal)
            self.assertEqual(report["status"], "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED")
            self.assertEqual(report["trace_to_blackbox_session_clock_alignment"],
                             "NOT_ESTABLISHED")
            self.assertIn("UNVERIFIED", panel.details.toPlainText())
        document["result"]["sha256"] = "b"*64
        journal.write_text(json.dumps(document), encoding="utf-8")
        result = panel.review_clock_journal_path(journal)
        self.assertEqual(result["status"], "JOURNAL_TRACE_HASH_MISMATCH")
        self.assertIn("NOT_ESTABLISHED", panel.details.toPlainText())

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
