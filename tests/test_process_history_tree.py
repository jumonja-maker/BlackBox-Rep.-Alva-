"""Actual Qt tree/reader regressions with explicitly synthetic imported data."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.process_tree import resource_tree_page
from blackbox_core.session_v2 import FILENAME, SessionV2Writer
from blackbox_core.session_view import SessionView
from test_investigation_v2 import ORIGIN, observation


def recorded_tree(folder):
    writer = SessionV2Writer(folder, pid=123, created=1., name="TEST_ONLY_ROOT", origin_ns=ORIGIN)
    for n in range(1, 4):
        row = observation(n)
        row["children_total"] = 2
        row["children"] = [dict(pid=200, created=2., parent_pid=123, name="TEST_ONLY_CHILD",
                                cpu_user_s=n * 2., cpu_system_s=0., rss_bytes=8 * 1048576,
                                private_bytes=None, handle_count=0, thread_count=1),
                           dict(pid=300, created=3., parent_pid=200, name="TEST_ONLY_GRANDCHILD",
                                cpu_user_s=n * .5, cpu_system_s=0., rss_bytes=4 * 1048576,
                                private_bytes=2 * 1048576, handle_count=5, thread_count=1)]
        writer.submit("detail", row)
    writer.finish("COMPLETED")


class ProcessHistoryTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def test_page_has_bounded_ancestors_and_cpu_over_100_without_source_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            before = hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest()
            with SessionView.open(folder) as view:
                page = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9, after=2, limit=1)
            self.assertEqual([r["instance_id"] for r in page["rows"]], [3])
            self.assertEqual({r["instance_id"] for r in page["ancestors"]}, {1, 2})
            self.assertTrue(all(r["context_only"] for r in page["ancestors"]))
            self.assertFalse(page["has_more"])
            self.assertFalse(page["ancestor_context_truncated"])
            with SessionView.open(folder) as view:
                all_rows = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9)["rows"]
            self.assertEqual(all_rows[1]["resources"]["cpu_peak_percent_one_cpu"], 200.)
            self.assertEqual(all_rows[1]["resources"]["handles_peak"], 0)
            self.assertIsNone(all_rows[1]["resources"]["private_peak_bytes"])
            self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)

    def test_ambiguous_parent_pid_is_not_forced_into_one_instance(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                db.execute("""INSERT INTO process_instances(pid,creation_time,parent_pid,first_observed_ns,
                    last_observed_ns,source_kind) VALUES(200,1.5,123,?,?,'TEST_ONLY')""",
                    (ORIGIN, ORIGIN+5*10**9))
                db.commit()
            with SessionView.open(folder) as view:
                child = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9)["rows"][2]
            self.assertIsNone(child["parent_instance_candidate"])
            self.assertEqual(child["parent_link_quality"], "AMBIGUOUS_PARENT_INSTANCE")

    def test_cpu_gap_does_not_create_a_peak_and_ancestor_context_is_capped(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                # Explicit import fault: a gap/reset is not high CPU evidence.
                db.execute("UPDATE samples SET series_seq=series_seq*10 WHERE instance_id=2")
                # Deep imported chain: context must stop after 256 records.
                db.executemany("""INSERT INTO process_instances(instance_id,pid,creation_time,parent_pid,
                    first_observed_ns,last_observed_ns,source_kind)
                    VALUES(?,?,1,?,?,?,'TEST_ONLY')""",
                    ((i, 1000+i, 1000+i-1, ORIGIN, ORIGIN+5*10**9) for i in range(4, 400)))
                db.commit()
            with SessionView.open(folder) as view:
                child = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9)["rows"][1]
                page = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9, after=398, limit=1)
            self.assertIsNone(child["resources"]["cpu_peak_percent_one_cpu"])
            self.assertIsNone(child["resources"]["cpu_seconds"])
            self.assertEqual(len(page["ancestors"]), 256)
            self.assertTrue(page["ancestor_context_truncated"])

    def test_real_qt_nested_context_language_and_cyclic_import(self):
        from PySide6.QtCore import Qt
        from blackbox_universal.process_history_view import RecordedProcessTree
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            with SessionView.open(folder) as view:
                page = resource_tree_page(view, ORIGIN, ORIGIN+5*10**9, after=2, limit=1)
            widget = RecordedProcessTree()
            try:
                widget.apply_page(page, selected_instance=3)
                root = widget.topLevelItem(0)
                self.assertEqual(widget.topLevelItemCount(), 1)
                self.assertEqual(root.data(0, Qt.ItemDataRole.UserRole), 1)
                self.assertEqual(root.child(0).child(0).data(0, Qt.ItemDataRole.UserRole), 3)
                self.assertEqual(widget.selected_instance(), 3)
                self.assertIn("context", root.text(0))
                self.assertEqual(root.text(4), "—")
                self.assertIn("UNVERIFIED_IMPORT", root.toolTip(0))
                widget.set_language("RU")
                self.assertIn("контекст", widget.topLevelItem(0).text(0))
                self.assertEqual(widget.selected_instance(), 3)
                self.assertIn("ВОЗРАСТ", widget.headerItem().text(8))
                # Deliberately malformed import: no Qt cycle or silent link.
                page["ancestors"][0]["parent_instance_candidate"] = 3
                widget.apply_page(page)
                self.assertEqual(widget.topLevelItemCount(), 3)
                self.assertIn("INVALID_CYCLIC", widget.item_for_instance(3).toolTip(0))
            finally:
                widget.close()
                widget.deleteLater()
                self.app.processEvents()

    def test_selected_child_opens_its_history_and_preserves_recording_target(self):
        from blackbox_universal.window import UniversalWindow
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            before = hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest()
            window = UniversalWindow(isolated=False, allow_update_check=False)
            window._timer.stop()
            window.probe.pid = 98765
            def drain():
                end = time.monotonic()+12
                while window._interval_worker is not None and time.monotonic()<end:
                    self.app.processEvents()
                    time.sleep(.005)
                self.assertIsNone(window._interval_worker)
            try:
                window._load_session_interval(folder)
                drain()
                node = window.process_history_table.item_for_instance(2)
                self.assertIsNotNone(node.parent())
                self.assertEqual(node.text(2), "200.000")
                self.assertEqual(node.text(5), "—")
                self.assertEqual(node.text(7), "0")
                window.process_history_table.setCurrentItem(node)
                drain()
                self.assertEqual(window._interval_process, 2)
                self.assertEqual(window._interval_packet["interval"]["series"], "CHILD")
                self.assertEqual(window._interval_packet["interval"]["coverage"]["selected_samples"], 3)
                self.assertEqual(window._interval_packet["threads"]["status"], "THREADS_NOT_OBSERVED_FOR_INSTANCE")
                self.assertIn("PID 200", window.thread_detail_status.text())
                self.assertEqual(window.probe.pid, 98765)
                self.assertEqual(window.stack.count(), 5)
                self.assertFalse(window.probe.active)
                window._set_language("RU")
                self.assertEqual(window.process_history_table.selected_instance(), 2)
                self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)
            finally:
                drain()
                window.close()
                self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
