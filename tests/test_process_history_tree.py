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
from blackbox_core.session_view import SessionReadError, SessionView
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

    def test_invalid_imported_process_scalars_are_rejected_without_source_mutation(self):
        faults = (("pid", -1), ("pid", "bad-import"),
                  ("creation_time", float("inf")), ("creation_time", "bad-import"),
                  ("parent_pid", -1), ("parent_pid", 1.5),
                  ("first_observed_ns", -1), ("first_observed_ns", "bad-import"),
                  ("last_observed_ns", ORIGIN), ("last_observed_ns", "bad-import"),
                  ("absence_observed_ns", -1), ("absence_observed_ns", "bad-import"),
                  ("absence_observed_ns", ORIGIN+2*10**9))
        for column, value in faults:
            with self.subTest(column=column, value=value), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp)
                recorded_tree(folder)
                with closing(sqlite3.connect(folder/FILENAME)) as db:
                    db.execute("PRAGMA ignore_check_constraints=ON")
                    db.execute(f"UPDATE process_instances SET {column}=? WHERE instance_id=2", (value,))
                    db.commit()
                before = hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest()
                with SessionView.open(folder) as view:
                    with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_PROCESS_INSTANCE"):
                        view.process_page()
                self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)

    def test_invalid_imported_ancestor_is_rejected_before_hierarchy_arithmetic(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                db.execute("UPDATE process_instances SET last_observed_ns='bad-import' WHERE instance_id=2")
                db.commit()
            before = hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest()
            with SessionView.open(folder) as view:
                # The resource row itself is valid; its separately fetched
                # context ancestor must pass the same imported-data checks.
                self.assertEqual(view.process_page(after=2, limit=1)["rows"][0]["instance_id"], 3)
                with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_PROCESS_INSTANCE"):
                    resource_tree_page(view, ORIGIN, ORIGIN+5*10**9, after=2, limit=1)
            self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)

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
                page['rows'][0]['executable_name']='<img src="file:///TEST_ONLY_PRIVATE.png">'
                widget.apply_page(page)
                tip=widget.item_for_instance(3).toolTip(0)
                self.assertNotIn('<img',tip)
                self.assertIn('&lt;img',tip)
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
                self.assertIn("PID 200", window.thread_detail_status.text())
                self.assertIn("не записывались", window.thread_detail_status.text())
                self.assertNotIn("Включите подробный сбор", window.thread_detail_status.text())
                window._set_language("EN")
                self.assertIn("PID 200", window.thread_detail_status.text())
                self.assertIn("were not captured", window.thread_detail_status.text())
                self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)
            finally:
                drain()
                window.close()
                self.app.processEvents()

    def test_loaded_tid_selection_and_localized_headers_survive_language_switch(self):
        from PySide6.QtCore import Qt
        from blackbox_universal.window import UniversalWindow
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);recorded_tree(folder)
            window=UniversalWindow(isolated=False,allow_update_check=False)
            window._timer.stop()
            try:
                window._set_language('EN');window._load_session_interval(folder)
                end=time.monotonic()+12
                while window._interval_worker is not None and time.monotonic()<end:
                    self.app.processEvents();time.sleep(.005)
                self.assertIsNone(window._interval_worker)
                table=window.thread_detail_table
                self.assertEqual(table.rowCount(),1)
                table.selectRow(0);before=table.item(0,5).text()
                for language,title in [('RU','СРЕДНЯЯ CPU %'),('EN','MEAN CPU %')]:
                    window._set_language(language)
                    self.assertEqual(table.horizontalHeaderItem(2).text(),title)
                    self.assertEqual(table.horizontalHeaderItem(2).data(Qt.ItemDataRole.UserRole),'MEAN CPU %')
                    self.assertEqual(table.currentRow(),0)
                    self.assertTrue(table.selectionModel().selectedRows())
                    self.assertEqual(table.item(0,5).text(),before)
                    self.assertIn('PID 123',window.thread_detail_status.text())
            finally:
                window.close();self.app.processEvents()

    def test_thread_read_error_survives_language_switch_without_restoring_old_ok(self):
        from blackbox_universal.window import UniversalWindow
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            window = UniversalWindow(isolated=False, allow_update_check=False)
            window._timer.stop()
            try:
                window._set_language("EN")
                window._load_session_interval(folder)
                end = time.monotonic()+12
                while window._interval_worker is not None and time.monotonic()<end:
                    self.app.processEvents()
                    time.sleep(.005)
                self.assertIsNone(window._interval_worker)
                self.assertIn("PID 123", window.thread_detail_status.text())
                table = window.thread_detail_table
                self.assertEqual(table.rowCount(), 1)
                table.selectRow(0)
                before = table.item(0, 5).text()
                # Exercise the worker's error delivery on a real loaded Qt
                # view, retaining the last cells and the user's selection.
                window._thread_detail_ready(None, "DETAIL_READ_UNAVAILABLE")
                for language, text in (("RU", "Данные потоков недоступны; исходная запись не изменена."),
                                       ("EN", "Thread detail is unavailable; source data were not changed.")):
                    window._set_language(language)
                    self.assertEqual(window.thread_detail_status.text(), text)
                    self.assertNotIn("PID 123", window.thread_detail_status.text())
                    self.assertEqual(table.item(0, 5).text(), before)
                    self.assertTrue(table.selectionModel().selectedRows())
            finally:
                window.close()
                self.app.processEvents()

    def test_malformed_import_fails_in_worker_and_preserves_error_after_language_switch(self):
        from blackbox_universal.window import UniversalWindow
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            recorded_tree(folder)
            window = UniversalWindow(isolated=False, allow_update_check=False)
            window._timer.stop()
            def drain():
                end = time.monotonic()+12
                while window._interval_worker is not None and time.monotonic()<end:
                    self.app.processEvents()
                    time.sleep(.005)
                self.assertIsNone(window._interval_worker)
            try:
                window._set_language("EN")
                window._load_session_interval(folder)
                drain()
                self.assertIsNotNone(window._interval_packet)
                self.assertTrue(window.export_interval_btn.isEnabled())
                old_node = window.process_history_table.item_for_instance(1)
                old_thread_cpu = window.thread_detail_table.item(0, 5).text()
                with closing(sqlite3.connect(folder/FILENAME)) as db:
                    db.execute("UPDATE process_instances SET first_observed_ns='bad-import' WHERE instance_id=1")
                    db.commit()
                before = hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest()
                with SessionView.open(folder) as view:
                    with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_PROCESS_INSTANCE"):
                        view.process_page()
                window._load_session_interval(folder)
                drain()
                self.assertIsNone(window._interval_packet)
                self.assertFalse(window.export_interval_btn.isEnabled())
                # A rejected packet never reaches the tree or TID renderers.
                self.assertIs(window.process_history_table.item_for_instance(1), old_node)
                self.assertEqual(window.thread_detail_table.item(0, 5).text(), old_thread_cpu)
                for language, text in (("RU", "Интервал недоступен; исходные файлы не изменены."),
                                       ("EN", "Selected interval is unavailable; source files were not changed.")):
                    window._set_language(language)
                    self.assertEqual(window.interval_summary.text(), text)
                    self.assertIsNone(window._interval_packet)
                    self.assertFalse(window.export_interval_btn.isEnabled())
                self.assertEqual(hashlib.sha256((folder/FILENAME).read_bytes()).hexdigest(), before)
            finally:
                drain()
                window.close()
                self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
