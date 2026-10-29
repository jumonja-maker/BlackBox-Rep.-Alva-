"""BB-DEEP-001 Qt contracts; executed only by GitHub-hosted CI.

Backend doubles test GUI choices and lifecycle, not native Windows behavior.
Actual Windows inspection and intervention have a separate acceptance job.
"""
import os
import threading
import time
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_universal.deep_inspector_bridge import DeepInspectorBridge
from blackbox_universal.deep_inspector_panel import OverviewInspectorPanel, SECTIONS


class FakeBridge(QObject):
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    idle = Signal()
    closed = Signal(object)
    recovery_required = Signal(object)

    def __init__(self):
        super().__init__()
        self.target = (234, 1000.0)
        self.generation = 1
        self.busy = False
        self.admin_active = False
        self.cleanup_required = False
        self.calls = []

    def submit(self, operation, parameters=None, **kwargs):
        if self.busy:
            return False
        self.calls.append((operation, parameters or {}, kwargs))
        return True

    def capabilities(self):
        self.calls.append(("capabilities", {}, {}))
        return True

    def elevate(self, operations):
        self.calls.append(("elevate", {"operations": operations}, {}))
        return True

    def end_admin(self):
        self.calls.append(("end_admin", {}, {}))
        return True

    def export(self, destination):
        self.calls.append(("export", {"destination": destination}, {}))
        return True

    def cancel(self):
        self.calls.append(("cancel", {}, {}))

    def retry_cleanup(self):
        self.calls.append(("retry_cleanup", {}, {}))

    def shutdown(self):
        self.calls.append(("shutdown", {}, {}))
        self.closed.emit({"status": "COMPLETED"})

    def set_target(self, pid, created):
        value = (pid, created) if pid else None
        if value != self.target:
            self.target = value
            self.generation += 1
            self.target_changed.emit()


class DeepInspectorGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget()
        self.window.language = "EN"
        self.bridge = FakeBridge()
        self.panel = OverviewInspectorPanel(self.window, bridge=self.bridge)
        self.panel.resize(850, 800)
        self.panel.show()
        self.app.processEvents()

    def tearDown(self):
        self.panel.close()
        self.window.close()
        self.panel.deleteLater()
        self.window.deleteLater()
        self.app.processEvents()

    def test_nine_sections_are_local_and_opening_never_starts_work(self):
        self.assertEqual(self.panel.section.count(), 9)
        self.assertEqual(self.panel.pages.count(), 9)
        for index, (key, _, _) in enumerate(SECTIONS):
            self.panel.section.setCurrentIndex(index)
            self.assertEqual(self.panel.section.currentData(), key)
            self.assertEqual(self.panel.pages.currentIndex(), index)
        self.assertEqual(self.bridge.calls, [])

    def test_memory_backing_file_and_unknown_owner_remain_visible_with_column_budget(self):
        row = {"base": 4096, "size": 4096, "allocation_base": 4096,
               "allocation_protection": 32, "protection": 32, "state": 4096,
               "type": 0x1000000, "state_name": "COMMIT", "type_name": "IMAGE",
               "mapped_file_path": r"\Device\HarddiskVolume3\controlled.exe",
               "image_name": "controlled.exe", "mapped_file_status": "OBSERVED",
               "association_kind": "IMAGE_FILE_BACKING", "mapped_file_source": "WIN32_GET_MAPPED_FILE_NAME"}
        denied = {**row, "base": 8192, "mapped_file_path": None, "image_name": None,
                  "mapped_file_status": "ACCESS_DENIED", "mapped_file_winerror": 5}
        for language in ("EN", "RU"):
            self.window.language = language
            self.panel.retranslate()
            self.panel._show_result("memory", {"operation": "memory_map", "status": "INCOMPLETE_EVIDENCE",
                                                "data": {"rows": [row, denied]}})
            table = self.panel._tables["memory"]
            self.assertLessEqual(table.columnCount(), 12)
            rendered = [table.item(r, c).text() for r in range(table.rowCount())
                        for c in range(table.columnCount()) if table.item(r, c) is not None]
            self.assertIn(row["mapped_file_path"], rendered)
            self.assertIn("IMAGE_FILE_BACKING", rendered)
            self.assertIn("ACCESS_DENIED", rendered)
            self.assertEqual(rendered.count("controlled.exe"), 1)
        self.assertFalse(self.bridge.calls)

    def test_required_controls_exist_and_translate_without_commands(self):
        required = {"capabilities", "before", "after", "compare", "cancel", "end_admin", "retry_cleanup",
                    "processes", "modules", "threads", "thread_stacks", "wait_chains", "handles",
                    "memory_map", "memory_read", "memory.write", "memory.rollback", "network", "disk",
                    "debug.attach", "debug.pause", "debug.continue", "debug.step", "debug.context", "debug.detach",
                    "debug.breakpoints", "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove",
                    "thread.suspend", "thread.resume", "dump", "dump_inspect", "symbols_verify", "export", "trace_evidence",
                    "profile.etw", "captured_trace", "profiling", "stack_pdb", "dump_read_memory",
                    "historical_network_interval", "historical_disk_interval", "stack_frame_module"}
        self.assertTrue(required.issubset(self.panel._action_buttons))
        english = {k: b.text() for k, b in self.panel._action_buttons.items()}
        self.window.language = "RU"
        self.panel.retranslate()
        for key in required:
            self.assertNotEqual(self.panel._action_buttons[key].text(), english[key], key)
            self.assertEqual(self.panel._action_buttons[key].accessibleName(), self.panel._action_buttons[key].text())
        self.window.language = "EN"
        self.panel.retranslate()
        self.assertEqual({k: b.text() for k, b in self.panel._action_buttons.items()}, english)
        self.assertEqual(self.bridge.calls, [])

    def test_read_buttons_dispatch_real_operation_names(self):
        for key in ("processes", "modules", "threads", "handles", "memory_map", "network", "disk", "wait_chains", "timeline", "debug.breakpoints", "debug.context"):
            self.panel._action_buttons[key].click()
            self.assertEqual(self.bridge.calls[-1][0], key)

    def test_memory_input_validation_precedes_confirmation_and_write(self):
        self.panel.memory_address.setText("0x12340000")
        self.panel.expected_bytes.setText("01 02")
        self.panel.new_bytes.setText("03")
        with patch.object(self.panel, "_confirm") as confirm:
            self.panel._action_buttons["memory.write"].click()
        confirm.assert_not_called()
        self.assertEqual(self.bridge.calls, [])
        self.assertIn("MEMORY_BYTES_MUST_HAVE_EQUAL_BOUNDED_LENGTH", self.panel.status_label.text())

    def test_memory_write_exact_bytes_and_restore_id_require_confirmation(self):
        self.panel.memory_address.setText("0x12340000")
        self.panel.expected_bytes.setText("01 02")
        self.panel.new_bytes.setText("03 04")
        with patch.object(self.panel, "_confirm", return_value=False):
            self.panel._action_buttons["memory.write"].click()
        self.assertEqual(self.bridge.calls, [])
        with patch.object(self.panel, "_confirm", return_value=True) as confirmation:
            self.panel._action_buttons["memory.write"].click()
        operation, parameters, options = self.bridge.calls[-1]
        self.assertEqual(operation, "memory.write")
        self.assertEqual(parameters, {"address": 0x12340000, "expected_hex": "0102", "value_hex": "0304"})
        self.assertTrue(options["confirmed"])
        confirmation.assert_called_once_with(operation, parameters)
        self.panel._receive({"operation": "memory.write", "status": "COMPLETED", "data": {"change_id": "change-1"}})
        self.assertEqual(self.panel.write_id.text(), "change-1")
        with patch.object(self.panel, "_confirm", return_value=True):
            self.panel._action_buttons["memory.rollback"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"change_id": "change-1"})

    def test_memory_confirmation_cannot_rebind_to_changed_or_reselected_target(self):
        for return_to_original in (False, True):
            with self.subTest(return_to_original=return_to_original):
                self.panel.set_target(234, 1000., "original")
                self.panel.memory_address.setText("0x20000")
                self.panel.expected_bytes.setText("00")
                self.panel.new_bytes.setText("01")
                def changed_during_confirmation(*_):
                    self.panel.set_target(235, 2000., "replacement")
                    if return_to_original:
                        self.panel.set_target(234, 1000., "original selected again")
                    return True
                with patch.object(self.panel, "_confirm", side_effect=changed_during_confirmation):
                    self.panel._action_buttons["memory.write"].click()
                self.assertEqual(self.bridge.calls, [])
                self.assertIn("CANCELLED", self.panel.status_label.text())
                self.assertIsNone(self.panel._last_request)

    def test_elevation_consent_cannot_authorize_a_replacement_target(self):
        self.panel._request("modules")
        self.panel._receive({"operation": "modules", "status": "ADMIN_REQUIRED", "data": {}})
        count = len(self.bridge.calls)
        with patch("blackbox_universal.deep_inspector_panel.QMessageBox") as message_box:
            dialog = message_box.return_value
            grant = object()
            dialog.addButton.return_value = grant
            dialog.clickedButton.return_value = grant
            dialog.exec.side_effect = lambda: self.panel.set_target(235, 2000., "replacement")
            self.panel._elevate()
        self.assertEqual(len(self.bridge.calls), count)
        self.assertIsNone(self.panel._pending_retry)
        self.assertIn("CANCELLED", self.panel.status_label.text())

    def test_file_selection_cannot_carry_destination_to_a_new_target(self):
        for action in (self.panel._record_etw, self.panel._export):
            with self.subTest(action=action.__name__):
                self.panel.set_target(234, 1000., "original")
                def changed_during_picker(*_):
                    self.panel.set_target(235, 2000., "replacement")
                    return "chosen-for-original.etl", ""
                with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", side_effect=changed_during_picker), \
                     patch.object(self.panel, "_confirm") as confirm:
                    action()
                confirm.assert_not_called()
                self.assertEqual(self.bridge.calls, [])
                self.assertIn("CANCELLED", self.panel.status_label.text())

    def test_multistep_dialog_chains_stop_after_target_changes(self):
        def changed_during_type(*_):
            self.panel.set_target(235, 2000., "replacement")
            return "Minidump", True
        with patch("blackbox_universal.deep_inspector_panel.QInputDialog.getItem", side_effect=changed_during_type), \
             patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName") as save:
            self.panel._dump()
        save.assert_not_called()
        self.panel.set_target(234, 1000., "original")
        def changed_during_pe(*_):
            self.panel.set_target(235, 2000., "replacement")
            return "original.exe", ""
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getOpenFileName", side_effect=changed_during_pe) as choose:
            self.panel._symbols()
        self.assertEqual(choose.call_count, 1)
        self.assertEqual(self.bridge.calls, [])

    def test_trace_instance_picker_discards_old_request_after_target_change(self):
        self.panel._trace_request = {"index_path": "original.sqlite3", "limit": 200}
        def changed_during_instance(*args):
            self.panel.set_target(235, 2000., "replacement")
            return args[3][0], True
        with patch("blackbox_universal.deep_inspector_panel.QInputDialog.getItem", side_effect=changed_during_instance):
            self.panel._choose_trace_instance({"candidate_instances": [
                {"process_instance": 8, "pid": 234, "first_ms": 0, "last_ms": 10}]})
        self.assertIsNone(self.panel._trace_request)
        self.assertEqual(self.bridge.calls, [])
        self.assertIn("CANCELLED", self.panel.status_label.text())

    def test_thread_selection_carries_lifetime_not_tid_alone(self):
        result = {"operation": "threads", "status": "COMPLETED", "data": {
            "threads": [{"tid": 75, "thread_created_100ns": 133400000000000000}]}}
        self.panel._show_result("threads", result)
        self.panel._tables["threads"].selectRow(0)
        self.app.processEvents()
        with patch.object(self.panel, "_confirm", return_value=True):
            self.panel._action_buttons["thread.suspend"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"tid": 75, "thread_created_100ns": 133400000000000000})
        self.panel.thread_created.clear()
        count = len(self.bridge.calls)
        self.panel._action_buttons["thread.resume"].click()
        self.assertEqual(len(self.bridge.calls), count)

    def test_oversized_memory_write_refuses_before_confirmation(self):
        self.panel.memory_address.setText("0x20000")
        self.panel.expected_bytes.setText("00" * 4097)
        self.panel.new_bytes.setText("01" * 4097)
        with patch.object(self.panel, "_confirm") as confirm:
            self.panel._action_buttons["memory.write"].click()
        confirm.assert_not_called()
        self.assertEqual(self.bridge.calls, [])
        self.assertIn("MEMORY_WRITE_LIMIT_4096_BYTES", self.panel.status_label.text())

    @staticmethod
    def current_stack_frame():
        return {"address": 0x10020, "module": "controlled.dll", "module_base": 0x10000, "rva": 0x20,
                "module_identity": {"base": 0x10000, "size": 0x1000, "name": "controlled.dll",
                                    "path": "controlled.dll", "snapshot_pe": {"image_size": 0x1000, "guid": "observed-guid", "age": 1},
                                    "snapshot_binding": "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH", "source": "SAME_PSS_CAPTURE"},
                "symbol": {"name": "ControlledFunction", "source_location": {"file": "controlled.c", "line": 19}},
                "symbol_binding": "PSS_CLONE_CODEVIEW_AND_LOCAL_PE_PDB_MATCH"}

    def test_current_stack_frames_navigate_only_snapshot_bound_module(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("threads"))
        self.panel._request_section = "threads"
        frame = self.current_stack_frame()
        self.panel._receive({"operation": "thread_stacks", "status": "COMPLETED", "generation": 1,
                             "target": {"pid": 234, "created_100ns": 12345, "image_path": "controlled.exe"}, "data": {"rows": [
            {"tid": 75, "created_100ns": 4567, "captured_100ns": 6789, "kind": "LIVE_PSS_THREAD_CONTEXT",
             "historical_etw_stack": False, "frames": [frame], "unwind_completeness": "NOT_PROVEN"}]}})
        self.panel._tables["threads"].selectRow(0)
        self.app.processEvents()
        self.assertEqual(self.panel.stack_frames.rowCount(), 1)
        self.assertIn("Current thread stack", self.panel.stack_source_label.text())
        self.assertIn("FILETIME 4567", self.panel.stack_source_label.text())
        self.assertEqual(self.panel.stack_frames.item(0, 1).text(), "0x10020")
        self.assertEqual(self.panel.stack_frames.item(0, 4).text(), "ControlledFunction")
        self.assertIn("controlled.c", self.panel.stack_frames.item(0, 5).text())
        self.panel.stack_frames.selectRow(0)
        self.app.processEvents()
        self.assertTrue(self.panel._action_buttons["stack_frame_module"].isEnabled())
        self.panel._action_buttons["stack_frame_module"].click()
        self.assertEqual(self.panel.section.currentData(), "modules")
        module = self.panel._section_results["modules"]["data"]["rows"][0]
        self.assertEqual(module["base"], 0x10000)
        self.assertEqual(module["frame_address"], 0x10020)
        self.assertEqual(module["source"], "SAME_PSS_CAPTURE")
        self.assertEqual(self.panel._section_results["modules"]["data"]["stack_context"]["thread_created_100ns"], 4567)
        self.assertEqual(self.panel.memory_address.text(), "0x10020")
        self.assertEqual(self.panel.stack_module_base.text(), "0x10000")
        self.assertEqual(self.bridge.calls, [])

    def test_selecting_another_thread_preserves_unresolved_pc_without_old_symbol(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("threads"))
        self.panel._request_section = "threads"
        rows = [{"tid": 75, "created_100ns": 4567, "kind": "LIVE_PSS_THREAD_CONTEXT",
                 "historical_etw_stack": False, "frames": [self.current_stack_frame()]},
                {"tid": 76, "created_100ns": 4568, "kind": "LIVE_PSS_THREAD_CONTEXT",
                 "historical_etw_stack": False, "frames": [{"address": 0x123456, "module": None, "rva": None}]}]
        self.panel._receive({"operation": "thread_stacks", "status": "INCOMPLETE_EVIDENCE", "data": {"rows": rows}})
        self.panel._tables["threads"].selectRow(0)
        self.panel.stack_frames.selectRow(0)
        self.app.processEvents()
        self.panel._tables["threads"].selectRow(1)
        self.app.processEvents()
        self.panel.stack_frames.selectRow(0)
        self.app.processEvents()
        self.assertEqual(self.panel.thread_tid.text(), "76")
        self.assertEqual(self.panel.thread_created.text(), "4568")
        self.assertEqual(self.panel.stack_frames.item(0, 1).text(), "0x123456")
        self.assertEqual(self.panel.stack_frames.item(0, 4).text(), "—")
        self.assertEqual(self.panel.stack_frames.item(0, 2).text(), "—")
        self.assertFalse(self.panel._action_buttons["stack_frame_module"].isEnabled())
        self.assertEqual(self.panel.stack_module_base.text(), "")

    def test_historical_stack_module_never_populates_live_thread_or_memory_inputs(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("threads"))
        self.panel._request_section = "threads"
        module = {"schema": "blackbox.trace-module/1", "source": "TRACEEVENT_NATIVE_LOAD_WINDOW",
                  "process_instance": 8, "module_file_index": 0, "image_base": "0x10000", "image_size": 0x1000,
                  "image_timestamp": 1, "load_time_ms": 0, "unload_time_ms": 100, "pdb_guid": None,
                  "pdb_age": None, "module_name": "recorded.dll"}
        row = {"pid": 234, "tid": 75, "process_instance": 8, "time_ms": 20, "source": "HISTORICAL_TRACE",
               "frames": [{"address": "0x10020", "name": "RecordedName", "module": module, "rva": 0x20}]}
        self.panel.thread_tid.setText("999")
        self.panel.thread_created.setText("1001")
        self.panel.memory_address.setText("0x7777")
        self.panel._receive({"operation": "trace_evidence", "status": "INCOMPLETE_EVIDENCE", "data": {
            "trace_selection": {"process_instance": 8}, "events": [row]}})
        self.panel._tables["threads"].selectRow(0)
        self.app.processEvents()
        self.panel.stack_frames.selectRow(0)
        self.app.processEvents()
        self.assertIn("Historical trace stack", self.panel.stack_source_label.text())
        self.assertIn("NOT_ESTABLISHED", self.panel.stack_source_label.text())
        self.assertEqual(self.panel.thread_tid.text(), "")
        self.assertEqual(self.panel.thread_created.text(), "")
        self.assertEqual(self.panel.memory_address.text(), "")
        self.assertEqual(self.panel.stack_frames.item(0, 4).text(), "RecordedName")
        self.assertTrue(self.panel._action_buttons["stack_frame_module"].isEnabled())
        self.panel._action_buttons["stack_frame_module"].click()
        self.assertEqual(self.panel._section_results["modules"]["data"]["rows"][0]["inspection_scope"], "HISTORICAL_TRACE_MODULE")
        self.assertEqual(self.panel.memory_address.text(), "")
        self.assertEqual(self.bridge.calls, [])

    def test_stack_frames_are_bounded_and_target_change_rejects_stale_stack_result(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("threads"))
        self.panel._request_section = "threads"
        packet = {"operation": "thread_stacks", "generation": 1, "status": "INCOMPLETE_EVIDENCE", "data": {"rows": [
            {"tid": 75, "created_100ns": 4567, "kind": "LIVE_PSS_THREAD_CONTEXT", "historical_etw_stack": False,
             "frames": [{"address": i + 1} for i in range(140)]}]}}
        self.panel._receive(packet)
        self.panel._tables["threads"].selectRow(0)
        self.app.processEvents()
        self.assertEqual(self.panel.stack_frames.rowCount(), 128)
        self.assertIn("omitted: 12", self.panel.stack_source_label.text())
        self.panel.set_target(235, 2000., "new instance")
        self.assertEqual(self.panel.stack_frames.rowCount(), 0)
        self.assertIsNone(self.panel._stack_context)
        self.panel._receive(packet)
        self.assertEqual(self.panel._tables["threads"].rowCount(), 0)
        self.assertFalse(self.panel._action_buttons["stack_frame_module"].isEnabled())

    def test_debug_buttons_confirm_and_propagate_stopped_context(self):
        self.panel._receive({"operation": "debug.pause", "status": "COMPLETED", "data": {
            "state": "PAUSED", "stopped_tid": 23, "thread_created_100ns": 123456}})
        self.assertEqual(self.panel.debug_tid.text(), "23")
        self.assertEqual(self.panel.debug_state_label.text(), "DEBUG: PAUSED")
        self.panel.breakpoint_address.setText("0x20000")
        self.panel.breakpoint_id.setText("bp-1")
        for operation in ("debug.attach", "debug.pause", "debug.continue", "debug.step", "debug.detach",
                          "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove"):
            count = len(self.bridge.calls)
            with patch.object(self.panel, "_confirm", return_value=False):
                self.panel._action_buttons[operation].click()
            self.assertEqual(len(self.bridge.calls), count)
            with patch.object(self.panel, "_confirm", return_value=True):
                self.panel._action_buttons[operation].click()
            self.assertEqual(self.bridge.calls[-1][0], operation)
            self.assertTrue(self.bridge.calls[-1][2]["confirmed"])

    def test_before_after_stay_separate_and_target_change_invalidates_them(self):
        self.assertFalse(self.panel._action_buttons["compare"].isEnabled())
        self.panel._receive({"operation": "snapshot", "request_tag": "before", "status": "COMPLETED", "data": {"snapshot_id": "before-1"}})
        self.panel._receive({"operation": "snapshot", "request_tag": "after", "status": "COMPLETED", "data": {"snapshot_id": "after-1"}})
        self.assertTrue(self.panel._action_buttons["compare"].isEnabled())
        self.panel._action_buttons["compare"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"before_id": "before-1", "after_id": "after-1"})
        self.panel.set_target(235, 1001., "replacement")
        self.assertIsNone(self.panel._before_id)
        self.assertIsNone(self.panel._after_id)
        self.assertFalse(self.panel._action_buttons["compare"].isEnabled())

    def test_busy_operation_disables_mutation_but_keeps_cancel(self):
        self.bridge.busy = True
        self.bridge.busy_changed.emit(True)
        self.assertFalse(self.panel._action_buttons["memory.write"].isEnabled())
        self.assertFalse(self.panel._action_buttons["debug.attach"].isEnabled())
        self.assertTrue(self.panel.cancel_button.isEnabled())
        self.panel.cancel_button.click()
        self.assertEqual(self.bridge.calls[-1][0], "cancel")

    def test_retained_owner_blocks_new_actions_and_exposes_cleanup_retry(self):
        self.bridge.busy = True
        self.bridge.cleanup_required = True
        self.bridge.busy_changed.emit(True)
        self.assertFalse(self.panel._action_buttons["memory.write"].isEnabled())
        self.assertFalse(self.panel._action_buttons["debug.attach"].isEnabled())
        self.assertFalse(self.panel.cancel_button.isEnabled())
        self.assertTrue(self.panel._action_buttons["retry_cleanup"].isEnabled())
        self.panel._action_buttons["retry_cleanup"].click()
        self.assertEqual(self.bridge.calls[-1][0], "retry_cleanup")

    def test_uac_cancel_never_retries_the_requested_operation(self):
        self.panel._request("modules")
        self.panel._receive({"operation": "modules", "status": "ADMIN_REQUIRED", "data": {}})
        self.assertFalse(self.panel.elevate_button.isHidden())
        self.panel._pending_retry = dict(self.panel._last_request)
        self.panel._receive({"operation": "elevate", "request_kind": "elevate", "status": "UAC_CANCELLED", "data": {}})
        count = len(self.bridge.calls)
        self.panel._idle()
        self.assertEqual(len(self.bridge.calls), count)
        self.assertIn("UAC_CANCELLED", self.panel.status_label.text())

    def test_recovery_unconfirmed_is_visible_and_not_rendered_as_success(self):
        self.panel._receive({"operation": "debug.detach", "status": "RECOVERY_UNCONFIRMED",
                             "error": "OWN_THREAD_RESUME_FAILED", "winerror": 5,
                             "data": {}, "limitations": ["OWN_THREAD_RESUME_NOT_CONFIRMED"]})
        self.assertIn("RECOVERY_UNCONFIRMED", self.panel.status_label.text())
        self.assertIn("OWN_THREAD_RESUME_NOT_CONFIRMED", self.panel.summary.text())
        self.assertIn("bold", self.panel.status_label.styleSheet())
        self.window.language = "RU"
        self.panel.retranslate()
        self.assertIn("Восстановление не подтверждено", self.panel.status_label.text())
        self.assertIn("OWN_THREAD_RESUME_FAILED", self.panel.status_label.text())
        self.assertIn("WinError 5", self.panel.status_label.text())

    def test_file_dialog_actions_only_submit_explicit_chosen_paths(self):
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getOpenFileName",
                   side_effect=[("sample.exe", ""), ("sample.pdb", ""), ("saved.dmp", ""), ("trace.sqlite3", "")]):
            self.panel._symbols()
            self.panel._inspect_dump()
            self.panel._trace()
        self.assertEqual(self.bridge.calls[-3][0:2], ("symbols_verify", {"pe_path": "sample.exe", "pdb_path": "sample.pdb"}))
        self.assertEqual(self.bridge.calls[-2][0:2], ("dump_inspect", {"path": "saved.dmp"}))
        self.assertEqual(self.bridge.calls[-1][0:2], ("trace_evidence", {"index_path": "trace.sqlite3", "limit": 200}))
        self.assertNotIn("process_instance", self.bridge.calls[-1][1])

    def test_dump_type_destination_and_confirmation_are_explicit(self):
        with patch("blackbox_universal.deep_inspector_panel.QInputDialog.getItem", return_value=("Extended dump with memory", True)), \
             patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("selected.dmp", "")), \
             patch.object(self.panel, "_confirm", return_value=True):
            self.panel._dump()
        operation, params, options = self.bridge.calls[-1]
        self.assertEqual(operation, "dump")
        self.assertEqual(params["destination"], "selected.dmp")
        self.assertTrue(params["full"])
        self.assertTrue(options["confirmed"])

    def test_etw_profile_needs_confirmation_and_actual_captured_file(self):
        self.assertFalse(self.panel._action_buttons["captured_trace"].isEnabled())
        self.panel.profile_seconds.setValue(3)
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("selected.etl", "")), \
             patch.object(self.panel, "_confirm", return_value=False):
            self.panel._action_buttons["profile.etw"].click()
        self.assertEqual(self.bridge.calls, [])
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("selected.etl", "")), \
             patch.object(self.panel, "_confirm", return_value=True):
            self.panel._action_buttons["profile.etw"].click()
        operation, parameters, options = self.bridge.calls[-1]
        self.assertEqual(operation, "profile.etw")
        self.assertEqual(parameters, {"duration_seconds": 3, "profile": "BLACKBOX.Deep.Light",
                                      "destination": "selected.etl", "systemwide_confirmed": True})
        self.assertTrue(options["confirmed"])
        self.assertEqual(options["timeout_seconds"], 120)
        self.panel._receive({"operation": "profile.etw", "status": "OPERATION_FAILED",
                             "data": {"destination": "partial.etl", "trace_bytes": 0}})
        self.assertFalse(self.panel._action_buttons["captured_trace"].isEnabled())
        self.panel._receive({"operation": "profile.etw", "status": "COMPLETED",
                             "data": {"destination": "unverified.etl", "trace_bytes": 123}})
        self.assertFalse(self.panel._action_buttons["captured_trace"].isEnabled())
        self.panel._receive({"operation": "profile.etw", "status": "COMPLETED",
                             "data": {"destination": "captured.etl", "trace_bytes": 123, "saved_verified": True}})
        self.assertTrue(self.panel._action_buttons["captured_trace"].isEnabled())
        self.assertEqual(self.panel._captured_trace, "captured.etl")
        self.window._navigate = Mock()
        self.window.decoder_panel = Mock()
        self.panel._open_captured_trace()
        self.window._navigate.assert_called_once_with("decoder")
        from pathlib import Path
        self.window.decoder_panel.start_decode.assert_called_once_with(Path("captured.etl"))
        self.panel._receive({"operation": "profile.etw", "status": "INCOMPLETE_EVIDENCE",
                             "data": {"destination": "partial.etl", "trace_bytes": 12, "saved_verified": True}})
        self.assertFalse(self.panel._action_buttons["captured_trace"].isEnabled())

    def test_etw_file_cancellation_never_requests_confirmation_or_capture(self):
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("", "")), \
             patch.object(self.panel, "_confirm") as confirm:
            self.panel._action_buttons["profile.etw"].click()
        confirm.assert_not_called()
        self.assertEqual(self.bridge.calls, [])
        self.assertEqual(self.panel.profile_kind.count(), 1)
        self.assertEqual(self.panel.profile_seconds.minimum(), 1)
        self.assertEqual(self.panel.profile_seconds.maximum(), 30)

    def test_etw_scoped_elevation_retry_preserves_exact_confirmed_destination(self):
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("selected.etl", "")), \
             patch.object(self.panel, "_confirm", return_value=True):
            self.panel._record_etw()
        original = self.bridge.calls[-1]
        self.panel._receive({"operation": "profile.etw", "status": "ADMIN_REQUIRED", "data": {}})
        self.panel._pending_retry = dict(self.panel._last_request)
        self.panel._receive({"operation": "elevate", "request_kind": "elevate", "status": "COMPLETED", "data": {}})
        self.panel._idle()
        self.assertEqual(self.bridge.calls[-1], original)
        self.assertIsNone(self.panel._pending_retry)

    def test_selected_disk_interval_preserves_recorded_identity_source_and_units(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("disk"))
        self.panel._request("trace_evidence", {"index_path": "chosen.sqlite3", "process_instance": 8, "limit": 200})
        row = {"category": "disk", "event_id": 31, "trace_relative_ms": 20.0, "pid": 234,
               "process_instance": 8, "tid": 71, "provider_guid": "source", "event_name": "DiskIO/Write",
               "source": "HISTORICAL_KERNEL_EVENT_METADATA_UNVERIFIED", "fields": {"FileName": "controlled.dat"},
               "recorded_size_fields": {}, "recorded_timing_fields": {}, "latency_ms": 10.0,
               "latency_status": "COMPLETION_EVENT_REPORTED_QPC_DURATION_UNVERIFIED",
               "event_transfer_bytes": 128, "trace_interval_start_ms": 10.0, "trace_interval_end_ms": 20.0}
        self.panel._receive({"operation": "trace_evidence", "status": "INCOMPLETE_EVIDENCE", "data": {
            "source_trace_sha256": "a" * 64, "trace_selection": {"pid": 234, "process_instance": 8}, "io_events": [row]}})
        table = self.panel._tables["disk"]
        headers = [table.horizontalHeaderItem(i).text() for i in range(table.columnCount())]
        self.assertIn("Reported duration, ms", headers)
        self.assertIn("Event transfer, bytes", headers)
        self.assertFalse(self.panel._action_buttons["historical_disk_interval"].isEnabled())
        table.selectRow(0)
        self.app.processEvents()
        self.assertTrue(self.panel._action_buttons["historical_disk_interval"].isEnabled())
        self.panel._action_buttons["historical_disk_interval"].click()
        operation, parameters, _ = self.bridge.calls[-1]
        self.assertEqual(operation, "trace_evidence")
        self.assertEqual(parameters["index_path"], "chosen.sqlite3")
        self.assertEqual(parameters["process_instance"], 8)
        self.assertEqual(parameters["expected_source_trace_sha256"], "a" * 64)
        self.assertEqual(parameters["tid"], 71)
        self.assertEqual(parameters["start_ms"], 10.0)
        self.assertGreater(parameters["end_ms"], 20.0)
        self.assertLess(parameters["end_ms"], 20.0000001)
        self.assertEqual(self.panel.section.currentData(), "timeline")
        self.panel._receive({"operation": "trace_evidence", "status": "INCOMPLETE_EVIDENCE", "data": {
            "source_trace_sha256": "a" * 64, "trace_selection": dict(parameters, pid=234), "events": []}})
        self.assertIn("Recorded interval, ms", self.panel.summary.text())
        self.assertIn("association with the live process remains unestablished", self.panel.summary.text())

    def test_unbound_trace_rows_cannot_be_opened_as_an_interval(self):
        self.panel.section.setCurrentIndex(self.panel.section.findData("network"))
        self.panel._show_result("network", {"operation": "trace_evidence", "data": {
            "trace_selection": {"process_instance": 8},
            "io_events": [{"category": "network", "process_instance": 8, "trace_relative_ms": 20.0}]}})
        self.panel._tables["network"].selectRow(0)
        self.app.processEvents()
        self.assertFalse(self.panel._action_buttons["historical_network_interval"].isEnabled())
        self.panel._open_trace_interval()
        self.assertEqual(self.bridge.calls, [])

    def test_offline_dump_read_does_not_silently_shorten_requested_size(self):
        self.panel._dump_path = "saved.dmp"
        self.panel.memory_address.setText("0x20000")
        self.panel.memory_size.setValue(4097)
        self.panel._read_dump_memory()
        self.assertEqual(self.bridge.calls, [])
        self.assertIn("SAVED_DUMP_READ_LIMIT_4096_BYTES", self.panel.status_label.text())
        self.panel.memory_size.setValue(64)
        self.panel._read_dump_memory()
        self.assertEqual(self.bridge.calls[-1][0:2], ("dump_read_memory", {
            "path": "saved.dmp", "address": 0x20000, "size": 64}))

    def test_table_output_is_bounded_and_treated_as_plain_text(self):
        self.panel._receive({"operation": "processes", "status": "INCOMPLETE_EVIDENCE", "data": {
            "rows": [{"pid": i, "name": "<script>not markup</script>"} for i in range(800)]}})
        table = self.panel._tables["processes"]
        self.assertEqual(table.rowCount(), 500)
        self.assertIn("500 / 800", self.panel.summary.text())
        self.assertEqual(table.item(0, 1).text(), "<script>not markup</script>")


class _FakeService:
    def __init__(self, *, block=False, close_failure=False):
        self.admin_active = False
        self.block = block
        self.close_failure = close_failure
        self.started = threading.Event()
        self.closed = False
        self.identities = []
        self.executed = []
        self.exported = []

    def identity(self, pid):
        self.identities.append(pid)
        return ProcessIdentity(pid, 133400000000000000, "controlled.exe")

    def execute(self, request, cancel_event=None):
        self.executed.append(request)
        self.started.set()
        if self.block:
            if not cancel_event.wait(4):
                raise TimeoutError("TEST_CANCEL_NOT_RECEIVED")
            return {"status": "CANCELLED", "operation": request.operation, "data": {}}
        return {"status": "COMPLETED", "operation": request.operation, "data": {"pid": request.target.pid}}

    def export_journal(self, destination, *, cancel_event=None):
        self.exported.append((destination, cancel_event))
        self.started.set()
        if self.block:
            if cancel_event is None or not cancel_event.wait(4):
                raise TimeoutError("TEST_EXPORT_CANCEL_NOT_RECEIVED")
            return {"status": "CANCELLED", "operation": "journal.export", "data": {"export_published": False}}
        return {"status": "COMPLETED", "operation": "journal.export", "data": {"path": destination}}

    def close(self):
        self.closed = True
        if self.close_failure:
            raise RuntimeError("CONTROLLED_CLEANUP_FAILURE")
        return {"status": "COMPLETED", "data": {"cleanup": "VERIFIED"}}


class DeepInspectorBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.app.processEvents()
        self.assertTrue(predicate())

    def test_lazy_identity_and_worker_do_not_run_on_select(self):
        made = []
        service = _FakeService()
        bridge = DeepInspectorBridge(service_factory=lambda: (made.append(threading.get_ident()), service)[1])
        bridge.set_target(123, 1000.)
        self.assertEqual(made, [])
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            self.assertTrue(bridge.submit("modules"))
            self.wait(lambda: bridge.worker is None)
        self.assertNotEqual(made[0], threading.get_ident())
        self.assertEqual(results[0]["status"], "COMPLETED")
        bridge.shutdown()
        self.wait(lambda: bridge.worker is None)
        self.assertTrue(service.closed)

    def test_pid_reuse_before_first_action_refuses_native_execution(self):
        service = _FakeService()
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 2000.
            bridge.submit("memory_read", {"address": 1, "size": 1})
            self.wait(lambda: bridge.worker is None)
        self.assertEqual(results[0]["status"], "PROCESS_CHANGED")
        self.assertEqual(service.identities, [])
        self.assertEqual(service.executed, [])
        bridge.shutdown()
        self.wait(lambda: bridge.worker is None)

    def test_export_receives_worker_cancellation_and_returns_typed_refusal(self):
        service = _FakeService(block=True)
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        results = []
        bridge.result_ready.connect(results.append)
        try:
            with patch("psutil.Process") as process:
                process.return_value.create_time.return_value = 1000.
                self.assertTrue(bridge.export("explicit-metadata.jsonl"))
                worker = bridge.worker
                self.wait(service.started.is_set)
                self.assertEqual(service.exported[0][0], "explicit-metadata.jsonl")
                self.assertIs(service.exported[0][1], worker.cancel_event)
                bridge.cancel()
                self.wait(lambda: bridge.worker is None)
            self.assertEqual(results[0]["status"], "CANCELLED")
            self.assertFalse(results[0]["data"]["export_published"])
            self.assertEqual(service.executed, [])
        finally:
            bridge.cancel()
            bridge.shutdown()
            self.wait(lambda: bridge.worker is None)

    def test_switch_cancels_old_work_and_drops_stale_evidence_then_closes(self):
        service = _FakeService(block=True)
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            bridge.submit("modules")
            self.wait(service.started.is_set)
            bridge.set_target(456, 2000.)
            self.wait(lambda: bridge.worker is None and not bridge.busy)
        self.assertEqual(results, [])
        self.assertTrue(service.closed)
        self.assertIsNone(bridge._identity)

    def test_async_close_failure_surfaces_recovery_unconfirmed(self):
        service = _FakeService(close_failure=True)
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            bridge.submit("modules")
            self.wait(lambda: bridge.worker is None)
        closed = []
        recovery = []
        bridge.closed.connect(closed.append)
        bridge.recovery_required.connect(recovery.append)
        bridge.shutdown()
        self.wait(lambda: len(recovery) == 1)
        self.assertEqual(closed, [])
        self.assertIs(bridge._service, service)
        self.assertTrue(bridge.cleanup_required)
        self.assertEqual(recovery[0]["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("CONTROLLED_CLEANUP_FAILURE", recovery[0]["error"])
        service.close_failure = False
        self.assertTrue(bridge.retry_cleanup())
        self.wait(lambda: len(closed) == 1)
        self.assertEqual(closed[0]["status"], "COMPLETED")
        self.assertFalse(bridge.has_session)

    def test_retained_owner_keeps_old_service_on_target_switch_until_cleanup_succeeds(self):
        service = _FakeService()
        calls = []
        def retain_then_release():
            calls.append("close")
            return ({"status": "RECOVERY_UNCONFIRMED", "data": {
                "owner_retained": True, "retry_cleanup_required": True}}
                if len(calls) == 1 else {"status": "COMPLETED", "data": {"cleanup": "VERIFIED"}})
        service.close = retain_then_release
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            bridge.submit("modules")
            self.wait(lambda: bridge.worker is None)
        recovery = []
        bridge.recovery_required.connect(recovery.append)
        bridge.set_target(456, 2000.)
        self.wait(lambda: len(recovery) == 1)
        self.assertIs(bridge._service, service)
        self.assertTrue(bridge.busy)
        self.assertFalse(bridge.submit("memory.write", {"address": 1}, confirmed=True))
        self.assertEqual(len(service.executed), 1)
        self.assertEqual(bridge.target, (456, 2000.))
        self.assertTrue(bridge.retry_cleanup())
        self.wait(lambda: bridge.worker is None and not bridge.busy)
        self.assertIsNone(bridge._service)
        self.assertFalse(bridge.cleanup_required)
        self.assertEqual(calls, ["close", "close"])
        bridge.shutdown()

    def test_expired_cached_admin_status_does_not_remain_active(self):
        bridge = DeepInspectorBridge(service_factory=lambda: _FakeService())
        bridge.admin_active = True
        bridge._admin_expires = time.monotonic() - 1
        bridge._expire_admin_status()
        self.assertFalse(bridge.admin_active)
        bridge.shutdown()


class DeepOverviewIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_window_close_is_deferred_while_diagnostic_owner_is_retained(self):
        from blackbox_universal.window import UniversalWindow
        window = UniversalWindow(allow_update_check=False)
        window._timer.stop()
        window.show()
        self.app.processEvents()
        bridge = window.deep_inspector_panel.bridge
        bridge._service = object()
        bridge._closing = True
        bridge.cleanup_required = True
        try:
            with patch.object(bridge, "retry_cleanup", return_value=False) as retry:
                self.assertFalse(window.close())
            retry.assert_called_once()
            self.assertTrue(window.isVisible())
            self.assertTrue(window._pending_close)
            with patch("blackbox_universal.window.QMessageBox.warning") as warning:
                window._deep_inspector_recovery_required({"status": "RECOVERY_UNCONFIRMED", "data": {"owner_retained": True}})
            warning.assert_called_once()
            self.assertFalse(window._deep_close_complete)
            self.assertTrue(window.deep_inspector_toggle.isChecked())
            self.assertTrue(window.isVisible())
        finally:
            bridge._service = None
            bridge.cleanup_required = False
            bridge._closing = False
            from qt_test_support import close_and_drain
            close_and_drain(window, self.app)

    def test_about_uses_package_version_and_keeps_deep_panel_lazy(self):
        from blackbox_universal import __version__
        from blackbox_universal.window import UniversalWindow
        window = UniversalWindow(allow_update_check=False)
        window._timer.stop()
        try:
            self.assertEqual(window.stack.count(), 5)
            self.assertTrue(window.deep_inspector_panel.isHidden())
            self.assertFalse(window.deep_inspector_panel.bridge.has_session)
            for language in ("RU", "EN"):
                window._set_language(language)
                with patch("blackbox_universal.window.QMessageBox.about") as about:
                    window._about()
                message = about.call_args.args[2]
                self.assertIn("v" + __version__, message)
                self.assertIn("BB-DEEP-001", message)
                self.assertNotIn("v0.3.6", message)
        finally:
            from qt_test_support import close_and_drain
            close_and_drain(window, self.app)
