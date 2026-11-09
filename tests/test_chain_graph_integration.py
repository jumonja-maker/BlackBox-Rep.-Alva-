"""Hosted Qt/controller contracts for shared Chain/Investigation native owners.

No native process or UAC is launched by these synthetic ownership fixtures.
They exercise the production exact-cancellation and late-retry controllers.
"""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_universal.deep_inspector_bridge import DeepInspectorBridge
from blackbox_universal.deep_inspector_panel import OverviewInspectorPanel
from blackbox_core.investigation_graph_contracts import SCHEMA


class ExactDiagnosticCancellationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.bridge = DeepInspectorBridge(service_factory=lambda: self.fail("NATIVE_SERVICE_MUST_NOT_START"))
        self.bridge._status_timer.stop()
        self.token = (7, (234, 1000.0))
        self.bridge.generation, self.bridge.target = self.token

    def tearDown(self):
        self.bridge.worker = None
        self.bridge._queued_command = None
        self.bridge.deleteLater()
        self.app.processEvents()

    def command(self, tag="inv:attempt", *, generation=7, target=(234, 1000.0), kind="action"):
        return {"tag": tag, "generation": generation, "target": target, "kind": kind}

    def test_foreign_running_and_queued_requests_are_never_cancelled(self):
        worker = SimpleNamespace(command=self.command("chain:foreign"), cancel=Mock())
        queued = self.command("chain:queued")
        self.bridge.worker, self.bridge._queued_command = worker, queued
        self.assertFalse(self.bridge.cancel_request("inv:attempt", *self.token))
        worker.cancel.assert_not_called()
        self.assertIs(self.bridge._queued_command, queued)
        for generation, target in ((6, self.token[1]), (7, (235, 1000.0))):
            worker.command = self.command()
            self.assertFalse(self.bridge.cancel_request("inv:attempt", generation, target))
        worker.cancel.assert_not_called()

    def test_exact_queued_action_is_removed_without_cancelling_heartbeat(self):
        worker = SimpleNamespace(command=self.command("", kind="session_status"), cancel=Mock())
        self.bridge.worker = worker
        self.bridge._queued_command = self.command()
        self.bridge._service = SimpleNamespace(owner="retained synthetic owner")
        owner = self.bridge._service
        changed = []
        self.bridge.busy_changed.connect(changed.append)
        self.assertTrue(self.bridge.cancel_request("inv:attempt", *self.token))
        self.assertIsNone(self.bridge._queued_command)
        self.assertIs(self.bridge._service, owner)
        worker.cancel.assert_not_called()
        self.assertEqual(changed, [False])
        self.assertFalse(self.bridge._closing)
        self.bridge._service = None

    def test_exact_running_action_only_requests_cancel_and_keeps_foreign_queue(self):
        worker = SimpleNamespace(command=self.command(), cancel=Mock())
        queued = self.command("chain:queued")
        self.bridge.worker, self.bridge._queued_command = worker, queued
        self.bridge.cleanup_required = True
        self.assertTrue(self.bridge.cancel_request("inv:attempt", *self.token))
        worker.cancel.assert_called_once_with()
        self.assertIs(self.bridge.worker, worker)
        self.assertIs(self.bridge._queued_command, queued)
        self.assertTrue(self.bridge.cleanup_required, "Cancellation cannot certify owner cleanup")

    def test_missing_tag_and_invalid_generation_cannot_cancel_any_command(self):
        worker = SimpleNamespace(command=self.command(), cancel=Mock())
        self.bridge.worker = worker
        for tag, generation, target in (("", 7, self.token[1]), (None, 7, self.token[1]),
                                         ("inv:attempt", True, self.token[1]),
                                         ("inv:attempt", 7, None)):
            with self.subTest(tag=tag, generation=generation, target=target):
                self.assertFalse(self.bridge.cancel_request(tag, generation, target))
        worker.cancel.assert_not_called()


class GraphLatePermissionContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.window = QWidget()
        self.window.language = "EN"
        self.window._investigation_root = Path(self.tmp.name)
        self.window.probe = SimpleNamespace(session_folder=None)
        self.native = DeepInspectorBridge(service_factory=lambda: self.fail("NATIVE_SERVICE_MUST_NOT_START"))
        self.native._status_timer.stop()
        self.native.target, self.native.generation = (234, 1000.0), 3
        self.native.submit = Mock(return_value=True)
        self.deep = OverviewInspectorPanel(self.window, bridge=self.native)
        self.graph = self.deep.investigation_graph_panel
        case = {"schema": SCHEMA, "case_id": "synthetic-graph", "sources": [], "nodes": [],
                "edges": [], "coverage": {}, "limitations": [], "hypotheses": [], "actions": []}
        self.graph.load_case(case)
        self.graph.experiment_case = deepcopy(case)
        self.graph._live_identity = {"pid": 234, "created_100ns": 133000000000000000}
        self.graph._live_token = self.native.generation, self.native.target
        self.graph._experiment = {"experiment_id": "synthetic-experiment", "records": []}

    def tearDown(self):
        self.graph.shutdown()
        self.native._status_timer.stop()
        self.native.deleteLater()
        self.deep.deleteLater()
        self.window.deleteLater()
        self.app.processEvents()
        self.tmp.cleanup()

    def pending_permission(self):
        with patch.object(self.deep, "_confirm", return_value=True):
            self.assertTrue(self.graph._run_step("action", "memory.write", {}))
        pending = self.graph._pending_native
        pending["awaiting_uac"] = True
        self.deep._pending_retry = dict(self.deep._last_request)
        self.deep._last_result = {"request_kind": "elevate", "status": "COMPLETED", "data": {}}
        return pending, self.deep._last_request["execution_guard"]

    def test_guarded_graph_permission_preserves_tag_for_elevation_and_authorization(self):
        for authorize in (False, True):
            with self.subTest(authorize=authorize):
                self.graph._pending_native = None
                self.graph._experiment = {"experiment_id": "synthetic-experiment", "records": []}
                pending, guard = self.pending_permission()
                self.native.elevate = Mock(return_value=True)
                self.native.authorize_target = Mock(return_value=True)
                self.deep._last_result = {"status": "CONFIRMATION_REQUIRED" if authorize else "ADMIN_REQUIRED",
                    "next_action": "AUTHORIZE_TARGET_AND_OPERATION_SCOPE" if authorize else "REQUEST_UAC",
                    "target": self.graph._live_identity}

                def grant(dialog):
                    button = next(button for button in dialog.buttons()
                                  if dialog.buttonRole(button) == QMessageBox.ButtonRole.AcceptRole)
                    button.click()
                    return 0

                with patch.object(QMessageBox, "exec", new=grant):
                    self.graph.request_native_permission()
                chosen = self.native.authorize_target if authorize else self.native.elevate
                other = self.native.elevate if authorize else self.native.authorize_target
                chosen.assert_called_once()
                self.assertEqual(chosen.call_args.kwargs, {"tag": pending["tag"]})
                other.assert_not_called()
                self.assertTrue(guard())
                self.deep.release_investigation_guard(pending["tag"])

    def test_foreign_expected_permission_tag_cannot_open_a_modal_or_change_request(self):
        pending, guard = self.pending_permission()
        original = self.deep._last_request
        with patch.object(self.deep, "_elevate") as elevate:
            self.assertFalse(self.deep.request_investigation_elevation(expected_tag="chain:foreign"))
            elevate.assert_not_called()
        self.assertIs(self.deep._last_request, original)
        self.assertTrue(guard())

    def test_graph_cancel_revokes_actual_deep_idle_retry_without_closing_foreign_owner(self):
        pending, guard = self.pending_permission()
        self.assertTrue(guard())
        foreign = SimpleNamespace(command={"tag": "chain:foreign:elevate", "generation": 3,
                                         "target": self.native.target}, cancel=Mock())
        self.native.worker = foreign
        self.assertTrue(self.graph.cancel_native_step())
        self.assertFalse(guard())
        self.deep._idle()
        self.assertEqual(self.native.submit.call_count, 1)
        self.assertIsNone(self.deep._pending_retry)
        self.assertIsNone(self.deep._last_request)
        self.assertIs(self.native.worker, foreign)
        foreign.cancel.assert_not_called()
        self.native.worker = None

    def test_graph_generation_change_blocks_actual_deep_idle_retry(self):
        pending, guard = self.pending_permission()
        self.graph.open_case_context([{"source_type": "SESSION", "path": "/SYNTHETIC/other"}])
        self.assertFalse(guard())
        self.deep._idle()
        self.assertEqual(self.native.submit.call_count, 1)
        self.assertIsNone(self.deep._pending_retry)
        self.assertIsNone(self.deep._last_request)
        self.assertFalse(self.graph.uac_button.isEnabled())
