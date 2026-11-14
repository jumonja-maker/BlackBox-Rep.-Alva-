"""Real recorder finalization with an injected native identity boundary.

These fixtures exercise actual sampling, SQLite and writer shutdown on hosted
Linux/Windows. They do not claim independent Windows process-identity/UAC proof.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import psutil

from blackbox_core.chain_adapters import ChainRuntime, _direct_observe, _observe
from blackbox_core.chain_io import make_process_artifact
from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_core.research_worker import ResearchSession


class Context:
    def __init__(self, output):
        self.run_id = "observe-recorder-fixture"
        self.output_dir = output
        self.deadline = time.monotonic() + 30
        self.cancel = threading.Event()

    def check(self):
        if self.cancel.is_set():
            raise InterruptedError("WORKFLOW_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WORKFLOW_DEADLINE")


class ChainObserveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ctx = Context(self.root)
        if os.name == "nt":
            # Avoid manufacturing exact FILETIME from a rounded psutil float:
            # the recorder also retains its actual native run identity.
            from blackbox_core.deep_native import capture_identity
            self.identity = capture_identity(os.getpid())
        else:
            self.identity = ProcessIdentity(os.getpid(),
                116444736000000000 + int(psutil.Process().create_time() * 10_000_000))
        self.inputs = {"process": make_process_artifact(self.identity)}
        self.session = ResearchSession(output_root=self.root)
        self.session.probe.background_events = True
        self.runtime = ChainRuntime(research=self.session, output_root=self.root)
        self.owners = {}
        command = self.session.command

        def tracked_command(value):
            result = command(value)
            if value.get("op") == "start":
                self.owners.update(store=self.session.probe._store,
                    book=self.session.book, writer=self.session.probe._store.v2,
                    journal=self.session.probe._store._journal)
            return result

        self.patch_command = patch.object(self.session, "command", side_effect=tracked_command)
        self.patch_command.start()
        self.addCleanup(self.patch_command.stop)
        self.patch_identity = patch("blackbox_core.deep_native.capture_identity_checked", return_value=self.identity)
        self.patch_identity.start()
        self.addCleanup(self.patch_identity.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self.session.probe.active or self.session.book is not None:
            self.session.stop("USER_STOPPED")

    def _assert_actual_finalization(self):
        self.assertFalse(self.session.probe.active)
        self.assertIsNone(self.session.probe._store)
        self.assertIsNone(self.session.book)
        for name in ("store", "book"):
            with self.assertRaises(sqlite3.ProgrammingError):
                self.owners[name].db.execute("SELECT 1")
        self.assertFalse(self.owners["writer"].thread.is_alive())
        self.assertIsNone(self.owners["writer"].failure)
        self.assertFalse(self.owners["journal"]._worker.is_alive())
        folder = self.session.probe.session_folder
        with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT exit_code FROM metadata").fetchone(), ("COMPLETED",))
        with closing(sqlite3.connect(folder / "session-v2.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT status,exit_code FROM sessions").fetchone(),
                             ("CLOSED", "COMPLETED"))
        with closing(sqlite3.connect(folder / "research.sqlite3")) as db:
            state = json.loads(db.execute("SELECT data FROM context WHERE key='state'").fetchone()[0])
            health = json.loads(db.execute("SELECT data FROM context WHERE key='capture_health'").fetchone()[0])
        self.assertEqual(state, "COMPLETED")
        self.assertTrue(health["recording_resources_closed"])

    def test_direct_recording_uses_authoritative_snapshot_and_actual_closed_owners(self):
        outcome = _observe(self.runtime)(self.ctx, self.inputs, {"duration_seconds": .05})
        self.assertEqual(outcome.status, "COMPLETED")
        self.assertTrue(outcome.cleanup["confirmed"])
        self.assertEqual(outcome.cleanup["stop_result"], {"state": "COMPLETED",
            "base_recording_state": "COMPLETED", "errors": [], "cleanup_required": False})
        snapshot = self.session.snapshot()
        self.assertNotIn("active", snapshot)
        self.assertIs(snapshot["observation_active_at_export"], False)
        self.assertIs(outcome.cleanup["recording_finalization"]["observation_active_at_export"], False)
        self._assert_actual_finalization()

    def test_missing_conflicting_or_negative_boundary_cannot_be_promoted_by_completed_stop(self):
        original = _direct_observe(self.runtime, self.identity, {}, .05, self.ctx)
        self._assert_actual_finalization()
        gui_packet = deepcopy(original)
        gui_packet["snapshot"]["active"] = False
        gui_outcome = _observe(ChainRuntime(observe_call=lambda *args: gui_packet))(self.ctx, self.inputs, {})
        self.assertEqual(gui_outcome.status, "COMPLETED")
        self.assertTrue(gui_outcome.cleanup["confirmed"])
        for boundary in ("missing_authoritative", "active_authoritative", "conflicting_gui",
                         "stop_requires_cleanup", "missing_stop_errors"):
            with self.subTest(boundary=boundary):
                packet = deepcopy(original)
                if boundary == "missing_authoritative":
                    packet["snapshot"].pop("observation_active_at_export")
                    packet["snapshot"]["active"] = False
                elif boundary == "active_authoritative":
                    packet["snapshot"]["observation_active_at_export"] = True
                elif boundary == "conflicting_gui":
                    packet["snapshot"]["active"] = True
                elif boundary == "stop_requires_cleanup":
                    packet["stop_result"]["cleanup_required"] = True
                else:
                    packet["stop_result"].pop("errors")
                runtime = ChainRuntime(observe_call=lambda *args: packet)
                outcome = _observe(runtime)(self.ctx, self.inputs, {})
                self.assertEqual(outcome.status, "RECOVERY_UNCONFIRMED")
                self.assertFalse(outcome.cleanup["confirmed"])
                self.assertEqual(outcome.cleanup["stop_result"], packet["stop_result"])
        # A persisted negative close boundary independently vetoes the original
        # successful Stop ACK. This is an explicit malformed-proof fixture.
        folder = self.session.probe.session_folder
        with closing(sqlite3.connect(folder / "research.sqlite3")) as db:
            health = json.loads(db.execute("SELECT data FROM context WHERE key='capture_health'").fetchone()[0])
            health["recording_resources_closed"] = False
            db.execute("UPDATE context SET data=? WHERE key='capture_health'", (json.dumps(health),))
            db.commit()
        outcome = _observe(ChainRuntime(observe_call=lambda *args: original))(self.ctx, self.inputs, {})
        self.assertEqual(outcome.status, "RECOVERY_UNCONFIRMED")
        self.assertFalse(outcome.cleanup["confirmed"])
        self.assertIs(outcome.cleanup["recording_finalization"]["persisted_recording_resources_closed"], False)

    def test_cancelled_recording_preserves_actual_stop_ack_without_claiming_workflow_completed(self):
        tick = self.session.tick

        def cancel_after_actual_sample():
            result = tick()
            self.ctx.cancel.set()
            return result

        with patch.object(self.session, "tick", side_effect=cancel_after_actual_sample):
            outcome = _observe(self.runtime)(self.ctx, self.inputs, {"duration_seconds": 1})
        self.assertEqual(outcome.status, "CANCELLED")
        self.assertTrue(outcome.cleanup["confirmed"])
        self.assertEqual(outcome.cleanup["stop_result"]["state"], "COMPLETED")
        self.assertTrue(outcome.execution_started)
        self.assertTrue(outcome.cleanup["completion_evidence_readback"]["separate_from_execution_deadline"])
        self.assertFalse(outcome.cleanup["completion_evidence_readback"]["collection_allowed"])
        self._assert_actual_finalization()

    def test_recording_binding_keeps_float_birth_qualified_and_does_not_invent_filetime(self):
        outcome = _observe(self.runtime)(self.ctx, self.inputs, {"duration_seconds": .05})
        self.assertEqual(outcome.status, "COMPLETED")
        metadata = outcome.outputs["session"].value
        self.assertEqual(metadata["requested_target"]["created_100ns"], self.identity.created_100ns)
        self.assertEqual(metadata["recorded_target"]["pid"], self.identity.pid)
        if os.name == "nt":
            self.assertEqual(metadata["recorded_target"]["created_100ns"], self.identity.created_100ns)
            self.assertEqual(metadata["comparison"], "RECORDED_EXACT_FILETIME_FIELDS_MATCH_SOURCE_NOT_AUTHENTICATED")
        else:
            self.assertNotIn("created_100ns", metadata["recorded_target"])
            self.assertEqual(metadata["comparison"], "RECORDED_PID_AND_FLOAT_BIRTH_COMPATIBLE_NOT_EXACT_FILETIME")
        self.assertEqual(metadata["producer_authentication"], "NOT_ESTABLISHED")

    def test_stale_callback_cannot_attribute_another_persisted_target_to_requested_identity(self):
        original = _direct_observe(self.runtime, self.identity, {}, .05, self.ctx)
        folder = self.session.probe.session_folder
        other = type(self.identity)(self.identity.pid + 1000, self.identity.created_100ns)
        wrong_inputs = {"process": make_process_artifact(other)}
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.glob("*.sqlite3")}
        result = _observe(ChainRuntime(observe_call=lambda *args: original))(self.ctx, wrong_inputs, {})
        self.assertEqual(result.status, "OPERATION_FAILED")
        self.assertEqual(result.outputs, {})
        self.assertTrue(result.cleanup["confirmed"])
        self.assertEqual(result.cleanup["stop_result"], original["stop_result"])
        self.assertIn("WORKFLOW_RECORDED_TARGET_IDENTITY_MISMATCH", result.reason_code)
        self.assertEqual({path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.glob("*.sqlite3")}, before)

    def test_recorded_exact_filetime_mismatch_vetoes_compatible_float_birth(self):
        original = _direct_observe(self.runtime, self.identity, {}, .05, self.ctx)
        folder = self.session.probe.session_folder
        with closing(sqlite3.connect(folder / "research.sqlite3")) as db:
            experiment = json.loads(db.execute("SELECT data FROM context WHERE key='experiment'").fetchone()[0])
            experiment["run_identity"] = {"identity_status": "OS_OBSERVED_EXACT_FILETIME",
                "process_identity": {"pid": self.identity.pid, "created_100ns": self.identity.created_100ns + 1}}
            db.execute("UPDATE context SET data=? WHERE key='experiment'", (json.dumps(experiment),))
            db.commit()
        before = hashlib.sha256((folder / "research.sqlite3").read_bytes()).hexdigest()
        result = _observe(ChainRuntime(observe_call=lambda *args: original))(self.ctx, self.inputs, {})
        self.assertEqual(result.status, "OPERATION_FAILED")
        self.assertEqual(result.outputs, {})
        self.assertTrue(result.cleanup["confirmed"])
        self.assertIn("WORKFLOW_RECORDED_TARGET_IDENTITY_MISMATCH", result.reason_code)
        self.assertEqual(hashlib.sha256((folder / "research.sqlite3").read_bytes()).hexdigest(), before)

    def test_late_reference_failure_preserves_actual_cancelled_stop_and_cleanup_proof(self):
        original = _direct_observe(self.runtime, self.identity, {}, .05, self.ctx)
        original["execution_status"] = "CANCELLED"
        self.ctx.cancel.set()
        with patch("blackbox_core.chain_adapters._file", side_effect=OSError("FIXTURE_REFERENCE_READBACK_FAILED")):
            result = _observe(ChainRuntime(observe_call=lambda *args: original))(self.ctx, self.inputs, {})
        self.assertEqual(result.status, "CANCELLED")
        self.assertEqual(result.outputs, {})
        self.assertTrue(result.cleanup["confirmed"])
        self.assertEqual(result.cleanup["stop_result"], original["stop_result"])
        self.assertTrue(result.execution_started)
        self.assertIn("FIXTURE_REFERENCE_READBACK_FAILED", result.reason_code)
        self.assertEqual(result.cleanup["completion_evidence_readback"]["status"], "REFERENCE_UNAVAILABLE")

    def test_missing_start_ack_keeps_execution_unknown_and_conflicting_ack_has_no_artifact(self):
        original = _direct_observe(self.runtime, self.identity, {}, .05, self.ctx)
        missing = deepcopy(original)
        missing["start_result"] = None
        missing["execution_status"] = "TIMED_OUT"
        result = _observe(ChainRuntime(observe_call=lambda *args: missing))(self.ctx, self.inputs, {})
        self.assertIsNone(result.execution_started)
        self.assertEqual(result.status, "TIMED_OUT")
        self.assertTrue(result.cleanup["confirmed"])
        wrong = deepcopy(original)
        wrong["start_result"]["folder"] = str(self.root / "OTHER_RECORDING")
        result = _observe(ChainRuntime(observe_call=lambda *args: wrong))(self.ctx, self.inputs, {})
        self.assertEqual(result.status, "OPERATION_FAILED")
        self.assertEqual(result.outputs, {})
        self.assertTrue(result.cleanup["confirmed"])
        self.assertIn("WORKFLOW_RECORDED_SESSION_START_ACK_MISMATCH", result.reason_code)


if __name__ == "__main__":
    unittest.main()
