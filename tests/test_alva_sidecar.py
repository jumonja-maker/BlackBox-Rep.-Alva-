"""Public integration acceptance: a genuine Alva API contract, fake package in QA.

These fake Components test our *wire* and Windows-executable isolation layer;
only a separate authorized private Alva environment can establish real Alva QA.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from blackbox_rep_alva.contracts import Sample
from blackbox_rep_alva.storage import SessionStore
from blackbox_rep_alva import alva_sidecar_worker as worker
from blackbox_universal.platform_connector import (
    _summary, _validate_output, inspect_external,
    save_session_diagnostics, ConnectionError,
)


class FakeHostContract:
    """Deterministic test double, explicitly NOT actual private Alva."""
    executions = []

    def __init__(self, parts, *, allow_dispatch=False):
        assert allow_dispatch
        self.parts = {p.name: p for p in parts}
        self.state = "new"

    def __enter__(self):
        self.state = "ready"
        return self

    def __exit__(self, *args):
        self.state = "closed"

    def open_scope(self, *, permitted_operations):
        assert set(permitted_operations) == set(self.parts)
        return FakeScope(self, permitted_operations)


class FakeScope:
    def __init__(self, host, permitted):
        self.host, self.permitted = host, permitted

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def invoke_with_diagnostics(self, request):
        assert request.keys() == {"schema_version", "operation", "payload"}
        assert request["schema_version"] == 1
        name = request["operation"]
        assert name in self.permitted
        FakeHostContract.executions.append(name)
        fn = self.host.parts[name].fn
        data = fn(request["payload"])
        return type("Call", (), {
            "response": {"status": "ok", "result": data},
            "diagnostics": {"result": {
                "contract_verdict": "CHECK_ACCEPTED",
                "visibility": "SCOPE_ONLY",
                "ai_handoff": {"status": "ok"}}},
            "execution_state": "RESPONSE_AVAILABLE"})()


class FakeComponent:
    def __init__(self, name, fn):
        self.name, self.fn = name, fn


def checked(method, predicate):
    value = method()
    assert predicate(value)
    return value


class WorkerContractTests(unittest.TestCase):
    def test_three_finite_scoped_operations_exactly_once(self):
        FakeHostContract.executions.clear()
        root = ModuleType("alva")
        host = ModuleType("alva.host")
        root.Component = FakeComponent
        root.invoke_adapter_checked = checked
        root.__version__ = "test-double-only"
        host.ComponentHost = FakeHostContract
        packet = {
            "operation": "inspect",
            "schema_version": 1,
            "summary": {"sample_count": 7, "peak_rss_bytes": 100,
                        "peak_cpu_percent": 25.0,
                        "observation_error_count": 2,
                        "closed": True, "state": "COMPLETED"},
        }
        with patch.dict(sys.modules, {"alva": root, "alva.host": host}):
            result = worker._run(packet)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["component_count"], 3)
        self.assertEqual(FakeHostContract.executions, list(worker.OPERATIONS))
        self.assertEqual(result["operations"][0]["observation"]["samples_present"], True)
        self.assertEqual(result["operations"][2]["observation"]["observer_error_count"], 2)
        self.assertFalse(result["alva_origin_authenticated"])
        self.assertFalse(result["target_root_cause_proven"])
        self.assertFalse(result["permission_to_act"])
        self.assertEqual(_validate_output(result)["component_count"], 3)

    def test_worker_never_receives_process_name_pid_or_private_files(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            store = SessionStore(folder, os.getpid())
            store.write_sample(Sample(1100, 150, 11.5, 2, 2, 4, 0))
            store.finish("COMPLETED")
            location = store.folder
            store.close()
            packet = _summary(location)
            encoded = json.dumps(packet)
            self.assertNotIn("pid", encoded.casefold())
            self.assertNotIn("path", encoded.casefold())
            self.assertEqual(packet["sample_count"], 1)
            self.assertEqual(packet["state"], "COMPLETED")

    def test_fake_worker_response_with_forged_attestation_rejected(self):
        bad = {"status": "ok", "bridge_schema": 1,
               "mode": "EXTERNAL_ALVA_SCOPED_INSPECTION",
               "alva_version": "fake", "alva_origin_authenticated": True,
               "target_root_cause_proven": False,
               "permission_to_act": False,
               "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
               "operations": [], "component_count": 3}
        with self.assertRaises(ConnectionError):
            _validate_output(bad)
        bad["alva_origin_authenticated"] = False
        with self.assertRaises(ConnectionError):
            _validate_output(bad)

    def test_shell_command_isolated_and_bounded_without_pythonpath(self):
        with tempfile.TemporaryDirectory() as temp:
            interp = Path(temp) / ("python.exe" if os.name == "nt" else "python3")
            interp.write_bytes(b"test")
            info = {"status": "unavailable", "error_code": "ALVA_NOT_INSTALLED"}
            completed = subprocess.CompletedProcess(
                ["python"], 2, stdout=json.dumps(info).encode())
            with patch("blackbox_universal.platform_connector.subprocess.run",
                       return_value=completed) as invoked:
                result = inspect_external(interp)
            self.assertEqual(result["status"], "unavailable")
            command = invoked.call_args.args[0]
            self.assertEqual(command[1:3], ["-I", "-u"])
            self.assertEqual(invoked.call_args.kwargs["input"].count(b"pid"), 0)
            self.assertNotIn("PYTHONPATH", invoked.call_args.kwargs["env"])
            self.assertEqual(invoked.call_args.kwargs["timeout"], 20)

    def test_report_records_error_when_external_alva_is_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            session = root / "session"
            session.mkdir()
            with patch("blackbox_universal.platform_connector.inspect_external",
                       side_effect=ConnectionError("ALVA_WORKER_UNAVAILABLE")):
                result = save_session_diagnostics(Path(sys.executable), session)
            self.assertEqual(result["status"], "error")
            report = json.loads((session / "alva-diagnostics.json").read_text())
            self.assertEqual(report["error_code"], "ALVA_WORKER_UNAVAILABLE")
            self.assertFalse(report["permission_to_act"])

    def test_manual_recheck_never_overwrites_saved_alva_diagnostics(self):
        from blackbox_universal.window import _AlvaWorker
        with tempfile.TemporaryDirectory() as td:
            session = Path(td)
            existing = session / "alva-diagnostics.json"
            existing.write_text('{"status":"original"}', encoding="utf-8")
            worker = _AlvaWorker(Path(sys.executable), session, persist=False)
            with patch("blackbox_universal.window.inspect_external",
                       return_value={"status": "ok"}) as inspect, \\
                 patch("blackbox_universal.window.save_session_diagnostics") as save:
                worker.run()
                inspect.assert_called_once_with(Path(sys.executable), session)
                save.assert_not_called()
            self.assertEqual(existing.read_text(encoding="utf-8"),
                             '{"status":"original"}')

    def test_external_connect_never_executes_without_explicit_interpreter(self):
        with self.assertRaises(ConnectionError):
            inspect_external(Path("python.exe"))


if __name__ == "__main__":
    unittest.main()
