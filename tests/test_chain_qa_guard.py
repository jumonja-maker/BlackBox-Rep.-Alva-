"""Actual Qt callback failure boundaries for source/frozen QA control flow.

These controlled Python faults are not evidence of a native process crash.
Execution belongs to hosted CI; startup import failure uses a disposable child.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QWidget

import app as product
from blackbox_core.chain_qa_guard import ChainQaFailureGuard


class ChainQaFailureGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.guard = ChainQaFailureGuard(self.root / "failure.json")
        previous = self.guard.install()
        self.addCleanup(setattr, sys, "excepthook", previous)

    def test_real_qtimer_callback_error_latches_without_logging_exception_payload(self):
        delivered = []

        def failing_callback():
            delivered.append(True)
            raise RuntimeError("CONTROLLED_SECRET_VALUE_MUST_NEVER_APPEAR_IN_DIAGNOSTIC")

        QTimer.singleShot(0, failing_callback)
        self.app.processEvents()
        self.assertEqual(delivered, [True])
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.guard.exit_code(0), 1)
        self.assertEqual(self.guard.exit_code(37), 37)
        proof = self.guard.apply({"status": "PASS"})
        self.assertEqual(proof["status"], "FAIL")
        raw = (self.root / "failure.json").read_text(encoding="ascii")
        self.assertNotIn("CONTROLLED_SECRET", raw)
        self.assertNotIn(str(self.root), raw)
        data = json.loads(raw)
        self.assertEqual(data["first"]["error_type"], "RuntimeError")
        self.assertLessEqual(len(data["first"]["frames"]), 12)
        self.assertTrue(all(Path(row["file"]).name == row["file"] for row in data["first"]["frames"]))

    def test_logging_failure_cannot_clear_latch_or_replace_primary_proof(self):
        try:
            raise ValueError("CONTROLLED_PRIVATE_MESSAGE")
        except ValueError:
            with patch.object(Path, "write_text", side_effect=PermissionError("CONTROLLED_LOG_DENIAL")):
                self.guard.record(*sys.exc_info())
        original = {"status": "FAIL", "error": "ACTUAL_PRIMARY", "reason": "ACTUAL_PRIMARY_REASON",
                    "cleanup": {"confirmed": False, "status": "RECOVERY_UNCONFIRMED"}}
        proof = self.guard.apply(deepcopy(original))
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.guard.exit_code(0), 1)
        self.assertEqual(proof["error"], original["error"])
        self.assertEqual(proof["reason"], original["reason"])
        self.assertEqual(proof["cleanup"], original["cleanup"])

    def test_main_checks_healthy_and_callback_failure_after_last_window_close(self):
        for fail_close in (False, True):
            with self.subTest(fail_close=fail_close):
                self.guard = ChainQaFailureGuard(self.root / "failure.json")
                sys.excepthook = self.guard.record
                output = self.root / ("close-fault" if fail_close else "healthy")
                events = []

                class FinalWindow(QWidget):
                    def __init__(self, **_):
                        super().__init__()

                    def closeEvent(window, event):
                        events.append("actual-close")
                        if fail_close:
                            def failed_after_close():
                                events.append("actual-qt-callback")
                                raise RuntimeError("CONTROLLED_CLOSE_CALLBACK")
                            QTimer.singleShot(0, failed_after_close)
                        event.accept()

                def completed_harness(_app, _window, destination, *_args, **_kwargs):
                    events.append("harness-pass")
                    destination.mkdir(parents=True)
                    proof = {"status": "PASS", "scope": "CONTROLLED_MAIN_EXIT_FIXTURE_NOT_NATIVE_ACCEPTANCE"}
                    (destination / "result.json").write_text(json.dumps(proof), encoding="ascii")
                    return proof

                with patch.object(product, "_CHAIN_QA_GUARD", self.guard), \
                        patch.object(product, "UniversalWindow", FinalWindow), \
                        patch("blackbox_core.chain_qa.source_proof", return_value={"fixture": True}), \
                        patch("blackbox_universal.chain_qa.run_chain_gui", side_effect=completed_harness):
                    code = product.main(["--chain-e2e", str(output), "--chain-evidence", str(self.root),
                                         "--chain-gui-only", "--qa-commit-sha", "0" * 40])
                persisted = json.loads((output / "gui" / "result.json").read_text(encoding="ascii"))
                self.assertEqual(events[:2], ["harness-pass", "actual-close"])
                self.assertEqual(code, 1 if fail_close else 0)
                self.assertEqual(persisted["status"], "FAIL" if fail_close else "PASS")
                self.assertEqual(self.guard.failed, fail_close)
                if fail_close:
                    self.assertEqual(events[-1], "actual-qt-callback")

    def test_startup_import_failure_exits_before_windowed_fallback_and_logs_only_metadata(self):
        script = "\n".join((
            "import builtins, runpy, sys",
            "original = builtins.__import__",
            "def controlled_import(name, *args, **kwargs):",
            "    if name.startswith('PySide6'):",
            "        raise ImportError('CONTROLLED_STARTUP_SECRET_MUST_NOT_BE_LOGGED')",
            "    return original(name, *args, **kwargs)",
            "builtins.__import__ = controlled_import",
            "sys.argv = ['app.py', '--chain-e2e', 'unused-qa-output']",
            "runpy.run_path(" + repr(str(Path(product.__file__).resolve())) + ", run_name='__main__')",
        ))
        completed = subprocess.run([sys.executable, "-c", script], cwd=self.root,
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        raw = (self.root / "blackbox-chain-qa-error.json").read_text(encoding="ascii")
        self.assertEqual(json.loads(raw)["first"]["error_type"], "ImportError")
        self.assertNotIn("CONTROLLED_STARTUP_SECRET", raw)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
