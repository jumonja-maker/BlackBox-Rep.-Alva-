"""Injected diagnostic contracts; actual medium-token acceptance stays in CI.

These saved metadata and launch-result fixtures never claim Windows execution.
"""
import argparse
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import qa_chain_builder as qa


class MediumDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "guard.json"
        self.sha = "a" * 40
        self.started = time.monotonic_ns()
        self.value = {"scope": "CHAIN_QA_PYTHON_FAILURE_METADATA_ONLY", "pid": 12345,
            "source_sha": self.sha, "first_recorded_monotonic_ns": time.monotonic_ns(), "count": 1,
            "first": {"error_type": "ImportError", "frames": [
                {"file": "app.py", "function": "<module>", "line": 60}],
                "value": "CONTROLLED_PRIVATE_EXCEPTION_VALUE_NOT_FOR_LOGS"}}

    def read_guard(self, *, previous=None):
        self.path.write_text(json.dumps(self.value), encoding="ascii")
        return qa._fresh_guard_failure(self.path, pid=12345, source_sha=self.sha,
                                       started_ns=self.started, previous_stamp=previous)

    def test_only_fresh_matching_pid_sha_and_monotonic_metadata_is_transported(self):
        answer = self.read_guard()
        self.assertEqual(answer["status"], "BOUND_CURRENT_CHILD_METADATA")
        self.assertEqual(answer["pid"], 12345)
        self.assertEqual(answer["first"]["error_type"], "ImportError")
        self.assertNotIn("CONTROLLED_PRIVATE", json.dumps(answer))
        baseline = deepcopy(self.value)
        for field, wrong in (("pid", 99), ("source_sha", "b" * 40),
                             ("first_recorded_monotonic_ns", self.started - 1)):
            with self.subTest(field=field):
                self.value = {**baseline, field: wrong}
                self.assertEqual(self.read_guard()["status"], "NOT_BOUND_TO_CURRENT_CHILD")
        self.value = baseline
        self.read_guard()
        previous = qa._guard_stamp(self.path)
        self.assertEqual(qa._fresh_guard_failure(self.path, pid=12345, source_sha=self.sha,
            started_ns=self.started, previous_stamp=previous)["status"],
            "UNCHANGED_PREVIOUS_FILE_NOT_CURRENT_CHILD")

    def test_missing_and_unbounded_or_path_metadata_stays_unconfirmed(self):
        missing = qa._fresh_guard_failure(self.path, pid=12345, source_sha=self.sha,
                                         started_ns=self.started, previous_stamp=None)
        self.assertEqual(missing["status"], "NOT_PRESENT_OR_UNREADABLE")
        self.value["first"]["frames"][0]["file"] = "C:\\private\\app.py"
        self.assertEqual(self.read_guard()["status"], "INVALID_BOUNDED_GUARD_METADATA")
        self.path.write_text("x" * 32769, encoding="ascii")
        oversized = qa._fresh_guard_failure(self.path, pid=12345, source_sha=self.sha,
                                            started_ns=self.started, previous_stamp=None)
        self.assertEqual(oversized["status"], "READBACK_UNCONFIRMED")

    def test_actual_returned_exit_and_token_are_logged_before_refusal_without_retry(self):
        args = argparse.Namespace(source_sha=self.sha, evidence_root=self.root, output=self.root / "out",
            exe=None, gui_only=False, standard_token=True, decoder=None, probe=None, diagnostic_helper=None)
        for code, sid in ((0xC0000135, "S-1-16-8192"), (0, "S-1-16-4096")):
            with self.subTest(code=code, sid=sid):
                child = {"pid": 12345, "exit_code": code, "child_token_integrity": {"sid": sid},
                         "medium_integrity_requested": True, "parent_token_unchanged": True,
                         "job_assigned_before_resume": True}
                output = io.StringIO()
                with patch.object(qa, "source_proof"), \
                        patch("tools.qa_decoder_standard_token.restricted_interpreter", return_value=Path("pythonw.exe")), \
                        patch("tools.qa_decoder_standard_token.restricted_child", return_value=child) as launch, \
                        redirect_stdout(output):
                    with self.assertRaisesRegex(AssertionError, "R60_ACTUAL_CHAIN_MEDIUM_TOKEN_PROCESS_FAILED"):
                        qa.run(args)
                self.assertEqual(launch.call_count, 1)
                actual_command = launch.call_args.args[0]
                self.assertEqual(actual_command[0], "pythonw.exe")
                self.assertNotIn("-X", actual_command)
                self.assertNotIn("faulthandler", actual_command)
                lines = [line.partition("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC ")[2]
                         for line in output.getvalue().splitlines()
                         if line.startswith("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC ")]
                self.assertEqual(len(lines), 1)
                observed = json.loads(lines[0])
                self.assertEqual(observed["exit_code"], code)
                self.assertEqual(observed["windows_status_hex"], "0x%08x" % code)
                self.assertEqual(observed["child_token_integrity"]["sid"], sid)
                self.assertNotIn("R60_CHAIN_ACCEPTANCE_RECEIPT", output.getvalue())

    def test_bootstrap_controls_differ_only_by_option_and_do_not_create_application_output(self):
        # Receipt/marker injection verifies orchestration, not Windows behavior.
        output = self.root / "application-output"
        directory = self.root / "application-output-bootstrap"
        interpreter = self.root / "pythonw.exe"
        interpreter.write_bytes(b"CONTROLLED_INTERPRETER_FILE_NOT_A_WINDOWS_BINARY")
        args = argparse.Namespace(output=output, source_sha=self.sha)
        commands = []

        def controlled_launch(command, **kwargs):
            commands.append(list(command))
            self.assertTrue(kwargs["medium_integrity"])
            self.assertEqual(kwargs["timeout_seconds"], 30)
            self.assertEqual(kwargs["cwd"], qa.ROOT)
            option = "-X" in command
            pid = 10000 + len(commands)
            if not option:
                (directory / "without-option.entered").write_bytes(b"ENTRY_REACHED\n")
                (directory / "without-option.json").write_text(json.dumps({
                    "schema": "blackbox.r60.windowed-bootstrap/1", "pid": pid, "source_sha": self.sha,
                    "option_present": False, "stderr_is_none": True, "faulthandler_enabled": False,
                    "version": [3, 11, 9]}), encoding="ascii")
            return {"pid": pid, "exit_code": 1 if option else 0,
                "token_integrity": {"sid": "S-1-16-8192"}, "child_token_integrity": {"sid": "S-1-16-8192"},
                "medium_integrity_requested": True, "job_assigned_before_resume": True,
                "parent_token_unchanged": True, "qa_default_dacl_adjustment": {
                    "after": {"fixture": "CONTROLLED_SAME_POLICY"}, "child_readback": {"fixture": "CONTROLLED_SAME_POLICY"}}}

        with redirect_stdout(io.StringIO()):
            result = qa._diagnose_windowed_bootstrap(args, interpreter, controlled_launch)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][1:3], ["-X", "faulthandler"])
        self.assertEqual(commands[0][:1] + commands[0][3:], commands[1])
        self.assertTrue(result["hypothesis_supported"])
        self.assertFalse(result["application_acceptance_established"])
        self.assertFalse(result["application_or_native_query_retried"])
        self.assertFalse(output.exists())
        self.assertEqual(json.loads((directory / "result.json").read_text())["scope"],
                         "BOOTSTRAP_DIAGNOSTIC_NOT_APPLICATION_ACCEPTANCE")

    def test_console_keeps_option_and_frozen_medium_keeps_its_original_executable(self):
        args = argparse.Namespace(source_sha=self.sha, evidence_root=self.root, output=self.root / "out",
            exe=None, gui_only=False, standard_token=False, decoder=None, probe=None, diagnostic_helper=None)
        with patch.object(qa, "source_proof"), \
                patch.object(qa.subprocess, "run", return_value=SimpleNamespace(returncode=7)) as console, \
                redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(AssertionError, "R60_SOURCE_OR_FROZEN_CHAIN_PROCESS_FAILED"):
                qa.run(args)
        self.assertEqual(console.call_count, 1)
        self.assertEqual(console.call_args.args[0][1:3], ["-X", "faulthandler"])
        args.exe = self.root / "frozen.exe"
        args.exe.write_bytes(b"CONTROLLED_EXECUTABLE_REFERENCE_NOT_A_NATIVE_FIXTURE")
        args.standard_token = True
        child = {"pid": 1, "exit_code": 1, "child_token_integrity": {"sid": "S-1-16-8192"}}
        with patch.object(qa, "source_proof"), \
                patch("tools.qa_decoder_standard_token.restricted_interpreter") as select, \
                patch("tools.qa_decoder_standard_token.restricted_child", return_value=child) as launch, \
                redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(AssertionError, "R60_ACTUAL_CHAIN_MEDIUM_TOKEN_PROCESS_FAILED"):
                qa.run(args)
        select.assert_not_called()
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(launch.call_args.args[0][0], str(args.exe.resolve()))
        self.assertNotIn("-X", launch.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
