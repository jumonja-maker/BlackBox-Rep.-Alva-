"""Injected diagnostic contracts; actual medium-token acceptance stays in CI.

These saved metadata and launch-result fixtures never claim Windows execution.
"""
import argparse
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
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
                lines = [line.partition("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC ")[2]
                         for line in output.getvalue().splitlines()
                         if line.startswith("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC ")]
                self.assertEqual(len(lines), 1)
                observed = json.loads(lines[0])
                self.assertEqual(observed["exit_code"], code)
                self.assertEqual(observed["windows_status_hex"], "0x%08x" % code)
                self.assertEqual(observed["child_token_integrity"]["sid"], sid)
                self.assertNotIn("R60_CHAIN_ACCEPTANCE_RECEIPT", output.getvalue())


if __name__ == "__main__":
    unittest.main()
