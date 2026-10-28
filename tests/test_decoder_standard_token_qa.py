"""Acceptance-proof validation only; actual tokens require Windows CI."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tools.qa_decoder_standard_token import (read_worker_proof, restricted_interpreter,
                                             validate_worker)


class RestrictedLauncherTests(unittest.TestCase):
    def test_windowed_worker_uses_exact_same_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            console = root / "python.exe"
            console.write_bytes(b"console interpreter")
            with self.assertRaisesRegex(AssertionError, "WINDOWED_INTERPRETER_MISSING"):
                restricted_interpreter(console)
            windowed = root / "pythonw.exe"
            windowed.write_bytes(b"windowed interpreter")
            self.assertEqual(restricted_interpreter(console), windowed.resolve())
            foreign = root / "unrelated.exe"
            foreign.write_bytes(b"not the recorded Python runtime")
            with self.assertRaisesRegex(AssertionError, "EXPECTED_WINDOWS_CPYTHON"):
                restricted_interpreter(foreign)

    def test_missing_proof_preserves_actual_child_failure_status(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(AssertionError, "PROOF_MISSING_CHILD_EXIT_0xC0000142"):
                read_worker_proof(temp, {"exit_code": 0xC0000142})
            with self.assertRaisesRegex(AssertionError, "PROOF_MISSING_CHILD_EXIT_0x00000000"):
                read_worker_proof(temp, {"exit_code": 0})
            expected = {"status": "FAIL", "reason": "observed decoder failure"}
            (Path(temp) / "standard-token-worker.json").write_text(json.dumps(expected), encoding="utf-8")
            self.assertEqual(read_worker_proof(temp, {"exit_code": 1}), expected)


class RestrictedProofTests(unittest.TestCase):
    def setUp(self):
        self.plan = [{"format": name, "input_sha256": name + "digest", "rows": 12}
                     for name in ("ETL", "EVENTPIPE")]
        self.child = {"pid": 10, "exit_code": 0}
        self.proof = {"pid": 10, "status": "PASS", "captures_started": False,
                      "privilege": {"mode": "STANDARD", "windows": True},
                      "traces": [{**item, "status": "PASS", "helper_pid": 11 + n,
                                  "helper_exit_code": 0, "index_readable": True}
                                 for n, item in enumerate(self.plan)]}

    def test_admin_or_nonwindows_proof_cannot_certify_standard_token(self):
        for privilege in ({"mode": "ADMINISTRATOR", "windows": True},
                          {"mode": "STANDARD", "windows": False}):
            proof = deepcopy(self.proof); proof["privilege"] = privilege
            with self.assertRaisesRegex(AssertionError, "STANDARD_WORKER_PROOF"):
                validate_worker(proof, self.child, self.plan)

    def test_success_text_does_not_hide_wrong_trace_or_helper_failure(self):
        for field, value in (("input_sha256", "foreign"), ("helper_exit_code", 7),
                             ("rows", 0), ("helper_pid", 10), ("index_readable", False)):
            with self.subTest(field=field):
                proof = deepcopy(self.proof); proof["traces"][0][field] = value
                with self.assertRaisesRegex(AssertionError, "STANDARD_TRACE_RESULT"):
                    validate_worker(proof, self.child, self.plan)

    def test_missing_format_or_different_worker_is_rejected(self):
        proof = deepcopy(self.proof); proof["traces"].pop()
        with self.assertRaisesRegex(AssertionError, "STANDARD_TRACE_COVERAGE"):
            validate_worker(proof, self.child, self.plan)
        with self.assertRaisesRegex(AssertionError, "STANDARD_WORKER_PROOF"):
            validate_worker(self.proof, {"pid": 99, "exit_code": 0}, self.plan)


if __name__ == "__main__":
    unittest.main()
