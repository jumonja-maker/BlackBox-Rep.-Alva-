from __future__ import annotations
import unittest
from io import StringIO
from contextlib import redirect_stdout
from blackbox_rep_alva.cli import main

class CliTests(unittest.TestCase):
    def test_missing_session_is_explicit_error(self):
        with redirect_stdout(StringIO()) as out:
            status=main(["summary", "this-session-does-not-exist"])
        self.assertEqual(status,2)
        self.assertIn("INVALID_DATA",out.getvalue())

    def test_bad_pid_and_output(self):
        with redirect_stdout(StringIO()) as out:
            status=main(["record", "--pid", "0", "--output", "missing"])
        self.assertEqual(status,2)
        self.assertIn("INVALID_DATA",out.getvalue())
