"""Human-first contract: no AI handoff is required, generated or advertised."""
from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest

from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_rep_alva.cli import main


class HumanFirstContractTests(unittest.TestCase):
    def test_one_human_session_generates_html_json_sqlite_not_ai_handoff(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = ReadOnlyProbe(Path(temp))
            recorder.attach(os.getpid())
            recorder.start()
            recorder.tick()
            recorder.stop()
            self.assertEqual(recorder.session_state, "COMPLETED")
            folder = recorder.session_folder
            self.assertTrue((folder / "session.sqlite3").is_file())
            self.assertTrue((folder / "report.json").is_file())
            self.assertTrue((folder / "report.html").is_file())
            self.assertFalse((folder / "ai-handoff.json").exists())
            self.assertIn("BlackBox Process Observation",
                          (folder / "report.html").read_text("utf-8"))
            snapshot = recorder.snapshot()
            self.assertTrue(snapshot["report_generated"])
            self.assertNotIn("handoff_generated", snapshot)
            self.assertFalse(snapshot["root_cause_proven"])

    def test_ai_handoff_cli_command_is_not_part_of_product(self):
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["handoff", "some-session"])
        self.assertEqual(error.exception.code, 2)

    def test_internal_platform_cli_command_is_not_advertised(self):
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["alva-check"])
        self.assertEqual(error.exception.code, 2)

    def test_normal_cli_is_still_accessible_without_alva_or_ai(self):
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["--help"])
        self.assertEqual(error.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
