"""Disk budgets are enforced from actually observed bytes, never a made-up total."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.storage_budget import recording_size
from blackbox_core.research_worker import ResearchSession


class LogicalSizeScanTests(unittest.TestCase):
    def test_small_directory_is_scanned_even_after_soft_clock_budget(self):
        # A 100-ms scheduling pause is common on loaded Windows runners.
        # We still inspect a small bounded set rather than misreporting
        # an obvious 17 MiB owned file as an unknown total.
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            with (folder / "recorded.bin").open("wb") as stream:
                stream.truncate(17 * 1024**2)
            result = recording_size(folder, max_seconds=0)
            self.assertEqual(result["status"], "OBSERVED_LOGICAL_FILE_BYTES")
            self.assertEqual(result["bytes"], 17 * 1024**2)
            self.assertNotIn("observed_partial_bytes", result)

    def test_incomplete_scan_is_not_published_as_complete_total(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            (folder / "a.bin").write_bytes(b"a" * 600)
            (folder / "b.bin").write_bytes(b"b" * 700)
            result = recording_size(folder, max_entries=1)
            self.assertEqual(result["status"], "METADATA_BUDGET_EXHAUSTED")
            self.assertIsNone(result["bytes"])
            self.assertIn(result["observed_partial_bytes"], (600, 700))

    def test_observed_partial_over_budget_stops_without_faking_total(self):
        with tempfile.TemporaryDirectory() as root:
            session = ResearchSession(root)
            session.command({"op": "attach", "args": {"pid": os.getpid()}})
            session.command({"op": "capture_policy",
                             "args": {"policy": {"max_session_mb": 16}}})
            session.command({"op": "start"})
            try:
                observed = {"bytes": None, "observed_partial_bytes": 17 * 1024**2,
                            "status": "METADATA_BUDGET_EXHAUSTED", "entries": 32}
                with patch("blackbox_core.storage_budget.recording_size",
                           return_value=observed):
                    session._health()
                self.assertFalse(session.probe.active)
                self.assertEqual(session.research_state, "STORAGE_LIMIT_REACHED")
                self.assertIsNone(observed["bytes"])
                self.assertEqual(observed["status"], "METADATA_BUDGET_EXHAUSTED")
            finally:
                session.stop()

    def test_unknown_subthreshold_partial_does_not_claim_over_budget(self):
        with tempfile.TemporaryDirectory() as root:
            session = ResearchSession(root)
            session.command({"op": "attach", "args": {"pid": os.getpid()}})
            session.command({"op": "capture_policy",
                             "args": {"policy": {"max_session_mb": 16}}})
            session.command({"op": "start"})
            try:
                observed = {"bytes": None, "observed_partial_bytes": 1200,
                            "status": "METADATA_BUDGET_EXHAUSTED", "entries": 32}
                with patch("blackbox_core.storage_budget.recording_size",
                           return_value=observed):
                    session._health()
                self.assertTrue(session.probe.active)
                self.assertEqual(session.research_state, "RECORDING")
            finally:
                session.stop()


if __name__ == "__main__":
    unittest.main()
