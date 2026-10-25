"""Regression: QA fixture readiness is complete, atomic and no-clobber.

These are test-stand filesystem contracts, not a substitute for real OS sampling.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_universal import qa_fixtures


class AtomicReadyHandoffTests(unittest.TestCase):
    def test_consumer_never_sees_partial_ready_json(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ready = root / "ready.json"
            data = {"fixture": "BB-DI-001/REAL_OS_WORKLOAD",
                    "pid": 123, "sensor_pid": 123, "thread_ids": [1, 2]}
            observed = []

            def deliberately_split_dump(obj, handle):
                serialized = json.dumps(obj)
                split = len(serialized) // 2
                handle.write(serialized[:split])
                handle.flush()
                observed.append((ready.exists(),
                                 (root / ".ready.json.pending").is_file()))
                handle.write(serialized[split:])

            with patch.object(qa_fixtures.json, "dump",
                              side_effect=deliberately_split_dump):
                qa_fixtures._publish_ready(root, data)
            self.assertEqual(observed, [(False, True)])
            self.assertEqual(json.loads(ready.read_text(encoding="utf-8")), data)
            self.assertFalse((root / ".ready.json.pending").exists())

    def test_existing_ready_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ready = root / "ready.json"
            ready.write_text('{"owner":"original"}', encoding="utf-8")
            with self.assertRaises(FileExistsError):
                qa_fixtures._publish_ready(root, {"owner": "second"})
            self.assertEqual(ready.read_text(encoding="utf-8"),
                             '{"owner":"original"}')
            self.assertFalse((root / ".ready.json.pending").exists())

    def test_foreign_pending_file_is_not_deleted_on_collision(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pending = root / ".ready.json.pending"
            pending.write_bytes(b"preexisting-foreign-marker")
            with self.assertRaises(FileExistsError):
                qa_fixtures._publish_ready(root, {"fixture": "new"})
            self.assertEqual(pending.read_bytes(), b"preexisting-foreign-marker")
            self.assertFalse((root / "ready.json").exists())


if __name__ == "__main__":
    unittest.main()
