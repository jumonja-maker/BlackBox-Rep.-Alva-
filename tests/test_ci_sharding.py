"""Verify shard completeness and fail-closed behavior without invoking QA tests."""
from pathlib import Path
import tempfile
import unittest
from tools.qa_unittest_shards import SHARD_PATTERNS, assigned_sources


class HostedWindowsUnitPartitionTests(unittest.TestCase):
    def test_every_real_test_file_is_owned_once(self):
        root = Path(__file__).resolve().parent
        groups = assigned_sources(root)
        all_files = {p.name for p in root.glob("test_*.py")}
        self.assertEqual(set.union(*(set(g) for g in groups.values())), all_files)
        self.assertEqual(sum(map(len, groups.values())), len(all_files))
        self.assertEqual(set(groups), set(SHARD_PATTERNS))

    def test_missing_suite_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "MISSING_WINDOWS_TEST_SOURCES"):
                assigned_sources(Path(directory))


if __name__ == "__main__":
    unittest.main()
