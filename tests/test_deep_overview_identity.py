"""Selected instance identity must survive the Overview worker boundary."""
from types import SimpleNamespace
import unittest

from blackbox_universal.monitor import ReadOnlyProbe


class OverviewInspectionIdentityTests(unittest.TestCase):
    def test_snapshot_preserves_selected_creation_time_without_pid_relookup(self):
        probe = ReadOnlyProbe()
        probe.pid = 4321
        probe._core = SimpleNamespace(created=1700000000.125)
        snapshot = probe.snapshot()
        self.assertEqual(snapshot["observed_process"]["pid"], 4321)
        self.assertEqual(snapshot["pid_creation_time"], 1700000000.125)

    def test_no_selected_instance_does_not_fabricate_a_creation_time(self):
        probe = ReadOnlyProbe()
        self.assertIsNone(probe.snapshot()["pid_creation_time"])


if __name__ == "__main__":
    unittest.main()
