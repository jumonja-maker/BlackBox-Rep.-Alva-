"""Consumer-side regression cases added without modifying the upstream v0.1.1 tests.

All cases are offline, deterministic and stdlib-only; no Qt or psutil required.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_investigation import (
    InvestigationError, Policy, analyze, analyze_session, analyze_snapshot, load_session,
)
from blackbox_investigation.optin_probe import observe_selected_process
from test_investigation import fixture_session


class MaliciousPolicy:
    @property
    def max_samples(self):
        raise AssertionError("INVALID_POLICY must be rejected before attribute access")


class ConsumerHardeningTests(unittest.TestCase):
    def assert_code(self, code, callback, *args, **kwargs):
        with self.assertRaises(InvestigationError) as ctx:
            callback(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)

    def test_wrong_policy_types_are_rejected_consistently(self):
        snapshot = {"schema_version": 1, "product": "BLACK.BOX Universal",
                    "observed_process": {"pid": 10}, "recent_samples": []}
        with tempfile.TemporaryDirectory() as tmp:
            session = fixture_session(Path(tmp) / "valid-session")
            original = (session / "session.sqlite3").read_bytes()
            for bad in ("bad", 17, False, {}, [], MaliciousPolicy()):
                with self.subTest(value=type(bad).__name__):
                    self.assert_code("INVALID_POLICY", analyze, [], policy=bad)
                    self.assert_code("INVALID_POLICY", analyze_snapshot, snapshot, policy=bad)
                    self.assert_code("INVALID_POLICY", load_session, session, policy=bad)
                    self.assert_code("INVALID_POLICY", analyze_session, session, policy=bad)
            self.assertEqual((session / "session.sqlite3").read_bytes(), original)

    def test_policy_failure_does_not_open_sqlite(self):
        with patch("blackbox_investigation.sqlite_adapter.sqlite3.connect",
                   side_effect=AssertionError("SQLite must not be read")):
            self.assert_code("INVALID_POLICY", load_session, "nonexistent", policy="bad")
            self.assert_code("INVALID_POLICY", analyze_session, "nonexistent", policy="bad")

    def test_invalid_session_path_type_uses_stable_code(self):
        for bad in (None, 123, object(), [], {}):
            with self.subTest(value=type(bad).__name__):
                self.assert_code("INVALID_SESSION_PATH", load_session, bad)
                self.assert_code("INVALID_SESSION_PATH", analyze_session, bad)

    def test_overlong_snapshot_is_rejected_before_item_conversion(self):
        snapshot = {"schema_version": 1, "product": "BLACK.BOX Universal",
                    "observed_process": {"pid": 44},
                    "recent_samples": [object()] * 5}
        self.assert_code("SAMPLE_LIMIT", analyze_snapshot, snapshot,
                         policy=Policy(max_samples=4))

    def test_expected_created_is_checked_before_psutil_import(self):
        import builtins
        real_import = builtins.__import__
        seen = []

        def tracked_import(name, *args, **kwargs):
            if name == "psutil":
                seen.append(name)
                raise AssertionError("must not import/access psutil for invalid input")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=tracked_import):
            for bad in (True, 0, -1, "now", float('nan'), float('inf')):
                with self.subTest(value=repr(bad)):
                    self.assert_code("INVALID_CREATION_TIME", observe_selected_process,
                                     202, expected_created=bad)
        self.assertEqual(seen, [])

    def test_valid_session_and_partial_interval_still_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = fixture_session(Path(tmp) / "session")
            policy = Policy()
            parsed = load_session(folder, policy=policy)
            self.assertEqual(parsed["coverage"]["total_samples"], 4)
            whole = analyze_session(folder, policy=policy)
            self.assertTrue(whole["coverage"]["full_session_covered"])
            partial = analyze_session(folder, interval_start_ms=1000,
                                      interval_end_ms=2000, policy=policy)
            self.assertEqual(partial["coverage"]["selected_samples"], 2)
            self.assertEqual(partial["coverage"]["omitted_samples"], 2)
            self.assertEqual(partial["schema_version"], 2)
            self.assertIn("PARTIAL_SESSION_INTERVAL", partial["warnings"])


if __name__ == "__main__":
    unittest.main()
