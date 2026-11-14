"""Negative release authorization contracts; only GitHub-hosted test execution."""
import copy
import json
import unittest
from unittest.mock import patch

from tools.publish_v061_after_ci import (
    PR_FILES, QUALIFIED_DELTA_FILES, F3_LONG_SHA, PREVIOUS_RELEASE_SHA,
    OLD_ZIP_SHA, OLD_SIDECAR_SHA, verify_scope, verify_qualified_delta,
    verify_old_release, require_base_recording,
)


class V061OwnerReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"filename": name, "status": kind} for name, kind in PR_FILES.items()]
        self.delta = [{"filename": name} for name in QUALIFIED_DELTA_FILES]
        self.old = {
            "tag_name": "v0.6.0", "draft": False, "prerelease": False,
            "target_commitish": PREVIOUS_RELEASE_SHA,
            "assets": [
                {"name": "BLACK.BOX-Universal-Windows.zip", "size": 115958681,
                 "state": "uploaded", "digest": "sha256:" + OLD_ZIP_SHA},
                {"name": "BLACK.BOX-Universal-Windows.zip.sha256", "size": 99,
                 "state": "uploaded", "digest": "sha256:" + OLD_SIDECAR_SHA},
            ],
        }

    def test_only_owner_approved_release_file_scope(self):
        verify_scope(self.rows)
        for changed in ("src/blackbox_core/chain_engine.py",
                        "blackbox_universal/monitor.py", "blackbox_universal/research_bridge.py"):
            rows = copy.deepcopy(self.rows)
            rows[0]["filename"] = changed
            with self.subTest(path=changed), self.assertRaisesRegex(
                    ValueError, "V061_UNAPPROVED_RELEASE_SOURCE_FILE"):
                verify_scope(rows)
        for bad in (self.rows[:-1], self.rows + [self.rows[0]]):
            with self.assertRaisesRegex(ValueError, "V061_SOURCE_SCOPE_COUNT_MISMATCH"):
                verify_scope(bad)

    def test_historical_5h30_not_reused_if_core_or_admission_changes(self):
        verify_qualified_delta(self.delta)
        for file in ("src/blackbox_core/session_v2.py",
                     "src/blackbox_core/chain_engine.py",
                     "blackbox_universal/monitor.py",
                     "tools/qa_chain_endurance.py"):
            rows = copy.deepcopy(self.delta)
            rows[0]["filename"] = file
            with self.subTest(file=file), self.assertRaisesRegex(
                    ValueError, "V061_F3_NATIVE_OR_RECORDING_SOURCE_CHANGED"):
                verify_qualified_delta(rows)
        with self.assertRaisesRegex(ValueError, "V061_F3_DELTA_INCOMPLETE"):
            verify_qualified_delta(self.delta[:-1])

    def test_immutable_v060_zip_sidecar_and_source_required(self):
        verify_old_release(self.old)
        for change in (
            lambda o: o.update(target_commitish=F3_LONG_SHA),
            lambda o: o["assets"][0].update(size=0),
            lambda o: o["assets"][1].update(digest="sha256:" + "0"*64),
            lambda o: o.update(draft=True),
            lambda o: o["assets"].append({"name": "extra.zip"}),
        ):
            row = copy.deepcopy(self.old)
            change(row)
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_old_release(row)

    def test_base_recording_receipt_must_have_actual_seconds_and_cleanup(self):
        base = {
            "source_sha": F3_LONG_SHA, "status": "PASS", "profile": "STANDARD",
            "requested_seconds": 19800,
            "verdict": {"actual_seconds": 19800.0,
                        "gui_cleanup": {"status": "COMPLETED", "helper_alive": False,
                                        "running_qthreads": 0}},
        }
        class Result:
            stdout = "PROGRAM_ENDURANCE_RECEIPT " + json.dumps(base) + "\n"
        with patch("tools.publish_v061_after_ci.subprocess.run", return_value=Result()):
            self.assertEqual(require_base_recording("repo", 1, "STANDARD", 19800)["seconds"],
                             19800.0)
        base["verdict"]["gui_cleanup"]["helper_alive"] = True
        class Failed:
            stdout = "PROGRAM_ENDURANCE_RECEIPT " + json.dumps(base) + "\n"
        with patch("tools.publish_v061_after_ci.subprocess.run", return_value=Failed()):
            with self.assertRaisesRegex(ValueError, "V061_BASE_GUI_PERSISTED_LIFECYCLE_UNVERIFIED"):
                require_base_recording("repo", 1, "STANDARD", 19800)
        class Missing:
            stdout = ""
        with patch("tools.publish_v061_after_ci.subprocess.run", return_value=Missing()):
            with self.assertRaisesRegex(ValueError, "V061_BASE_GUI_RECEIPT_MISSING_OR_DUPLICATE"):
                require_base_recording("repo", 1, "STANDARD", 19800)


if __name__ == "__main__":
    unittest.main()
