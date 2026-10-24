"""A workflow event merge ref must never masquerade as the tested checkout."""
from pathlib import Path
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from blackbox_universal.provenance import source_identity


class ProvenanceTests(unittest.TestCase):
    def test_source_identity_reads_actual_checkout_independently(self):
        expected="a"*40
        results=[SimpleNamespace(returncode=0,stdout=expected+"\n"),
                 SimpleNamespace(returncode=0,stdout="b"*40+"\n"),SimpleNamespace(returncode=0,stdout="")]
        with patch("blackbox_universal.provenance.subprocess.run",side_effect=results), \
             patch.dict("os.environ",{"GITHUB_SHA":"c"*40}):
            result=source_identity(expected)
        self.assertEqual(result["actual_source_sha"],expected)
        self.assertEqual(result["workflow_event_sha"],"c"*40)
        self.assertEqual(result["source_identity_status"],"VERIFIED_EXPECTED_HEAD")
        self.assertNotIn("checkout_sha",result)
    def test_dirty_checkout_cannot_verify(self):
        results=[SimpleNamespace(returncode=0,stdout="a"*40),SimpleNamespace(returncode=0,stdout="b"*40),
                 SimpleNamespace(returncode=1,stdout="")]
        with patch("blackbox_universal.provenance.subprocess.run",side_effect=results):
            self.assertEqual(source_identity("a"*40)["source_identity_status"],"MISMATCH_OR_DIRTY")
    def test_frozen_identity_uses_bundled_manifest_without_git(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp,"blackbox-build.json").write_text(json.dumps({"schema_version":1,"source_sha":"a"*40,
                "source_tree_sha":"b"*40,"tracked_worktree_clean":True}))
            with patch("sys.frozen",True,create=True),patch("sys._MEIPASS",temp,create=True), \
                 patch("blackbox_universal.provenance.subprocess.run",side_effect=AssertionError("Git on destination forbidden")):
                self.assertEqual(source_identity("a"*40)["source_identity_status"],"VERIFIED_EXPECTED_HEAD")


if __name__=="__main__":unittest.main()
