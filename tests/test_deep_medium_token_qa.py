"""Actual hosted Windows token contracts; no Linux emulation of integrity levels."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from tools.qa_decoder_standard_token import restricted_child, restricted_interpreter, token_integrity


@unittest.skipUnless(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
                     os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                     "Actual child tokens require a disposable GitHub-hosted Windows runner")
class DeepMediumIntegrityContracts(unittest.TestCase):
    def launch(self, *, medium):
        parent_before = token_integrity()
        with tempfile.TemporaryDirectory(prefix="deep medium token ") as temporary:
            destination = Path(temporary) / "worker token.json"
            script = (
                "import json,os,sys; from pathlib import Path; "
                "from tools.qa_decoder_standard_token import token_integrity; "
                "from blackbox_core.windows_research import privilege; "
                "Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),"
                "'integrity':token_integrity(),'privilege':privilege()}),encoding='utf-8')"
            )
            options = {"medium_integrity": True} if medium else {}
            child = restricted_child([restricted_interpreter(sys.executable), "-c", script, destination],
                                     cwd=Path(__file__).resolve().parents[1], timeout_seconds=30, **options)
            self.assertEqual(child["exit_code"], 0)
            self.assertTrue(destination.is_file(), "Actual restricted child must write its own token evidence")
            worker = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(token_integrity(), parent_before, "Setting child IL must never mutate the parent token")
        self.assertEqual(worker["pid"], child["pid"])
        self.assertEqual(worker["privilege"], {"mode": "STANDARD", "windows": True})
        self.assertTrue(child["job_assigned_before_resume"])
        return parent_before, child, worker

    def test_explicit_medium_option_changes_real_token_and_worker_reads_it_back(self):
        _, child, worker = self.launch(medium=True)
        self.assertEqual(worker["integrity"]["sid"], "S-1-16-8192")
        self.assertEqual(worker["integrity"]["rid"], 8192)
        self.assertEqual(child["token_integrity"], worker["integrity"])
        self.assertEqual(child["child_token_integrity"], worker["integrity"])
        self.assertEqual(child["interactive_uac_secure_desktop"], "NOT_TESTED")

    def test_default_retains_existing_integrity_without_relabeling_old_decoder_qa(self):
        parent, child, worker = self.launch(medium=False)
        self.assertEqual(worker["integrity"], parent)
        self.assertNotIn("medium_integrity_requested", child)


if __name__ == "__main__":
    unittest.main()
