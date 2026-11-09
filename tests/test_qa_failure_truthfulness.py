"""Cleanup success cannot erase an actual earlier research QA failure."""
import unittest

from blackbox_universal.research_e2e import finalized_proof


class ResearchQaFailureTruthfulnessTests(unittest.TestCase):
    def test_late_normal_helper_exit_preserves_latched_failure(self):
        proof = {"status": "AWAITING_HELPER_SHUTDOWN", "verified": True}
        finalized_proof(proof, 0, "COMMAND_quit: CLEANUP_UNCONFIRMED")
        self.assertEqual(proof["status"], "FAIL")
        self.assertEqual(proof["reason"], "COMMAND_quit: CLEANUP_UNCONFIRMED")
        self.assertEqual(proof["helper_exit_code"], 0)

    def test_already_failed_proof_cannot_be_promoted_by_later_callbacks(self):
        proof = {"status": "FAIL", "reason": "FIRST_FAILURE"}
        finalized_proof(proof, 0)
        finalized_proof(proof, 0, "SECOND_FAILURE")
        self.assertEqual(proof["status"], "FAIL")
        self.assertEqual(proof["reason"], "FIRST_FAILURE")

    def test_success_needs_successful_proof_and_normal_helper_exit(self):
        for code, expected in ((0, "PASS"), (1, "FAIL"), (-1, "FAIL"), (None, "FAIL")):
            with self.subTest(code=code):
                proof = finalized_proof({"status": "AWAITING_HELPER_SHUTDOWN"}, code)
                self.assertEqual(proof["status"], expected)


if __name__ == '__main__':
    unittest.main()
