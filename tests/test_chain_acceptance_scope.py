"""An explicit functional audit cannot silently replace full R60 lifecycle QA."""
import unittest

from tools.qa_chain_builder import acceptance_plan, program_dispatch_identity


class ChainAcceptanceScopeTests(unittest.TestCase):
    def test_default_dispatch_and_candidate_pr_retain_every_full_gate(self):
        for event in ("pull_request", "workflow_dispatch"):
            with self.subTest(event=event):
                plan = acceptance_plan(event)
                self.assertTrue(plan["contracts"])
                self.assertTrue(plan["native"])
                self.assertTrue(plan["lifecycle"])
                self.assertFalse(plan["technical_audit"])
                self.assertFalse(plan['base_program_endurance'])
                self.assertFalse(any(plan[key] for key in ("gui_only", "medium_only", "workspace_only")))

    def test_manual_technical_audit_retains_all_functional_jobs_without_a_full_candidate_claim(self):
        plan = acceptance_plan("workflow_dispatch", "technical-audit")
        self.assertTrue(plan["contracts"] and plan["native"] and plan["technical_audit"])
        self.assertFalse(plan["lifecycle"])
        self.assertFalse(plan['base_program_endurance'])
        self.assertFalse(any(plan[key] for key in ("gui_only", "medium_only", "workspace_only")))

    def test_technical_audit_cannot_be_selected_by_pr_or_unknown_scope(self):
        for event, scope in (("pull_request", "technical-audit"), ("push", "technical-audit"),
                             ('pull_request', 'base-program-endurance'),
                             ("workflow_dispatch", "gui-only"), ("workflow_dispatch", "")):
            with self.subTest(event=event, scope=scope), self.assertRaises(AssertionError):
                acceptance_plan(event, scope)

    def test_base_gui_long_dispatch_cannot_claim_r60_functional_or_scheduler_acceptance(self):
        plan=acceptance_plan('workflow_dispatch','base-program-endurance')
        self.assertTrue(plan['base_program_endurance'])
        self.assertFalse(any(value for key,value in plan.items() if key!='base_program_endurance'))
        self.assertEqual(program_dispatch_identity('a'*40,'a'*40,'123'),123)
        for sha,run_id in (('b'*40,'123'),('a'*40,''),('a'*40,'0'),('a'*40,'not-a-run')):
            with self.subTest(sha=sha,run_id=run_id),self.assertRaises(AssertionError):
                program_dispatch_identity('a'*40,sha,run_id)


if __name__ == "__main__":
    unittest.main()
