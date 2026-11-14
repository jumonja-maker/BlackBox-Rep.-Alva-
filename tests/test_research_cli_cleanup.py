"""CLI setup failure never bypasses the existing ResearchSession stop owner."""
from types import SimpleNamespace
from contextlib import redirect_stdout
from io import StringIO
import json
import unittest
from unittest.mock import patch
from blackbox_core.research_cli import main


class ResearchCliCleanupTests(unittest.TestCase):
    def test_public_cli_normalizes_sensor_and_cleanup_runtime_failures(self):
        from blackbox_core.cli import main as cli_main
        for reason in ('BASE_SENSOR_UNAVAILABLE','TEST_ONLY_CLEANUP_UNCONFIRMED'):
            with self.subTest(reason=reason), \
                 patch('blackbox_core.research_cli.main',side_effect=RuntimeError(reason)):
                output=StringIO()
                with redirect_stdout(output):status=cli_main(['research','record'])
                self.assertEqual(status,2)
                self.assertEqual(json.loads(output.getvalue()),
                                 {'status':'error','code':reason,'stage':'research'})

    def test_every_setup_failure_reaches_stop_and_never_reports_success(self):
        for failed in ("attach", "configure", "interval", "start", "detailed"):
            with self.subTest(failed=failed):
                calls = []

                class PartialSession:
                    def __init__(self, output):
                        self.probe = SimpleNamespace(active=False)

                    def command(self, value):
                        op = value["op"]
                        calls.append(op)
                        if op == "start":
                            self.probe.active = True  # Partial setup really owns an active recording.
                        if op == failed:
                            raise ValueError("TEST_ONLY_SETUP_FAILURE_" + failed)

                    def stop(self):
                        calls.append("stop")
                        self.probe.active = False
                        return {'cleanup_required':False,'errors':[]}

                    def tick(self):
                        raise AssertionError("Failed setup must never enter recording loop")

                with patch("blackbox_core.research_worker.ResearchSession", PartialSession), \
                     patch("builtins.print") as output:
                    with self.assertRaisesRegex(ValueError, "TEST_ONLY_SETUP_FAILURE_" + failed):
                        main(["record", "--pid", "42", "--output", ".", "--detailed"])
                    output.assert_not_called()
                self.assertEqual(calls[-1], "stop")
                self.assertEqual(calls.count("stop"), 1)

    def test_unconfirmed_setup_cleanup_is_not_reported_as_success(self):
        class FailedCleanup:
            def __init__(self, output):
                self.probe = SimpleNamespace(active=True)

            def command(self, value):
                raise ValueError("TEST_ONLY_PARTIAL_SETUP")

            def stop(self):
                raise RuntimeError("TEST_ONLY_CLEANUP_UNCONFIRMED")

        with patch("blackbox_core.research_worker.ResearchSession", FailedCleanup), \
             patch("builtins.print") as output:
            with self.assertRaisesRegex(RuntimeError, "TEST_ONLY_CLEANUP_UNCONFIRMED") as error:
                main(["record", "--pid", "42", "--output", "."])
            self.assertIsInstance(error.exception.__context__, ValueError)
            output.assert_not_called()

    def test_actual_stop_receipt_controls_cleanup_and_incomplete_exit_status(self):
        for cleanup,state,errors in ((True,'COMPLETED',[]),(False,'INCOMPLETE',['TEST_ONLY_LOSS']),
                                     (False,'COMPLETED',[])):
            with self.subTest(cleanup=cleanup,state=state):
                class StoppedSession:
                    def __init__(self,output):
                        self.probe=SimpleNamespace(active=False,session_folder='TEST_ONLY_FOLDER',
                            session_state='COMPLETED',total_samples=0)
                        self.research_state=state
                        self.research_error=None
                    def command(self,value):pass
                    def stop(self):return {'cleanup_required':cleanup,'errors':errors}
                output=StringIO()
                with patch('blackbox_core.research_worker.ResearchSession',StoppedSession),redirect_stdout(output):
                    if cleanup:
                        with self.assertRaisesRegex(RuntimeError,'RESEARCH_RESOURCE_CLEANUP_UNCONFIRMED'):
                            main(['record','--pid','42','--output','.'])
                        self.assertEqual(output.getvalue(),'')
                    else:
                        status=main(['record','--pid','42','--output','.'])
                        self.assertEqual(status,2 if errors else 0)
                        self.assertEqual(json.loads(output.getvalue())['state'],state)
