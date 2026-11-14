"""Cleanup and debugger success cannot erase an actual earlier QA failure."""
from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock

from blackbox_universal.research_e2e import finalized_proof
from tools.qa_linux_unit_gdb import UNIT_CODE, child_result, debugger_command


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


class LinuxNativeChildExitTruthfulnessTests(unittest.TestCase):
    SHA = 'a' * 40

    def proof(self, **changes):
        return {'source_sha': self.SHA, 'inferior_started': True, 'inferior_pid': 123,
                'inferior_exited': True, 'child_exit_code': 0, 'child_exit_signal': None,
                'debugger_error': None, **changes}

    def result(self, proof, debugger_code=0):
        return child_result(proof, debugger_code, self.SHA)

    def test_debugger_success_without_an_actual_inferior_exit_cannot_pass(self):
        for proof in (None, {}, self.proof(inferior_started=False), self.proof(inferior_pid=0),
                      self.proof(inferior_pid=True), self.proof(inferior_exited=False),
                      self.proof(source_sha='b' * 40), self.proof(debugger_error='run failed')):
            with self.subTest(proof=proof):
                self.assertEqual(self.result(proof)[0], 125)

    def test_actual_unittest_failure_and_native_signal_survive_debugger_status(self):
        self.assertEqual(self.result(self.proof(child_exit_code=1))[0], 1)
        self.assertEqual(self.result(self.proof(child_exit_code=7), 7)[0], 7)
        for debugger_code in (0, 255, -11):
            with self.subTest(debugger_code=debugger_code):
                self.assertEqual(self.result(self.proof(child_exit_code=None, child_exit_signal=11),
                                             debugger_code), (139, 'LINUX_UNIT_CHILD_SIGNAL_11'))

    def test_unknown_ambiguous_or_boolean_exit_values_cannot_pass(self):
        for code, signal in ((None, None), (0, 11), (True, None), (None, True), (-1, None),
                             (256, None), (None, 0), (None, 65)):
            with self.subTest(code=code, signal=signal):
                self.assertEqual(self.result(self.proof(child_exit_code=code, child_exit_signal=signal))[0], 125)

    def test_child_success_also_requires_successful_debugger_completion(self):
        self.assertEqual(self.result(self.proof()), (0, 'LINUX_UNIT_CHILD_SUCCESS'))
        self.assertEqual(self.result(self.proof(), 1)[0], 125)

    def test_inferior_code_is_owned_file_not_fragile_multiline_gdb_argument(self):
        with tempfile.TemporaryDirectory() as owned:
            command, result_path = debugger_command(owned, self.SHA)
            driver = Path(command[-1])
            self.assertEqual(command[command.index('--args') + 1:], [sys.executable, str(driver)])
            self.assertEqual(driver.parent, Path(owned))
            self.assertEqual(result_path.parent, Path(owned))
            self.assertEqual(driver.read_text(encoding='utf-8'), "import sys\nsys.path[0] = ''\n" + UNIT_CODE)
            self.assertTrue(Path(command[command.index('-x') + 1]).is_file())
            self.assertNotIn('-c', command)
            self.assertTrue(all('\n' not in argument for argument in command))


class LinuxUnitDriverSafetyTests(unittest.TestCase):
    @contextmanager
    def controlled_driver(self, *, environment=None, main_failure=None):
        events = []
        faults = ModuleType('faulthandler')
        faults.enable = Mock(side_effect=lambda **_kwargs: events.append('fatal_enabled'))
        faults.dump_traceback_later = Mock(side_effect=AssertionError('PERIODIC_WATCHDOG_FORBIDDEN'))
        faults.cancel_dump_traceback_later = Mock(side_effect=AssertionError('PERIODIC_WATCHDOG_FORBIDDEN'))
        suite = ModuleType('unittest')

        def main(*_args, **_kwargs):
            events.append('full_suite_requested')
            if main_failure is not None:
                raise main_failure

        suite.main = Mock(side_effect=main)
        if environment is None:
            environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}
        runner = ModuleType('os')
        runner.environ = dict(environment)
        modules = {'faulthandler': faults, 'os': runner, 'unittest': suite}

        def import_module(name, _globals=None, _locals=None, _fromlist=(), level=0):
            if level or name not in modules:
                raise AssertionError('UNEXPECTED_UNIT_DRIVER_IMPORT:' + name)
            return modules[name]

        namespace = {'__builtins__': {'__import__': import_module, 'SystemExit': SystemExit}}
        yield namespace, events, faults, suite

    def assert_driver_calls(self, events, faults, suite):
        self.assertEqual(events, ['fatal_enabled', 'full_suite_requested'])
        faults.enable.assert_called_once_with(all_threads=True)
        faults.dump_traceback_later.assert_not_called()
        faults.cancel_dump_traceback_later.assert_not_called()
        suite.main.assert_called_once_with(module=None, argv=['unittest', 'discover', '-s', 'tests', '-v'])

    def test_actual_unit_driver_keeps_fatal_reporting_and_exact_full_suite_without_watchdog(self):
        with self.controlled_driver() as (namespace, events, faults, suite):
            exec(UNIT_CODE, namespace)
            self.assert_driver_calls(events, faults, suite)

    def test_actual_unit_driver_rejects_non_hosted_execution_before_diagnostics_or_suite(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true'}, {'RUNNER_ENVIRONMENT': 'github-hosted'},
                            {'GITHUB_ACTIONS': 'false', 'RUNNER_ENVIRONMENT': 'github-hosted'},
                            {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}):
            with self.subTest(environment=environment), \
                    self.controlled_driver(environment=environment) as (namespace, events, faults, suite):
                with self.assertRaises(SystemExit) as failure:
                    exec(UNIT_CODE, namespace)
                self.assertEqual(str(failure.exception), 'FULL_LINUX_UNIT_SUITE_REQUIRES_GITHUB_HOSTED_RUNNER')
                self.assertEqual(events, [])
                faults.enable.assert_not_called()
                faults.dump_traceback_later.assert_not_called()
                faults.cancel_dump_traceback_later.assert_not_called()
                suite.main.assert_not_called()

    def test_actual_unit_driver_propagates_suite_exit_and_python_failure(self):
        for failure in (SystemExit(0), SystemExit(7), RuntimeError('CONTROLLED_SUITE_FAILURE')):
            with self.subTest(failure=repr(failure)), \
                    self.controlled_driver(main_failure=failure) as (namespace, events, faults, suite):
                with self.assertRaises(type(failure)) as caught:
                    exec(UNIT_CODE, namespace)
                self.assertIs(caught.exception, failure)
                self.assert_driver_calls(events, faults, suite)


if __name__ == '__main__':
    unittest.main()
