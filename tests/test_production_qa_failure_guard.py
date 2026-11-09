"""Real callback/exit proof owns its QApplication in a hosted child process."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from blackbox_core.chain_qa_guard import ChainQaFailureGuard
from blackbox_universal.production_qa import apply_callback_failure, check_callback_guard


def expected_source():
    expected = os.environ.get('BB_QA_SOURCE_SHA')
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if not expected and event_path:
        event = json.loads(Path(event_path).read_text(encoding='utf-8'))
        expected = (event.get('pull_request') or {}).get('head', {}).get('sha')
    expected = expected or os.environ.get('GITHUB_SHA')
    if not re.fullmatch(r'[0-9a-f]{40}', expected or ''):
        raise AssertionError('PRODUCTION_CALLBACK_FIXTURE_EXPECTED_SOURCE_REQUIRED')
    return expected


def callback_fixture():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise AssertionError('PRODUCTION_CALLBACK_FIXTURE_REQUIRES_HOSTED_RUNNER')
    from PySide6.QtCore import QThread, QTimer
    from PySide6.QtWidgets import QApplication, QWidget
    from blackbox_universal.provenance import source_identity
    case = unittest.TestCase()
    expected = expected_source()
    identity = source_identity(expected)
    case.assertEqual(identity['source_identity_status'], 'VERIFIED_EXPECTED_HEAD')
    app = QApplication([])
    app.setQuitOnLastWindowClosed(False)
    owned = QWidget()
    owned.show()
    app.processEvents()
    delivered = []
    with tempfile.TemporaryDirectory() as temporary:
        guard = ChainQaFailureGuard(Path(temporary) / 'callback.json')
        guard.source_sha = expected
        previous = guard.install()
        try:
            def fail():
                delivered.append(True)
                raise RuntimeError('CONTROLLED_QA_CALLBACK_FAILURE')
            QTimer.singleShot(0, fail)
            app.processEvents()
            case.assertEqual(delivered, [True])
            case.assertTrue(guard.failed)
            with case.assertRaisesRegex(RuntimeError, 'QA_UNHANDLED_PYTHON_CALLBACK'):
                check_callback_guard(guard)
            check_callback_guard(guard, cleanup=True)
            owned.close()
            app.processEvents()
            cleanup = {'status': 'COMPLETED', 'window_visible': owned.isVisible(),
                       'running_qthreads': sum(worker.isRunning() for worker in owned.findChildren(QThread)),
                       'scope': 'CONTROLLED_QT_FIXTURE_NO_RECORDING_HELPER_STARTED'}
            case.assertFalse(cleanup['window_visible'])
            case.assertEqual(cleanup['running_qthreads'], 0)
            result = apply_callback_failure({'state': 'COMPLETED', 'cleanup': cleanup}, guard)
            case.assertEqual(result['state'], 'FAILED')
            case.assertEqual(result['cleanup']['status'], 'COMPLETED')
            case.assertEqual(result['unhandled_python_failure']['source_sha'], expected)
            case.assertEqual(result['unhandled_python_failure']['first']['error_type'], 'RuntimeError')
            persisted = json.loads(guard.log_path.read_text(encoding='utf-8'))
            case.assertEqual(persisted, guard.metadata())
            case.assertEqual(persisted['pid'], os.getpid())
            case.assertEqual(guard.exit_code(0), 1)
        finally:
            owned.close()
            owned.deleteLater()
            app.processEvents()
            sys.excepthook = previous
        case.assertIs(sys.excepthook, previous)
        print('PRODUCTION_QA_CALLBACK_FIXTURE ' + json.dumps({
            'status': 'PASS', 'scope': 'ISOLATED_ACTUAL_QT_CONTROLLED_CALLBACK_NOT_RECORDING_ACCEPTANCE',
            'source_identity': identity, 'result': result, 'exit_code': guard.exit_code(0),
            'hook_restored': True, 'callback_delivered': delivered}, sort_keys=True), flush=True)
        return guard.exit_code(0)


class ProductionQaCallbackFailureTests(unittest.TestCase):
    def test_real_timer_exception_fails_normal_pump_without_poisoning_parent_modal(self):
        expected = expected_source()
        environment = {**os.environ, 'BB_QA_SOURCE_SHA': expected, 'QT_QPA_PLATFORM': 'offscreen'}
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--callback-fixture'],
                               cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 1, child.stdout[-8000:] + child.stderr[-8000:])
        lines = [line.split('PRODUCTION_QA_CALLBACK_FIXTURE ', 1)[1] for line in child.stdout.splitlines()
                 if line.startswith('PRODUCTION_QA_CALLBACK_FIXTURE ')]
        self.assertEqual(len(lines), 1, child.stdout[-8000:] + child.stderr[-8000:])
        proof = json.loads(lines[0])
        self.assertEqual(proof['status'], 'PASS')
        self.assertEqual(proof['result']['state'], 'FAILED')
        self.assertEqual(proof['source_identity']['actual_source_sha'], expected)
        self.assertEqual(proof['source_identity']['source_identity_status'], 'VERIFIED_EXPECTED_HEAD')
        self.assertTrue(proof['hook_restored'])
        self.assertEqual(proof['callback_delivered'], [True])
        self.assertNotEqual(proof['result']['unhandled_python_failure']['pid'], os.getpid())
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QDialog
        app = QApplication.instance() or QApplication([])
        previous_quit_policy = app.quitOnLastWindowClosed()
        app.setQuitOnLastWindowClosed(False)
        dialog = QDialog()
        dialog.setObjectName('parentModalAfterIsolatedCallbackExit')
        observed = []
        timer = QTimer(dialog)
        timer.setSingleShot(True)
        def accept_owned_modal():
            observed.append((dialog.isVisible(), app.activeModalWidget() is dialog))
            dialog.accept()
        timer.timeout.connect(accept_owned_modal)
        try:
            timer.start(20)
            self.assertEqual(dialog.exec(), QDialog.DialogCode.Accepted)
            self.assertEqual(observed, [(True, True)])
        finally:
            timer.stop()
            dialog.close()
            dialog.deleteLater()
            app.processEvents()
            app.setQuitOnLastWindowClosed(previous_quit_policy)
        print('PRODUCTION_QA_CALLBACK_ISOLATION ' + json.dumps({
            'status': 'PASS', 'source_sha': expected, 'child': proof,
            'parent_modal_visible_accepted': True, 'parent_quit_policy_restored':
                app.quitOnLastWindowClosed() == previous_quit_policy}, sort_keys=True), flush=True)

    def test_prior_failure_and_unconfirmed_owner_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard=ChainQaFailureGuard(Path(temporary)/'callback.json')
            guard.failed=True
            result={'state':'FAILED','error':'ORIGINAL_STORAGE_FAILURE',
                    'cleanup':{'status':'RECOVERY_UNCONFIRMED','helper_alive':True}}
            apply_callback_failure(result,guard)
            self.assertEqual(result['error'],'ORIGINAL_STORAGE_FAILURE')
            self.assertEqual(result['cleanup']['status'],'RECOVERY_UNCONFIRMED')
            self.assertTrue(result['cleanup']['helper_alive'])


if __name__ == '__main__':
    if sys.argv[1:] == ['--callback-fixture']:
        raise SystemExit(callback_fixture())
    unittest.main()
