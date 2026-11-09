"""Actual Qt callback failure remains failed while QA-owned cleanup drains."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from blackbox_core.chain_qa_guard import ChainQaFailureGuard
from blackbox_universal.production_qa import apply_callback_failure, check_callback_guard


class ProductionQaCallbackFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app=QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def test_real_timer_exception_fails_normal_pump_and_cannot_be_erased_during_cleanup(self):
        from PySide6.QtCore import QTimer
        with tempfile.TemporaryDirectory() as temporary:
            guard=ChainQaFailureGuard(Path(temporary)/'callback.json');guard.source_sha='a'*40
            previous=guard.install()
            try:
                def fail():raise RuntimeError('CONTROLLED_QA_CALLBACK_FAILURE')
                QTimer.singleShot(0,fail)
                self.app.processEvents()
                self.assertTrue(guard.failed)
                with self.assertRaisesRegex(RuntimeError,'QA_UNHANDLED_PYTHON_CALLBACK'):
                    check_callback_guard(guard)
                check_callback_guard(guard,cleanup=True)
                result={'state':'COMPLETED','cleanup':{'status':'COMPLETED','helper_alive':False}}
                apply_callback_failure(result,guard)
                self.assertEqual(result['state'],'FAILED')
                self.assertEqual(result['cleanup']['status'],'COMPLETED')
                self.assertEqual(result['unhandled_python_failure']['source_sha'],'a'*40)
                self.assertEqual(result['unhandled_python_failure']['first']['error_type'],'RuntimeError')
            finally:sys.excepthook=previous

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


if __name__=='__main__':unittest.main()
