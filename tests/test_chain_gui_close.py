"""Real Qt close scheduling with explicit synthetic ownership fixtures.

These tests prove GUI cleanup ordering, not actual native owner release. The
separate hosted Windows source/frozen harness verifies real helper cleanup.
"""
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from blackbox_universal.chain_bridge import _ChainTask
from blackbox_universal.window import UniversalWindow


class IndependentOwnerCloseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = UniversalWindow(output_root=Path(self.temp.name), allow_update_check=False)
        self.window._timer.stop()
        self.window.show()
        self.chain = self.window.chain_builder_panel.bridge
        self.deep = self.window.deep_inspector_panel.bridge
        self.wait(lambda: not self.chain.busy)

    def wait(self, condition):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return
            time.sleep(.005)
        self.fail("CLOSE_FIXTURE_WORKER_DID_NOT_DRAIN")

    def tearDown(self):
        self.deep._service = None
        self.deep.cleanup_required = False
        self.deep._closing = False
        self.chain._native_contexts.clear()
        self.chain._owned_session_run_id = None
        from qt_test_support import close_and_drain
        close_and_drain(self.window, self.app, timeout=15)
        self.temp.cleanup()

    def test_retained_deep_cleanup_is_requested_during_a_real_pending_passive_catalog_worker(self):
        entered, release = threading.Event(), threading.Event()
        class BlockedCatalog(_ChainTask):
            def run(self):
                entered.set()
                if not release.wait(10):
                    return
                super().run()
        self.deep._service = object()  # Explicit retained-owner GUI fixture.
        self.deep._closing = True
        self.deep.cleanup_required = True
        with patch("blackbox_universal.chain_bridge._ChainTask", BlockedCatalog), \
                patch.object(self.deep, "retry_cleanup", return_value=False) as retry:
            self.assertTrue(self.chain.submit("catalog"))
            self.wait(entered.is_set)
            try:
                self.assertFalse(self.window.close())
                retry.assert_called_once()
                self.assertTrue(self.chain.busy)
                self.assertTrue(self.window.isVisible())
                self.assertFalse(self.window._chain_close_complete)
                self.assertFalse(self.window._deep_close_complete)
            finally:
                # Remove only our synthetic fixture before actual queued close
                # events run; no fake native completion signal is emitted.
                self.deep._service = None
                self.deep.cleanup_required = False
                self.deep._closing = False
                release.set()
                self.wait(lambda: not self.chain.busy)

    def test_active_workflow_preflight_drains_before_shared_deep_shutdown(self):
        entered, release = threading.Event(), threading.Event()
        class BlockedStart(_ChainTask):
            def run(self):
                entered.set()
                release.wait(10)
                # Explicit GUI scheduling fixture: no diagnostic action starts.
        self.deep._service = object()
        with patch("blackbox_universal.chain_bridge._ChainTask", BlockedStart), \
                patch.object(self.window.deep_inspector_panel, "shutdown") as deep_shutdown:
            self.assertTrue(self.chain.submit("start"))
            self.wait(entered.is_set)
            try:
                self.assertFalse(self.window.close())
                deep_shutdown.assert_not_called()
                self.assertTrue(self.chain.worker.cancel_event.is_set())
                self.assertFalse(self.window._chain_close_complete)
                self.assertTrue(self.window.isVisible())
                release.set()
                self.wait(lambda: self.window._chain_close_complete and deep_shutdown.call_count > 0)
                self.assertTrue(self.window.isVisible())  # Deep did not acknowledge completion.
                self.assertFalse(self.window._deep_close_complete)
            finally:
                self.deep._service = None
                release.set()
                self.wait(lambda: not self.chain.busy)

    def test_retained_runtime_context_does_not_become_independent_when_worker_is_idle(self):
        self.deep._service = object()
        self.chain._owned_session_run_id = "synthetic-chain-owner"
        self.chain._native_contexts["synthetic-chain-owner"] = {"context_id": "synthetic-owned-context"}
        with patch.object(self.chain, "shutdown") as chain_shutdown, \
                patch.object(self.window.deep_inspector_panel, "shutdown") as deep_shutdown:
            self.assertFalse(self.window.close())
            chain_shutdown.assert_called_once()
            deep_shutdown.assert_not_called()
            self.assertFalse(self.window._chain_close_complete)
            self.assertTrue(self.window.isVisible())


if __name__ == "__main__":
    unittest.main()
