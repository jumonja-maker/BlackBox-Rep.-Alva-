"""Checked-close policy fixtures; no local native or destructive execution."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from blackbox_core import owned_unlink as owned


class OwnedFileCleanupTests(unittest.TestCase):
    def opened(self, close):
        owner = owned.WindowsFile.__new__(owned.WindowsFile)
        owner.handle = 987
        owner.k = SimpleNamespace(CloseHandle=close)
        owner.identity, owner.final, owner.directory = ["WIN32_FILE_ID", 3, 4], "/fixture/file", False
        return owner

    def test_normal_close_consumes_exact_capability_once(self):
        close = Mock(return_value=True)
        owner = self.opened(close)
        self.assertTrue(owner.close()["confirmed"])
        self.assertIsNone(owner.handle)
        self.assertTrue(owner.close()["confirmed"])
        close.assert_called_once_with(987)

    def test_rejected_close_keeps_original_owner_and_requires_ack_before_success(self):
        close = Mock(side_effect=[False, True])
        owner = self.opened(close)
        with patch.object(owned.C, "get_last_error", return_value=5, create=True):
            with self.assertRaises(owned.OwnedFileCloseUnconfirmed) as failure:
                owner.close()
        self.assertIs(failure.exception.owner, owner)
        self.assertTrue(failure.exception.cleanup_required)
        self.assertFalse(failure.exception.cleanup["confirmed"])
        self.assertEqual(owner.handle, 987)
        self.assertTrue(owner.close()["confirmed"])
        self.assertIsNone(owner.handle)
        self.assertEqual([call.args for call in close.call_args_list], [(987,), (987,)])

    def test_ambiguous_exception_and_invalid_handle_are_not_retried_numerically(self):
        for failed in (OSError("TEST_ONLY_CLOSE_OUTCOME_UNKNOWN"), 6):
            with self.subTest(failed=failed):
                close = Mock(side_effect=failed) if isinstance(failed, Exception) else Mock(return_value=False)
                owner = self.opened(close)
                with patch.object(owned.C, "get_last_error", return_value=6, create=True):
                    with self.assertRaises(owned.OwnedFileCloseUnconfirmed):
                        owner.close()
                with self.assertRaises(owned.OwnedFileCloseUnconfirmed):
                    owner.close()
                close.assert_called_once_with(987)
                self.assertEqual(owner.handle, 987)
                self.assertFalse(owner.cleanup_evidence["retry_allowed"])

    def test_file_identity_and_disposition_cannot_return_success_when_close_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "retained-user-data.bin"
            source.write_bytes(b"ACTUAL SOURCE MUST REMAIN UNCHANGED BY POLICY FIXTURE")
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            platform = SimpleNamespace(name="nt", path=os.path)
            root_identity = {"identity": ["WIN32_FILE_ID", 1, 2], "final_path": str(root), "directory": True}
            for operation in ("identity", "remove"):
                with self.subTest(operation=operation):
                    owner = self.opened(Mock(return_value=False))
                    owner.final = os.path.normcase(os.path.normpath(str(source)))
                    owner.remove = Mock()  # No actual Windows disposition/erase is simulated as proof.
                    with patch.object(owned, "os", platform), \
                         patch.object(owned, "checked", side_effect=lambda path: path), \
                         patch.object(owned, "WindowsFile", return_value=owner), \
                         patch.object(owned.C, "get_last_error", return_value=5, create=True):
                        with self.assertRaises(owned.OwnedFileCloseUnconfirmed) as failure:
                            if operation == "identity":
                                owned.file_identity(source)
                            else:
                                with patch.object(owned, "file_identity", return_value=root_identity):
                                    owned.remove_entry(root, source.name,
                                        {"identity": owner.identity, "directory": False}, root_identity)
                    self.assertIs(failure.exception.owner, owner)
                    self.assertFalse(failure.exception.cleanup["confirmed"])
                    self.assertEqual(owner.handle, 987)
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
