"""BB-DEEP-001 contracts and durable evidence; executed only by hosted CI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from blackbox_core.deep_contracts import ActionRequest, ProcessIdentity, canonical_operation
from blackbox_core.deep_helper import validate_parameters
from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core.deep_service import InspectorService, verify_helper_hello


class DeepContractsTests(unittest.TestCase):
    def test_exact_identity_and_typed_scope(self):
        identity = ProcessIdentity(42, 133000000000000001, "example.exe")
        self.assertEqual(ProcessIdentity.from_dict(identity.to_dict()), identity)
        self.assertEqual(canonical_operation("memory_restore"), "memory.rollback")
        for pid, created in ((True, 1), (0, 1), (42, True), (42, 0), (42, 2**64)):
            with self.subTest(pid=pid, created=created), self.assertRaises(ValueError):
                ProcessIdentity(pid, created)
        for timeout in (True, 0, -1, float("nan"), float("inf"), 121):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                ActionRequest("snapshot", identity, timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            ActionRequest("execute_shell", identity, {"command": "anything"})
        with self.assertRaises(ValueError):
            ActionRequest("memory.write", identity, {"_confirmed": True})

    def test_native_handles_and_arbitrary_commands_never_cross_public_boundary(self):
        for key in ("file_handle", "handle", "recovery_handle", "source_file_handle", "command", "shell", "argv"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_parameters({key: 123})

    def test_hello_requires_nonce_exact_instance_and_expected_image(self):
        executable = str(Path(__file__).resolve())
        identity = ProcessIdentity(42, 133000000000000001, executable)
        nonce = "ab" * 32
        hello = {"kind": "hello", "protocol": 1, "nonce": nonce, "identity": identity.to_dict()}
        verify_helper_hello(hello, nonce, identity, executable)
        invalid = [dict(hello, nonce="cd" * 32), dict(hello, protocol=2),
                   dict(hello, identity=ProcessIdentity(43, identity.created_100ns, executable).to_dict()),
                   dict(hello, identity=ProcessIdentity(42, identity.created_100ns + 1, executable).to_dict())]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises((PermissionError, ValueError)):
                verify_helper_hello(item, nonce, identity, executable)
        with self.assertRaises(PermissionError):
            verify_helper_hello(hello, nonce, identity, executable + ".different")


class DeepJournalTests(unittest.TestCase):
    def test_sensitive_payloads_removed_and_windows_connections_released(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            journal = EvidenceJournal(directory / "evidence")
            secret = "BB_DEEP_PRIVATE_MEMORY_SENTINEL_95a1"
            journal.append({"operation_id": "one", "parameters": {"value_hex": secret},
                            "data": {"payload": secret, "command_line": ["tool", secret]},
                            "before": {"original_bytes": secret}, "status": "COMPLETED"})
            path = journal.export(directory / "safe.jsonl")
            self.assertNotIn(secret, path.read_text())
            self.assertNotIn(secret.encode(), journal.path.read_bytes())
            self.assertEqual(journal.timeline()[0]["status"], "COMPLETED")
            renamed = journal.path.with_suffix(".closed")
            journal.path.rename(renamed)  # Windows catches any leaked SQLite connection here.
            renamed.unlink()

    def test_atomic_no_clobber_and_tampering_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = EvidenceJournal(root / "evidence")
            journal.append({"operation_id": "one", "status": "COMPLETED"})
            target = root / "existing.jsonl"
            target.write_text("unchanged")
            with self.assertRaises(FileExistsError):
                journal.export(target)
            self.assertEqual(target.read_text(), "unchanged")
            connection = sqlite3.connect(journal.path)
            try:
                connection.execute("UPDATE actions SET record_json='{}'")
                connection.commit()
            finally:
                connection.close()
            rejected = root / "tampered.jsonl"
            with self.assertRaisesRegex(ValueError, "HASH_CHAIN"):
                journal.export(rejected)
            self.assertFalse(rejected.exists())
            self.assertFalse(list(root.glob(".blackbox-deep-export-*")))

    def test_before_after_rejects_different_process_lifetimes(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = EvidenceJournal(temporary)
            first = ProcessIdentity(42, 100).to_dict()
            before = journal.snapshot(first, {"threads": 2})
            after = journal.snapshot(first, {"threads": 3})
            compared = journal.compare(before, after)
            self.assertEqual(compared["before"], {"threads": 2})
            self.assertEqual(compared["after"], {"threads": 3})
            self.assertEqual(compared["interpretation"], "OBSERVED_DIFFERENCE_NOT_CAUSAL_PROOF")
            reused = journal.snapshot(ProcessIdentity(42, 101).to_dict(), {"threads": 3})
            with self.assertRaisesRegex(ValueError, "IDENTITY_MISMATCH"):
                journal.compare(before, reused)


class DeepServiceIntentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.service = InspectorService(Path(self.temporary.name) / "journal")
        self.identity = ProcessIdentity(42, 133000000000000001, "controlled.exe")

    def test_confirmation_required_without_launch(self):
        with patch.object(self.service.broker, "launch") as launch:
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": "01", "value_hex": "02"}))
        self.assertEqual(answer["status"], "CONFIRMATION_REQUIRED")
        launch.assert_not_called()

    def test_failed_intent_prevents_any_helper_operation(self):
        with patch.object(self.service.journal, "append", side_effect=OSError("disk full")), \
                patch.object(self.service, "_ensure_session") as ensure:
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": "01", "value_hex": "02"}, True))
        self.assertEqual(answer["status"], "OPERATION_FAILED")
        self.assertIn("DURABLE_INTENT_FAILED", answer["error"])
        ensure.assert_not_called()

    def test_pre_cancelled_request_returns_typed_status_without_launch(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(self.service, "_ensure_session") as ensure:
            answer = self.service.execute(ActionRequest("snapshot", self.identity), cancel_event=cancelled)
        self.assertEqual(answer["status"], "CANCELLED")
        ensure.assert_not_called()
        self.assertEqual(self.service.journal.timeline()[0]["status"], "CANCELLED")

    def test_timeline_results_do_not_recursively_embed_journal(self):
        for _ in range(20):
            answer = self.service.execute(ActionRequest("timeline", self.identity))
            self.assertEqual(answer["status"], "COMPLETED")
        latest = self.service.journal.timeline()[0]
        self.assertNotIn("entries", latest["data"])
        self.assertIn("returned_entries", latest["data"])

    def test_native_mutation_follows_durable_intent_and_result_failure_is_unconfirmed(self):
        sent = []
        class Channel:
            def send(inner, message, **kwargs):
                entries = self.service.journal.timeline()
                self.assertEqual(entries[0]["phase"], "REQUESTED")
                sent.append(message)

            def receive(inner, **kwargs):
                return {"kind": "result", "request_id": sent[-1]["request_id"],
                        "result": {"status": "COMPLETED", "data": {}, "limitations": []}}
        self.service._channel = Channel()
        fake_os = types.SimpleNamespace(name="nt", path=os.path, getpid=os.getpid)
        original = self.service.journal.append
        count = [0]
        def append(record):
            count[0] += 1
            if count[0] == 2:
                raise OSError("result disk full")
            return original(record)
        with patch("blackbox_core.deep_service.os", fake_os), \
                patch.object(self.service, "_ensure_session", return_value=None), \
                patch.object(self.service.journal, "append", side_effect=append):
            answer = self.service.execute(ActionRequest("memory.write", self.identity,
                                                       {"address": 4096, "expected_hex": "01", "value_hex": "02"}, True))
        self.assertEqual(len(sent), 1)
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("RESULT_JOURNAL_COMMIT_FAILED", answer["error"])


if __name__ == "__main__":
    unittest.main()
