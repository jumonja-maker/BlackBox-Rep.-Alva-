"""Trace cleanup consumers, using real disposable recording databases.

The trace journals and raw bytes below are TEST ONLY fixtures; no native trace
process is started. Application/test execution belongs on hosted CI.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
import zipfile

from blackbox_core.casebook import CaseBook, export_case, verify_package
from blackbox_core.contracts import Sample
from blackbox_core.library_catalog import LibraryCatalog, recording_metadata
from blackbox_core import retention_delete
from blackbox_core.storage import SessionStore


class TraceConsumerAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "library"
        self.root.mkdir()
        self.catalog = LibraryCatalog(self.root)

    def recording(self):
        store = SessionStore(self.root, 123, started_with="TEST_ONLY_TRACE_CONSUMER")
        try:
            store.write_sample(Sample(0, 100, None, 1, 0, 0, 0))
            folder = store.folder
            book = CaseBook(folder, 123, 1.0, {
                "scenario": "Trace consumer audit", "profile": "STANDARD",
                "interval_ms": 2000,
            })
            try:
                book.put("TEST_ONLY_FIXTURE", {"native_capture_started": False})
            finally:
                book.close("COMPLETED")
            store.finish("COMPLETED")
        finally:
            store.close()
        row = self.catalog.record_owned(folder, recording_metadata(folder), finalized=True)
        self.assertEqual(row["origin"], "LOCAL_APP_MARKED")
        self.assertEqual(row["state"], "COMPLETED")
        return folder, row

    def trace(self, folder, kind, state, *, proven):
        artifacts = folder / "artifacts"
        artifacts.mkdir(exist_ok=True)
        data = {"state": state, "consent": "EXPLICIT_USER_COMMAND",
                "capture_complete": state == "COMPLETED"}
        if kind == "WPR":
            data["instance"] = "BLACKBOX_" + uuid4().hex
            name = data["instance"] + ".trace.json"
            proof = {"confirmed": True, "scope": "EXACT_NAMED_WPR_INSTANCE",
                     "instance": data["instance"]}
        else:
            data["uid"] = uuid4().hex
            name = "EVENTPIPE_" + data["uid"] + ".trace.json"
            proof = {"confirmed": True,
                     "scope": "EXACT_OWNED_EVENTPIPE_PROCESS_BOUNDARY", "uid": data["uid"]}
        if proven:
            data["resource_cleanup"] = proof
        journal = artifacts / name
        self.write_journal(journal, data)
        # This sorts before the journal during deletion, so a later journal
        # failure leaves a genuinely partially deleted payload to resume.
        raw = artifacts / "zzzz-trace-payload.bin"
        raw.write_bytes(b"TEST_ONLY_RAW_TRACE_BYTES")
        return journal, raw, data, proof

    @staticmethod
    def write_journal(path, data):
        # Rewrite the existing file in place: resume must recheck content even
        # when the original inventory still recognizes the same native file ID.
        path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    def move_to_trash(self, row):
        plan = self.catalog.plan_trash([row["entry_id"]])
        result = self.catalog.apply_trash(plan["confirmation_token"])
        self.assertEqual(result["results"][0]["status"], "MOVED_TO_TRASH")
        trashed = self.catalog.entry(row["entry_id"])
        self.assertEqual(trashed["state"], "TRASH")
        return Path(trashed["folder"])

    def assert_export_and_trash_refuse(self, folder, row, journal):
        original = {p.name: p.read_bytes() for p in folder.glob("*.sqlite3")}
        journal_bytes = journal.read_bytes()
        destination = Path(self.temp.name) / (uuid4().hex + ".zip")
        with self.assertRaisesRegex(ValueError, "STOP_TRACE_BEFORE_SENSITIVE_EXPORT"):
            export_case(folder, destination, include_sensitive=True)
        with self.assertRaisesRegex(ValueError, "LIBRARY_TRACE_STILL_ACTIVE"):
            self.catalog.plan_trash([row["entry_id"]])
        self.assertFalse(destination.exists())
        self.assertTrue(folder.is_dir())
        self.assertEqual(journal.read_bytes(), journal_bytes)
        self.assertEqual({p.name: p.read_bytes() for p in folder.glob("*.sqlite3")}, original)
        self.assertEqual(self.catalog.entry(row["entry_id"])["state"], "COMPLETED")

    def test_state_only_failed_and_completed_traces_do_not_authorize_any_consumer(self):
        for kind in ("WPR", "EVENTPIPE"):
            for state in ("FAILED", "COMPLETED"):
                with self.subTest(kind=kind, state=state):
                    folder, row = self.recording()
                    journal, raw, data, proof = self.trace(folder, kind, state, proven=False)
                    self.assert_export_and_trash_refuse(folder, row, journal)
                    self.assertEqual(raw.read_bytes(), b"TEST_ONLY_RAW_TRACE_BYTES")

                    # Trash can only be entered after a separate exact proof;
                    # losing it afterward must still prevent permanent purge.
                    known = dict(data, resource_cleanup=proof)
                    self.write_journal(journal, known)
                    payload = self.move_to_trash(row)
                    surviving = payload / "artifacts" / journal.name
                    self.write_journal(surviving, data)
                    with patch("blackbox_core.retention_delete.remove_entry") as unlink:
                        with self.assertRaisesRegex(ValueError, "LIBRARY_TRACE_STILL_ACTIVE"):
                            self.catalog.plan_purge([row["entry_id"]])
                        unlink.assert_not_called()
                    self.assertEqual(self.catalog.entry(row["entry_id"])["state"], "TRASH")
                    self.assertTrue((payload / "session.sqlite3").is_file())
                    self.assertEqual(surviving.read_text(encoding="utf-8"),
                                     json.dumps(data, sort_keys=True))

    def test_exact_cleanup_proofs_allow_sensitive_export_trash_and_purge(self):
        keep = self.root / "KEEP_UNRELATED.bin"
        keep.write_bytes(b"KEEP")
        for kind in ("WPR", "EVENTPIPE"):
            for state in ("FAILED", "COMPLETED"):
                with self.subTest(kind=kind, state=state):
                    folder, row = self.recording()
                    journal, raw, _, _ = self.trace(folder, kind, state, proven=True)
                    journal_bytes, raw_bytes = journal.read_bytes(), raw.read_bytes()
                    destination = Path(self.temp.name) / (uuid4().hex + ".zip")
                    result = export_case(folder, destination, include_sensitive=True)
                    self.assertTrue(result["manifest"]["sensitive_artifacts_included"])
                    self.assertEqual(verify_package(destination)["integrity"], "VERIFIED")
                    with zipfile.ZipFile(destination) as package:
                        self.assertEqual(package.read("artifacts/" + journal.name), journal_bytes)
                        self.assertEqual(package.read("artifacts/" + raw.name), raw_bytes)
                    self.assertEqual(journal.read_bytes(), journal_bytes)
                    self.assertEqual(raw.read_bytes(), raw_bytes)
                    payload = self.move_to_trash(row)
                    plan = self.catalog.plan_purge([row["entry_id"]])
                    result = self.catalog.apply_purge(plan["confirmation_token"])
                    self.assertEqual(result["results"][0]["status"], "PURGED")
                    self.assertFalse(payload.exists())
                    self.assertEqual(keep.read_bytes(), b"KEEP")

    def test_exact_cleanup_proof_for_another_journal_basename_is_refused(self):
        for kind in ("WPR", "EVENTPIPE"):
            with self.subTest(kind=kind):
                folder, row = self.recording()
                journal, _, _, _ = self.trace(folder, kind, "COMPLETED", proven=True)
                foreign_name = (("BLACKBOX_" if kind == "WPR" else "EVENTPIPE_") +
                                uuid4().hex + ".trace.json")
                foreign = journal.with_name(foreign_name)
                journal.rename(foreign)
                self.assert_export_and_trash_refuse(folder, row, foreign)

                foreign.rename(journal)
                payload = self.move_to_trash(row)
                (payload / "artifacts" / journal.name).rename(payload / "artifacts" / foreign_name)
                with self.assertRaisesRegex(ValueError, "LIBRARY_TRACE_STILL_ACTIVE"):
                    self.catalog.plan_purge([row["entry_id"]])
                self.assertTrue((payload / "session.sqlite3").is_file())

    def test_resumed_purge_revalidates_changed_trace_before_review_and_before_unlink(self):
        for kind in ("WPR", "EVENTPIPE"):
            for state in ("FAILED", "COMPLETED"):
                with self.subTest(kind=kind, state=state):
                    folder, row = self.recording()
                    journal, raw, known, _ = self.trace(folder, kind, state, proven=True)
                    payload = self.move_to_trash(row)
                    journal = payload / "artifacts" / journal.name
                    raw = payload / "artifacts" / raw.name
                    plan = self.catalog.plan_purge([row["entry_id"]])
                    real_unlink = retention_delete.remove_entry

                    def interrupt_at_journal(root, relative, expected, root_expected):
                        if relative == "artifacts/" + journal.name:
                            raise OSError("TEST_ONLY_INTERRUPTED_AT_TRACE_JOURNAL")
                        return real_unlink(root, relative, expected, root_expected)

                    with patch("blackbox_core.retention_delete.remove_entry",
                               side_effect=interrupt_at_journal):
                        result = self.catalog.apply_purge(plan["confirmation_token"])
                    self.assertEqual(result["results"][0]["status"], "PURGE_PARTIAL")
                    self.assertFalse(raw.exists())
                    self.assertTrue(journal.is_file())
                    self.assertTrue((payload / "session.sqlite3").is_file())
                    manifest = payload.parent / "purge-manifest.json"
                    original_manifest = manifest.read_bytes()

                    unknown = deepcopy(known)
                    unknown.pop("resource_cleanup")
                    self.write_journal(journal, unknown)
                    with patch("blackbox_core.retention_delete.remove_entry") as unlink:
                        with self.assertRaisesRegex(ValueError, "LIBRARY_TRACE_STILL_ACTIVE"):
                            self.catalog.plan_purge([row["entry_id"]])
                        unlink.assert_not_called()
                    self.assertEqual(manifest.read_bytes(), original_manifest)

                    self.write_journal(journal, known)
                    resumed = self.catalog.plan_purge([row["entry_id"]])
                    self.write_journal(journal, unknown)
                    with patch("blackbox_core.retention_delete.remove_entry") as unlink:
                        with self.assertRaisesRegex(ValueError, "LIBRARY_TRACE_STILL_ACTIVE"):
                            self.catalog.apply_purge(resumed["confirmation_token"])
                        unlink.assert_not_called()
                    self.assertEqual(self.catalog.entry(row["entry_id"])["state"], "PURGE_PARTIAL")
                    self.assertTrue((payload / "session.sqlite3").is_file())
                    self.assertEqual(journal.read_text(encoding="utf-8"),
                                     json.dumps(unknown, sort_keys=True))

                    # A fresh exact proof and fresh explicit review can finish
                    # the same interrupted payload; refusal does not destroy it.
                    self.write_journal(journal, known)
                    fresh = self.catalog.plan_purge([row["entry_id"]])
                    result = self.catalog.apply_purge(fresh["confirmation_token"])
                    self.assertEqual(result["results"][0]["status"], "PURGED")
                    self.assertFalse(payload.exists())

    def test_sensitive_export_cancels_between_trace_journals_before_staging(self):
        folder, _ = self.recording()
        self.trace(folder, "WPR", "COMPLETED", proven=True)
        self.trace(folder, "EVENTPIPE", "FAILED", proven=True)
        destination = Path(self.temp.name) / "cancelled.zip"
        checkpoints = []

        def cancel():
            checkpoints.append(True)
            # Initial request check, first journal, then second journal.
            return len(checkpoints) >= 3

        with patch("blackbox_core.export_recovery.export_stage") as stage:
            with self.assertRaises(InterruptedError):
                export_case(folder, destination, include_sensitive=True, cancel=cancel)
            stage.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(len(list((folder / "artifacts").glob("*.trace.json"))), 2)
        self.assertTrue((folder / "session.sqlite3").is_file())

    def test_sensitive_export_refuses_trace_journal_overflow_before_staging(self):
        folder, _ = self.recording()
        for _ in range(65):
            self.trace(folder, "WPR", "COMPLETED", proven=True)
        destination = Path(self.temp.name) / "too-many-traces.zip"
        with patch("blackbox_core.export_recovery.export_stage") as stage:
            with self.assertRaisesRegex(ValueError, "TRACE_JOURNAL_EXPORT_BUDGET"):
                export_case(folder, destination, include_sensitive=True)
            stage.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(len(list((folder / "artifacts").glob("*.trace.json"))), 65)
        self.assertTrue((folder / "session.sqlite3").is_file())


if __name__ == "__main__":
    unittest.main()
