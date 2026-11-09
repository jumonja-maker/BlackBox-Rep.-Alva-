"""Imported identity/clock and recovery ownership stay bounded and explicit.

Fixtures are synthetic files. These tests run only in the hosted workflows;
they make no claim about physical Windows or authenticated import provenance.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from blackbox_core.casebook import context
from blackbox_core.contracts import Sample
from blackbox_core.export_recovery import ExportTransaction, owner_alive, recover_export
from blackbox_core.library_catalog import LibraryCatalog, recording_metadata
from blackbox_core.library_files import atomic_json
from blackbox_core.retention_delete import _alive
from blackbox_core.session_v2 import FILENAME, SessionV2Writer
from blackbox_core.session_view import SessionReadError, SessionView, _validated_session_clock
from blackbox_core.storage import SessionStore


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def v2_fixture(folder):
    from test_investigation_v2 import observation, ORIGIN
    folder.mkdir()
    owner = SessionV2Writer(folder, pid=123, created=1.0, name="TEST_ONLY_ROOT", origin_ns=ORIGIN)
    try:
        owner.submit("detail", observation(1))
        owner.submit("detail", observation(2))
        owner.finish("COMPLETED", timeout=60)
    finally:
        if owner.thread.is_alive():
            owner.thread.join(timeout=10)
        if owner.thread.is_alive():
            raise AssertionError("FIXTURE_V2_WRITER_NOT_CLOSED")
    return folder / FILENAME


class ImportedSessionScopeTests(unittest.TestCase):
    def assert_rejected_unchanged(self, folder, reason):
        source = folder / FILENAME
        before = digest(source)
        with self.assertRaisesRegex(SessionReadError, reason):
            with SessionView.open(folder):
                self.fail("invalid imported session opened")
        self.assertEqual(digest(source), before)

    def test_target_cannot_relabel_another_instances_root_counters(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "recording"
            source = v2_fixture(folder)
            with closing(sqlite3.connect(source)) as db:
                db.execute("""INSERT INTO process_instances(instance_id,pid,creation_time,parent_pid,
                    executable_name,first_observed_ns,last_observed_ns,source_kind)
                    VALUES(2,456,2.0,123,'TEST_ONLY_OTHER',1000000000,3000000000,'TEST_ONLY')""")
                db.execute("UPDATE targets SET root_pid=456,root_creation_time=2.0")
                db.commit()
            self.assert_rejected_unchanged(folder, "INVALID_SCHEMA2_ROOT_INSTANCE")

    def test_missing_target_instance_fails_with_the_same_stable_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "recording"
            source = v2_fixture(folder)
            with closing(sqlite3.connect(source)) as db:
                db.execute("UPDATE targets SET root_pid=999")
                db.commit()
            self.assert_rejected_unchanged(folder, "INVALID_SCHEMA2_ROOT_INSTANCE")

    def test_invalid_recorded_clock_fields_are_rejected_without_repairing_source(self):
        faults = (("anchor_utc_ns", "bad-import"), ("anchor_monotonic_ns", float("inf")),
                  ("monotonic_origin_ns", -1), ("started_utc_ns", -1),
                  ("anchor_uncertainty_ns", -1), ("monotonic_resolution_ns", 0),
                  ("ended_monotonic_ns", 0), ("clock_source", ""))
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "recording"
            source = v2_fixture(folder)
            for field, value in faults:
                with self.subTest(field=field):
                    with closing(sqlite3.connect(source)) as db:
                        original = db.execute("SELECT " + field + " FROM sessions").fetchone()[0]
                        db.execute("UPDATE sessions SET " + field + "=?", (value,))
                        db.commit()
                    self.assert_rejected_unchanged(folder, "INVALID_IMPORTED_SESSION_CLOCK")
                    with closing(sqlite3.connect(source)) as db:
                        db.execute("UPDATE sessions SET " + field + "=?", (original,))
                        db.commit()

    def test_zero_epoch_origin_and_uncertainty_are_preserved_as_known(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "recording"
            source = v2_fixture(folder)
            with closing(sqlite3.connect(source)) as db:
                for field in ("started_utc_ns", "monotonic_origin_ns", "anchor_monotonic_ns",
                              "anchor_utc_ns", "anchor_uncertainty_ns"):
                    db.execute("UPDATE sessions SET " + field + "=0")
                db.commit()
            before = digest(source)
            with SessionView.open(folder) as view:
                self.assertEqual(view.reader.root_instance, 1)
                self.assertEqual(view.metadata["anchor_utc_ns"], 0)
                self.assertEqual(view.metadata["monotonic_origin_ns"], 0)
                self.assertEqual(view.interval(series="DETAILED")["coverage"]["selected_samples"], 2)
            self.assertEqual(digest(source), before)

    def test_clock_scalar_validator_does_not_coerce_boolean_or_missing_fields(self):
        baseline = dict(started_utc_ns=0, monotonic_origin_ns=0, anchor_monotonic_ns=0,
                        anchor_utc_ns=0, anchor_uncertainty_ns=0, monotonic_resolution_ns=1,
                        ended_monotonic_ns=None, clock_source="TEST_ONLY_RECORDED_CLOCK")
        _validated_session_clock(baseline)
        for field in ("started_utc_ns", "monotonic_origin_ns", "anchor_monotonic_ns",
                      "anchor_utc_ns", "anchor_uncertainty_ns", "monotonic_resolution_ns"):
            for value in (None, False, True, float("nan"), float("inf"), "0"):
                candidate = {**baseline, field: value}
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                        SessionReadError, "INVALID_IMPORTED_SESSION_CLOCK"):
                    _validated_session_clock(candidate)
            missing = deepcopy(baseline)
            missing.pop(field)
            with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_SESSION_CLOCK"):
                _validated_session_clock(missing)

    def test_schema1_cannot_present_root_samples_as_a_child_or_detailed_series(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp), 123, started_with="TEST_ONLY_LEGACY")
            folder = store.folder
            try:
                store.write_sample(Sample(0, 0, 0.0, 1, 0, 0, 0))
                store.write_sample(Sample(1000, 100, 25.0, 1, 10, 0, 0))
                store.finish("COMPLETED")
            finally:
                store.close()
            before = digest(folder / "session.sqlite3")
            with SessionView.open(folder) as view:
                for instance in (7, 0, True):
                    for read in (lambda: view.bounds(instance_id=instance),
                                 lambda: view.interval(instance_id=instance),
                                 lambda: view.thread_summary(instance_id=instance),
                                 lambda: list(view.reader.iter_samples(0, 10**9, instance_id=instance))):
                        with self.subTest(instance=instance), self.assertRaisesRegex(
                                SessionReadError, "LEGACY_PROCESS_INSTANCE_UNSUPPORTED"):
                            read()
                with self.assertRaisesRegex(SessionReadError, "LEGACY_SERIES_UNSUPPORTED"):
                    view.interval(series="DETAILED")
                self.assertEqual(view.interval()["coverage"]["selected_samples"], 2)
                self.assertEqual(view.interval()["metrics"]["rss_bytes"]["min"], 0)
            self.assertEqual(digest(folder / "session.sqlite3"), before)


class RecoveryOwnershipTests(unittest.TestCase):
    def test_only_nonexistent_pid_or_valid_different_birth_releases_original_owner(self):
        import psutil
        data = {"owner_pid": 123, "owner_created": 2.0}
        for check in (owner_alive, _alive):
            with self.subTest(check=check.__name__):
                with patch("psutil.Process", return_value=SimpleNamespace(create_time=lambda: 2.0)):
                    self.assertTrue(check(data))
                    for created in (None, False, True, 0, -1, "2", float("nan"), float("inf"), 10**330):
                        self.assertTrue(check({**data, "owner_created": created}))
                    self.assertTrue(check({"owner_pid": 123}))
                    self.assertTrue(check({}))
                    self.assertFalse(check({**data, "owner_created": 3.0}))
                for actual in (float("nan"), float("inf"), 10**330):
                    with patch("psutil.Process", return_value=SimpleNamespace(create_time=lambda: actual)):
                        self.assertTrue(check(data))
                with patch("psutil.Process", side_effect=psutil.NoSuchProcess(123)):
                    self.assertFalse(check(data))
                    self.assertFalse(check({**data, "owner_created": 10**330}))
                with patch("psutil.Process", side_effect=psutil.AccessDenied(123)):
                    self.assertTrue(check(data))

    def test_active_export_with_missing_birth_never_starts_publication_or_deletion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "KEEP.txt").write_text("USER FILE", encoding="utf-8")
            tx = ExportTransaction(root, kind="TEST_ONLY_OWNERSHIP")
            staged = tx.reserve("original.txt")
            staged.write_text("STAGED BY LIVE OWNER", encoding="utf-8")
            tx.prepare({"published.txt": staged})
            journal = json.loads(tx.journal.read_text(encoding="utf-8"))
            journal.pop("owner_created")
            tx.journal.write_text(json.dumps(journal), encoding="utf-8")
            before = digest(tx.journal), digest(staged)
            try:
                for action in ("FINISH", "DISCARD"):
                    with patch.object(ExportTransaction, "publish", side_effect=AssertionError("must not publish")), \
                         patch.object(ExportTransaction, "abort", side_effect=AssertionError("must not delete")):
                        with self.assertRaisesRegex(ValueError, "EXPORT_RECOVERY_OWNER_ACTIVE"):
                            recover_export(tx.journal, action=action, confirmed=True)
                    self.assertEqual((digest(tx.journal), digest(staged)), before)
                    self.assertFalse((root / "published.txt").exists())
                self.assertEqual((root / "KEEP.txt").read_text(encoding="utf-8"), "USER FILE")
            finally:
                tx.abort()

    def test_unknown_purge_owner_blocks_new_review_and_existing_consent_before_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            catalog = LibraryCatalog(root)
            store = SessionStore(root, 123, started_with="TEST_ONLY_PURGE_OWNER")
            folder = store.folder
            try:
                store.write_sample(Sample(0, 0, 0.0, 1, 0, 0, 0))
                store.finish("COMPLETED")
            finally:
                store.close()
            entry = catalog.record_owned(folder, recording_metadata(folder), finalized=True)
            catalog.apply_trash(catalog.plan_trash([entry["entry_id"]])["confirmation_token"])
            plan = catalog.plan_purge([entry["entry_id"]])
            payload = Path(catalog.entry(entry["entry_id"])["folder"])
            journal = payload.parent / "purge-state.json"
            atomic_json(journal, {"state": "PURGING", "owner_pid": os.getpid(), "owner_created": None})
            before = digest(journal), digest(payload / "session.sqlite3")
            with patch("blackbox_core.retention_delete.inventory", side_effect=AssertionError("owner is unknown")), \
                 patch("blackbox_core.retention_delete.remove_entry", side_effect=AssertionError("must not delete")):
                with self.assertRaisesRegex(ValueError, "PURGE_OWNER_STILL_ACTIVE"):
                    catalog.plan_purge([entry["entry_id"]])
                with self.assertRaisesRegex(ValueError, "PURGE_OWNER_STILL_ACTIVE"):
                    catalog.apply_purge(plan["confirmation_token"])
            self.assertEqual((digest(journal), digest(payload / "session.sqlite3")), before)
            self.assertEqual(catalog.entry(entry["entry_id"])["state"], "TRASH")


class ImportedContextBudgetTests(unittest.TestCase):
    def source(self, folder, rows):
        path = folder / "research.sqlite3"
        with closing(sqlite3.connect(path)) as db:
            # An imported file need not retain the native UNIQUE constraint.
            db.execute("CREATE TABLE context(key TEXT,data TEXT)")
            db.executemany("INSERT INTO context VALUES(?,?)", rows)
            db.commit()
        return path

    def rejected(self, rows, reason):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = self.source(folder, rows)
            before = digest(source)
            with self.assertRaisesRegex(ValueError, reason):
                context(folder)
            self.assertEqual(digest(source), before)

    def test_context_rejects_aggregate_row_value_and_byte_overflow(self):
        self.rejected([(str(index), "0") for index in range(129)], "RESEARCH_CONTEXT_BUDGET_EXCEEDED")
        self.rejected([("large", json.dumps("x" * 65535))], "RESEARCH_CONTEXT_BUDGET_EXCEEDED")
        self.rejected([(str(index), json.dumps("x" * 65534)) for index in range(33)],
                      "RESEARCH_CONTEXT_BUDGET_EXCEEDED")

    def test_context_rejects_duplicate_table_or_nested_json_keys_and_nonfinite_values(self):
        self.rejected([("state", '"COMPLETED"'), ("state", '"RECORDING"')],
                      "INVALID_RESEARCH_CONTEXT_DUPLICATE_KEY")
        self.rejected([("experiment", '{"profile":"STANDARD","profile":"DETAILED"}')],
                      "INVALID_RESEARCH_CONTEXT_DUPLICATE_KEY")
        self.rejected([("experiment", '{"unknown":NaN}')], "INVALID_RESEARCH_CONTEXT_NONFINITE_JSON")

    def test_context_keeps_known_zero_missing_and_unknown_fields_without_source_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = self.source(folder, [("state", '"COMPLETED"'),
                ("experiment", '{"zero":0,"missing":null,"flag":false,"future_field":"kept"}')])
            before = digest(source)
            result = context(folder)
            self.assertEqual(result["experiment"], {"zero": 0, "missing": None, "flag": False,
                                                    "future_field": "kept"})
            self.assertEqual(digest(source), before)


class LibraryEnumerationBudgetTests(unittest.TestCase):
    def test_enumeration_entry_limit_precedes_any_registration_or_cursor_advance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            catalog = LibraryCatalog(root)
            catalog.policy({"days": 0, "max_bytes": 0})
            before = {path.name: digest(path) for path in root.iterdir() if path.is_file()}
            listing = MagicMock()
            listing.__enter__.return_value = (SimpleNamespace(name="session-" + f"{index:032d}")
                                              for index in range(10001))
            with patch("blackbox_core.library_catalog.os.scandir", return_value=listing), \
                 patch.object(catalog, "register", side_effect=AssertionError("must finish enumeration first")):
                with self.assertRaisesRegex(ValueError, "LIBRARY_SCAN_ENUMERATION_BUDGET"):
                    catalog.scan(after="", limit=1)
            self.assertEqual({path.name: digest(path) for path in root.iterdir() if path.is_file()}, before)

    def test_enumeration_deadline_fails_before_registering_a_partial_sorted_page(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog = LibraryCatalog(Path(temp))
            listing = MagicMock()
            listing.__enter__.return_value = iter([SimpleNamespace(name="session-" + "f" * 32),
                                                  SimpleNamespace(name="session-" + "0" * 32)])
            with patch("blackbox_core.library_catalog.os.scandir", return_value=listing), \
                 patch("blackbox_core.library_catalog.time.monotonic", side_effect=[0.0, 0.1, 5.0]), \
                 patch.object(catalog, "register", side_effect=AssertionError("unseen lower names remain")):
                with self.assertRaisesRegex(ValueError, "LIBRARY_SCAN_ENUMERATION_BUDGET"):
                    catalog.scan(after="", limit=1)
            self.assertFalse((Path(temp) / "blackbox-library.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
