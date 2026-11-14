"""Native-adjacent policy fixtures, not Windows/UAC or real CDB evidence."""
from contextlib import closing, contextmanager, ExitStack
import ctypes as C
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core import symbols
from blackbox_core import deep_native as native
from blackbox_core import deep_native_stacks as stacks
from blackbox_core import deep_native_win as W
from blackbox_core import deep_helper as helper
from blackbox_core.deep_contracts import ProcessIdentity


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class EvidenceJournalSchemaBoundaryTests(unittest.TestCase):
    def test_foreign_same_named_database_is_rejected_before_creating_tables(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "deep-inspection.sqlite3"
            with closing(sqlite3.connect(source)) as db:
                db.execute("CREATE TABLE important(value TEXT)")
                db.execute("INSERT INTO important VALUES('KEEP USER DATA')")
                db.commit()
            before = digest(source)
            with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                EvidenceJournal(root)
            self.assertEqual(digest(source), before)
            with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as db:
                self.assertEqual(db.execute("SELECT name FROM sqlite_schema WHERE type='table'").fetchall(),
                                 [("important",)])
                self.assertEqual(db.execute("SELECT value FROM important").fetchone()[0], "KEEP USER DATA")

    def test_incomplete_or_non_database_collision_is_retained_unchanged(self):
        for contents in (b"", b"USER FILE NOT SQLITE"):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temp:
                source = Path(temp) / "deep-inspection.sqlite3"
                source.write_bytes(contents)
                before = digest(source)
                with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                    EvidenceJournal(temp)
                self.assertEqual(digest(source), before)

    def test_valid_legacy_journal_reopens_without_migration_and_retains_records(self):
        with tempfile.TemporaryDirectory() as temp:
            first = EvidenceJournal(temp)
            first.append({"operation_id": "LEGACY_RECORDED_RESULT", "operation": "threads", "status": "COMPLETED"})
            snapshot = first.snapshot({"pid": 123, "created_100ns": 456}, {"observed": 0, "unknown": None})
            with closing(sqlite3.connect(first.path)) as db:
                db.execute("PRAGMA application_id=0")
                db.commit()
            before = digest(first.path)
            second = EvidenceJournal(temp)
            self.assertEqual(digest(second.path), before)
            self.assertEqual(second.timeline()[0]["operation_id"], "LEGACY_RECORDED_RESULT")
            self.assertEqual(second.compare(snapshot, snapshot)["changed_sections"], [])
            second.append({"operation_id": "NEXT_EXPLICIT_RESULT", "operation": "threads", "status": "COMPLETED"})
            self.assertEqual(len(second.timeline()), 2)
            with closing(sqlite3.connect(second.path.as_uri() + "?mode=ro", uri=True)) as db:
                self.assertEqual(db.execute("PRAGMA application_id").fetchone()[0], 0)

    def test_trigger_or_nonreserved_sqlite_prefix_table_cannot_hide_in_recognized_schema(self):
        for sql in ("CREATE TRIGGER suppress BEFORE INSERT ON actions BEGIN SELECT RAISE(IGNORE); END",
                    "CREATE TABLE sqliteXforeign(value TEXT)",
                    "CREATE INDEX foreign_expression ON actions(length(zeroblob(65536)))"):
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as temp:
                journal = EvidenceJournal(temp)
                with closing(sqlite3.connect(journal.path)) as db:
                    db.execute(sql)
                    db.commit()
                before = digest(journal.path)
                with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                    EvidenceJournal(temp)
                with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                    journal.append({"operation_id": "MUST_NOT_EXECUTE_IMPORTED_SCHEMA"})
                self.assertEqual(digest(journal.path), before)

    def test_same_columns_with_foreign_check_constraint_are_refused_without_evaluating_or_writing(self):
        from blackbox_core.deep_journal import _JOURNAL_SQL
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "deep-inspection.sqlite3"
            with closing(sqlite3.connect(source)) as db:
                db.execute(_JOURNAL_SQL["actions"].rstrip().removesuffix(")") +
                           ",CHECK(length(zeroblob(65536))=65536))")
                db.execute(_JOURNAL_SQL["snapshots"])
                db.commit()
            before = digest(source)
            with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                EvidenceJournal(temp)
            self.assertEqual(digest(source), before)

    def test_database_replacement_after_open_is_rejected_before_next_append(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            journal = EvidenceJournal(root)
            foreign = root / "foreign.sqlite3"
            with closing(sqlite3.connect(foreign)) as db:
                db.execute("CREATE TABLE important(value TEXT)")
                db.execute("INSERT INTO important VALUES('KEEP')")
                db.commit()
            os.replace(foreign, journal.path)
            before = digest(journal.path)
            with self.assertRaisesRegex(ValueError, "JOURNAL_UNOWNED_OR_INVALID_SCHEMA"):
                journal.append({"operation_id": "MUST_NOT_MUTATE_REPLACEMENT"})
            self.assertEqual(digest(journal.path), before)


class CdbOutputBudgetTests(unittest.TestCase):
    def execute(self, root, process_factory):
        source = root / "TEST_ONLY_FORMAT_FIXTURE.dmp"
        source.write_bytes(b"TEST ONLY; NO NATIVE DUMP OR DEBUGGER EXECUTION")
        before = digest(source)
        try:
            with patch.object(symbols, "debugger_tool", return_value="TEST_ONLY_CDB"), \
                 patch.object(symbols.subprocess, "Popen", side_effect=process_factory):
                return symbols.inspect_dump(source, root)
        finally:
            self.assertEqual(digest(source), before)

    def test_growing_debugger_log_stops_only_actual_child_and_reports_budget_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            launches = []
            class Process:
                returncode = None
                kills = 0
                def __init__(self, args, **options):
                    self.args, self.log = args, options["stdout"]
                    launches.append(self)
                def poll(self):
                    return self.returncode
                def wait(self, timeout):
                    if self.returncode is not None:
                        return self.returncode
                    self.log.truncate(symbols.MAX_CDB_LOG_BYTES + 1)
                    raise subprocess.TimeoutExpired(self.args, timeout)
                def kill(self):
                    self.kills += 1
                    self.returncode = -9
            with self.assertRaisesRegex(OSError, "STACK_ANALYSIS_OUTPUT_BUDGET_EXCEEDED"):
                self.execute(root, Process)
            self.assertEqual(len(launches), 1)
            self.assertEqual(launches[0].kills, 1)
            self.assertEqual(launches[0].args[-2:], ["-c", ".reload;~* kb;q"])
            output, = root.glob("stacks-*.txt")
            self.assertEqual(output.stat().st_size, symbols.MAX_CDB_LOG_BYTES + 1)

    def test_completed_log_is_checked_and_never_claims_a_hard_filesystem_quota(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            class Process:
                returncode = None
                def __init__(self, args, **options):
                    self.log = options["stdout"]
                def wait(self, timeout):
                    self.log.write(b"TEST_ONLY_DEBUGGER_OUTPUT\n")
                    self.log.flush()
                    self.returncode = 0
                    return 0
                def poll(self):
                    return self.returncode
                def kill(self):
                    raise AssertionError("a completed child must not be killed")
            result = self.execute(root, Process)
            self.assertEqual(result["status"], "DEBUGGER_OUTPUT")
            self.assertFalse(result["root_cause_proven"])
            self.assertEqual(result["output_budget_bytes"], symbols.MAX_CDB_LOG_BYTES)
            self.assertEqual(result["output_budget_enforcement"], "POLLED_SOFT_LIMIT_NOT_FILESYSTEM_QUOTA")


class LiveStackCleanupContractTests(unittest.TestCase):
    def setUp(self):
        self.inspector = native.ProcessInspector(ProcessIdentity(123, 456))

    def owner(self, failing):
        calls = []
        failures = {failing: 1}
        def action(name, success):
            def invoke(*args):
                calls.append(name)
                if failures.get(name, 0):
                    failures[name] -= 1
                    if name == "symbols" and hasattr(C, "set_last_error"):
                        C.set_last_error(0)
                    return False if name == "symbols" else 87
                return success
            return invoke
        images = ExitStack()
        images.callback(lambda: calls.append("images"))
        return {"kernel": SimpleNamespace(current_process=lambda: -1), "clone": 11,
                "initialized": True, "cleanup": action("symbols", True),
                "images": images, "callbacks": (object(),), "marker": 22,
                "marker_free": action("marker", 0), "snapshot": 33,
                "free": action("snapshot", 0)}, calls

    def test_exact_pending_capabilities_retry_in_order_without_double_releasing_acknowledged_ones(self):
        for failing, first in (("symbols", ["symbols"]),
                               ("marker", ["symbols", "images", "marker"]),
                               ("snapshot", ["symbols", "images", "marker", "snapshot"])):
            with self.subTest(failing=failing):
                owner, calls = self.owner(failing)
                inspector = native.ProcessInspector(ProcessIdentity(123, 456))
                with inspector.query_cleanup_scope("thread_stacks") as scope:
                    resource = stacks._track_live_stack_owner(inspector, owner)
                    self.assertFalse(native._close_native_resource(resource))
                result = scope.attach({"status": "OPERATION_FAILED", "data": {}})
                self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
                self.assertTrue(result["data"]["owner_retained"])
                self.assertFalse(result["native_query_cleanup"]["confirmed"])
                self.assertEqual(calls, first)
                with patch.object(inspector, "_modules", side_effect=AssertionError("must not recapture")):
                    with self.assertRaisesRegex(native.NativeError, "PREVIOUS_LIVE_STACK_OWNER"):
                        stacks.collect_stacks(inspector, {}, None, None)
                final = inspector.close()
                self.assertEqual(final["status"], "COMPLETED")
                self.assertTrue(final["data"]["cleanup"]["confirmed"])
                self.assertEqual(inspector._owned_native_handles, [])
                self.assertEqual(calls, first + (["symbols", "images", "marker", "snapshot"] if failing == "symbols"
                    else ["marker", "snapshot"] if failing == "marker" else ["snapshot"]))
                self.assertNotIn("callbacks", owner)

    def test_ambiguous_release_does_not_retry_a_numeric_capability_or_claim_close(self):
        owner, calls = self.owner(None)
        owner["marker_free"] = lambda value: 6
        resource = stacks._track_live_stack_owner(self.inspector, owner)
        self.assertFalse(native._close_native_resource(resource))
        first = list(calls)
        result = self.inspector.close()
        self.assertEqual(result["status"], "RECOVERY_UNCONFIRMED")
        self.assertTrue(result["data"]["owner_retained"])
        self.assertFalse(self.inspector.closed)
        self.assertEqual(calls, first)
        self.assertEqual(owner["snapshot"], 33)

    def test_partial_snapshot_startup_retains_resource_and_refuses_recapture_until_close_ack(self):
        calls = []
        attempts = {"free": 0}
        def capture(process, flags, context, pointer):
            C.cast(pointer, C.POINTER(W.HANDLE))[0] = 33
            calls.append("capture")
            return 0
        def query(*args):
            calls.append("query")
            return 87
        def free(*args):
            calls.append("free")
            attempts["free"] += 1
            return 87 if attempts["free"] == 1 else 0
        def bind(library, name, *signature):
            return {"PssCaptureSnapshot": capture, "PssFreeSnapshot": free,
                    "PssQuerySnapshot": query, "PssWalkMarkerCreate": lambda *args: 0,
                    "PssWalkMarkerFree": lambda *args: 0, "PssWalkSnapshot": lambda *args: 259}[name]
        def wow64(process, machine, native_machine):
            C.cast(native_machine, C.POINTER(W.U16))[0] = 0x8664
            return True
        @contextmanager
        def opened(rights):
            yield SimpleNamespace(dll=object(), wow64=wow64, current_process=lambda: -1), 7
        with patch.object(self.inspector, "_open", side_effect=opened), \
             patch.object(self.inspector, "_modules", return_value={"rows": []}), \
             patch.object(W, "bind", side_effect=bind):
            with self.assertRaisesRegex(native.NativeError, "LIVE_STACK_SNAPSHOT_RELEASE_NOT_ACKNOWLEDGED"):
                stacks.collect_stacks(self.inspector, {}, None, None)
        self.assertEqual(calls, ["capture", "query", "free"])
        self.assertEqual(self.inspector.close()["status"], "COMPLETED")
        self.assertEqual(calls, ["capture", "query", "free", "free"])

    @unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8, "Actual Windows x64 PSS/DbgHelp only")
    def test_real_windows_pss_and_dbghelp_resources_remain_owned_until_explicit_retry(self):
        # Actual self-process snapshot/marker/symbol session; only the first
        # release acknowledgement is withheld. No fake native success fallback.
        kernel = W.Kernel()
        capture = W.bind(kernel.dll, "PssCaptureSnapshot", W.U32, W.HANDLE, W.U32, W.U32, C.POINTER(W.HANDLE))
        query = W.bind(kernel.dll, "PssQuerySnapshot", W.U32, W.HANDLE, W.U32, W.PTR, W.U32)
        free = W.bind(kernel.dll, "PssFreeSnapshot", W.U32, W.HANDLE, W.HANDLE)
        marker_create = W.bind(kernel.dll, "PssWalkMarkerCreate", W.U32, W.PTR, C.POINTER(W.HANDLE))
        marker_free = W.bind(kernel.dll, "PssWalkMarkerFree", W.U32, W.HANDLE)
        inspector = native.ProcessInspector(native.capture_identity(os.getpid()))
        snapshot, clone, marker = W.HANDLE(), W.HANDLE(), W.HANDLE()
        error = capture(kernel.current_process(), 0x1, 0, C.byref(snapshot))
        if error:
            if snapshot:
                self.assertEqual(free(kernel.current_process(), snapshot), 0)
            self.skipTest("Actual hosted PSS capability unavailable: " + str(error))
        owner = {"kernel": kernel, "snapshot": snapshot, "clone": clone, "marker": marker,
                 "free": free, "marker_free": marker_free, "images": ExitStack(), "initialized": False}
        resource = stacks._track_live_stack_owner(inspector, owner)
        try:
            self.assertEqual(query(snapshot, 1, C.byref(clone), C.sizeof(clone)), 0)
            self.assertTrue(clone)
            self.assertEqual(marker_create(None, C.byref(marker)), 0)
            dbg = W.library("dbghelp")
            initialize = W.bind(dbg, "SymInitializeW", W.BOOL, W.HANDLE, C.c_wchar_p, W.BOOL)
            cleanup = W.bind(dbg, "SymCleanup", W.BOOL, W.HANDLE)
            with native._DBGHELP_LOCK:
                self.assertTrue(initialize(clone, "", False))
            attempts = []
            def withheld(handle):
                attempts.append(handle.value)
                if len(attempts) == 1:
                    C.set_last_error(0)
                    return False
                return cleanup(handle)
            owner.update(initialized=True, library=dbg, cleanup=withheld)
            self.assertFalse(native._close_native_resource(resource))
            self.assertTrue(owner["initialized"])
            self.assertTrue(owner["snapshot"])
            self.assertTrue(owner["marker"])
            result = inspector.close()
            self.assertEqual(result["status"], "COMPLETED")
            self.assertTrue(result["data"]["cleanup"]["confirmed"])
            self.assertEqual(attempts, [clone.value, clone.value])
            self.assertIsNone(owner["snapshot"])
            self.assertIsNone(owner["marker"])
        finally:
            # Test failure still releases the original capability, never by PID
            # or an inferred replacement owner.
            owner.pop("release_unconfirmed", None)
            resource["retry_close_allowed"] = True
            inspector.close()


class HelperOutputDuplicateTests(unittest.TestCase):
    def setUp(self):
        self.inspector = native.ProcessInspector(ProcessIdentity(123, 456))
        self.kernel = Mock()
        self.kernel.GetCurrentProcess.return_value = -1
        self.kernel.GetFileType.return_value = 1
        self.kernel.CloseHandle.return_value = True
        def duplicate(parent, source, current, pointer, rights, inherited, options):
            C.cast(pointer, C.POINTER(helper.W.HANDLE))[0] = 88
            return True
        self.kernel.DuplicateHandle.side_effect = duplicate

    def test_actual_duplicate_is_registered_before_validation_and_normal_close_is_acknowledged_once(self):
        def validate(handle):
            self.assertEqual([row["handle"] for row in self.inspector._owned_native_handles], [88])
            return 1
        self.kernel.GetFileType.side_effect = validate
        handle, resource = helper._duplicate_parent_file(self.kernel, 7, 9, owned_inspector=self.inspector)
        self.assertEqual(handle, 88)
        proof = helper._release_output_duplicate(self.inspector, resource)
        self.assertTrue(proof["confirmed"])
        self.assertEqual(self.inspector._owned_native_handles, [])
        self.kernel.CloseHandle.assert_called_once_with(88)

    def test_false_close_retains_exact_duplicate_and_helper_cannot_report_cleanup_confirmed(self):
        self.kernel.CloseHandle.side_effect = [False, True]
        with patch.object(helper.C, "get_last_error", return_value=5, create=True):
            handle, resource = helper._duplicate_parent_file(self.kernel, 7, 9, owned_inspector=self.inspector)
            proof = helper._release_output_duplicate(self.inspector, resource)
        recipient, managed = SimpleNamespace(retained_cleanup=None), SimpleNamespace(cleanup_required=False)
        response = helper._attach_output_cleanup({"status": "COMPLETED", "data": {},
            "native_query_cleanup": {"confirmed": True, "status": "CONFIRMED"}}, proof,
            recipient=recipient, managed=managed)
        self.assertEqual(response["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(response["data"]["reported_operation_status"], "COMPLETED")
        self.assertTrue(response["data"]["owner_retained"])
        self.assertFalse(response["native_query_cleanup"]["confirmed"])
        self.assertIs(recipient.retained_cleanup, response)
        self.assertTrue(managed.cleanup_required)
        self.assertEqual(self.inspector.close()["status"], "COMPLETED")
        self.assertEqual([call.args for call in self.kernel.CloseHandle.call_args_list], [(handle,), (handle,)])

    def test_ambiguous_exception_or_invalid_numeric_handle_is_never_blindly_retried(self):
        for failure in (OSError("TEST_ONLY_CLOSE_ACK_LOST"), 6):
            with self.subTest(failure=failure):
                inspector = native.ProcessInspector(ProcessIdentity(123, 456))
                self.kernel.CloseHandle.reset_mock()
                self.kernel.CloseHandle.side_effect = failure if isinstance(failure, Exception) else None
                self.kernel.CloseHandle.return_value = False
                with patch.object(helper.C, "get_last_error", return_value=6, create=True):
                    handle, resource = helper._duplicate_parent_file(self.kernel, 7, 9, owned_inspector=inspector)
                    proof = helper._release_output_duplicate(inspector, resource)
                self.assertFalse(proof["confirmed"])
                self.assertFalse(proof["retry_allowed"])
                self.assertEqual(inspector.close()["status"], "RECOVERY_UNCONFIRMED")
                self.kernel.CloseHandle.assert_called_once_with(handle)

    def test_partial_output_validation_failure_retains_failed_close_on_original_inspector(self):
        for failure in (3, OSError("TEST_ONLY_FILE_TYPE_QUERY_FAILED")):
            with self.subTest(failure=failure):
                inspector = native.ProcessInspector(ProcessIdentity(123, 456))
                self.kernel.CloseHandle.side_effect = [False, True]
                self.kernel.GetFileType.side_effect = failure if isinstance(failure, Exception) else None
                self.kernel.GetFileType.return_value = 3
                with patch.object(helper.C, "get_last_error", return_value=5, create=True):
                    with self.assertRaises((OSError, ValueError)) as error:
                        helper._duplicate_parent_file(self.kernel, 7, 9, owned_inspector=inspector)
                self.assertFalse(error.exception.borrowed_output_cleanup["confirmed"])
                self.assertEqual(len(inspector._owned_native_handles), 1)
                self.assertEqual(inspector.close()["status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
