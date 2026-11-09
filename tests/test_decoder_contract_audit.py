"""Saved-index/native entry boundary regressions, not capture attestation.

Synthetic records intentionally exercise real index readers and analysis code.
All tests and optional native-host execution run only on hosted runners.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from blackbox_core.decoder_index import GCAdapter, _saved_json, read_index
from blackbox_core.decoder_limits import DecodeBudget, check_json_shape
from blackbox_core.decoder_modules import number
from blackbox_core.decoder_calltree import build_calltree
from blackbox_core.decoder_io import build_disk_io_report, build_file_io_report
from blackbox_core.decoder_waits import build_wait_report
from test_decoder_modules import native_row, write_index


class DecoderContractAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_huge_numbers_nonfinite_exponents_and_malformed_semantics_are_rejected(self):
        from blackbox_universal.decoder_index_navigation import navigation_filters
        from blackbox_core.decoder_io import _number as io_number
        from blackbox_core.decoder_waits import _number as wait_number
        huge = 10**330
        self.assertFalse(number(huge))
        self.assertFalse(io_number(huge))
        self.assertFalse(wait_number(huge))
        with self.assertRaises(ValueError):
            DecodeBudget(timeout=huge)
        with self.assertRaises(ValueError):
            navigation_filters(start_ms=huge)
        with self.assertRaisesRegex(ValueError, "NONFINITE"):
            check_json_shape(json.loads('{"nested":[1e999]}'))
        with self.assertRaisesRegex(ValueError, "STRUCTURE_BUDGET"):
            check_json_shape([0] * 20001)
        for semantic in (False, [], "unknown"):
            with self.subTest(semantic=semantic), self.assertRaisesRegex(ValueError, "SEMANTIC"):
                GCAdapter().accept({"semantic": semantic})

    def test_tracerpt_hash_bounds_a_stream_that_grew_after_its_initial_size_check(self):
        from io import BytesIO
        from blackbox_core.trace_decode import file_hash
        source=SimpleNamespace(open=lambda mode:BytesIO(b"growing-source"))
        with patch("blackbox_core.trace_decode.MAX_TRACE_INPUT_BYTES",4):
            with self.assertRaisesRegex(ValueError,"TRACE_DECODE_INPUT_SIZE_LIMIT"):
                file_hash(source)

    def test_cpu_profile_corruption_cannot_be_presented_as_an_ordinary_stack_group(self):
        base, _ = write_index(self.root, [native_row(), native_row(2)])
        original = base.read_bytes()
        for index, (field, value) in enumerate((("sample_count", -1), ("frames_json", "{}"),
                ("frames_json", "[null]"), ("frames_json", '[{"name":"x","address":"0x1","bad":1e999}]'),
                ("frames_without_names", 99), ("signature_sha256", "0" * 64), ("process_instance", -99))):
            path = self.root / f"corrupt-profile-{index}.sqlite3"
            shutil.copyfile(base, path)
            with closing(sqlite3.connect(path)) as db:
                db.execute(f"UPDATE stack_profiles SET {field}=?", (value,))
                db.commit()
            before = path.read_bytes()
            with self.subTest(field=field), self.assertRaises(ValueError):
                read_index(path, mode="cpu_stacks")
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(base.read_bytes(), original)

    def test_native_module_metadata_and_counts_are_checked_against_recorded_identity(self):
        base, _ = write_index(self.root, [native_row()])
        for index, (field, value) in enumerate((("frame_count", 0), ("module_key", "0" * 64),
                                              ("process_instance", 9), ("data", "[]"))):
            path = self.root / f"corrupt-module-{index}.sqlite3"
            shutil.copyfile(base, path)
            with closing(sqlite3.connect(path)) as db:
                db.execute(f"UPDATE trace_modules SET {field}=?", (value,))
                db.commit()
            before = path.read_bytes()
            with self.subTest(field=field), self.assertRaises(ValueError):
                read_index(path, mode="modules")
            self.assertEqual(path.read_bytes(), before)

    def test_gc_profile_corruption_cannot_turn_elapsed_pairs_into_application_pause(self):
        from test_decoder_index import event
        base,_=write_index(self.root,[event(1,"gc_start",stamp=1,generation=2,gc_type="Blocking"),
                                     event(2,"gc_stop",stamp=4)])
        self.assertFalse(read_index(base,mode="gc_summary")["rows"][0]["event"]["is_application_pause"])
        for index,(field,value) in enumerate((("kind","APPLICATION_PAUSE"),("interval_count",-1),
                ("total_duration_ms",1),("max_duration_ms",-1),("first_start_ms",9),
                ("runtime",None),("first_event_id",0))):
            path=self.root/f"corrupt-gc-{index}.sqlite3"
            shutil.copyfile(base,path)
            with closing(sqlite3.connect(path)) as db:
                db.execute(f"UPDATE gc_profiles SET {field}=?",(value,))
                db.commit()
            before=path.read_bytes()
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,"INVALID_INDEX_PROFILE"):
                read_index(path,mode="gc_summary")
            self.assertEqual(path.read_bytes(),before)

    def test_all_analysis_readers_refuse_views_and_nonfinite_saved_summary(self):
        base, _ = write_index(self.root, [native_row()])
        readers = (build_calltree, build_wait_report, build_file_io_report, build_disk_io_report)
        view = self.root / "view.sqlite3"
        shutil.copyfile(base, view)
        with closing(sqlite3.connect(view)) as db:
            db.execute("ALTER TABLE events RENAME TO actual_events")
            db.execute("CREATE VIEW events AS SELECT * FROM actual_events")
            db.commit()
        bad = self.root / "nonfinite.sqlite3"
        shutil.copyfile(base, bad)
        with closing(sqlite3.connect(bad)) as db:
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            summary["untrusted_extra"] = float("inf")
            db.execute("UPDATE metadata SET value=? WHERE key='summary'", (json.dumps(summary),))
            db.commit()
        for path in (view, bad):
            before = path.read_bytes()
            for reader in readers:
                with self.subTest(path=path.name, reader=reader.__name__), self.assertRaises(ValueError):
                    reader(path)
            self.assertEqual(path.read_bytes(), before)

    def test_virtual_tables_with_comments_cannot_masquerade_as_ordinary_index_tables(self):
        from blackbox_core.decoder_index import require_index_tables
        with closing(sqlite3.connect(":memory:")) as db:
            try:
                db.execute("CREATE /* source comment */ VIRTUAL TABLE events USING fts5(data)")
            except sqlite3.OperationalError as error:
                if "no such module" in str(error):
                    self.skipTest("SQLite FTS5 fixture capability unavailable")
                raise
            with self.assertRaisesRegex(ValueError,"INVALID_INDEX_TABLES"):
                require_index_tables(db,("events",))

    def test_calltree_metadata_budget_omits_whole_paths_without_invented_self_samples(self):
        rows = [native_row(index) for index in range(1, 5)]
        for index, row in enumerate(rows):
            row["frames"][0]["unknown_metadata"] = "x" * 6000 + str(index)
        source, _ = write_index(self.root, rows)
        before = source.read_bytes()
        with patch("blackbox_core.decoder_calltree.MAX_TREE_METADATA_BYTES", 1000):
            result = build_calltree(source)
        coverage = result["coverage"]
        self.assertEqual(coverage["samples_selected"], 4)
        self.assertEqual(coverage["samples_omitted_metadata_budget"], 4)
        self.assertEqual(coverage["samples_represented"], 0)
        self.assertEqual(sum(node["self_samples"] for node in result["nodes"]), 0)
        self.assertEqual(coverage["retained_frame_metadata_bytes"], 0)
        self.assertEqual(source.read_bytes(), before)

    def test_imported_lone_surrogate_keeps_exact_json_and_has_a_valid_utf8_html_view(self):
        from blackbox_core.decoder_calltree import calltree_html, export_analysis
        row = native_row()
        row["frames"][0]["name"] = "imported\ud800name"
        source, _ = write_index(self.root, [row])
        result = build_calltree(source)
        target = self.root / "analysis.json"
        export_analysis(result,target)
        decoded = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(decoded,result)
        content = calltree_html(result)
        content.encode("utf-8",errors="strict")
        self.assertIn(r"\ud800",content)

    def test_navigation_copy_never_removes_preexisting_destination_sidecars(self):
        from blackbox_universal.decoder_index_navigation import copy_navigation_index
        source, _ = write_index(self.root, [native_row()])
        before = source.read_bytes()
        for index, suffix in enumerate(("-wal", "-shm", "-journal")):
            output = self.root / f"private-{index}.sqlite3"
            unrelated = Path(str(output)+suffix)
            unrelated.write_bytes(b"preexisting user file")
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "DESTINATION_NOT_NEW"):
                copy_navigation_index(source, output, expected_index_sha256="0" * 64)
            self.assertEqual(unrelated.read_bytes(), b"preexisting user file")
            self.assertFalse(output.exists())
        self.assertEqual(source.read_bytes(), before)

    def test_index_publication_refuses_an_unrelated_sidecar_even_if_it_appears_during_build(self):
        from blackbox_core.decoder_index import build_index
        source,_=write_index(self.root,[native_row()])
        stream=self.root/"index.sqlite3.jsonl"
        before=stream.read_bytes()
        for index,suffix in enumerate(("-wal","-shm","-journal")):
            output=self.root/f"new-index-{index}.sqlite3"
            unrelated=Path(str(output)+suffix)
            def competing_writer():
                unrelated.write_bytes(b"unrelated new auxiliary")
            with self.subTest(suffix=suffix),self.assertRaisesRegex(ValueError,"DESTINATION_MUST_BE_NEW"):
                build_index(stream,output,input_sha256="a"*64,format_name=".etl",before_publish=competing_writer)
            self.assertFalse(output.exists())
            self.assertEqual(unrelated.read_bytes(),b"unrelated new auxiliary")
        self.assertEqual(stream.read_bytes(),before)
        self.assertTrue(source.is_file())
        self.assertEqual(list(self.root.glob(".decoder-building-*")),[])

    def test_index_export_refuses_active_sidecars_and_preserves_existing_outputs(self):
        from blackbox_core.decoder_export import export_index_copy
        source, _ = write_index(self.root, [native_row()])
        before = source.read_bytes()
        wal = Path(str(source)+"-wal")
        wal.write_bytes(b"uncheckpointed journal fixture")
        output = self.root / "copy.sqlite3"
        with self.assertRaisesRegex(ValueError, "SOURCE_NOT_CLOSED"):
            export_index_copy(source, output)
        self.assertFalse(output.exists())
        self.assertEqual(wal.read_bytes(), b"uncheckpointed journal fixture")
        self.assertEqual(source.read_bytes(), before)
        wal.unlink()
        for index,suffix in enumerate(("-wal","-shm","-journal")):
            proposed=self.root/f"export-sidecar-{index}.sqlite3"
            unrelated=Path(str(proposed)+suffix)
            unrelated.write_bytes(b"unrelated destination auxiliary")
            with self.subTest(suffix=suffix),self.assertRaisesRegex(ValueError,"OUTPUT_EXISTS"):
                export_index_copy(source,proposed)
            self.assertFalse(proposed.exists())
            self.assertEqual(unrelated.read_bytes(),b"unrelated destination auxiliary")
        export_index_copy(source, output)
        self.assertEqual(output.read_bytes(), before)
        with self.assertRaises(ValueError):
            export_index_copy(source, output)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".blackbox-index-export-*")), [])

    def test_pdb_kind_basename_and_inline_columns_fail_before_invented_locations(self):
        from blackbox_core.decoder_codeview import _text, inline_ranges
        from blackbox_core.decoder_pdb import IdentityUnavailable, inspect_local_identity
        with patch("blackbox_core.decoder_pdb._local_file", side_effect=AssertionError("unexpected file access")):
            with self.assertRaisesRegex(IdentityUnavailable, "UNSUPPORTED_LOCAL_IDENTITY_KIND"):
                inspect_local_identity("unused", "unknown")
        with self.assertRaisesRegex(IdentityUnavailable, "INVALID_PDB_STRING"):
            _text(b"C:\\private\\\x00", 0, basename=True)
        annotations = bytes((9, 10, 13, 5, 1, 0, 4, 1))
        with self.assertRaisesRegex(IdentityUnavailable, "INVALID_INLINE_SOURCE_COLUMNS"):
            inline_ranges(annotations, procedure_start=100, procedure_end=120,
                          location={"file":"fixture.c","line":10}, files={},
                          budget=SimpleNamespace(check=lambda: None))

    def test_unknown_clock_model_and_malformed_journal_source_do_not_gain_a_qpc_mapping(self):
        from uuid import uuid4
        from blackbox_core.decoder_alignment import ALIGNED, QPC_MODEL, project_event_time
        from blackbox_core.trace_clock_evidence import assess_trace_capture_metadata
        model = {"status":ALIGNED,"frequency_hz":1000000000,"session_origin_ns":0,
            "valid_qpc_min_ticks":1,"valid_qpc_max_ticks":100,"offset_lower_ns":0,"offset_upper_ns":1,
            "session_uuid":str(uuid4()),"source_trace_sha256":"a"*64}
        self.assertEqual(project_event_time(model,{"source_ticks":"50"})["status"],"NOT_ESTABLISHED")
        self.assertEqual(project_event_time({**model,"clock_model":QPC_MODEL},{"source_ticks":"50"})["status"],ALIGNED)
        for source in (None, [], {}, "\ud800"):
            with self.subTest(source=source):
                report = assess_trace_capture_metadata({"format":".etl"},{"source":source})
                self.assertEqual(report["status"],"INVALID_CAPTURE_JOURNAL")
                self.assertEqual(report["trace_to_blackbox_session_clock_alignment"],"NOT_ESTABLISHED")
        self.assertEqual(assess_trace_capture_metadata(None,{"source":"ETW_WPR"})["status"],"INVALID_TRACE_INDEX_SUMMARY")

    def test_duplicate_session_clock_records_cannot_be_selected_by_first_row(self):
        from uuid import uuid4
        from blackbox_core.decoder_alignment import SESSION_CLOCK_SCHEMA, read_session_clock
        source = self.root / "clock.sqlite3"
        session_uuid = str(uuid4())
        record = {"schema":SESSION_CLOCK_SCHEMA,"session_uuid":session_uuid,"monotonic_origin_ns":1,
            "anchor_monotonic_ns":1,"anchor_utc_ns":2,"anchor_uncertainty_ns":0,
            "clock_source":"PYTHON_MONOTONIC_NS_AND_TIME_NS"}
        with closing(sqlite3.connect(source)) as db:
            db.executescript("PRAGMA user_version=2; CREATE TABLE sessions(session_uuid,monotonic_origin_ns,"
                "anchor_monotonic_ns,anchor_utc_ns,anchor_uncertainty_ns,clock_source,ended_monotonic_ns);"
                "CREATE TABLE clock_evidence(schema,evidence_json);")
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",(session_uuid,1,1,2,0,record["clock_source"],None))
            db.executemany("INSERT INTO clock_evidence VALUES(?,?)",[(SESSION_CLOCK_SCHEMA,json.dumps(record))]*2)
            db.commit()
        before = source.read_bytes()
        with self.assertRaisesRegex(ValueError,"SESSION_CLOCK_IDENTITY_AMBIGUOUS"):
            read_session_clock(source)
        self.assertEqual(source.read_bytes(),before)

    def test_native_host_invalid_paths_report_failure_without_publishing(self):
        from blackbox_core.decoder_service import helper_path
        helper = helper_path()
        if not helper.is_file():
            self.skipTest("Hosted native decoder build required; no CLI acceptance claimed")
        for source in ("", "//unsupported-network/source.etl"):
            output = self.root / "native-output.jsonl"
            result = subprocess.run([str(helper), source, str(output)], capture_output=True, timeout=15)
            with self.subTest(source=source):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"DECODER_FAILED:", result.stderr)
                self.assertNotIn(b"Unhandled exception", result.stderr)
                self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which("clang") and shutil.which("lld-link"), "Hosted native PDB compiler required")
    def test_inline_lineage_budgets_reject_expansion_without_changing_compiler_files(self):
        from blackbox_core.decoder_native_symbols import load_native_symbols
        from tools.qa_decoder_symbols import build_probe
        _, pe, pdb = build_probe(self.root)
        original = (pe.read_bytes(),pdb.read_bytes())
        self.assertGreater(len(load_native_symbols(pe,pdb).inline_sites),0)
        for limit, reason in (("MAX_INLINE_DEPTH","INLINE_DEPTH_BUDGET"),
                              ("MAX_INLINE_PARENT_REFERENCES","INLINE_LINEAGE_BUDGET")):
            with self.subTest(limit=limit), patch("blackbox_core.decoder_native_symbols."+limit,0):
                with self.assertRaisesRegex(ValueError,reason):
                    load_native_symbols(pe,pdb)
        self.assertEqual((pe.read_bytes(),pdb.read_bytes()),original)


if __name__ == "__main__":
    unittest.main()
