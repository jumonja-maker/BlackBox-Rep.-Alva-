"""Portable checks for the real-app QA download boundary, not Windows evidence."""
from contextlib import closing, redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import sqlite3
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.qa_decoder_apps import (decode_trace, etw_observations, installed, native_pe_identity,
                                   observed_process_image, safe_extract)
from tools.qa_decoder_budget_diagnostic import (PAIRS, parse_args, validate_noise_oracle,
                                                validate_original_source, validate_rejection)


class ControlledBudgetProtocolTests(unittest.TestCase):
    """Protocol fixtures only; real rejection additionally requires hosted ETW."""
    def oracle(self):
        return {'schema': 'blackbox.scheduler-noise/1', 'status': 'COMPLETED', 'pid': 123,
            'created_100ns': '1000', 'pairs': PAIRS, 'stop_requested': True,
            'all_threads_joined': True, 'native_handles_created': 2 * PAIRS,
            'native_handles_closed': 2 * PAIRS, 'cleanup_required': False, 'errors': [],
            'qpc_frequency_hz': 10000000, 'workers': [
                {'tid': 100 + n, 'created_100ns': str(2000 + n), 'handoffs': 100,
                 'begin_qpc': 10, 'end_qpc': 1000} for n in range(2 * PAIRS)]}

    def test_noise_receipt_needs_every_join_handle_handoff_and_exact_process(self):
        validate_noise_oracle(self.oracle(), 123, '1000')
        for field, value in (('pid', 124), ('created_100ns', '1001'), ('all_threads_joined', False),
                             ('native_handles_closed', 2 * PAIRS - 1), ('stop_requested', False),
                             ('cleanup_required', True), ('errors', ['OWNED_EXIT_UNCONFIRMED'])):
            with self.subTest(field=field):
                oracle = self.oracle(); oracle[field] = value
                with self.assertRaises(AssertionError):
                    validate_noise_oracle(oracle, 123, '1000')
        oracle = self.oracle(); oracle['workers'][0]['handoffs'] = 0
        with self.assertRaisesRegex(AssertionError, 'REAL_HANDOFFS'):
            validate_noise_oracle(oracle, 123, '1000')

    def test_expected_prefix_alone_is_not_a_native_reproduction(self):
        meta = {'status': 'TRUNCATED', 'rows': 250000, 'input_sha256': 'a' * 64,
                'import_completeness': 'BOUNDED_PREFIX'}
        native = {'switch_rows': 12000, 'ready_rows': 12000, 'noise_tids_observed': 16,
                  'qpc_frequency_matches': True}
        validate_rejection(meta, 'a' * 64, native)
        for field, value in (('switch_rows', 0), ('ready_rows', 0),
                             ('noise_tids_observed', 0), ('qpc_frequency_matches', False)):
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE'):
                validate_rejection(meta, 'a' * 64, {**native, field: value})
        with self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE'):
            validate_rejection(meta, 'a' * 64, {**native, 'switch_rows': 1, 'ready_rows': 1})
        for change in ({'status': 'DECODED'}, {'rows': 0}, {'input_sha256': 'b' * 64},
                       {'import_completeness': 'ALL_EMITTED_RECORDS'}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'REPRODUCTION_NOT_ESTABLISHED'):
                validate_rejection({**meta, **change}, 'a' * 64, native)

    def test_noise_child_cannot_take_parent_helper_or_source_arguments(self):
        self.assertTrue(parse_args(['--noise-child', '--output', 'own-noise-root']).noise_child)
        for arguments in (['--output', 'root'], ['--noise-child', '--output', 'root', '--helper', 'decoder'],
                          ['--noise-child', '--output', 'root', '--source-sha', 'a' * 40]):
            with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()), \
                    patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                parse_args(arguments)
            self.assertEqual(error.exception.code, 2)

    def test_negative_prefix_still_requires_original_predecode_hash_and_size(self):
        diagnostic = {'schema': 'blackbox.decoder-app-trace-diagnostic/1',
            'source_sha256': 'a' * 64, 'source_bytes': 100, 'metadata_input_sha256_matches': True}
        self.assertEqual(validate_original_source(diagnostic, 'a' * 64, 100), {
            'source_sha256': 'a' * 64, 'source_bytes': 100, 'metadata_input_sha256_matches': True})
        for change in ({'source_sha256': 'b' * 64}, {'source_bytes': 101}, {'source_bytes': 100.0},
                       {'metadata_input_sha256_matches': False}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'ORIGINAL_SOURCE_CHANGED'):
                validate_original_source({**diagnostic, **change}, 'a' * 64, 100)


class ApplicationTraceDiagnosticTests(unittest.TestCase):
    def exercise_decode(self, *, status="DECODED", rows=12, metadata_hash=None,
                        changed_source=False, expected_failure=None, hostile_counts=False):
        # This is an explicit metadata-handling regression. decode_file is
        # mocked; actual ETW/EventPipe and third-party workloads remain CI gates.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "PRIVATE_PATH_MUST_NOT_APPEAR_IN_LOGS.etl"
            original = b"explicit trace-metadata fixture, not actual ETW"
            source.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            output = root / "7zip"
            output.mkdir()
            summary_path = root / "isolated-job-summary.txt"
            meta = {"status": status, "rows": rows,
                "input_sha256": digest if metadata_hash is None else metadata_hash,
                "import_completeness": "BOUNDED_PREFIX" if status == "TRUNCATED" else "ALL_EMITTED_RECORDS",
                "decoder_reported_lost_events": None, "events_with_stacks": 7,
                "events_with_errors": 0, "bounded_events": 1,
                "reliability": {"event_limit": 250000},
                "engine": {"protocol": "blackbox.trace-event/1"},
                "profiles": {"private_note": "PRIVATE_METADATA_MUST_NOT_APPEAR_IN_LOGS"}}
            if hostile_counts:
                meta.update(events_with_stacks="PRIVATE_COUNTER_MUST_NOT_APPEAR_IN_LOGS",
                            events_with_errors=True, bounded_events=2**100)
                meta["reliability"] = {"event_limit": -1}

            def decoded(*args, **kwargs):
                if changed_source:
                    source.write_bytes(b"different original source bytes")
                return meta

            terminal = io.StringIO()
            helper = root / "decoder-helper.exe"
            result = None
            with patch("tools.qa_decoder_apps.decode_file", side_effect=decoded) as decoder, \
                    patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}), \
                    redirect_stdout(terminal):
                if expected_failure:
                    with self.assertRaisesRegex(AssertionError, expected_failure):
                        decode_trace(source, output, helper)
                else:
                    result = decode_trace(source, output, helper)
            decoder.assert_called_once_with(source, output / "decoded.sqlite3", timeout=90)
            self.assertEqual(json.loads((output / "decoder-summary.json").read_text(encoding="utf-8")), meta)
            diagnostic = json.loads((output / "decoder-diagnostic.json").read_text(encoding="utf-8"))
            logged = terminal.getvalue()
            self.assertTrue(logged.startswith("THIRD_PARTY_DECODER_TRACE_DETAIL "))
            self.assertEqual(json.loads(logged.split(" ", 1)[1]), diagnostic)
            summary = summary_path.read_text(encoding="utf-8")
            self.assertEqual(json.loads(summary.split("Third-party trace decode ", 1)[1]), diagnostic)
            for private in (str(source), str(root), "PRIVATE_PATH", "PRIVATE_METADATA", "PRIVATE_COUNTER"):
                self.assertNotIn(private, logged + summary + json.dumps(diagnostic))
            self.assertEqual(diagnostic["source_sha256"], digest)
            self.assertEqual(diagnostic["source_bytes"], len(original))
            self.assertEqual(diagnostic["decoder_status"], status)
            self.assertEqual(diagnostic["rows"], rows)
            return result, meta, diagnostic

    def test_complete_trace_keeps_full_metadata_and_emits_safe_diagnostic(self):
        result, meta, diagnostic = self.exercise_decode(hostile_counts=True)
        self.assertIs(result[1], meta)
        self.assertTrue(diagnostic["metadata_input_sha256_matches"])
        self.assertEqual(diagnostic["application"], "7-Zip")
        self.assertEqual(diagnostic["source_format"], ".etl")
        for field in ("events_with_stacks", "events_with_errors", "bounded_events", "event_limit"):
            self.assertIsNone(diagnostic[field])

    def test_truncated_trace_remains_failure_and_saves_actual_prefix_metadata(self):
        _, _, diagnostic = self.exercise_decode(status="TRUNCATED", rows=250000,
            expected_failure="APP_TRACE_NOT_COMPLETELY_DECODED")
        self.assertEqual(diagnostic["import_completeness"], "BOUNDED_PREFIX")
        self.assertEqual(diagnostic["event_limit"], 250000)

    def test_zero_decoded_rows_remain_failure_with_saved_diagnostic(self):
        self.exercise_decode(rows=0, expected_failure="APP_TRACE_NOT_COMPLETELY_DECODED")

    def test_metadata_hash_mismatch_remains_failure(self):
        _, _, diagnostic = self.exercise_decode(metadata_hash="f" * 64,
            expected_failure="APP_TRACE_HASH_CHANGED")
        self.assertFalse(diagnostic["metadata_input_sha256_matches"])

    def test_changed_original_still_fails_and_reports_original_hash_and_size(self):
        self.exercise_decode(changed_source=True, expected_failure="APP_TRACE_HASH_CHANGED")


class ApplicationImageIdentityTests(unittest.TestCase):
    def test_explicit_application_precedes_path_shim_and_owns_observed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "program-files-7z.exe"
            shim = root / "chocolatey-7z.exe"
            native.write_bytes(b"native-file-identity-fixture")
            shim.write_bytes(b"launcher-file-identity-fixture")
            with patch("tools.qa_decoder_apps.shutil.which", return_value=str(shim)):
                self.assertEqual(installed("7z", [native]), native.resolve())
            with self.assertRaisesRegex(AssertionError, "OWNED_PROCESS_IMAGE_MISMATCH"):
                observed_process_image(shim, native)
            self.assertEqual(observed_process_image(native, native), str(native.resolve()))

    def pe_header_fixture(self, *, magic=0x20B, managed=False, dll=False):
        # Explicit binary-format fixture only; never executed and never
        # presented as acceptance of an actual Windows application.
        directory_at = 112 if magic == 0x20B else 96
        optional_size = directory_at + 16 * 8
        data = bytearray(128 + 24 + optional_size)
        data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664 if magic == 0x20B else 0x14C)
        struct.pack_into("<HH", data, 148, optional_size, 0x2002 if dll else 0x2)
        struct.pack_into("<H", data, 152, magic)
        struct.pack_into("<I", data, 152 + directory_at - 4, 16)
        if managed:
            struct.pack_into("<II", data, 152 + directory_at + 14 * 8, 0x2000, 72)
        return data

    def test_clr_launcher_cannot_certify_native_application_for_either_pe_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for magic in (0x10B, 0x20B):
                with self.subTest(magic=magic):
                    binary.write_bytes(self.pe_header_fixture(magic=magic, managed=True))
                    with self.assertRaisesRegex(AssertionError, "CLR_LAUNCHER_OR_MANAGED_IMAGE_REJECTED"):
                        native_pe_identity(binary)
                    binary.write_bytes(self.pe_header_fixture(magic=magic))
                    proof = native_pe_identity(binary)
                    self.assertEqual(proof["code_kind"], "NATIVE_PE_NO_CLR_COM_DESCRIPTOR")
                    self.assertEqual(proof["clr_com_descriptor_bytes"], 0)

    def test_truncated_header_and_dll_do_not_count_as_native_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for data in (b"MZ", self.pe_header_fixture()[:-1], self.pe_header_fixture(dll=True)):
                with self.subTest(length=len(data)):
                    binary.write_bytes(data)
                    with self.assertRaises(AssertionError):
                        native_pe_identity(binary)


class ApplicationLifetimeEvidenceTests(unittest.TestCase):
    def observations(self, rows, pids):
        # Explicit protocol fixture: this exercises acceptance proof handling,
        # not Windows ETW capture or third-party application execution.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE events(data TEXT NOT NULL)")
                db.executemany("INSERT INTO events VALUES (?)",
                               [(json.dumps(row),) for row in rows])
                db.commit()
            return etw_observations(path, pids)

    def test_absent_or_missing_pid_identity_is_not_lifetime_evidence(self):
        for rows in ([], [{"pid": 10}], [{"pid": 10, "process_instance": 1}]):
            with self.subTest(rows=rows):
                observed = self.observations(rows, [10, 20])
                self.assertFalse(observed["pid_reuse_ambiguous"])
                self.assertFalse(observed["pid_lifetimes_confirmed"])
        self.assertFalse(self.observations([], [])["pid_lifetimes_confirmed"])

    def test_each_owned_pid_needs_one_unique_observed_lifetime(self):
        rows = [{"pid": 10, "process_instance": 0},
                {"pid": 20, "process_instance": 1},
                {"pid": 20, "process_instance": 1}]
        self.assertTrue(self.observations(rows, [10, 20])["pid_lifetimes_confirmed"])
        rows.append({"pid": 10, "process_instance": 2})
        observed = self.observations(rows, [10, 20])
        self.assertTrue(observed["pid_reuse_ambiguous"])
        self.assertFalse(observed["pid_lifetimes_confirmed"])


class ApplicationArchiveBoundaryTests(unittest.TestCase):
    def archive(self, root, entries):
        path = root / "app.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name, value in entries:
                z.writestr(name, value)
        return path

    def test_complete_validation_precedes_any_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("../outside", b"not allowed")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())
            self.assertFalse((root / "outside").exists())

    def test_windows_case_collision_and_file_directory_conflict_rejected(self):
        for entries in [[("App.exe", b"a"), ("app.exe", b"b")],
                        [("assets", b"a"), ("assets/one", b"b")]]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(AssertionError):
                    safe_extract(self.archive(root, entries), root / "output")
                self.assertFalse((root / "output").exists())

    def test_link_member_rejected_without_writing_earlier_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            symlink = zipfile.ZipInfo("link")
            symlink.create_system = 3
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          (symlink, "../../escape")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())

    def test_fixed_payload_retains_runtime_and_omits_active_updater_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("localization/english.xml", b"text"),
                                          ("updater/gup.exe", b"not executed"),
                                          ("plugins/Plugin.dll", b"not executed")])
            safe_extract(archive, root / "output")
            self.assertEqual((root / "output/notepad++.exe").read_bytes(), b"owned-fixture")
            self.assertEqual((root / "output/localization/english.xml").read_bytes(), b"text")
            self.assertFalse((root / "output/updater").exists())
            self.assertFalse((root / "output/plugins").exists())


if __name__ == "__main__":
    unittest.main()
