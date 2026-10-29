"""Parser/control tests for the native acceptance harness, run by Actions only.

These in-memory format fixtures are deliberately not native acceptance results.
The actual Windows runner must execute qa_deep_inspection.py separately.
"""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.qa_deep_inspection import compiler_environment, minidump_evidence, require_hosted_windows
from tools.qa_deep_endurance import verify_samples


def synthetic_dump(*, full=False, truncate_memory=False):
    threads = struct.pack("<I", 1) + bytes(48)
    modules = struct.pack("<I", 1) + bytes(108)
    system = bytes(56)
    count = 4 if full else 3
    cursor = 32 + count * 12
    entries = []
    payload = bytearray()
    for kind, value in ((3, threads), (4, modules), (7, system)):
        entries.append(struct.pack("<III", kind, len(value), cursor))
        payload.extend(value)
        cursor += len(value)
    if full:
        memory = struct.pack("<QQQQ", 1, cursor + 32, 0x12340000, 4)
        entries.append(struct.pack("<III", 9, len(memory), cursor))
        payload.extend(memory)
        payload.extend(b"ab" if truncate_memory else b"abcd")
    header = struct.pack("<6IQ", 0x504D444D, 0xA793, count, 32, 0, 0, 2 if full else 0)
    return header + b"".join(entries) + payload


class DeepAcceptanceEvidenceContracts(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Real cmd.exe quoting is a Windows contract")
    def test_compiler_setup_with_spaces_preserves_diagnostics_but_not_environment(self):
        self._exercise_cmd_setup(exit_code=0)

    @unittest.skipUnless(os.name == "nt", "Real cmd.exe quoting is a Windows contract")
    def test_compiler_setup_failure_preserves_actual_batch_diagnostic(self):
        self._exercise_cmd_setup(exit_code=27)

    def _exercise_cmd_setup(self, *, exit_code):
        actual_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="deep compiler quoting ") as temporary:
            root = Path(temporary)
            installer = root / "Microsoft Visual Studio/Installer/vswhere.exe"
            installer.parent.mkdir(parents=True)
            installer.write_bytes(b"NOT_EXECUTED_DISCOVERY_FIXTURE")
            location = root / "Visual Studio With Spaces"
            setup = location / "VC/Auxiliary/Build/vcvars64.bat"
            setup.parent.mkdir(parents=True)
            setup.write_text('@echo setup diagnostic from actual cmd.exe\n'
                             '@set "BB_COMPILER_TEST_PRIVATE_VALUE=must-not-be-an-artifact"\n'
                             f'@exit /b {exit_code}\n', encoding="ascii")
            output = root / "build output"
            output.mkdir()

            def run(command, **kwargs):
                if isinstance(command, list) and command[0] == str(installer):
                    return subprocess.CompletedProcess(command, 0, str(location) + "\n", "")
                return actual_run(command, **kwargs)

            with patch.dict(os.environ, {"ProgramFiles(x86)": str(root)}), \
                    patch("tools.qa_deep_inspection.shutil.which", side_effect=[None, "cl.exe"]), \
                    patch("tools.qa_deep_inspection.subprocess.run", side_effect=run):
                if exit_code:
                    with self.assertRaisesRegex(AssertionError, "COMPILER_SETUP_FAILED"):
                        compiler_environment(output)
                else:
                    compiler, environment = compiler_environment(output)
                    self.assertEqual(compiler, "cl.exe")
                    self.assertEqual(environment["BB_COMPILER_TEST_PRIVATE_VALUE"],
                                     "must-not-be-an-artifact")
            self.assertIn("setup diagnostic from actual cmd.exe",
                          (output / "compiler-setup.log").read_text(encoding="utf-8"))
            for artifact in output.iterdir():
                self.assertNotIn("must-not-be-an-artifact", artifact.read_text(encoding="utf-8"))

    def test_native_executable_harness_refuses_non_actions(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"}):
            with self.assertRaisesRegex(AssertionError, "GITHUB_HOSTED_WINDOWS"):
                require_hosted_windows()

    def test_minidump_directory_and_live_buffer_are_independently_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-format-only.dmp"
            path.write_bytes(synthetic_dump(full=True))
            result = minidump_evidence(path, full=True, expected_address=0x12340000, expected_hex="61626364")
            self.assertTrue(result["known_native_buffer_verified"])
            self.assertEqual(result["counts"], {"threads": 1, "modules": 1, "memory64_regions": 1})
            with self.assertRaisesRegex(AssertionError, "DIFFERS_FROM_LIVE_ORACLE"):
                minidump_evidence(path, full=True, expected_address=0x12340000, expected_hex="61626365")

    def test_truncated_full_dump_does_not_pass_by_header_alone(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "truncated.dmp"
            path.write_bytes(synthetic_dump(full=True, truncate_memory=True))
            with self.assertRaisesRegex(AssertionError, "PAYLOAD_TRUNCATED"):
                minidump_evidence(path, full=True)

    def test_extended_request_cannot_accept_normal_dump(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "normal.dmp"
            path.write_bytes(synthetic_dump())
            with self.assertRaisesRegex(AssertionError, "MEMORY64_STREAM_REQUIRED"):
                minidump_evidence(path, full=True)

    def test_directory_cannot_point_outside_actual_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.dmp"
            raw = bytearray(synthetic_dump())
            struct.pack_into("<I", raw, 12, len(raw) + 1)
            path.write_bytes(raw)
            with self.assertRaisesRegex(AssertionError, "DIRECTORY_OUT_OF_BOUNDS"):
                minidump_evidence(path, full=False)

    def test_duration_and_continuous_target_progress_both_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-observations-only.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE samples(seq INTEGER,elapsed REAL,heartbeat INTEGER,io_cycles INTEGER,"
                           "network_cycles INTEGER,qa_rss INTEGER,target_rss INTEGER,helper_pid INTEGER,helper_rss INTEGER)")
                db.executemany("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)",
                               [(1, 0, 1, 1, 1, 10, 20, 90, 30), (2, 30, 2, 2, 2, 11, 21, 90, 31)])
                db.commit()
            result = verify_samples(path, 30)
            self.assertEqual(result["observed_span_seconds"], 30)
            with self.assertRaisesRegex(AssertionError, "MEASURED_INTERVAL"):
                verify_samples(path, 19800)
            with closing(sqlite3.connect(path)) as db:
                db.execute("UPDATE samples SET network_cycles=1 WHERE seq=2")
                db.commit()
            with self.assertRaisesRegex(AssertionError, "WORKLOAD_PROGRESS"):
                verify_samples(path, 30)


if __name__ == "__main__":
    unittest.main()
