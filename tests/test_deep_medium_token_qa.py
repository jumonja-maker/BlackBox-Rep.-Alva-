"""Real medium-token child/grandchild IPC contract on hosted Windows only."""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.optional_jobs import OwnedProcess
from blackbox_core.windows_research import privilege
from tools.qa_decoder_standard_token import (
    current_medium_startup_diagnostics, restricted_child, restricted_interpreter,
    token_default_dacl, token_integrity,
)

MARKER = b"BLACKBOX_MEDIUM_OWNED_PIPE_CONTRACT\n"
HOSTED_WINDOWS = (os.name == "nt" and C.sizeof(C.c_void_p) == 8 and
                  os.environ.get("GITHUB_ACTIONS") == "true" and
                  os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")


def _grandchild():
    if not HOSTED_WINDOWS:
        return 2
    # pythonw has no Python console streams. Use only the real redirected
    # process HANDLEs supplied by subprocess, exactly as a native helper does.
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.GetStdHandle.argtypes, kernel.GetStdHandle.restype = [W.DWORD], W.HANDLE
    kernel.ReadFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    kernel.ReadFile.restype = W.BOOL
    kernel.WriteFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    kernel.WriteFile.restype = W.BOOL
    buffer, read = C.create_string_buffer(128), W.DWORD()
    if not kernel.ReadFile(kernel.GetStdHandle(0xFFFFFFF6), buffer, len(buffer), C.byref(read), None):
        raise C.WinError(C.get_last_error())
    value = {"pid": os.getpid(), "privilege": privilege(), "integrity": token_integrity(),
             "default_dacl": token_default_dacl(), "received_expected_marker": buffer.raw[:read.value] == MARKER}
    encoded = json.dumps(value, ensure_ascii=True).encode("ascii") + b"\n"
    output, written = C.create_string_buffer(encoded), W.DWORD()
    if (not kernel.WriteFile(kernel.GetStdHandle(0xFFFFFFF5), output, len(encoded), C.byref(written), None)
            or written.value != len(encoded)):
        raise C.WinError(C.get_last_error())
    return 0


def _worker(destination):
    if not HOSTED_WINDOWS:
        return 2
    proof = {"status": "RUNNING", "pid": os.getpid(), "privilege": privilege(),
             "integrity": token_integrity(), "default_dacl": token_default_dacl()}
    owner = None
    try:
        proof["startup"] = current_medium_startup_diagnostics()
        owner = OwnedProcess([sys.executable, str(Path(__file__).resolve()), "--medium-grandchild"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             detach_console=True)
        stdout, stderr = owner.process.communicate(MARKER, timeout=20)
        if owner.process.returncode or len(stdout) > 65536:
            raise AssertionError("MEDIUM_GRANDCHILD_FAILED: " + str(owner.process.returncode) + ": " +
                                 stderr.decode("utf-8", "replace")[:1000])
        proof["grandchild"] = json.loads(stdout)
        proof["owned_process"] = {"pid": owner.process.pid, "exit_code": owner.process.returncode,
                                  "windows_creation_flags": owner.windows_creation_flags,
                                  "redirected_stdin_stdout": True}
        proof["status"] = "COMPLETED"
    except BaseException as error:
        proof.update(status="FAILED", error=type(error).__name__, reason=str(error),
                     traceback=traceback.format_exc()[-12000:])
    finally:
        cleanup_errors = []
        if owner is not None:
            try:
                owner.close(kill=True)
            except Exception as error:
                cleanup_errors.append({"resource": "owned_process", "reason": str(error)[:1000]})
            for stream in (owner.process.stdin, owner.process.stdout, owner.process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except Exception as error:
                        cleanup_errors.append({"resource": "redirected_stream", "reason": str(error)[:1000]})
        proof["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            proof["status"] = "FAILED"
        Path(destination).write_text(json.dumps(proof, indent=2), encoding="utf-8")
    return 0 if proof["status"] == "COMPLETED" else 1


@unittest.skipUnless(HOSTED_WINDOWS, "Actual token/pipe contract requires a GitHub-hosted Windows x64 runner")
class DeepMediumTokenNativeContract(unittest.TestCase):
    def test_default_retains_existing_token_defaults_without_relabeling_old_decoder_qa(self):
        # Existing decoder QA deliberately retains its original IL. This
        # independent child proof uses no PIPE or grandchild, as before.
        parent_before = {"integrity": token_integrity(), "default_dacl": token_default_dacl()}
        with tempfile.TemporaryDirectory(prefix="deep default token ") as temporary:
            destination = Path(temporary) / "worker token.json"
            script = (
                "import json,os,sys; from pathlib import Path; "
                "from tools.qa_decoder_standard_token import token_integrity,token_default_dacl; "
                "from blackbox_core.windows_research import privilege; "
                "Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),"
                "'integrity':token_integrity(),'default_dacl':token_default_dacl(),"
                "'privilege':privilege()}),encoding='utf-8')"
            )
            child = restricted_child([restricted_interpreter(sys.executable), "-c", script, destination],
                                     cwd=ROOT, timeout_seconds=30)
            self.assertEqual(child["exit_code"], 0, str(child))
            self.assertTrue(destination.is_file(), "Restricted child must write its own token evidence")
            worker = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(worker["pid"], child["pid"])
        self.assertEqual(worker["privilege"], {"mode": "STANDARD", "windows": True})
        self.assertEqual(worker["integrity"], parent_before["integrity"])
        self.assertEqual(worker["default_dacl"], parent_before["default_dacl"])
        self.assertTrue(child["job_assigned_before_resume"])
        self.assertNotIn("medium_integrity_requested", child)
        self.assertNotIn("qa_default_dacl_adjustment", child)
        self.assertEqual(parent_before, {"integrity": token_integrity(), "default_dacl": token_default_dacl()})

    def test_medium_token_owns_pipes_and_grandchild_without_changing_parent(self):
        parent_before = {"integrity": token_integrity(), "default_dacl": token_default_dacl()}
        with tempfile.TemporaryDirectory(prefix="blackbox-medium-native-") as temporary:
            destination = Path(temporary) / "worker-proof.json"
            child = restricted_child([restricted_interpreter(sys.executable), str(Path(__file__).resolve()),
                                      "--medium-worker", str(destination)],
                                     cwd=ROOT, timeout_seconds=60, medium_integrity=True)
            self.assertTrue(destination.is_file(), str(child))
            proof = json.loads(destination.read_text(encoding="utf-8"))
        details = json.dumps({"launcher": child, "worker": proof}, ensure_ascii=True)
        self.assertEqual(child["exit_code"], 0, details)
        self.assertEqual(proof["status"], "COMPLETED", details)
        self.assertFalse(proof["cleanup_errors"], details)
        self.assertEqual(proof["pid"], child["pid"])
        for process in (proof, proof["grandchild"]):
            self.assertEqual(process["privilege"], {"mode": "STANDARD", "windows": True}, details)
            self.assertEqual(process["integrity"]["sid"], "S-1-16-8192", details)
        self.assertEqual(proof["integrity"], child["token_integrity"])
        self.assertEqual(proof["integrity"], child["child_token_integrity"])
        self.assertTrue(child["job_assigned_before_resume"])
        self.assertEqual(child["interactive_uac_secure_desktop"], "NOT_TESTED")
        self.assertNotEqual(proof["grandchild"]["pid"], proof["pid"])
        self.assertEqual(proof["grandchild"]["pid"], proof["owned_process"]["pid"])
        self.assertEqual(proof["owned_process"]["windows_creation_flags"], 0x8)
        self.assertTrue(proof["grandchild"]["received_expected_marker"], details)
        self.assertEqual(proof["startup"]["stages"]["create_pipe_default_security"]["status"], "SUCCEEDED", details)
        self.assertEqual(proof["startup"]["stages"]["duplicate_owned_temporary_file"]["status"], "SUCCEEDED", details)
        self.assertFalse(proof["startup"]["cleanup_errors"], details)
        adjustment = child["qa_default_dacl_adjustment"]
        expected = f"D:(A;;GA;;;{adjustment['token_user_sid']})(A;;GA;;;SY)"
        self.assertEqual(adjustment["after"]["sddl_dacl"], expected, details)
        self.assertEqual(adjustment["child_readback"], proof["default_dacl"])
        self.assertEqual(proof["grandchild"]["default_dacl"], proof["default_dacl"])
        self.assertFalse(adjustment["existing_object_or_file_acl_changes"])
        self.assertTrue(child["parent_token_unchanged"])
        self.assertEqual(child["parent_token_before"], child["parent_token_after"])
        self.assertEqual(parent_before, {"integrity": token_integrity(), "default_dacl": token_default_dacl()})


if __name__ == "__main__":
    if sys.argv[1:2] == ["--medium-grandchild"]:
        raise SystemExit(_grandchild())
    if sys.argv[1:2] == ["--medium-worker"] and len(sys.argv) == 3:
        raise SystemExit(_worker(sys.argv[2]))
    unittest.main()
