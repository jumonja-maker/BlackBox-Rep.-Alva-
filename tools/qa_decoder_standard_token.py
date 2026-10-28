"""Decode already-captured real traces with admin SID/privileges removed.

Uses the same restricted-token mechanism as qa_standard_token.py. That tool's
launcher is specific to GUI --research-e2e, so it is deliberately unchanged.
This launcher additionally owns a kill-on-close Windows job before the suspended
child starts. No accounts, ACLs, policies, capture sessions or services are added.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from blackbox_core.decoder_index import file_hash, read_index
from blackbox_core.decoder_service import decode_file
from blackbox_core.optional_jobs import OwnedProcess
from blackbox_core.windows_research import privilege


def require(value, message):
    if not value:
        raise AssertionError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def trace_plan(trace_root):
    """Only the two named artifacts produced by real qa_decoder.py are used."""
    root = Path(trace_root).resolve(strict=True)
    plan = []
    for kind, name, index_name in (("ETL", "owned.etl", "etl.sqlite3"),
                                    ("EVENTPIPE", "fixture.nettrace", "eventpipe.sqlite3")):
        source = root / name
        baseline = root / index_name
        require(source.is_file() and not source.is_symlink() and baseline.is_file(),
                "REAL_CAPTURED_TRACE_OR_ADMIN_INDEX_MISSING")
        before = file_hash(source)
        meta = read_index(baseline, limit=1)["summary"]
        require(meta["status"] == "DECODED" and meta["rows"] > 0 and
                meta["input_sha256"] == before, "ADMIN_TRACE_BASELINE_NOT_CONFIRMED")
        plan.append({"format": kind, "source": str(source), "input_sha256": before,
                     "baseline_index": str(baseline), "rows": meta["rows"],
                     "events_with_stacks": meta["events_with_stacks"],
                     "gc_pairs": meta.get("gc", {}).get("gc_pairs", 0)})
    return plan


def worker(helper, trace_root, output):
    """The interpreter and all native helper children inherit the restricted token."""
    output = Path(output).resolve(strict=True)
    proof = {"status": "RUNNING", "pid": os.getpid(), "privilege": privilege(),
             "source_sha": os.environ.get("GITHUB_SHA"), "captures_started": False,
             "decoder_helper_sha256": file_hash(helper), "traces": []}
    code = 1
    try:
        require(os.name == "nt" and proof["privilege"] == {"mode": "STANDARD", "windows": True},
                "ACTUAL_STANDARD_WINDOWS_TOKEN_NOT_CONFIRMED")
        for item in trace_plan(trace_root):
            owners = []
            def start_owned(*args, **kwargs):
                owner = OwnedProcess(*args, **kwargs)
                owners.append(owner)
                return owner
            index = output / (item["format"].lower() + ".sqlite3")
            with patch("blackbox_core.decoder_service.helper_path", return_value=helper), \
                    patch("blackbox_core.optional_jobs.OwnedProcess", side_effect=start_owned):
                meta = decode_file(Path(item["source"]), index, timeout=90)
            require(len(owners) == 1 and owners[0].process.returncode == 0,
                    "STANDARD_NATIVE_HELPER_SUCCESS_NOT_CONFIRMED")
            page = read_index(index, limit=1)
            require(page["rows"] and page["summary"] == meta,
                    "STANDARD_INDEX_NOT_READABLE")
            require(meta["status"] == "DECODED" and meta["rows"] == item["rows"] and
                    meta["events_with_stacks"] == item["events_with_stacks"] and
                    meta.get("gc", {}).get("gc_pairs", 0) == item["gc_pairs"] and
                    meta["input_sha256"] == item["input_sha256"],
                    "STANDARD_RESULT_DIFFERS_FROM_ACTUAL_ADMIN_BASELINE")
            require(file_hash(Path(item["source"])) == item["input_sha256"],
                    "STANDARD_DECODE_MODIFIED_CAPTURE")
            proof["traces"].append({**item, "status": "PASS", "index": str(index),
                                    "helper_pid": owners[0].process.pid,
                                    "helper_exit_code": owners[0].process.returncode,
                                    "index_readable": True, "summary": meta})
        proof["status"] = "PASS"
        code = 0
    except BaseException as exc:
        proof.update(status="FAIL", error=type(exc).__name__, reason=str(exc)[:1000])
    finally:
        save(output / "standard-token-worker.json", proof)
    return code


def restricted_child(args, *, cwd, timeout_seconds=210):
    """Launch the temporary restricted token in an owned job, no shell or PATH."""
    require(os.name == "nt", "WINDOWS_REQUIRED")
    kernel = C.WinDLL("kernel32", use_last_error=True)
    adv = C.WinDLL("advapi32", use_last_error=True)
    class Sid(C.Structure):
        _fields_ = [("sid", C.c_void_p), ("attributes", W.DWORD)]
    class Startup(C.Structure):
        _fields_ = [("cb", W.DWORD), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR), ("title", W.LPWSTR),
                    ("x", W.DWORD), ("y", W.DWORD), ("width", W.DWORD), ("height", W.DWORD),
                    ("cols", W.DWORD), ("rows", W.DWORD), ("fill", W.DWORD), ("flags", W.DWORD),
                    ("show", W.WORD), ("reserved_bytes", W.WORD), ("reserved_ptr", C.c_void_p),
                    ("stdin", W.HANDLE), ("stdout", W.HANDLE), ("stderr", W.HANDLE)]
    class Process(C.Structure):
        _fields_ = [("process", W.HANDLE), ("thread", W.HANDLE), ("pid", W.DWORD), ("tid", W.DWORD)]
    class Basic(C.Structure):
        _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64), ("flags", W.DWORD),
                    ("min_working", C.c_size_t), ("max_working", C.c_size_t), ("active", W.DWORD),
                    ("affinity", C.c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]
    class Io(C.Structure):
        _fields_ = [(name, C.c_uint64) for name in
                    ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
    class Limits(C.Structure):
        _fields_ = [("basic", Basic), ("io", Io), ("process_memory", C.c_size_t),
                    ("job_memory", C.c_size_t), ("peak_process", C.c_size_t), ("peak_job", C.c_size_t)]
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.LocalFree.argtypes = [C.c_void_p]; kernel.LocalFree.restype = C.c_void_p
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]; kernel.WaitForSingleObject.restype = W.DWORD
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
    kernel.CreateJobObjectW.argtypes = [C.c_void_p, W.LPCWSTR]; kernel.CreateJobObjectW.restype = W.HANDLE
    kernel.SetInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
    kernel.TerminateJobObject.argtypes = [W.HANDLE, W.UINT]
    kernel.ResumeThread.argtypes = [W.HANDLE]; kernel.ResumeThread.restype = W.DWORD
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    adv.ConvertStringSidToSidW.argtypes = [W.LPCWSTR, C.POINTER(C.c_void_p)]
    adv.CreateRestrictedToken.argtypes = [W.HANDLE, W.DWORD, W.DWORD, C.POINTER(Sid), W.DWORD,
                                         C.c_void_p, W.DWORD, C.c_void_p, C.POINTER(W.HANDLE)]
    adv.CreateProcessAsUserW.argtypes = [W.HANDLE, W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p,
                                        W.BOOL, W.DWORD, C.c_void_p, W.LPCWSTR,
                                        C.POINTER(Startup), C.POINTER(Process)]
    original = W.HANDLE(); restricted = W.HANDLE(); admin_sid = C.c_void_p()
    process = Process(); job = None; started = False
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0xB, C.byref(original)):
            raise OSError(C.get_last_error(), "QA_OPEN_TOKEN_FAILED")
        if not adv.ConvertStringSidToSidW("S-1-5-32-544", C.byref(admin_sid)):
            raise OSError(C.get_last_error(), "QA_ADMIN_SID_FAILED")
        disabled = Sid(admin_sid, 0)
        if not adv.CreateRestrictedToken(original, 1, 1, C.byref(disabled), 0, None, 0, None, C.byref(restricted)):
            raise OSError(C.get_last_error(), "QA_RESTRICT_TOKEN_FAILED")
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise OSError(C.get_last_error(), "QA_OWNED_JOB_FAILED")
        limits = Limits(); limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        if not kernel.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)):
            raise OSError(C.get_last_error(), "QA_OWNED_JOB_LIMIT_FAILED")
        startup = Startup(); startup.cb = C.sizeof(startup)
        command = C.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in args]))
        if not adv.CreateProcessAsUserW(restricted, str(args[0]), command, None, None, False,
                                        0x4 | 0x08000000, None, str(cwd), C.byref(startup), C.byref(process)):
            raise OSError(C.get_last_error(), "QA_RESTRICTED_START_FAILED")
        started = True
        if not kernel.AssignProcessToJobObject(job, process.process):
            raise OSError(C.get_last_error(), "QA_RESTRICTED_JOB_ASSIGNMENT_FAILED")
        if kernel.ResumeThread(process.thread) == 0xFFFFFFFF:
            raise OSError(C.get_last_error(), "QA_RESTRICTED_RESUME_FAILED")
        waited = kernel.WaitForSingleObject(process.process, int(timeout_seconds * 1000))
        if waited != 0:
            raise TimeoutError("STANDARD_DECODER_QA_TIMEOUT_OR_WAIT_FAILED_" + str(waited))
        code = W.DWORD()
        if not kernel.GetExitCodeProcess(process.process, C.byref(code)):
            raise OSError(C.get_last_error(), "QA_RESTRICTED_EXIT_UNAVAILABLE")
        return {"pid": process.pid, "exit_code": code.value,
                "token": "ADMIN_SID_DISABLED_PRIVILEGES_REMOVED",
                "cleanup": "OWNED_JOB_KILL_ON_CLOSE"}
    finally:
        if job:
            kernel.TerminateJobObject(job, 1)
        if started:
            # Also covers failure to assign the still-suspended child to job.
            if kernel.WaitForSingleObject(process.process, 0) != 0:
                kernel.TerminateProcess(process.process, 1)
            kernel.WaitForSingleObject(process.process, 3000)
        for handle in (process.thread, process.process, job, restricted, original):
            if handle:
                kernel.CloseHandle(handle)
        if admin_sid:
            kernel.LocalFree(admin_sid)


def validate_worker(proof, child, plan):
    require(child["exit_code"] == 0 and proof.get("pid") == child["pid"] and
            proof.get("status") == "PASS" and
            proof.get("privilege") == {"mode": "STANDARD", "windows": True} and
            proof.get("captures_started") is False, "STANDARD_WORKER_PROOF_NOT_CONFIRMED")
    rows = proof.get("traces", [])
    require(len(rows) == len(plan), "STANDARD_TRACE_COVERAGE_INCOMPLETE")
    for result, expected in zip(rows, plan):
        require(result.get("format") == expected["format"] and result.get("status") == "PASS" and
                result.get("input_sha256") == expected["input_sha256"] and
                result.get("rows") == expected["rows"] and result.get("helper_exit_code") == 0 and
                result.get("helper_pid") != proof["pid"] and result.get("index_readable") is True,
                "STANDARD_TRACE_RESULT_NOT_CONFIRMED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    helper = args.helper.resolve(strict=True)
    if args.worker:
        return worker(helper, args.trace_root, args.output)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "source_sha": os.environ.get("GITHUB_SHA"),
              "scope": "ACTUAL_RESTRICTED_WINDOWS_TOKEN_OFFLINE_DECODE",
              "captures_started": False, "physical_uac_account_acl_matrix": False}
    code = 1
    try:
        if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
            report.update(status="NOT_EXECUTED", reason="DISPOSABLE_WINDOWS_CI_REQUIRED")
            return 2
        plan = trace_plan(args.trace_root)
        report["inputs"] = plan
        report["parent_privilege"] = privilege()
        child = restricted_child([Path(sys.executable).resolve(strict=True), Path(__file__).resolve(),
                                  "--worker", "--helper", helper, "--trace-root", args.trace_root.resolve(),
                                  "--output", output], cwd=ROOT)
        report["child"] = child
        proof = json.loads((output / "standard-token-worker.json").read_text(encoding="utf-8"))
        report["worker"] = proof
        validate_worker(proof, child, plan)
        require(all(file_hash(Path(x["source"])) == x["input_sha256"] for x in plan),
                "STANDARD_QA_MODIFIED_ORIGINAL_TRACE")
        report["status"] = "PASS"
        code = 0
    except Exception as exc:
        report.update(status="FAIL", error=type(exc).__name__, reason=str(exc)[:1000])
    finally:
        save(output / "standard-token-qa.json", report)
    print("STANDARD_TOKEN_DECODER_QA_" + report["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
