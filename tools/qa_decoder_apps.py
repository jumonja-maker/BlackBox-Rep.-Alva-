"""Owned, bounded Windows acceptance with three actual third-party applications.

This is an explicit CI test tool, never invoked by the application. Workloads
and their oracles are controlled; observations come from real ETW/EventPipe or
Win32 APIs. Missing applications/sources remain NOT_EXECUTED, never fake PASS.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import random
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import urllib.request
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from blackbox_core.decoder_index import file_hash
from blackbox_core.decoder_service import decode_file
from blackbox_core.optional_jobs import OwnedProcess

NPP_VERSION = "8.9.8.1"
NPP_ARCHIVE = "npp.8.9.8.1.portable.x64.zip"
NPP_URL = ("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/"
           f"download/v{NPP_VERSION}/{NPP_ARCHIVE}")
# Independently matched official npp.8.9.8.1.checksums.sha256 AND the GitHub
# release-asset digest on 2026-10-28. No floating 'latest' URL is executed.
NPP_SHA256 = "beddf5548e75c97930d1575ba1c7d113e6e2b33d0a200310e734ca08e225f414"
MAX_DOWNLOAD = 32 * 1024**2
MAX_TRACE = 256 * 1024**2


class NotExecuted(Exception):
    """A real prerequisite is absent; it is not an application success."""


def require(value, message):
    if not value:
        raise AssertionError(message)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2,
                                    allow_nan=False), encoding="utf-8")


def safe_extract(archive, destination):
    """Reject paths/types/bombs before writing anything into a fresh QA root."""
    destination = Path(destination)
    require(not destination.exists(), "APP_EXTRACTION_DESTINATION_EXISTS")
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        require(len(infos) <= 3000 and sum(x.file_size for x in infos) <= 128 * 1024**2,
                "APP_ARCHIVE_BUDGET")
        seen = set()
        regular = set()
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            require(name and path.parts and not path.is_absolute() and ".." not in path.parts and
                    "\\" not in name and ":" not in name and
                    name.casefold() not in seen and
                    mode not in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO),
                    "UNSAFE_APP_ARCHIVE")
            seen.add(name.casefold())
            if not info.is_dir():
                regular.add(name.casefold())
        for info in infos:
            parts = PurePosixPath(info.filename).parts
            require(all("/".join(parts[:i]).casefold() not in regular
                        for i in range(1, len(parts))), "APP_ARCHIVE_FILE_DIRECTORY_COLLISION")
        destination.mkdir()
        for info in infos:
            # This fixture does not execute the bundled updater or plugins.
            if PurePosixPath(info.filename).parts[0].lower() in ("updater", "plugins"):
                continue
            z.extract(info, destination)


def pinned_notepad(output):
    archive = output / NPP_ARCHIVE
    try:
        with urllib.request.urlopen(NPP_URL, timeout=30) as response, archive.open("xb") as stream:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                require(total <= MAX_DOWNLOAD, "NOTEPAD_DOWNLOAD_BUDGET")
                stream.write(block)
    except (OSError, TimeoutError) as exc:
        raise NotExecuted("PINNED_NOTEPAD_DOWNLOAD_UNAVAILABLE: " + str(exc)[:200]) from exc
    require(file_hash(archive) == NPP_SHA256, "PINNED_NOTEPAD_HASH_MISMATCH")
    folder = output / "notepad-portable"
    safe_extract(archive, folder)
    binary = folder / "notepad++.exe"
    require(binary.is_file(), "PINNED_NOTEPAD_BINARY_MISSING")
    return binary, {"version": NPP_VERSION, "source_url": NPP_URL,
                    "archive_sha256": NPP_SHA256,
                    "provenance": "PINNED_OFFICIAL_PORTABLE_DOWNLOAD_SHA256_VERIFIED",
                    "checksum_source": NPP_URL.rsplit("/", 1)[0] +
                    f"/npp.{NPP_VERSION}.checksums.sha256",
                    "isolation": "OWNED_PORTABLE_NO_PLUGINS_OR_UPDATER"}


def installed(name, candidates):
    # Package-manager PATH entries can be launcher shims whose CPU, stacks and
    # files belong to the launcher, while the application runs as its child.
    choices = [*candidates, shutil.which(name)]
    for item in choices:
        if item and Path(item).is_file() and not Path(item).is_symlink():
            return Path(item).resolve()
    raise NotExecuted("APPLICATION_NOT_INSTALLED: " + name)


def native_pe_identity(binary):
    """Require a native executable, not a CLR-based package-manager launcher."""
    size = Path(binary).stat().st_size
    with Path(binary).open("rb") as stream:
        dos = stream.read(64)
        require(len(dos) == 64 and dos[:2] == b"MZ", "NATIVE_APP_DOS_HEADER_MISSING")
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        require(64 <= pe_offset <= min(size - 24, 1024**2), "NATIVE_APP_PE_HEADER_OUTSIDE_FILE")
        stream.seek(pe_offset)
        coff = stream.read(24)
        require(len(coff) == 24 and coff[:4] == b"PE\0\0", "NATIVE_APP_PE_HEADER_MISSING")
        machine, = struct.unpack_from("<H", coff, 4)
        optional_size, characteristics = struct.unpack_from("<HH", coff, 20)
        require(characteristics & 0x2 and not characteristics & 0x2000 and
                96 <= optional_size <= 4096, "NATIVE_APP_NOT_EXECUTABLE_IMAGE")
        optional = stream.read(optional_size)
        require(len(optional) == optional_size, "NATIVE_APP_OPTIONAL_HEADER_TRUNCATED")
        magic, = struct.unpack_from("<H", optional)
        require(magic in (0x10B, 0x20B), "NATIVE_APP_PE_MAGIC_UNSUPPORTED")
        directory_at = 96 if magic == 0x10B else 112
        require(optional_size >= directory_at, "NATIVE_APP_OPTIONAL_HEADER_TRUNCATED")
        count, = struct.unpack_from("<I", optional, directory_at - 4)
        require(count <= (optional_size - directory_at) // 8, "NATIVE_APP_DIRECTORY_TRUNCATED")
        clr = struct.unpack_from("<II", optional, directory_at + 14 * 8) if count > 14 else (0, 0)
        require(clr == (0, 0), "NATIVE_APP_CLR_LAUNCHER_OR_MANAGED_IMAGE_REJECTED")
    return {"format": "PE32" if magic == 0x10B else "PE32_PLUS",
            "machine": hex(machine), "clr_com_descriptor_rva": clr[0],
            "clr_com_descriptor_bytes": clr[1],
            "code_kind": "NATIVE_PE_NO_CLR_COM_DESCRIPTOR"}


def observed_process_image(image_path, binary):
    """Bind counters to the requested image before accepting its observations."""
    observed = Path(image_path).resolve(strict=True)
    require(os.path.samefile(observed, binary), "APP_OWNED_PROCESS_IMAGE_MISMATCH")
    return str(observed)


def owned_process_identity(process, binary):
    """Retain identity even when a fast extraction exits before psutil attaches.

    Popen owns this Windows process handle until cleanup. Its image and creation
    time are queried directly, without reopening an exited or reused PID.
    """
    require(os.name == "nt", "OWNED_WINDOWS_PROCESS_IDENTITY_REQUIRED")
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = W.BOOL
    kernel.GetProcessTimes.argtypes = [W.HANDLE, *([C.POINTER(W.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = W.BOOL
    handle = W.HANDLE(int(process._handle))
    name = C.create_unicode_buffer(32768); length = W.DWORD(len(name))
    if not kernel.QueryFullProcessImageNameW(handle, 0, name, C.byref(length)):
        raise OSError(C.get_last_error(), "APP_OWNED_HANDLE_IMAGE_UNAVAILABLE")
    observed = observed_process_image(name.value, binary)
    created = W.FILETIME(); exited = W.FILETIME(); kernel_time = W.FILETIME(); user_time = W.FILETIME()
    if not kernel.GetProcessTimes(handle, C.byref(created), C.byref(exited),
                                  C.byref(kernel_time), C.byref(user_time)):
        raise OSError(C.get_last_error(), "APP_OWNED_HANDLE_CREATION_TIME_UNAVAILABLE")
    ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
    return {"observed_image": str(observed), "owned_image_matches_requested": True,
            "image_identity_source": "OWNED_WINDOWS_PROCESS_HANDLE",
            "created": (ticks - 116444736000000000) / 10000000,
            "creation_time_filetime_ticks": str(ticks)}


def binary_identity(binary, *, version_args=None):
    data = {"path": str(binary), "sha256": file_hash(binary),
            "bytes": binary.stat().st_size, "provenance": "RUNNER_INSTALLED_EXACT_BINARY"}
    if version_args:
        probe = subprocess.run([str(binary), *version_args], capture_output=True,
                               timeout=15, text=True, errors="replace")
        require(probe.returncode == 0, "APP_VERSION_PROBE_FAILED")
        data["version_output"] = probe.stdout[:2000].strip()
    return data


def monitored_run(args, log, *, env=None, timeout=30):
    """Sample only a process launched here; terminate only its owned job."""
    import psutil
    with Path(log).open("xb") as stream:
        owner = OwnedProcess(args, stdout=stream, stderr=stream, env=env)
        p = owner.process
        proof = {"pid": p.pid, "cpu_seconds_observed": 0., "peak_rss_observed": 0,
                 "max_threads_observed": 0, "write_bytes_observed": 0,
                 "read_bytes_observed": 0}
        try:
            proof.update(owned_process_identity(p, args[0]))
            try:
                sensor = psutil.Process(p.pid)
            except psutil.NoSuchProcess:
                sensor = None
            deadline = time.monotonic() + timeout
            while p.poll() is None:
                require(time.monotonic() < deadline, "APP_WORKLOAD_DEADLINE")
                try:
                    if sensor is None:
                        sensor = psutil.Process(p.pid)
                    with sensor.oneshot():
                        cpu = sensor.cpu_times()
                        proof["cpu_seconds_observed"] = max(proof["cpu_seconds_observed"], cpu.user + cpu.system)
                        proof["peak_rss_observed"] = max(proof["peak_rss_observed"], sensor.memory_info().rss)
                        require(proof["peak_rss_observed"] <= 1024**3, "APP_WORKLOAD_RSS_BUDGET")
                        proof["max_threads_observed"] = max(proof["max_threads_observed"], sensor.num_threads())
                        io = sensor.io_counters()
                        for key in ("write_bytes", "read_bytes"):
                            proof[key + "_observed"] = max(proof[key + "_observed"], getattr(io, key))
                except psutil.NoSuchProcess:
                    break
                require(Path(log).stat().st_size <= 4 * 1024**2, "APP_WORKLOAD_LOG_BUDGET")
                time.sleep(.025)
            proof["exit_code"] = p.wait(timeout=5)
            require(proof["exit_code"] == 0, "APP_WORKLOAD_EXIT_NONZERO")
        finally:
            owner.close(kill=True)
    return proof


def decode_trace(source, output, helper):
    require(0 < source.stat().st_size <= MAX_TRACE, "ACTUAL_TRACE_SIZE_BUDGET")
    digest = file_hash(source)
    index = output / "decoded.sqlite3"
    with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
        meta = decode_file(source, index, timeout=90)
    require(meta["status"] == "DECODED" and meta["rows"] > 0,
            "APP_TRACE_NOT_COMPLETELY_DECODED")
    require(file_hash(source) == digest and meta["input_sha256"] == digest,
            "APP_TRACE_HASH_CHANGED")
    write_json(output / "decoder-summary.json", meta)
    return index, meta, {"path": str(source), "sha256": digest,
                         "bytes": source.stat().st_size, "index": str(index)}


def etw_observations(index, pids):
    from blackbox_core.decoder_cpu import classify_cpu_sample
    pids = set(pids)
    result = {"owned_pids": sorted(pids), "events": 0, "cpu_samples": 0,
              "cpu_samples_with_stacks": 0, "file_events": 0,
              "thread_events": 0, "schedule_events": 0, "event_names": {}}
    instances = {pid: set() for pid in pids}
    with closing(sqlite3.connect(index.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        for data, in db.execute("SELECT data FROM events"):
            row = json.loads(data)
            schedule = row.get("thread_schedule") or {}
            # The new typed schedule can attribute the outgoing thread while
            # generic ETW header PID belongs to the incoming thread.
            schedule_matches = any(isinstance(v, dict) and v.get("pid") in pids
                                   for v in schedule.values())
            if schedule_matches or row.get("pid") in pids and schedule:
                result["schedule_events"] += 1
            if row.get("pid") not in pids:
                continue
            result["events"] += 1
            if row.get("process_instance") is not None:
                instances[row["pid"]].add(row["process_instance"])
            name = row.get("name", "")
            if len(result["event_names"]) < 100 or name in result["event_names"]:
                result["event_names"][name] = result["event_names"].get(name, 0) + 1
            if classify_cpu_sample(row, "etw") == "PROCESS_SAMPLE":
                result["cpu_samples"] += 1
                result["cpu_samples_with_stacks"] += bool(row.get("frames"))
            if name.startswith(("FileIO/", "DiskIO/")):
                result["file_events"] += 1
            if name.startswith("Thread/"):
                result["thread_events"] += 1
    result["process_instances"] = {str(pid): sorted(values) for pid, values in instances.items()}
    result["pid_reuse_ambiguous"] = any(len(values) > 1 for values in instances.values())
    result["pid_lifetimes_confirmed"] = bool(pids) and all(len(values) == 1 for values in instances.values())
    return result


def start_schedule(output):
    from tools.qa_schedule_capture import OwnedScheduleCapture
    from blackbox_core.windows_research import privilege, wpr_tool
    if privilege()["mode"] != "ADMINISTRATOR" or not wpr_tool():
        raise NotExecuted("NATIVE_ETW_REQUIRES_WPR_AND_ADMINISTRATOR")
    capture = OwnedScheduleCapture(output)
    capture.start()
    return capture


def finish_schedule(capture, output, helper, pids, *, waits=False):
    raw = capture.stop()
    source = output / raw["path"]
    index, meta, identity = decode_trace(source, output, helper)
    observations = etw_observations(index, pids)
    from blackbox_core.decoder_waits import build_wait_report
    reports = []
    for pid in pids if waits else []:
        report = build_wait_report(index, pid=pid)
        write_json(output / f"waits-{pid}.json", report)
        reports.append({"pid": pid, "report": f"waits-{pid}.json",
                        "status": report.get("status"), "coverage": report.get("coverage"),
                        "totals": report.get("totals")})
    return {"trace": identity, "decoder_status": meta["status"],
            "observations": observations, "wait_reports": reports,
            "capture_complete": "UNKNOWN", "root_cause": "NOT_ESTABLISHED"}


def seven_zip(output, helper):
    binary = installed("7z", [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "7-Zip/7z.exe"])
    native = native_pe_identity(binary)
    identity = {**binary_identity(binary, version_args=["i"]), "native_image": native}
    source = output / "input.bin"
    rng = random.Random(20261028)
    source.write_bytes(rng.randbytes(8 * 1024**2))
    digest = file_hash(source)
    capture = start_schedule(output)
    proofs = []
    try:
        started = time.monotonic()
        for cycle in range(3):
            archive = output / f"roundtrip-{cycle}.7z"
            destination = output / f"roundtrip-{cycle}"
            proofs.append(monitored_run([str(binary), "a", "-t7z", "-mx=7", "-mmt=2", "-bd", "-y",
                                         str(archive), str(source)], output / f"compress-{cycle}.log"))
            proofs.append(monitored_run([str(binary), "x", "-bd", "-y", "-o" + str(destination),
                                         str(archive)], output / f"extract-{cycle}.log"))
            require(file_hash(destination / source.name) == digest,
                    "SEVENZIP_ROUNDTRIP_HASH_MISMATCH")
            if time.monotonic() - started >= 4:
                break
        trace = finish_schedule(capture, output, helper, [x["pid"] for x in proofs])
    finally:
        if capture.active:
            capture.cancel()
    observed = trace["observations"]
    checks = {"compression_extraction_hash_roundtrip": True,
              "owned_native_image_identity": all(x["owned_image_matches_requested"] for x in proofs),
              "cpu_counters": any(x["cpu_seconds_observed"] > 0 for x in proofs),
              "etw_cpu_samples": observed["cpu_samples"] > 0,
              "etw_cpu_stacks": observed["cpu_samples_with_stacks"] > 0,
              "etw_file_operations": observed["file_events"] > 0,
              "etw_threads": observed["thread_events"] > 0,
              "pid_lifetime_attribution": observed["pid_lifetimes_confirmed"]}
    result = {"status": "PASS" if all(checks.values()) else "FAIL",
            "capabilities": {k: "PASS" if v else "FAIL_NOT_OBSERVED" for k, v in checks.items()},
            "application": identity, "workloads": proofs,
            "oracle": {"input_bytes": source.stat().st_size, "input_sha256": digest,
                       "roundtrips_verified": len(proofs) // 2}, **trace}
    return result


POWERSHELL_WORKLOAD = r'''
param([string]$Output)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Diagnostics.Tracing;
[EventSource(Name="BlackBox-Apps-QA")]
public sealed class AppEvents : EventSource {
  public static readonly AppEvents Log = new AppEvents();
  [Event(1)] public void Phase(string phase) { WriteEvent(1, phase); }
}
public static class BlackBoxAppsProbe {
  public static long[] Run() {
    AppEvents.Log.Phase("START");
    long total = 0, loops = 0, checksum = 0;
    int gc = GC.CollectionCount(2);
    var timer = Stopwatch.StartNew();
    while (timer.ElapsedMilliseconds < 4000) {
      byte[] buffer = new byte[1024 * 1024];
      for (int i=0; i<buffer.Length; i+=4096) buffer[i]=(byte)(i+loops);
      total += buffer.Length;
      for (int i=0; i<100000; i++) checksum = (checksum + i * 17L) % 1000000007L;
      if (++loops % 8 == 0) GC.Collect(2, GCCollectionMode.Forced, true, true);
      GC.KeepAlive(buffer);
    }
    GC.Collect(2, GCCollectionMode.Forced, true, true);
    AppEvents.Log.Phase("COMPLETE");
    return new long[] { total, loops, GC.CollectionCount(2)-gc, checksum };
  }
}
'@
$result = [BlackBoxAppsProbe]::Run()
[ordered]@{pid=$PID; version=$PSVersionTable.PSVersion.ToString();
 allocated_bytes=$result[0]; loops=$result[1]; gen2_collections=$result[2];
 checksum=$result[3]; status='COMPLETED'} | ConvertTo-Json | Set-Content -Encoding utf8 $Output
'''


def powershell(output, helper):
    binary = installed("pwsh", [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "PowerShell/7/pwsh.exe"])
    identity = binary_identity(binary, version_args=["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
    script = output / "workload.ps1"
    script.write_text(POWERSHELL_WORKLOAD, encoding="utf-8")
    result_path = output / "workload-result.json"
    source = output / "powershell.nettrace"
    env = {**os.environ, "DOTNET_EnableEventPipe": "1", "DOTNET_EventPipeOutputPath": str(source),
           "DOTNET_EventPipeCircularMB": "16", "DOTNET_EventPipeOutputStreaming": "1",
           "DOTNET_EventPipeConfig": "Microsoft-Windows-DotNETRuntime:0x19:5,BlackBox-Apps-QA:0xFFFFFFFFFFFFFFFF:5,Microsoft-DotNETCore-SampleProfiler:0x0:5"}
    workload = monitored_run([str(binary), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
                              "-Output", str(result_path)], output / "powershell.log", env=env, timeout=60)
    oracle = json.loads(result_path.read_text(encoding="utf-8-sig"))
    require(oracle["pid"] == workload["pid"] and oracle["allocated_bytes"] > 0 and
            oracle["gen2_collections"] > 0 and oracle["status"] == "COMPLETED",
            "POWERSHELL_WORKLOAD_ORACLE_FAILED")
    index, meta, identity_trace = decode_trace(source, output, helper)
    phases = []; frames = 0; allocations = 0
    with closing(sqlite3.connect(index.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        for data, in db.execute("SELECT data FROM events WHERE pid=?", (workload["pid"],)):
            row = json.loads(data)
            if row.get("provider") == "BlackBox-Apps-QA":
                phases.append(row.get("payload", {}).get("phase"))
            frames += any("BlackBoxAppsProbe" in f.get("name", "") for f in row.get("frames", []))
            allocations += "AllocationTick" in row.get("name", "")
    profiles = meta.get("profiles", {})
    checks = {"real_workload_phase_events": "START" in phases and "COMPLETE" in phases,
              "gc_pairs": meta.get("gc", {}).get("gc_pairs", 0) > 0,
              "managed_cpu_samples_with_stacks": profiles.get("cpu_profiler_samples_with_stacks", 0) > 0,
              "known_workload_managed_frames": frames > 0,
              "allocation_events": allocations > 0,
              "allocation_and_gc_oracle": True}
    return {"status": "PASS" if all(checks.values()) else "FAIL",
            "capabilities": {k: "PASS" if v else "FAIL_NOT_OBSERVED" for k, v in checks.items()},
            "application": identity, "workload": workload,
            "oracle": oracle, "trace": identity_trace,
            "observations": {"phase_events": phases, "workload_stack_events": frames,
                             "allocation_tick_events": allocations, "gc": meta.get("gc"),
                             "profiles": profiles},
            "scope": "REAL_POWERSHELL_7_RUNNING_CONTROLLED_MANAGED_SCRIPT",
            "capture_complete": "UNKNOWN", "root_cause": "NOT_ESTABLISHED"}


def owned_windows(pid):
    user = C.WinDLL("user32", use_last_error=True)
    callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [callback, W.LPARAM]
    user.EnumChildWindows.argtypes = [W.HWND, callback, W.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    user.IsWindowVisible.argtypes = [W.HWND]
    user.IsWindowVisible.restype = W.BOOL
    found = []
    @callback
    def collect(hwnd, _):
        owner = W.DWORD()
        tid = user.GetWindowThreadProcessId(hwnd, C.byref(owner))
        if owner.value == pid:
            name = C.create_unicode_buffer(256)
            user.GetClassNameW(hwnd, name, 256)
            found.append({"hwnd": int(hwnd), "tid": tid, "class": name.value,
                          "visible": bool(user.IsWindowVisible(hwnd))})
        return True
    user.EnumWindows(collect, 0)
    for row in list(found):
        user.EnumChildWindows(row["hwnd"], collect, 0)
    return found


def send_owned(pid, hwnd, message, wparam=0, lparam=0):
    """Only pointer-free commands to a window revalidated as our owned child."""
    user = C.WinDLL("user32", use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM,
                                        W.UINT, W.UINT, C.POINTER(C.c_size_t)]
    user.SendMessageTimeoutW.restype = C.c_ssize_t
    owner = W.DWORD(); user.GetWindowThreadProcessId(hwnd, C.byref(owner))
    require(owner.value == pid, "NOTEPAD_WINDOW_OWNERSHIP_CHANGED")
    result = C.c_size_t()
    C.set_last_error(0)
    ok = user.SendMessageTimeoutW(hwnd, message, wparam, lparam, 0x2 | 0x20, 500, C.byref(result))
    require(ok, "OWNED_GUI_MESSAGE_FAILED_" + str(C.get_last_error()))
    return result.value


def notepad(output, helper):
    from blackbox_core.windows_research import window_observations
    binary, source_proof = pinned_notepad(output)
    identity = {**binary_identity(binary), **source_proof}
    source = output / "edited.txt"
    original = "BLACKBOX OWNED NOTEPAD ACCEPTANCE\r\n" * 128
    source.write_bytes(original.encode("ascii"))
    marker = "BLACKBOX_QA_APPENDED_20261028"
    capture = start_schedule(output)
    owner = None
    try:
        owner = OwnedProcess([str(binary), "-multiInst", "-nosession", "-noPlugin", str(source)])
        pid = owner.process.pid
        deadline = time.monotonic() + 15
        main = editor = None
        while time.monotonic() < deadline and owner.process.poll() is None:
            windows = owned_windows(pid)
            main = next((w for w in windows if w["class"] == "Notepad++"), None)
            editor = next((w for w in windows if w["class"] == "Scintilla" and w["visible"]), None)
            if main and editor:
                try:
                    if send_owned(pid, editor["hwnd"], 2006) == len(original):
                        break
                except AssertionError:
                    # Startup may still be loading the owned document. The
                    # overall deadline and process identity remain bounded.
                    pass
            time.sleep(.05)
        require(main and editor, "NOTEPAD_OWNED_EDITOR_WINDOW_MISSING")
        before = window_observations(pid)
        length = send_owned(pid, editor["hwnd"], 2006)  # SCI_GETLENGTH; no pointer.
        require(length == len(original), "NOTEPAD_INPUT_FILE_NOT_LOADED")
        send_owned(pid, editor["hwnd"], 2160, length, length)  # SCI_SETSEL.
        for character in marker:
            send_owned(pid, editor["hwnd"], 0x0102, ord(character))  # WM_CHAR.
        send_owned(pid, main["hwnd"], 0x0111, 41006)  # WM_COMMAND / IDM_FILE_SAVE.
        expected = (original + marker).encode("ascii")
        deadline = time.monotonic() + 5
        while source.read_bytes() != expected and time.monotonic() < deadline:
            time.sleep(.05)
        require(source.read_bytes() == expected, "NOTEPAD_REAL_SAVE_BYTES_MISMATCH")
        # Observe several idle message-loop waits, not an invented hang.
        responsiveness = [before]
        for _ in range(6):
            time.sleep(.2)
            responsiveness.append(window_observations(pid))
        require(any(w.get("status") == "RESPONDED" for item in responsiveness for w in item["windows"]),
                "NOTEPAD_WINDOW_RESPONSE_NOT_OBSERVED")
        trace = finish_schedule(capture, output, helper, [pid], waits=True)
        observed = trace["observations"]
        checks = {"open_edit_save_exact_bytes": True, "win32_window_responsiveness": True,
                  "etw_file_operations": observed["file_events"] > 0,
                  "etw_scheduler_events": observed["schedule_events"] > 0,
                  "observed_off_cpu_intervals": any(
                      r.get("coverage", {}).get("represented_intervals", 0) > 0 and
                      r.get("totals", {}).get("observed_off_cpu_ms", 0) > 0
                      for r in trace["wait_reports"]),
                  "pid_lifetime_attribution": observed["pid_lifetimes_confirmed"]}
        send_owned(pid, main["hwnd"], 0x0010)  # WM_CLOSE after verified save.
        owner.process.wait(timeout=10)
        return {"status": "PASS" if all(checks.values()) else "FAIL",
                "capabilities": {k: "PASS" if v else "FAIL_NOT_OBSERVED" for k, v in checks.items()},
                "application": identity, "pid": pid,
                "oracle": {"opened_bytes": len(original), "saved_bytes": len(expected),
                           "saved_sha256": hashlib.sha256(expected).hexdigest()},
                "window_observations": responsiveness, **trace,
                "hang_or_lock_cause": "NOT_CLAIMED_RESPONSIVE_IDLE_WORKLOAD"}
    finally:
        if capture.active:
            capture.cancel()
        if owner is not None:
            owner.close(kill=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "source_sha": os.environ.get("GITHUB_SHA"),
              "applications": {}, "physical_windows_10_11_acceptance": False,
              "scope": "DISPOSABLE_WINDOWS_CI_OWNED_THIRD_PARTY_WORKLOADS",
              "root_cause": "NOT_ESTABLISHED", "network_symbol_download": False}
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        report.update(status="NOT_EXECUTED", reason="ACTUAL_DISPOSABLE_WINDOWS_CI_REQUIRED")
        write_json(output / "apps-qa.json", report)
        return 2
    from blackbox_core.windows_research import privilege
    report["privilege"] = privilege()
    report["privilege_scope"] = "THIS_RUNNER_TOKEN_ONLY_NOT_A_STANDARD_ADMIN_MATRIX"
    helper = args.helper.resolve(strict=True)
    report["decoder_helper_sha256"] = file_hash(helper)
    started = time.monotonic()
    for name, run in (("7-Zip", seven_zip), ("PowerShell 7", powershell), ("Notepad++", notepad)):
        work = output / {"7-Zip": "7zip", "PowerShell 7": "powershell", "Notepad++": "notepad"}[name]
        work.mkdir()
        try:
            item = run(work, helper)
        except NotExecuted as exc:
            item = {"status": "NOT_EXECUTED", "reason": str(exc)[:500]}
        except Exception as exc:
            item = {"status": "FAIL", "error": type(exc).__name__, "reason": str(exc)[:1000]}
        report["applications"][name] = item
        write_json(work / "application-qa.json", item)
        write_json(output / "apps-qa.json", report)
    states = [x["status"] for x in report["applications"].values()]
    report["status"] = "FAIL" if "FAIL" in states else "NOT_EXECUTED" if "NOT_EXECUTED" in states else "PASS"
    report["duration_seconds"] = time.monotonic() - started
    write_json(output / "apps-qa.json", report)
    print("THIRD_PARTY_DECODER_QA_" + report["status"])
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "NOT_EXECUTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
