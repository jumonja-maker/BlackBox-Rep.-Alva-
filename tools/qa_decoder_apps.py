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
import math
import os
from pathlib import Path, PurePosixPath
import random
import re
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
# Only the controlled native-noise pair opts in. This does not change product
# timeouts, ordinary acceptance, or the separate noise/whole-diagnostic limits.
QA_WORKLOAD_POLICIES = {'ORDINARY_30': 30, 'CONTROLLED_NATIVE_60': 60}


def workload_policy_seconds(policy):
    require(type(policy) is str and policy in QA_WORKLOAD_POLICIES, 'UNKNOWN_FIXED_QA_WORKLOAD_POLICY')
    return QA_WORKLOAD_POLICIES[policy]


class NotExecuted(Exception):
    """A real prerequisite is absent; it is not an application success."""


def require(value, message):
    if not value:
        raise AssertionError(message)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2,
                                    allow_nan=False), encoding="utf-8")


def print_failure_diagnostics(report):
    """Print only controlled result metadata, never workload/source contents."""
    if report.get('status') == 'PASS':
        return
    keys = {
        '7-Zip': ('compression_extraction_hash_roundtrip','owned_native_image_identity',
            'cpu_counters','etw_cpu_samples','etw_cpu_stacks','etw_file_operations',
            'etw_threads','pid_lifetime_attribution'),
        'PowerShell 7': ('real_workload_phase_events','gc_pairs','managed_cpu_samples_with_stacks',
            'known_workload_managed_frames','allocation_events','allocation_and_gc_oracle'),
        'Notepad++': ('open_edit_save_exact_bytes','win32_window_responsiveness',
            'etw_file_operations','etw_scheduler_events','observed_off_cpu_intervals',
            'pid_lifetime_attribution')}
    result = {}
    for name, capabilities in keys.items():
        item = report.get('applications', {}).get(name, {})
        reason = item.get('reason')
        code = reason.split(':',1)[0] if type(reason) is str else None
        if code is not None and (not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',code) or
                not code.startswith(('APP_','APPLICATION_','NOTEPAD_','PINNED_NOTEPAD_','NATIVE_',
                    'ACTUAL_','POWERSHELL_','DECODER_','INVALID_','WAIT_','TYPED_',
                    'IMPORT_','DECODE_','OPTIONAL_','OWNED_','SOURCE_','INDEX_','TRACE_'))):
            code = 'NON_CODE_REASON_WITHHELD'
        error = item.get('error')
        result[name] = {'status':item.get('status') if item.get('status') in
            ('PASS','FAIL','NOT_EXECUTED') else 'NOT_RECORDED',
            'error_type':error if type(error) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}',error) else None,
            'reason_code':code,
            'capabilities':{key:value for key in capabilities
                for value in [(item.get('capabilities') or {}).get(key)]
                if value in ('PASS','FAIL_NOT_OBSERVED')}}
    print('THIRD_PARTY_DECODER_FAILURE_DIAGNOSTICS '+json.dumps({
        'scope':'FIXED_APPLICATION_STATUS_CODES_ONLY_NO_PAYLOAD_PATH_ADDRESS_ENVIRONMENT_OR_URL',
        'applications':result},sort_keys=True),flush=True)


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
            "creation_time_filetime_ticks": str(ticks),
            "cpu_user_seconds_held_handle": ((user_time.dwHighDateTime << 32) | user_time.dwLowDateTime) / 10000000,
            "cpu_kernel_seconds_held_handle": ((kernel_time.dwHighDateTime << 32) | kernel_time.dwLowDateTime) / 10000000,
            "exit_time_filetime_ticks": str((exited.dwHighDateTime << 32) | exited.dwLowDateTime)}


class _PriorityClientId(C.Structure):
    _fields_ = [('process', C.c_size_t), ('thread', C.c_size_t)]


class _PriorityFileTime(C.Structure):
    _fields_ = [('dwLowDateTime', C.c_uint32), ('dwHighDateTime', C.c_uint32)]


class _ThreadBasicPriorityInformation(C.Structure):
    # ThreadBasicInformation contains priorities, not ThreadState/wait reason.
    _fields_ = [('exit_status', C.c_int32), ('teb', C.c_void_p), ('client_id', _PriorityClientId),
                ('affinity', C.c_size_t), ('priority', C.c_int32), ('base_priority', C.c_int32)]


_retained_priority_query_handles = []
MAX_RETAINED_PRIORITY_QUERY_HANDLES = 128
_PRIORITY_ERROR_CODES = frozenset({
    'PRIORITY_UNSUPPORTED_NATIVE_ABI', 'PRIORITY_QUERY_BUDGET', 'PRIORITY_BIRTH_INVALID',
    'PRIORITY_BIRTH_QUERY_FAILED', 'PRIORITY_COUNTER_UNAVAILABLE',
    'PRIORITY_PROCESS_IDENTITY_CHANGED_OR_EXITED', 'PRIORITY_THREAD_OWNER_OR_EXIT_UNCONFIRMED',
    'PRIORITY_THREAD_BIRTH_CHANGED', 'PRIORITY_OWNED_PROCESS_INVALID', 'PRIORITY_THREAD_COUNT_UNSUPPORTED',
    'PRIORITY_THREAD_IDS_AMBIGUOUS', 'PRIORITY_THREAD_IDS_INVALID', 'PRIORITY_CLASS_UNAVAILABLE',
    'PRIORITY_PROCESS_BOOST_UNAVAILABLE', 'PRIORITY_RETAINED_QUERY_HANDLE_CAP',
    'PRIORITY_THREAD_OPEN_UNAVAILABLE', 'PRIORITY_NATIVE_QUERY_UNSUPPORTED',
    'PRIORITY_NATIVE_IDENTITY_OR_VALUE_INVALID', 'PRIORITY_THREAD_BOOST_UNAVAILABLE',
})


def _priority_native_api():
    require(os.name == 'nt' and C.sizeof(C.c_void_p) == 8 and
            C.sizeof(_PriorityFileTime) == 8 and
            C.sizeof(_ThreadBasicPriorityInformation) == 48 and
            _ThreadBasicPriorityInformation.priority.offset == 40 and
            _ThreadBasicPriorityInformation.base_priority.offset == 44,
            'PRIORITY_UNSUPPORTED_NATIVE_ABI')
    kernel = C.WinDLL('kernel32', use_last_error=True, winmode=0x800)
    native = C.WinDLL('ntdll', use_last_error=True, winmode=0x800)
    prototypes = {
        'GetProcessId': ([C.c_void_p], C.c_uint32),
        'GetThreadId': ([C.c_void_p], C.c_uint32),
        'GetProcessIdOfThread': ([C.c_void_p], C.c_uint32),
        'WaitForSingleObject': ([C.c_void_p, C.c_uint32], C.c_uint32),
        'GetProcessTimes': ([C.c_void_p, *([C.POINTER(_PriorityFileTime)] * 4)], C.c_int32),
        'GetThreadTimes': ([C.c_void_p, *([C.POINTER(_PriorityFileTime)] * 4)], C.c_int32),
        'GetPriorityClass': ([C.c_void_p], C.c_uint32),
        'GetProcessPriorityBoost': ([C.c_void_p, C.POINTER(C.c_int32)], C.c_int32),
        'GetProcessAffinityMask': ([C.c_void_p, C.POINTER(C.c_size_t), C.POINTER(C.c_size_t)], C.c_int32),
        'GetThreadPriorityBoost': ([C.c_void_p, C.POINTER(C.c_int32)], C.c_int32),
        'OpenThread': ([C.c_uint32, C.c_int32, C.c_uint32], C.c_void_p),
        'CloseHandle': ([C.c_void_p], C.c_int32),
        'QueryPerformanceCounter': ([C.POINTER(C.c_int64)], C.c_int32),
        'QueryPerformanceFrequency': ([C.POINTER(C.c_int64)], C.c_int32),
    }
    for name, (arguments, result) in prototypes.items():
        function = getattr(kernel, name)
        function.argtypes = arguments; function.restype = result
    native.NtQueryInformationThread.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p,
                                               C.c_uint32, C.POINTER(C.c_uint32)]
    native.NtQueryInformationThread.restype = C.c_int32
    return kernel, native


def observe_owned_thread_priorities(process, expected_creation_time, thread_births=None):
    """Read bounded scheduling facts through held, identity-checked handles.

    Two seconds is a best-effort query budget checked between APIs, never an
    OS deadline. No thread is suspended, waited for, reprioritized or mutated.
    Failed query-handle closure retains its capability and cannot be OBSERVED.
    """
    retained_before = len(_retained_priority_query_handles)
    result = {'schema': 'blackbox.owned-thread-priorities/1', 'status': 'NOT_ESTABLISHED',
        'scope': 'READ_ONLY_PRIORITIES_NOT_THREAD_STATE_WAIT_REASON_OR_CAUSE', 'queries_atomic': False,
        'query_budget_seconds': 2, 'budget_scope': 'CHECKED_BETWEEN_APIS_NOT_HARD_OS_BOUND',
        'process_identity_verified_before': False, 'process_identity_verified_after': False,
        'query_handles_closed_verified': retained_before == 0, 'cleanup_required': retained_before > 0,
        'retained_query_handles_before': retained_before,
        'query_handles_opened': 0, 'query_handles_closed': 0,
        'cleanup_scope': 'QUERY_HANDLES_ONLY_NOT_WORKLOAD_OR_JOB_CLEANUP_PROOF',
        'runtime_reported_logical_processors': 'NOT_ESTABLISHED',
        'processor_count_scope': 'RUNTIME_REPORTED_NOT_QUOTA_OR_EXCLUSIVE_ENTITLEMENT',
        'affinity': {'status': 'NOT_ESTABLISHED', 'scope': 'PRIMARY_GROUP_MASK_BIT_COUNTS_NOT_CPU_QUOTA'},
        'process_cpu': {'status': 'NOT_ESTABLISHED', 'scope': 'HELD_PROCESS_CUMULATIVE_100NS_NOT_UTILIZATION_OR_CAUSE'},
        'threads': [], 'errors': ['PRIORITY_PREVIOUS_QUERY_HANDLES_UNCONFIRMED'] if retained_before else []}
    deadline = time.monotonic() + 2
    last_cpu = {}
    try:
        logical = os.cpu_count()
        if type(logical) is int and 1 <= logical <= 4096:
            result['runtime_reported_logical_processors'] = logical
    except Exception:
        pass

    def check():
        require(time.monotonic() < deadline, 'PRIORITY_QUERY_BUDGET')

    def birth(value):
        require(type(value) is str and re.fullmatch(r'[0-9]{1,20}', value) and
                0 < int(value) <= 2**64 - 1, 'PRIORITY_BIRTH_INVALID')
        return int(value)

    def ticks(kernel, function, handle):
        check()
        first = _PriorityFileTime(); last = _PriorityFileTime(); kt = _PriorityFileTime(); ut = _PriorityFileTime()
        require(getattr(kernel, function)(handle, C.byref(first), C.byref(last), C.byref(kt), C.byref(ut)),
                'PRIORITY_BIRTH_QUERY_FAILED')
        if function == 'GetProcessTimes':
            last_cpu.update(user_100ns=(ut.dwHighDateTime << 32) | ut.dwLowDateTime,
                            kernel_100ns=(kt.dwHighDateTime << 32) | kt.dwLowDateTime)
        return (first.dwHighDateTime << 32) | first.dwLowDateTime

    def qpc(kernel, name='QueryPerformanceCounter'):
        check(); value = C.c_int64()
        require(getattr(kernel, name)(C.byref(value)) and 0 < value.value <= 2**63 - 1,
                'PRIORITY_COUNTER_UNAVAILABLE')
        return value.value

    def process_identity(kernel, handle, pid, expected):
        first_qpc = qpc(kernel)
        require(kernel.GetProcessId(handle) == pid and kernel.WaitForSingleObject(handle, 0) == 258 and
                ticks(kernel, 'GetProcessTimes', handle) == expected, 'PRIORITY_PROCESS_IDENTITY_CHANGED_OR_EXITED')
        return {**last_cpu, 'sample_begin_qpc': first_qpc, 'sample_end_qpc': qpc(kernel)}

    def thread_identity(kernel, handle, pid, tid, expected=None):
        check()
        require(kernel.GetThreadId(handle) == tid and kernel.GetProcessIdOfThread(handle) == pid and
                kernel.WaitForSingleObject(handle, 0) == 258, 'PRIORITY_THREAD_OWNER_OR_EXIT_UNCONFIRMED')
        actual = ticks(kernel, 'GetThreadTimes', handle)
        require(actual >= process_birth and (expected is None or actual == expected),
                'PRIORITY_THREAD_BIRTH_CHANGED')
        return actual

    try:
        kernel, native = _priority_native_api()
        pid = process.pid; handle = int(process._handle); process_birth = birth(expected_creation_time)
        require(type(pid) is int and 1 <= pid <= 2**32 - 1 and handle, 'PRIORITY_OWNED_PROCESS_INVALID')
        result['qpc_frequency_hz'] = qpc(kernel, 'QueryPerformanceFrequency')
        result['sample_begin_qpc'] = qpc(kernel)
        process_identity(kernel, handle, pid, process_birth)
        result.update(pid=pid, created_100ns=str(process_birth), process_identity_verified_before=True)
        if thread_births is None:
            import psutil
            check(); entries = psutil.Process(pid).threads()
            require(type(entries) is list and 1 <= len(entries) <= 32, 'PRIORITY_THREAD_COUNT_UNSUPPORTED')
            selected = {entry.id: None for entry in entries}
            require(len(selected) == len(entries), 'PRIORITY_THREAD_IDS_AMBIGUOUS')
        else:
            require(type(thread_births) is dict and 1 <= len(thread_births) <= 32,
                    'PRIORITY_THREAD_COUNT_UNSUPPORTED')
            selected = {tid: birth(created) for tid, created in thread_births.items()}
        require(all(type(tid) is int and 1 <= tid <= 2**32 - 1 for tid in selected),
                'PRIORITY_THREAD_IDS_INVALID')
        process_identity(kernel, handle, pid, process_birth)
        result['thread_count'] = len(selected)
        check(); priority_class = kernel.GetPriorityClass(handle)
        classes = {0x20: 'NORMAL', 0x40: 'IDLE', 0x80: 'HIGH', 0x100: 'REALTIME',
                   0x4000: 'BELOW_NORMAL', 0x8000: 'ABOVE_NORMAL'}
        require(priority_class in classes, 'PRIORITY_CLASS_UNAVAILABLE')
        process_boost = C.c_int32(); check()
        require(kernel.GetProcessPriorityBoost(handle, C.byref(process_boost)), 'PRIORITY_PROCESS_BOOST_UNAVAILABLE')
        process_mask = C.c_size_t(); system_mask = C.c_size_t(); check()
        if kernel.GetProcessAffinityMask(handle, C.byref(process_mask), C.byref(system_mask)) and process_mask.value and system_mask.value:
            result['affinity'].update(status='OBSERVED', process_mask_bit_count=process_mask.value.bit_count(),
                                      system_mask_bit_count=system_mask.value.bit_count())
        for tid, expected_thread_birth in sorted(selected.items()):
            check(); row = {'tid': tid, 'status': 'NOT_ESTABLISHED'}
            require(len(_retained_priority_query_handles) < MAX_RETAINED_PRIORITY_QUERY_HANDLES,
                    'PRIORITY_RETAINED_QUERY_HANDLE_CAP')
            # SYNCHRONIZE | THREAD_QUERY_INFORMATION; no suspend/write rights.
            thread = kernel.OpenThread(0x100000 | 0x40, False, tid)
            require(thread, 'PRIORITY_THREAD_OPEN_UNAVAILABLE')
            result['query_handles_opened'] += 1
            try:
                first_qpc = qpc(kernel)
                thread_birth = thread_identity(kernel, thread, pid, tid, expected_thread_birth)
                information = _ThreadBasicPriorityInformation(); returned = C.c_uint32()
                check()
                status = native.NtQueryInformationThread(thread, 0, C.byref(information),
                    C.sizeof(information), C.byref(returned))
                row['ntstatus'] = int(status) & 0xffffffff
                require(status == 0 and returned.value == C.sizeof(information), 'PRIORITY_NATIVE_QUERY_UNSUPPORTED')
                require(information.client_id.process == pid and information.client_id.thread == tid and
                        0 <= information.priority <= 31 and 0 <= information.base_priority <= 31,
                        'PRIORITY_NATIVE_IDENTITY_OR_VALUE_INVALID')
                disabled = C.c_int32(); check()
                require(kernel.GetThreadPriorityBoost(thread, C.byref(disabled)), 'PRIORITY_THREAD_BOOST_UNAVAILABLE')
                require(thread_identity(kernel, thread, pid, tid, thread_birth) == thread_birth,
                        'PRIORITY_THREAD_BIRTH_CHANGED')
                row.update(status='OBSERVED', created_100ns=str(thread_birth),
                    priority=information.priority, base_priority=information.base_priority,
                    priority_boost_disabled=bool(disabled.value), sample_begin_qpc=first_qpc,
                    sample_end_qpc=qpc(kernel))
            finally:
                try:
                    closed = bool(kernel.CloseHandle(thread))
                except BaseException:
                    closed = False
                if not closed:
                    _retained_priority_query_handles.append((kernel, thread, process))
                    result.update(query_handles_closed_verified=False, cleanup_required=True)
                    row['status'] = 'NOT_ESTABLISHED'
                    result['errors'].append('PRIORITY_QUERY_HANDLE_CLOSE_UNCONFIRMED')
                else:
                    result['query_handles_closed'] += 1
                result['threads'].append(row)
        cpu = process_identity(kernel, handle, pid, process_birth)
        result.update(process_identity_verified_after=True, priority_class=classes[priority_class],
                      priority_boost_disabled=bool(process_boost.value), sample_end_qpc=qpc(kernel))
        result['process_cpu'].update(status='OBSERVED', **cpu)
        if result['query_handles_closed_verified'] and all(row['status'] == 'OBSERVED' for row in result['threads']):
            result['status'] = 'OBSERVED'
    except BaseException as error:
        # Only our fixed machine codes are public; OS text/pointers never are.
        try:
            code = str(error)
        except BaseException:
            code = ''
        result['errors'].append(code if code in _PRIORITY_ERROR_CODES else 'PRIORITY_QUERY_UNAVAILABLE')
    result['errors'] = result['errors'][:8]
    result['retained_query_handles_after'] = len(_retained_priority_query_handles)
    return result


def binary_identity(binary, *, version_args=None):
    data = {"path": str(binary), "sha256": file_hash(binary),
            "bytes": binary.stat().st_size, "provenance": "RUNNER_INSTALLED_EXACT_BINARY"}
    if version_args:
        probe = subprocess.run([str(binary), *version_args], capture_output=True,
                               timeout=15, text=True, errors="replace")
        require(probe.returncode == 0, "APP_VERSION_PROBE_FAILED")
        data["version_output"] = probe.stdout[:2000].strip()
    return data


def workload_log_snapshot(log, owned_stream):
    """Hash at most a bounded, stable snapshot of this owned regular log."""
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    expected = os.fstat(owned_stream.fileno())
    require(stat.S_ISREG(expected.st_mode) and expected.st_size <= 4 * 1024**2, "APP_WORKLOAD_LOG_SNAPSHOT_BUDGET")
    with Path(log).open('rb') as source:
        before = os.fstat(source.fileno())
        require(fingerprint(before) == fingerprint(expected), "APP_WORKLOAD_LOG_SNAPSHOT_CHANGED")
        payload = source.read(4 * 1024**2 + 1)
        after = os.fstat(source.fileno())
    current = Path(log).stat()
    require(len(payload) == before.st_size <= 4 * 1024**2 and
            fingerprint(before) == fingerprint(after) == fingerprint(current), "APP_WORKLOAD_LOG_SNAPSHOT_CHANGED")
    return {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
            'observation': 'BOUNDED_STABLE_SNAPSHOT_NOT_FINAL_LOG'}


def project_workload_failure(value):
    """Finite public projection; never export argv, image paths or child text."""
    def number(value):
        return value if type(value) in (int, float) and 0 <= value <= 2**63 - 1 and math.isfinite(value) else "NOT_ESTABLISHED"
    result = {"schema": "blackbox.app-workload-failure/1", "status": "FAILED",
              "scope": "PARTIAL_OBSERVATIONS_BEFORE_FORCED_CLEANUP_NOT_CAUSE_OR_CLEANUP_PROOF"}
    for key in ("reason_code", "error_type"):
        result[key] = _qa_code(value.get(key))
    result["role"] = value.get("role") if value.get("role") in ("COMPRESS", "EXTRACT", "OTHER") else "OTHER"
    result["phase"] = value.get("phase") if value.get("phase") in ("IDENTITY", "SENSOR_ATTACH", "DEADLINE_CHECK",
        "RESOURCE_SAMPLE", "LOG_BUDGET_CHECK", "MONITOR_SLEEP", "WAIT") else "NOT_ESTABLISHED"
    result["cycle"] = value.get("cycle") if type(value.get("cycle")) is int and 0 <= value["cycle"] <= 2 else "NOT_ESTABLISHED"
    for key in ("pid", "configured_timeout_seconds", "elapsed_since_launch_seconds", "elapsed_monitor_seconds",
                "launch_duration_seconds", "identity_observation_seconds_after_launch", "resource_samples_observed",
                "deadline_check_elapsed_monitor_seconds", "last_resource_sample_begin_elapsed_monitor_seconds",
                "cpu_seconds_observed", "cpu_user_seconds_observed", "cpu_kernel_seconds_observed",
                "peak_rss_observed", "max_threads_observed", "write_bytes_observed", "read_bytes_observed",
                "cpu_user_seconds_held_handle", "cpu_kernel_seconds_held_handle"):
        result[key] = number(value.get(key))
    for key in ("poll_exit_code_before_cleanup", "wait_return_code", "last_loop_poll_exit_code"):
        item = value.get(key)
        result[key] = item if type(item) is int and -(2**31) <= item <= 2**32 - 1 else "NOT_ESTABLISHED"
    result["process_state_before_cleanup"] = value.get("process_state_before_cleanup") if value.get("process_state_before_cleanup") in ("RUNNING", "EXITED") else "NOT_ESTABLISHED"
    result["last_loop_poll_state"] = value.get("last_loop_poll_state") if value.get("last_loop_poll_state") in ("RUNNING", "EXITED") else "NOT_ESTABLISHED"
    result["held_counters_observation"] = "FAILURE_BEFORE_CLEANUP" if value.get("held_counters_observation") == "FAILURE_BEFORE_CLEANUP" else "NOT_ESTABLISHED"
    result["owned_image_matches_requested"] = value.get("owned_image_matches_requested") if type(value.get("owned_image_matches_requested")) is bool else "NOT_ESTABLISHED"
    result["image_identity_source"] = "OWNED_WINDOWS_PROCESS_HANDLE" if value.get("image_identity_source") == "OWNED_WINDOWS_PROCESS_HANDLE" else "NOT_ESTABLISHED"
    for key in ("creation_time_filetime_ticks", "exit_time_filetime_ticks"):
        item = value.get(key)
        result[key] = item if isinstance(item, str) and re.fullmatch(r"[0-9]{1,20}", item) else "NOT_ESTABLISHED"
    for key in ("poll_observation_error", "held_identity_observation_error", "log_observation_error", "cleanup_error"):
        if key in value:
            result[key] = _qa_code(value[key])
    log = value.get("log") if type(value.get("log")) is dict else {}
    digest = log.get("sha256")
    result["log"] = {"bytes": number(log.get("bytes")), "sha256": digest if isinstance(digest, str)
        and re.fullmatch(r"[a-f0-9]{64}", digest) else "NOT_ESTABLISHED", "scope": "HASH_ONLY_NO_RAW_CHILD_LOG",
        "observation": "BOUNDED_STABLE_SNAPSHOT_NOT_FINAL_LOG" if log.get('observation') ==
            'BOUNDED_STABLE_SNAPSHOT_NOT_FINAL_LOG' else 'NOT_ESTABLISHED'}
    return result


def emit_workload_failure(log, observation):
    observation = project_workload_failure(observation)
    try:
        write_json(Path(log).parent / "workload-failure.json", observation)
    except Exception as error:
        try:
            print("APP_WORKLOAD_FAILURE_WRITE_FAILED " + _qa_code(str(error)), flush=True)
        except Exception:
            pass
    try:
        print("APP_WORKLOAD_FAILURE_FACTS " + json.dumps(observation, sort_keys=True), flush=True)
    except Exception:
        pass
    return observation


def monitored_run(args, log, *, env=None, timeout=30, role="OTHER", cycle=None, failure_observer=None):
    """Sample only a process launched here; terminate only its owned job."""
    require(failure_observer is None or callable(failure_observer), 'INVALID_WORKLOAD_FAILURE_OBSERVER')
    import psutil
    with Path(log).open("xb") as stream:
        launch_started = time.monotonic()
        owner = OwnedProcess(args, stdout=stream, stderr=stream, env=env)
        launch_completed = time.monotonic()
        p = owner.process
        proof = {"pid": p.pid, "cpu_seconds_observed": 0., "peak_rss_observed": 0,
                 "max_threads_observed": 0, "write_bytes_observed": 0,
                 "read_bytes_observed": 0, "resource_samples_observed": 0,
                 "configured_timeout_seconds": timeout, "role": role, "cycle": cycle}
        monitor_started = None; identity_elapsed = None; primary_error = None; failure = None
        last_loop_code = 'NOT_ESTABLISHED'; deadline_observed = None; last_sample_begin = None
        observed_metrics = set()
        phase = 'IDENTITY'
        try:
            proof.update(owned_process_identity(p, args[0]))
            identity_elapsed = time.monotonic() - launch_started
            phase = 'SENSOR_ATTACH'
            try:
                sensor = psutil.Process(p.pid)
            except psutil.NoSuchProcess:
                sensor = None
            monitor_started = time.monotonic()
            deadline = monitor_started + timeout
            while (last_loop_code := p.poll()) is None:
                phase = 'DEADLINE_CHECK'
                deadline_observed = time.monotonic()
                require(deadline_observed < deadline, "APP_WORKLOAD_DEADLINE")
                try:
                    phase = 'RESOURCE_SAMPLE'
                    if sensor is None:
                        sensor = psutil.Process(p.pid)
                    with sensor.oneshot():
                        cpu = sensor.cpu_times()
                        proof["cpu_user_seconds_observed"] = cpu.user
                        proof["cpu_kernel_seconds_observed"] = cpu.system
                        proof["cpu_seconds_observed"] = max(proof["cpu_seconds_observed"], cpu.user + cpu.system)
                        observed_metrics.update(('cpu_seconds_observed', 'cpu_user_seconds_observed', 'cpu_kernel_seconds_observed'))
                        proof["peak_rss_observed"] = max(proof["peak_rss_observed"], sensor.memory_info().rss)
                        observed_metrics.add('peak_rss_observed')
                        require(proof["peak_rss_observed"] <= 1024**3, "APP_WORKLOAD_RSS_BUDGET")
                        proof["max_threads_observed"] = max(proof["max_threads_observed"], sensor.num_threads())
                        observed_metrics.add('max_threads_observed')
                        io = sensor.io_counters()
                        for key in ("write_bytes", "read_bytes"):
                            proof[key + "_observed"] = max(proof[key + "_observed"], getattr(io, key))
                            observed_metrics.add(key + '_observed')
                        proof["resource_samples_observed"] += 1
                        last_sample_begin = deadline_observed - monitor_started
                except psutil.NoSuchProcess:
                    break
                phase = 'LOG_BUDGET_CHECK'
                require(Path(log).stat().st_size <= 4 * 1024**2, "APP_WORKLOAD_LOG_BUDGET")
                phase = 'MONITOR_SLEEP'
                time.sleep(.025)
            phase = 'WAIT'
            proof["exit_code"] = p.wait(timeout=5)
            require(proof["exit_code"] == 0, "APP_WORKLOAD_EXIT_NONZERO")
            proof['elapsed_monitor_seconds'] = time.monotonic() - monitor_started
            proof['monitor_duration_scope'] = 'OBSERVED_MONITOR_DURATION_NOT_HARD_OS_DEADLINE'
        except BaseException as error:
            primary_error = error
            observed = time.monotonic()
            failure = {**proof, "role": role, "cycle": cycle, "phase": phase,
                "error_type": type(error).__name__, "reason_code": _qa_code(str(error)),
                "configured_timeout_seconds": timeout, "launch_duration_seconds": launch_completed - launch_started,
                "identity_observation_seconds_after_launch": identity_elapsed,
                "elapsed_since_launch_seconds": observed - launch_started,
                "elapsed_monitor_seconds": observed - monitor_started if monitor_started is not None else None,
                "deadline_check_elapsed_monitor_seconds": deadline_observed - monitor_started
                    if deadline_observed is not None and monitor_started is not None else None,
                "last_resource_sample_begin_elapsed_monitor_seconds": last_sample_begin,
                "last_loop_poll_state": "RUNNING" if last_loop_code is None else
                    "EXITED" if type(last_loop_code) is int else "NOT_ESTABLISHED",
                "last_loop_poll_exit_code": last_loop_code, "wait_return_code": proof.get("exit_code")}
            for key in ('cpu_user_seconds_held_handle', 'cpu_kernel_seconds_held_handle', 'exit_time_filetime_ticks'):
                failure.pop(key, None)
            for key in ("cpu_seconds_observed", "cpu_user_seconds_observed", "cpu_kernel_seconds_observed",
                        "peak_rss_observed", "max_threads_observed", "write_bytes_observed", "read_bytes_observed"):
                if key not in observed_metrics:
                    failure[key] = "NOT_ESTABLISHED"
            try:
                code = p.poll()
                failure.update(process_state_before_cleanup="RUNNING" if code is None else "EXITED",
                               poll_exit_code_before_cleanup=code)
            except Exception as secondary:
                failure["poll_observation_error"] = _qa_code(str(secondary))
            try:
                failure.update(owned_process_identity(p, args[0]))
                failure['held_counters_observation'] = 'FAILURE_BEFORE_CLEANUP'
            except Exception as secondary:
                failure["held_identity_observation_error"] = _qa_code(str(secondary))
            try:
                stream.flush()
                failure["log"] = workload_log_snapshot(log, stream)
            except Exception as secondary:
                failure["log_observation_error"] = _qa_code(str(secondary))
            failure = emit_workload_failure(log, failure)
            if failure_observer is not None:
                try:
                    failure_observer(owner, failure)
                except BaseException:
                    try:
                        print('APP_WORKLOAD_FAILURE_OBSERVER_UNAVAILABLE', flush=True)
                    except BaseException:
                        pass
            try:
                error.workload_failure = failure
            except Exception:
                pass
            raise
        finally:
            try:
                owner.close(kill=True)
            except BaseException as error:
                if primary_error is None:
                    raise
                failure["cleanup_error"] = _qa_code(str(error))
                emit_workload_failure(log, failure)
    return proof


def observe_native_output(path):
    """Measure the real private helper output before its normal temp cleanup."""
    from blackbox_core.decoder_limits import MAX_WORK_BYTES
    size = path.stat().st_size
    require(0 < size <= MAX_WORK_BYTES, "NATIVE_OBSERVATION_SIZE_BUDGET")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        stream.seek(max(0, size - 4096))
        tail = stream.read(4096).splitlines()
    facts = {"status": "UNCONFIRMED", "output_bytes": size, "output_sha256": digest,
             "byte_scope": "ACTUAL_NATIVE_JSONL_NOT_RESERIALIZED_INDEX_BYTES"}
    try:
        require(bool(tail), "NATIVE_OBSERVATION_FOOTER")
        footer = json.loads(tail[-1])
        require(type(footer) is dict and footer.get("type") == "footer" and
                footer.get("protocol") == "blackbox.trace-event/1" and
                footer.get("status") in ("DECODED", "TRUNCATED") and
                type(footer.get("rows")) is int and 0 <= footer["rows"] <= 250000 and
                size == path.stat().st_size, "NATIVE_OBSERVATION_FOOTER_OR_SIZE")
        facts.update(status="OBSERVED", footer={key: footer[key] for key in ("status", "rows")})
        reason = footer.get('truncation_reason', 'UNKNOWN')
        facts['native_truncation_reason'] = reason if reason in (None, 'MAX_EVENTS', 'MAX_OUTPUT', 'UNKNOWN') else 'UNRECOGNIZED'
    except Exception as error:
        facts["observation_error_code"] = _qa_code(str(error))
    return facts


def native_output_path(argv):
    """Recognize only the two documented native decode launch shapes."""
    if not isinstance(argv, (list, tuple)) or len(argv) not in (3, 4) or not all(isinstance(arg, str) for arg in argv):
        return None
    if len(argv) == 4 and argv[3] != '--inline-modules':
        return None
    return Path(argv[2])


def observed_module_encoding(meta):
    engine = meta.get('engine') if type(meta.get('engine')) is dict else {}
    value = engine.get('frame_module_encoding', 'INLINE_V1')
    return value if value in ('INLINE_V1', 'PER_EVENT_MODULES_V1') else 'UNRECOGNIZED'


def _emit_trace_diagnostic(source, output, meta, digest, source_bytes, native_observation=None,
                           native_module_encoding=None):
    """Log only fixed enums, bounded counts and the original source digest."""
    def count(value):
        return value if type(value) is int and 0 <= value <= 2**63 - 1 else None

    reliability = meta.get("reliability")
    reliability = reliability if isinstance(reliability, dict) else {}
    detail = {
        "schema": "blackbox.decoder-app-trace-diagnostic/1",
        "application": {"7zip": "7-Zip", "powershell": "PowerShell 7",
                        "notepad": "Notepad++"}.get(output.name, "UNSPECIFIED"),
        "source_format": source.suffix.lower() if source.suffix.lower() in
                         (".etl", ".nettrace", ".jsonl") else "UNSPECIFIED",
        "source_sha256": digest if isinstance(digest, str) and
                         re.fullmatch(r"[a-f0-9]{64}", digest) else None,
        "source_bytes": count(source_bytes),
        "decoder_status": meta.get("status") if meta.get("status") in
                          ("DECODED", "TRUNCATED") else "UNRECOGNIZED",
        "rows": count(meta.get("rows")),
        "metadata_input_sha256_matches": meta.get("input_sha256") == digest,
        "import_completeness": meta.get("import_completeness") if
            meta.get("import_completeness") in ("ALL_EMITTED_RECORDS", "BOUNDED_PREFIX")
            else "UNRECOGNIZED",
        "decoder_reported_lost_events": count(meta.get("decoder_reported_lost_events")),
        "events_with_stacks": count(meta.get("events_with_stacks")),
        "events_with_errors": count(meta.get("events_with_errors")),
        "bounded_events": count(meta.get("bounded_events")),
        "event_limit": count(reliability.get("event_limit")),
        "requested_native_module_encoding": native_module_encoding or "DEFAULT",
        "actual_native_module_encoding": observed_module_encoding(meta),
    }
    if native_observation:
        detail["native_output_bytes"] = count(native_observation.get("output_bytes"))
        value = native_observation.get("output_sha256")
        detail["native_output_sha256"] = value if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) else None
    write_json(output / "decoder-diagnostic.json", detail)
    record = json.dumps(detail, sort_keys=True, allow_nan=False)
    print("THIRD_PARTY_DECODER_TRACE_DETAIL " + record, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\n- Third-party trace decode " + record + "\n")


def decode_trace(source, output, helper, *, native_module_encoding=None):
    require(native_module_encoding is None or type(native_module_encoding) is str and
            native_module_encoding in ('INLINE_V1', 'PER_EVENT_MODULES_V1'), 'INVALID_QA_NATIVE_MODULE_ENCODING')
    require(0 < source.stat().st_size <= MAX_TRACE, "ACTUAL_TRACE_SIZE_BUDGET")
    source_bytes = source.stat().st_size
    digest = file_hash(source)
    index = output / "decoded.sqlite3"
    observations = []

    class ObservedNativeDecoder(OwnedProcess):
        def __init__(self, args, **kwargs):
            self._native_output = native_output_path(args)
            super().__init__(args, **kwargs)
            self._observation_done = False

        def close(self, *args, **kwargs):
            try:
                return super().close(*args, **kwargs)
            finally:
                if not self._observation_done:
                    self._observation_done = True
                    item = {"status": "UNCONFIRMED", "helper_exit_code": self.process.poll()}
                    try:
                        if self.process.poll() is not None:
                            require(self._native_output is not None, "NATIVE_OBSERVATION_LAUNCH_SHAPE")
                            item["output_bytes"] = self._native_output.stat().st_size
                            item.update(observe_native_output(self._native_output))
                    except Exception as error:
                        item["observation_error_code"] = _qa_code(str(error))
                    observations.append(item)

    try:
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper), \
                patch("blackbox_core.optional_jobs.OwnedProcess", ObservedNativeDecoder):
            options = {'native_module_encoding': native_module_encoding} if native_module_encoding is not None else {}
            meta = decode_file(source, index, timeout=90, **options)
    finally:
        try:
            write_json(output / "native-output-observation.json", {
                "schema": "blackbox.native-output-observation/1", "processes": observations})
        except Exception as error:
            print("NATIVE_OUTPUT_OBSERVATION_WRITE_FAILED " + _qa_code(str(error)), flush=True)
    write_json(output / "decoder-summary.json", meta)
    _emit_trace_diagnostic(source, output, meta, digest, source_bytes, observations[0] if observations else None,
                           native_module_encoding)
    require(meta["status"] == "DECODED" and meta["rows"] > 0,
            "APP_TRACE_NOT_COMPLETELY_DECODED")
    require(file_hash(source) == digest and meta["input_sha256"] == digest,
            "APP_TRACE_HASH_CHANGED")
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


def start_schedule(output, *, profile="schedule"):
    from tools.qa_schedule_capture import OwnedScheduleCapture
    from blackbox_core.windows_research import privilege, wpr_tool
    if privilege()["mode"] != "ADMINISTRATOR" or not wpr_tool():
        raise NotExecuted("NATIVE_ETW_REQUIRES_WPR_AND_ADMINISTRATOR")
    capture = OwnedScheduleCapture(output, profile=profile)
    capture.start()
    return capture


def finish_schedule(capture, output, helper, pids, *, waits=False, native_module_encoding=None):
    raw = capture.stop()
    source = output / raw["path"]
    options = {'native_module_encoding': native_module_encoding} if native_module_encoding is not None else {}
    index, meta, identity = decode_trace(source, output, helper, **options)
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


def validate_minimum_roundtrips(value):
    require(type(value) is int and 1 <= value <= 3, 'INVALID_QA_MINIMUM_ROUNDTRIPS')
    return value


def seven_zip(output, helper, *, profile="cpu_file", native_module_encoding=None, workload_policy='ORDINARY_30',
              minimum_roundtrips=1):
    validate_minimum_roundtrips(minimum_roundtrips)
    process_timeout = workload_policy_seconds(workload_policy)
    run_options = {'timeout': process_timeout} if workload_policy != 'ORDINARY_30' else {}
    binary = installed("7z", [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "7-Zip/7z.exe"])
    native = native_pe_identity(binary)
    identity = {**binary_identity(binary, version_args=["i"]), "native_image": native}
    source = output / "input.bin"
    rng = random.Random(20261028)
    source.write_bytes(rng.randbytes(8 * 1024**2))
    digest = file_hash(source)
    capture = start_schedule(output, profile=profile)
    proofs = []
    verified_roundtrips = 0
    try:
        observer = getattr(capture, 'observe_workload_failure', None)
        if callable(observer):
            run_options = {**run_options, 'failure_observer': observer}
        started = time.monotonic()
        for cycle in range(3):
            archive = output / f"roundtrip-{cycle}.7z"
            destination = output / f"roundtrip-{cycle}"
            proofs.append(monitored_run([str(binary), "a", "-t7z", "-mx=7", "-mmt=2", "-bd", "-y",
                                         str(archive), str(source)], output / f"compress-{cycle}.log",
                                         role="COMPRESS", cycle=cycle, **run_options))
            proofs.append(monitored_run([str(binary), "x", "-bd", "-y", "-o" + str(destination),
                                         str(archive)], output / f"extract-{cycle}.log",
                                         role="EXTRACT", cycle=cycle, **run_options))
            require(file_hash(destination / source.name) == digest,
                    "SEVENZIP_ROUNDTRIP_HASH_MISMATCH")
            verified_roundtrips += 1
            if time.monotonic() - started >= 4 and verified_roundtrips >= minimum_roundtrips:
                break
        write_json(output / "workload-oracle.json", {
            "schema": "blackbox.sevenzip-workload-oracle/1", "application": identity,
            "workload_policy": workload_policy, "requested_process_timeout_seconds": process_timeout,
            "requested_minimum_roundtrips": minimum_roundtrips,
            "input_bytes": source.stat().st_size, "input_sha256": digest,
            "roundtrips_verified": len(proofs) // 2, "workloads": proofs})
        options = {'native_module_encoding': native_module_encoding} if native_module_encoding is not None else {}
        trace = finish_schedule(capture, output, helper, [x["pid"] for x in proofs], **options)
    except BaseException as error:
        # Keep completed work and its input identity even when monitored_run
        # failed before returning a proof. This is never a completed oracle.
        try:
            if not (output / "workload-oracle.json").exists():
                write_json(output / "workload-oracle.json", {
                    "schema": "blackbox.sevenzip-workload-oracle/1", "status": "INCOMPLETE_WORKLOAD_FAILURE",
                    "workload_policy": workload_policy, "requested_process_timeout_seconds": process_timeout,
                    "requested_minimum_roundtrips": minimum_roundtrips,
                    "application": identity, "input_bytes": source.stat().st_size, "input_sha256": digest,
                    "roundtrips_verified": verified_roundtrips, "workloads": proofs,
                    "failure_reason_code": _qa_code(str(error))})
        except Exception as secondary:
            try:
                print("APP_PARTIAL_WORKLOAD_ORACLE_WRITE_FAILED " + _qa_code(str(secondary)), flush=True)
            except Exception:
                pass
        raise
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
                       "requested_minimum_roundtrips": minimum_roundtrips,
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


def owned_gui_user(pid, hwnd):
    user = C.WinDLL("user32", use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.GetWindowThreadProcessId.restype = W.DWORD
    owner = W.DWORD()
    tid = int(user.GetWindowThreadProcessId(hwnd, C.byref(owner)))
    require(owner.value == pid and tid > 0, "NOTEPAD_WINDOW_OWNERSHIP_CHANGED")
    return user, tid


def gui_message_failure(api, pid, tid, message, phase, timeout_ms):
    error = C.get_last_error()
    failure = AssertionError("OWNED_GUI_MESSAGE_FAILED_" + str(error) + '_' + phase)
    fact = {
        'schema': 'blackbox.owned-gui-failure/1', 'api': api, 'phase': phase,
        'pid': pid, 'window_tid_at_query': tid, 'message_code': message,
        'configured_timeout_ms': timeout_ms, 'winerror': error,
        'scope': 'OWNED_WINDOW_AT_QUERY_NOT_CAUSE_OR_THREAD_BIRTH_PROOF'}
    try:
        print('THIRD_PARTY_DECODER_GUI_FAILURE_FACTS ' + json.dumps(fact, sort_keys=True), flush=True)
    except Exception as diagnostic_error:
        failure.add_note('GUI_FAILURE_STDOUT_UNAVAILABLE:' + type(diagnostic_error).__name__)
    raise failure


def validate_gui_phase(phase):
    require(phase in ('UNSPECIFIED', 'STARTUP_LENGTH', 'VERIFY_DOCUMENT_LENGTH',
        'SELECT_END', 'APPEND_CHARACTER', 'SAVE_DOCUMENT', 'CLOSE_WINDOW'), 'NOTEPAD_UNSUPPORTED_GUI_PHASE')


def send_owned(pid, hwnd, message, wparam=0, lparam=0, *, phase='UNSPECIFIED'):
    """A synchronous read-only probe; action completion is checked separately."""
    require(message == 2006 and wparam == 0 and lparam == 0, 'NOTEPAD_UNSUPPORTED_GUI_QUERY')
    validate_gui_phase(phase)
    user, tid = owned_gui_user(pid, hwnd)
    user.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM,
                                        W.UINT, W.UINT, C.POINTER(C.c_size_t)]
    user.SendMessageTimeoutW.restype = C.c_ssize_t
    result = C.c_size_t()
    C.set_last_error(0)
    ok = user.SendMessageTimeoutW(hwnd, message, wparam, lparam, 0x2 | 0x20, 500, C.byref(result))
    if not ok:
        gui_message_failure('SendMessageTimeoutW', pid, tid, message, phase, 500)
    return result.value


def post_owned(pid, hwnd, message, wparam=0, lparam=0, *, expected_tid, phase):
    """Queue one fixed pointer-free action; never retry an ambiguous write."""
    require(type(message) is int and type(wparam) is int and type(lparam) is int and
        ((message == 2160 and 0 <= wparam == lparam <= 2**31 - 1) or
         (message == 0x0102 and 32 <= wparam <= 126 and lparam == 0) or
         (message == 0x0111 and wparam == 41006 and lparam == 0) or
         (message == 0x0010 and wparam == 0 and lparam == 0)), 'NOTEPAD_UNSUPPORTED_GUI_ACTION')
    validate_gui_phase(phase)
    user, tid = owned_gui_user(pid, hwnd)
    require(type(expected_tid) is int and tid == expected_tid, 'NOTEPAD_GUI_THREAD_CHANGED')
    user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.PostMessageW.restype = W.BOOL
    C.set_last_error(0)
    if not user.PostMessageW(hwnd, message, wparam, lparam):
        gui_message_failure('PostMessageW', pid, tid, message, phase, None)


def await_owned_length(owner, hwnd, expected, deadline, phase):
    while time.monotonic() < deadline:
        require(owner.process.poll() is None, 'NOTEPAD_OWNED_PROCESS_EXITED_DURING_LOAD')
        try:
            length = send_owned(owner.process.pid, hwnd, 2006, phase=phase)
            if length == expected:
                require(time.monotonic() <= deadline, 'NOTEPAD_DOCUMENT_READY_NOT_ESTABLISHED')
                return length
        except AssertionError as error:
            if not str(error).startswith('OWNED_GUI_MESSAGE_FAILED_1460_'):
                raise
        time.sleep(.05)
    raise AssertionError('NOTEPAD_DOCUMENT_READY_NOT_ESTABLISHED')


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
        document_ready = False
        while time.monotonic() < deadline and owner.process.poll() is None:
            windows = owned_windows(pid)
            main = next((w for w in windows if w["class"] == "Notepad++"), None)
            editor = next((w for w in windows if w["class"] == "Scintilla" and w["visible"]), None)
            if main and editor:
                try:
                    if send_owned(pid, editor["hwnd"], 2006, phase='STARTUP_LENGTH') == len(original):
                        document_ready = True
                        break
                except AssertionError as error:
                    # Startup may still be loading the owned document. The
                    # overall deadline and process identity remain bounded.
                    if not str(error).startswith('OWNED_GUI_MESSAGE_FAILED_1460_'):
                        raise
            time.sleep(.05)
        require(main and editor, "NOTEPAD_OWNED_EDITOR_WINDOW_MISSING")
        require(document_ready, 'NOTEPAD_DOCUMENT_READY_NOT_ESTABLISHED')
        require(main['tid'] == editor['tid'] and main['tid'] > 0, 'NOTEPAD_GUI_THREAD_NOT_ESTABLISHED')
        before = window_observations(pid)
        length = await_owned_length(owner, editor['hwnd'], len(original), deadline, 'VERIFY_DOCUMENT_LENGTH')
        require(length == len(original), "NOTEPAD_INPUT_FILE_NOT_LOADED")
        # The same GUI queue receives each action once in order. Actual saved
        # bytes, not queue acceptance, establish that editing and save completed.
        deadline = time.monotonic() + 5
        require(owner.process.poll() is None, 'NOTEPAD_OWNED_PROCESS_EXITED_BEFORE_EDIT')
        post_owned(pid, editor['hwnd'], 2160, length, length,
                   expected_tid=editor['tid'], phase='SELECT_END')
        for character in marker:
            post_owned(pid, editor['hwnd'], 0x0102, ord(character),
                       expected_tid=editor['tid'], phase='APPEND_CHARACTER')
        post_owned(pid, main['hwnd'], 0x0111, 41006,
                   expected_tid=main['tid'], phase='SAVE_DOCUMENT')
        expected = (original + marker).encode("ascii")
        while source.read_bytes() != expected and time.monotonic() < deadline:
            time.sleep(.05)
        require(source.read_bytes() == expected, "NOTEPAD_REAL_SAVE_BYTES_MISMATCH")
        require(time.monotonic() <= deadline, 'NOTEPAD_REAL_SAVE_DEADLINE_EXCEEDED')
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
        close_deadline = time.monotonic() + 10
        require(owner.process.poll() is None, 'NOTEPAD_OWNED_PROCESS_EXITED_BEFORE_CLOSE')
        post_owned(pid, main['hwnd'], 0x0010, expected_tid=main['tid'], phase='CLOSE_WINDOW')
        exit_code = owner.process.wait(timeout=max(0, close_deadline - time.monotonic()))
        require(exit_code == 0, 'NOTEPAD_OWNED_NORMAL_EXIT_NOT_CONFIRMED')
        require(time.monotonic() <= close_deadline, 'NOTEPAD_OWNED_CLOSE_DEADLINE_EXCEEDED')
        return {"status": "PASS" if all(checks.values()) else "FAIL",
                "capabilities": {k: "PASS" if v else "FAIL_NOT_OBSERVED" for k, v in checks.items()},
                "application": identity, "pid": pid,
                "oracle": {"opened_bytes": len(original), "saved_bytes": len(expected),
                           "normal_window_close_exit_code": exit_code,
                           "saved_sha256": hashlib.sha256(expected).hexdigest()},
                "window_observations": responsiveness, **trace,
                "hang_or_lock_cause": "NOT_CLAIMED_RESPONSIVE_IDLE_WORKLOAD"}
    finally:
        if capture.active:
            capture.cancel()
        if owner is not None:
            owner.close(kill=True)



def _qa_code(value):
    """Print only a bounded machine code, never application paths or payloads."""
    if not isinstance(value, str) or not value:
        return "UNSPECIFIED"
    candidate = value.split(":", 1)[0].strip()
    return candidate if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,95}", candidate) else "REDACTED_UNSTRUCTURED"


def _emit_app_diagnostic(name, item):
    """Keep actual PASS/FAIL semantics; make release-only failures inspectable."""
    status = _qa_code(item.get("status"))
    error_type = _qa_code(item.get("error"))
    reason_code = _qa_code(item.get("reason"))
    capability_map = item.get("capabilities")
    failing = (sorted(_qa_code(key) for key, value in capability_map.items()
                      if value != "PASS")[:24] if isinstance(capability_map, dict) else [])
    detail = {"application": name, "status": status, "error_type": error_type,
              "reason_code": reason_code, "failing_capabilities": failing}
    print("THIRD_PARTY_DECODER_QA_DETAIL " + json.dumps(detail, sort_keys=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\n- Third-party QA " + json.dumps(detail, sort_keys=True) + "\n")



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
        _emit_app_diagnostic(name, item)
    states = [x["status"] for x in report["applications"].values()]
    report["status"] = "FAIL" if "FAIL" in states else "NOT_EXECUTED" if "NOT_EXECUTED" in states else "PASS"
    report["duration_seconds"] = time.monotonic() - started
    write_json(output / "apps-qa.json", report)
    print_failure_diagnostics(report)
    print("THIRD_PARTY_DECODER_QA_" + report["status"])
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "NOT_EXECUTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
