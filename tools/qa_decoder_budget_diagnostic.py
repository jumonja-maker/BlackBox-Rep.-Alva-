"""CI-only Python budget negatives and a complete native Win32 noise A/B.

The historical a80 release trace is unavailable: its cause remains unknown.
All capture/decode/workload operations delegate to the existing real 7-Zip QA.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ctypes as C
from ctypes import wintypes as W
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from tools import qa_decoder_apps as apps
from tools.qa_deep_inspection import require_hosted_windows
from blackbox_universal.provenance import source_identity

PAIRS = 8
NOISE_SECONDS = 70
MAX_NOISE_RSS = 128 * 1024**2
MAX_NOISE_LOG = 64 * 1024
MAX_OUTPUT = 1152 * 1024**2
MIN_NOISE_ROWS = 10000
PRELUDE_SECONDS = 15
NATIVE_PRELUDE_SECONDS = 65
CONTROLLED_SECONDS = 660
# A real-noise stimulus floor, never a substitute for observing MAX_OUTPUT.
PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS = 10
MAX_PROGRESS_RECEIPTS = 281
EXPECTED_REASON = 'APP_TRACE_NOT_COMPLETELY_DECODED'
SEVENZIP_CAPABILITIES = frozenset({
    'compression_extraction_hash_roundtrip', 'owned_native_image_identity', 'cpu_counters',
    'etw_cpu_samples', 'etw_cpu_stacks', 'etw_file_operations', 'etw_threads', 'pid_lifetime_attribution',
})


def noise_policy(implementation):
    apps.require(type(implementation) is str and implementation in ('PYTHON_CTYPES_WIN32', 'NATIVE_WIN32'),
                 'NOISE_POLICY_IMPLEMENTATION_UNKNOWN')
    ttl, progress, owner = (70, 281, 85) if implementation == 'PYTHON_CTYPES_WIN32' else (180, 721, 195)
    return {'implementation': implementation, 'ttl_seconds': ttl, 'progress_limit': progress,
            'owner_seconds': owner}


def validate_noise_policy(receipt, implementation):
    policy = noise_policy(implementation)
    apps.require(type(receipt) is dict and receipt.get('implementation') == implementation and
        all(type(receipt.get(key)) is int and receipt[key] == policy[key]
            for key in ('ttl_seconds', 'progress_limit')), 'NOISE_ACTUAL_POLICY_MISMATCH')
    return {key: receipt[key] for key in ('implementation', 'ttl_seconds', 'progress_limit')}


def validate_requested_noise_policy(record, implementation):
    expected = noise_policy(implementation)
    apps.require(type(record) is dict and set(record) == set(expected) and
        type(record.get('implementation')) is str and record['implementation'] == implementation and
        all(type(record.get(key)) is int and record[key] == expected[key]
            for key in ('ttl_seconds', 'progress_limit', 'owner_seconds')),
        'CONTROLLED_PAIR_NOISE_POLICY_MISMATCH')
    return dict(record)


def bounded_failure(error, phase, leaf=None):
    """Keep numeric OS evidence without copying paths or exception messages."""
    kind = type(error).__name__
    fact = {'phase': phase, 'error_type': kind if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', kind)
            else 'OTHER_EXCEPTION', 'reason_code': apps._qa_code(str(error))}
    for field in ('winerror', 'errno'):
        value = getattr(error, field, None)
        fact[field] = value if type(value) is int and 0 <= value <= 2**32 - 1 else None
    if type(leaf) is str and re.fullmatch(r'progress-[0-9]{4}\.json', leaf):
        fact['receipt_leaf'] = leaf
    return fact


def read_json(path, limit=32768, *, phase_context=None):
    if phase_context is not None:
        phase_context['phase'] = 'RECEIPT_STAT'
    apps.require(0 < path.stat().st_size <= limit, 'DIAGNOSTIC_RECEIPT_SIZE')
    if phase_context is not None:
        phase_context['phase'] = 'RECEIPT_READ'
    raw = path.read_text(encoding='utf-8')
    if phase_context is not None:
        phase_context['phase'] = 'RECEIPT_PARSE'
    value = json.loads(raw)
    apps.require(type(value) is dict, 'DIAGNOSTIC_RECEIPT_TYPE')
    return value


def write_receipt(path, value):
    temporary = path.with_suffix('.tmp')
    apps.write_json(temporary, value)
    temporary.replace(path)


def kernel_api():
    kernel = C.WinDLL('kernel32', use_last_error=True, winmode=0x800)
    for name in ('GetCurrentProcess', 'GetCurrentThread'):
        getattr(kernel, name).restype = W.HANDLE
    kernel.GetCurrentThreadId.restype = W.DWORD
    for name in ('QueryPerformanceCounter', 'QueryPerformanceFrequency'):
        getattr(kernel, name).argtypes = [C.POINTER(C.c_longlong)]
        getattr(kernel, name).restype = W.BOOL
    kernel.CreateEventW.argtypes = [C.c_void_p, W.BOOL, W.BOOL, W.LPCWSTR]
    kernel.CreateEventW.restype = W.HANDLE
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    for name in ('SetEvent', 'CloseHandle'):
        getattr(kernel, name).argtypes = [W.HANDLE]
        getattr(kernel, name).restype = W.BOOL
    for name in ('GetProcessTimes', 'GetThreadTimes'):
        getattr(kernel, name).argtypes = [W.HANDLE, *([C.POINTER(W.FILETIME)] * 4)]
        getattr(kernel, name).restype = W.BOOL
    return kernel


def counter(kernel, name='QueryPerformanceCounter'):
    value = C.c_longlong()
    apps.require(getattr(kernel, name)(C.byref(value)), 'NOISE_COUNTER_UNAVAILABLE')
    return value.value


def creation_time(kernel, handle, name):
    values = [W.FILETIME() for _ in range(4)]
    apps.require(getattr(kernel, name)(handle, *[C.byref(v) for v in values]),
                 'NOISE_CREATION_TIME_UNAVAILABLE')
    return str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime)


def noise_child(output):
    require_hosted_windows()
    output.mkdir(parents=True, exist_ok=False)
    kernel = kernel_api()
    handles = []; threads = []; records = [None] * (2 * PAIRS)
    errors = []; stop = threading.Event(); barrier = threading.Barrier(2 * PAIRS + 1)
    proof = {'schema': 'blackbox.scheduler-noise/1', 'status': 'FAILED',
             'pid': os.getpid(), 'created_100ns': creation_time(kernel, kernel.GetCurrentProcess(), 'GetProcessTimes'),
             'qpc_frequency_hz': counter(kernel, 'QueryPerformanceFrequency'),
             'source_sha256': apps.file_hash(Path(__file__)), 'pairs': PAIRS,
             'implementation': 'PYTHON_CTYPES_WIN32', 'expected_native_handles': 2 * PAIRS,
             'ttl_seconds': NOISE_SECONDS, 'progress_limit': MAX_PROGRESS_RECEIPTS,
             'executable_sha256': apps.file_hash(Path(sys.executable))}

    def worker(index, mine, other):
        record = {'tid': kernel.GetCurrentThreadId(), 'handoffs': 0,
                  'created_100ns': creation_time(kernel, kernel.GetCurrentThread(), 'GetThreadTimes'),
                  'begin_qpc': counter(kernel)}
        records[index] = record
        try:
            barrier.wait(timeout=10)
            while not stop.is_set():
                result = kernel.WaitForSingleObject(mine, 250)
                if stop.is_set():
                    break
                if result == 258:
                    continue
                apps.require(result == 0, 'NOISE_WAIT_FAILED')
                apps.require(kernel.SetEvent(other), 'NOISE_HANDOFF_FAILED')
                record['handoffs'] += 1
        except BaseException:
            errors.append('NOISE_WORKER_FAILED'); stop.set()
        finally:
            record['end_qpc'] = counter(kernel)

    try:
        for pair in range(PAIRS):
            first = kernel.CreateEventW(None, False, True, None)
            second = kernel.CreateEventW(None, False, False, None)
            handles.extend(h for h in (first, second) if h)
            apps.require(first and second, 'NOISE_EVENT_CREATION_FAILED')
            for offset, mine, other in ((0, first, second), (1, second, first)):
                thread = threading.Thread(target=worker, args=(2 * pair + offset, mine, other), daemon=True)
                threads.append(thread); thread.start()
        barrier.wait(timeout=10)
        proof['begin_qpc'] = counter(kernel)
        write_receipt(output / 'ready.json', {**proof, 'status': 'READY', 'workers': records})
        deadline = time.monotonic() + NOISE_SECONDS
        sequence = 0; next_progress = time.monotonic()
        while not (output / 'stop.request').exists() and time.monotonic() < deadline and not errors:
            if time.monotonic() >= next_progress:
                sequence += 1
                apps.require(sequence <= MAX_PROGRESS_RECEIPTS, 'NOISE_PROGRESS_FILE_BUDGET')
                sample_begin = counter(kernel)
                counts = [{'tid': record['tid'], 'handoffs': record['handoffs']} for record in records]
                sample_end = counter(kernel)
                write_receipt(output / f'progress-{sequence:04d}.json', {
                    'schema': 'blackbox.scheduler-noise-progress/1', 'sequence': sequence,
                    'pid': proof['pid'], 'created_100ns': proof['created_100ns'],
                    'source_sha256': proof['source_sha256'], 'qpc_frequency_hz': proof['qpc_frequency_hz'],
                    'implementation': proof['implementation'], 'executable_sha256': proof['executable_sha256'],
                    'expected_native_handles': proof['expected_native_handles'],
                    'ttl_seconds': proof['ttl_seconds'], 'progress_limit': proof['progress_limit'],
                    'qpc': sample_end, 'sample_begin_qpc': sample_begin, 'sample_end_qpc': sample_end,
                    'workers': counts,
                    'total_handoffs': sum(record['handoffs'] for record in counts)})
                next_progress = time.monotonic() + .25
            time.sleep(.02)
        proof['stop_requested'] = (output / 'stop.request').exists()
    finally:
        stop.set()
        for handle in handles:
            if not kernel.SetEvent(handle):
                errors.append('NOISE_RELEASE_FAILED')
        join_deadline = time.monotonic() + 3
        for thread in threads:
            thread.join(timeout=max(0, join_deadline - time.monotonic()))
        joined = len(threads) == 2 * PAIRS and not any(t.is_alive() for t in threads)
        closed = 0
        if joined:
            for handle in handles:
                if kernel.CloseHandle(handle):
                    closed += 1
                else:
                    errors.append('NOISE_CLOSE_HANDLE_FAILED')
        proof.update(end_qpc=counter(kernel), workers=records, all_threads_joined=joined,
                     native_handles_created=len(handles), native_handles_closed=closed,
                     errors=errors[:32], cleanup_required=not joined or closed != 2 * PAIRS)
        if (proof.get('stop_requested') and joined and closed == 2 * PAIRS and not errors and
                all(record and record['handoffs'] > 0 for record in records)):
            proof['status'] = 'COMPLETED'
        write_receipt(output / 'oracle.json', proof)
    return 0 if proof['status'] == 'COMPLETED' else 1


class NoiseOwner:
    def __init__(self, output, producer):
        self.output = output; self.owner = None; self.log = None; self.errors = []
        self.producer = producer
        apps.require(producer['implementation'] in ('PYTHON_CTYPES_WIN32', 'NATIVE_WIN32') and
            producer['expected_native_handles'] == (16 if producer['implementation'] == 'PYTHON_CTYPES_WIN32' else 32),
            'NOISE_PRODUCER_CONTRACT')
        self.policy = noise_policy(producer['implementation'])
        self.policy_receipts = {'ready': 'NOT_ESTABLISHED', 'oracle': 'NOT_ESTABLISHED'}
        self.watcher_stop = threading.Event(); self.watcher = None
        self.started = None; self.max_rss = 0; self.cleanup = {'status': 'NOT_ESTABLISHED'}
        self.prelude = {'target_handoffs': 0, 'requested_minimum_seconds': 0,
                        'wait_seconds': 0, 'status': 'NOT_REQUIRED'}
        self.stop_observation = {'child_exit_code': 'NOT_ESTABLISHED',
                                 'parent_stop_requested': False}

    def start(self):
        import psutil
        self.log = (self.output.parent / 'noise.log').open('xb')
        executable = Path(self.producer['executable']).resolve(strict=True)
        apps.require(apps.file_hash(executable) == self.producer['executable_sha256'], 'NOISE_EXECUTABLE_CHANGED')
        command = ([str(executable), str(Path(__file__).resolve()), '--noise-child']
                   if self.producer['implementation'] == 'PYTHON_CTYPES_WIN32' else [str(executable)])
        self.owner = apps.OwnedProcess([*command, '--output', str(self.output)], stdout=self.log, stderr=self.log,
            detach_console=True)
        self.started = time.monotonic()
        self.identity = apps.owned_process_identity(self.owner.process, executable)
        process = psutil.Process(self.owner.process.pid)

        def watch():
            try:
                while not self.watcher_stop.wait(.05) and self.owner.process.poll() is None:
                    try:
                        self.max_rss = max(self.max_rss, process.memory_info().rss)
                    except psutil.NoSuchProcess:
                        apps.require(self.owner.process.poll() is not None, 'NOISE_PROCESS_IDENTITY_LOST')
                        break
                    apps.require(self.max_rss <= MAX_NOISE_RSS, 'NOISE_RSS_BUDGET')
                    apps.require(self.output.parent.joinpath('noise.log').stat().st_size <= MAX_NOISE_LOG,
                                 'NOISE_LOG_BUDGET')
                    apps.require(time.monotonic() - self.started <= self.policy['owner_seconds'], 'NOISE_OWNER_DEADLINE')
            except BaseException:
                self.errors.append('NOISE_WATCHDOG_FAILED')
                # Kill only this owned Job Object; this is never successful cleanup.
                try:
                    self.owner.close(kill=True)
                except BaseException:
                    self.errors.append('NOISE_FORCED_CLEANUP_UNCONFIRMED')

        self.watcher = threading.Thread(target=watch, name='native-noise-watchdog', daemon=True)
        self.watcher.start()
        deadline = time.monotonic() + 15
        while not (self.output / 'ready.json').is_file():
            apps.require(self.owner.process.poll() is None and not self.errors and time.monotonic() < deadline,
                         'NOISE_READY_NOT_ESTABLISHED')
            time.sleep(.02)
        ready = read_json(self.output / 'ready.json'); self.ready = ready
        self.policy_receipts['ready'] = validate_noise_policy(ready, self.producer['implementation'])
        apps.require(ready.get('status') == 'READY' and ready.get('pid') == self.owner.process.pid and
                     ready.get('created_100ns') == self.identity['creation_time_filetime_ticks'] and
                     all(ready.get(key) == self.producer[key] for key in
                         ('source_sha256', 'executable_sha256', 'implementation', 'expected_native_handles')),
                     'NOISE_IDENTITY_MISMATCH')

    def await_handoffs(self, target, whole_deadline, *, minimum_seconds=0):
        apps.require(type(target) is int and 0 <= target <= 2**63 - 1 and
            type(minimum_seconds) is int and minimum_seconds in (0, PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS) and
            (minimum_seconds == 0 or self.producer['implementation'] == 'PYTHON_CTYPES_WIN32'),
            'INVALID_NOISE_PRELUDE_REQUEST')
        prelude_limit = NATIVE_PRELUDE_SECONDS if self.producer['implementation'] == 'NATIVE_WIN32' else PRELUDE_SECONDS
        started = time.monotonic(); deadline = min(started + prelude_limit, whole_deadline)
        self.prelude = {'target_handoffs': target, 'requested_minimum_seconds': minimum_seconds,
                        'wait_seconds': 0, 'maximum_wait_seconds': prelude_limit, 'status': 'IN_PROGRESS'}
        previous = None
        context = {'phase': 'OWNER_POLL', 'leaf': None}
        try:
            while time.monotonic() < deadline:
                context.update(phase='OWNER_POLL', leaf=None)
                apps.require(not self.errors and self.owner.process.poll() is None, 'NOISE_PRELUDE_OWNER_FAILED')
                context['phase'] = 'PROGRESS_GLOB'
                paths = sorted(self.output.glob('progress-????.json'))
                apps.require(len(paths) <= self.policy['progress_limit'], 'NOISE_PROGRESS_FILE_BUDGET')
                if paths:
                    path = paths[-1]
                    context.update(phase='READ_PROGRESS_RECEIPT', leaf=path.name)
                    progress = read_json(path, phase_context=context)
                    context['phase'] = 'VALIDATE_PROGRESS'
                    validate_progress(progress, self.ready, previous, implementation=self.producer['implementation'])
                    previous = progress
                    self.prelude.update(observed_handoffs=progress['total_handoffs'], sequence=progress['sequence'])
                    context['phase'] = 'HASH_PROGRESS'
                    self.prelude['receipt_sha256'] = apps.file_hash(path)
                    context['phase'] = 'STAT_PROGRESS'
                    self.prelude['receipt_bytes'] = path.stat().st_size
                    context['phase'] = 'OWNER_RECHECK'
                    apps.require(not self.errors and self.owner.process.poll() is None,
                                 'NOISE_PRELUDE_OWNER_FAILED')
                    context['phase'] = 'ELAPSED_GUARD'
                    observed = time.monotonic()
                    self.prelude['wait_seconds'] = observed - started
                    apps.require(observed < deadline, 'COMPARABLE_NOISE_PRELUDE_NOT_ESTABLISHED')
                    if progress['total_handoffs'] >= target and observed - started >= minimum_seconds:
                        self.prelude['status'] = 'COMPLETED'
                        return
                context['phase'] = 'WAIT'
                time.sleep(.02)
            raise AssertionError('COMPARABLE_NOISE_PRELUDE_NOT_ESTABLISHED')
        except BaseException as error:
            self.prelude.update(status='FAILED', wait_seconds=time.monotonic() - started,
                failure=bounded_failure(error, context['phase'], context['leaf']))
            raise

    def stop(self):
        if self.cleanup.get('status') == 'COMPLETED':
            return
        apps.require(self.owner is not None, 'NOISE_OWNER_MISSING')
        ready = getattr(self, 'ready', {})
        self.stop_observation['child_ready'] = {name: ready.get(name) if type(ready.get(name)) is int
            and 0 <= ready[name] <= 2**63 - 1 else 'NOT_ESTABLISHED'
            for name in ('begin_qpc', 'qpc_frequency_hz')}
        try:
            before = self.owner.process.poll()
            self.stop_observation['child_exit_before_stop_request'] = before if type(before) is int else 'RUNNING'
        except Exception as error:
            self.stop_observation['pre_request_poll_error'] = apps._qa_code(str(error))
        try:
            kernel = kernel_api()
            self.stop_observation['parent_qpc_frequency_hz'] = counter(kernel, 'QueryPerformanceFrequency')
            self.stop_observation['parent_stop_request_begin_qpc'] = counter(kernel)
        except Exception as error:
            self.stop_observation['parent_clock_error'] = apps._qa_code(str(error))
        (self.output / 'stop.request').touch(exist_ok=False)
        self.stop_observation['parent_stop_requested'] = True
        try:
            if 'parent_clock_error' not in self.stop_observation:
                self.stop_observation['parent_stop_request_end_qpc'] = counter(kernel)
        except Exception as error:
            self.stop_observation['parent_clock_error'] = apps._qa_code(str(error))
        try:
            exit_code = self.owner.process.wait(timeout=8)
            self.stop_observation['child_exit_code'] = exit_code
        finally:
            collect_noise_stop_observation(self.output, self.stop_observation)
        apps.require(exit_code == 0, 'NOISE_EXIT_NOT_CONFIRMED')
        self.watcher_stop.set(); self.watcher.join(timeout=2)
        apps.require(not self.watcher.is_alive() and not self.errors, 'NOISE_WATCHDOG_NOT_CLOSED')
        self.oracle = read_json(self.output / 'oracle.json')
        self.policy_receipts['oracle'] = validate_noise_policy(self.oracle, self.producer['implementation'])
        validate_noise_oracle(self.oracle, self.owner.process.pid,
                              self.identity['creation_time_filetime_ticks'],
                              expected_handles=self.producer['expected_native_handles'],
                              implementation=self.producer['implementation'])
        apps.require(all(self.oracle.get(key) == self.producer[key] for key in
            ('source_sha256', 'executable_sha256', 'implementation', 'expected_native_handles')) and
            {w['tid']: w['created_100ns'] for w in self.oracle['workers']} ==
            {w['tid']: w['created_100ns'] for w in self.ready['workers']} and
            sum(w['handoffs'] for w in self.oracle['workers']) >= self.prelude.get('observed_handoffs', 0),
            'NOISE_FINAL_IDENTITY_OR_PROGRESS_CHANGED')
        # Read the live Job Object before close can hide a leaked descendant.
        class Accounting(C.Structure):
            _fields_ = [('times', C.c_int64 * 4), ('page_faults', W.DWORD),
                        ('total_processes', W.DWORD), ('active_processes', W.DWORD), ('terminated', W.DWORD)]
        kernel = self.owner.kernel
        kernel.QueryInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]
        kernel.QueryInformationJobObject.restype = W.BOOL
        accounting = Accounting(); handle = self.owner.job
        apps.require(handle and kernel.QueryInformationJobObject(handle, 1, C.byref(accounting),
                     C.sizeof(accounting), None) and accounting.active_processes == 0,
                     'NOISE_OWNED_DESCENDANTS_NOT_CONFIRMED_EXITED')
        self.owner.close(kill=False)
        kernel.GetHandleInformation.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
        kernel.GetHandleInformation.restype = W.BOOL
        flags = W.DWORD(); C.set_last_error(0)
        alive = kernel.GetHandleInformation(handle, C.byref(flags))
        apps.require(not alive and C.get_last_error() == 6, 'NOISE_JOB_HANDLE_CLOSURE_UNCONFIRMED')
        self.log.close()
        self.cleanup = {'status': 'COMPLETED', 'child_exit_code': 0,
                        'active_job_processes_before_close': 0, 'job_handle_closed_verified': True,
                        'all_threads_joined': True, 'native_handles_closed': self.producer['expected_native_handles'],
                        'max_rss_bytes': self.max_rss}

    def abort(self):
        self.watcher_stop.set()
        if self.watcher:
            self.watcher.join(timeout=3)
            if self.watcher.is_alive():
                self.cleanup = {'status': 'WATCHDOG_EXIT_UNCONFIRMED', 'cleanup_required': True}
                return
        if self.owner:
            self.owner.close(kill=True)
        exited = self.owner is not None and self.owner.process.poll() is not None
        if self.log and exited:
            self.log.close()
        self.cleanup = {'status': 'FORCED_OR_UNCONFIRMED_NOT_ACCEPTED',
                        'process_exit_observed': exited, 'cleanup_required': True}


def collect_noise_stop_observation(output, observation):
    """Read bounded child facts without certifying cleanup or hiding a failure."""
    def integer(value):
        return value if type(value) is int and 0 <= value <= 2**63 - 1 else 'NOT_ESTABLISHED'
    def boolean(value):
        return value if type(value) is bool else 'NOT_ESTABLISHED'
    def code(value):
        return value if isinstance(value, str) and re.fullmatch(r'(?:NATIVE_)?NOISE_[A-Z0-9_]{1,80}', value) else 'NOT_ESTABLISHED'
    try:
        path = output / 'oracle.json'
        oracle = read_json(path)
        projected = {'schema': oracle.get('schema') if oracle.get('schema') == 'blackbox.scheduler-noise/1'
                     else 'NOT_ESTABLISHED',
                     'status': oracle.get('status') if oracle.get('status') in ('COMPLETED', 'FAILED')
                     else 'NOT_ESTABLISHED',
                     'receipt_bytes': path.stat().st_size, 'receipt_sha256': apps.file_hash(path),
                     'acceptance_scope': 'UNVALIDATED_CHILD_RECEIPT_NOT_JOB_OR_HANDLE_CLOSURE_PROOF'}
        projected['implementation'] = oracle.get('implementation') if oracle.get('implementation') in (
            'NATIVE_WIN32', 'PYTHON_CTYPES_WIN32') else 'NOT_ESTABLISHED'
        for name in ('stop_requested', 'all_threads_joined', 'cleanup_required'):
            projected[name] = boolean(oracle.get(name))
        for name in ('pid', 'pairs', 'qpc_frequency_hz', 'begin_qpc', 'end_qpc',
                     'ttl_seconds', 'progress_limit',
                     'native_handles_created', 'native_handles_closed', 'event_handles_created',
                     'event_handles_closed', 'thread_handles_created', 'thread_handles_closed'):
            projected[name] = integer(oracle.get(name))
        created = oracle.get('created_100ns')
        projected['created_100ns'] = created if isinstance(created, str) and re.fullmatch(r'[0-9]{1,20}', created) else 'NOT_ESTABLISHED'
        errors = oracle.get('errors')
        projected['errors'] = [code(value) for value in errors[:32]] if type(errors) is list and len(errors) <= 32 else 'NOT_ESTABLISHED'
        workers = oracle.get('workers')
        if type(workers) is list and len(workers) == 2 * PAIRS:
            projected['workers'] = []
            for worker in workers:
                worker = worker if type(worker) is dict else {}
                item = {name: integer(worker.get(name)) for name in ('tid', 'handoffs', 'begin_qpc', 'end_qpc')}
                created = worker.get('created_100ns')
                item['created_100ns'] = created if isinstance(created, str) and re.fullmatch(r'[0-9]{1,20}', created) else 'NOT_ESTABLISHED'
                projected['workers'].append(item)
        else:
            projected['workers'] = 'NOT_ESTABLISHED'
        observation['child_oracle'] = projected
    except Exception as error:
        observation.setdefault('child_oracle', 'NOT_ESTABLISHED')
        observation['oracle_read_error'] = apps._qa_code(str(error))
    try:
        path = output.parent / 'noise.log'
        apps.require(path.stat().st_size <= MAX_NOISE_LOG, 'NOISE_LOG_BUDGET')
        observation['child_log'] = {'bytes': path.stat().st_size, 'sha256': apps.file_hash(path),
                                    'scope': 'HASH_ONLY_NO_RAW_CHILD_LOG'}
    except Exception as error:
        observation.setdefault('child_log', 'NOT_ESTABLISHED')
        observation['log_read_error'] = apps._qa_code(str(error))


def validate_noise_oracle(oracle, pid, created, *, expected_handles=2 * PAIRS, implementation=None):
    if implementation is not None:
        validate_noise_policy(oracle, implementation)
    workers = oracle.get('workers')
    apps.require(oracle.get('schema') == 'blackbox.scheduler-noise/1' and oracle.get('status') == 'COMPLETED'
        and oracle.get('pid') == pid and oracle.get('created_100ns') == created
        and oracle.get('pairs') == PAIRS and oracle.get('stop_requested') is True
        and oracle.get('all_threads_joined') is True and oracle.get('native_handles_created') == expected_handles
        and oracle.get('native_handles_closed') == expected_handles and oracle.get('cleanup_required') is False
        and oracle.get('errors') == [] and type(workers) is list and len(workers) == 2 * PAIRS,
        'NOISE_ORACLE_OR_CLEANUP_UNCONFIRMED')
    apps.require(type(oracle.get('qpc_frequency_hz')) is int and oracle['qpc_frequency_hz'] > 0 and
        len({w['tid'] for w in workers}) == 2 * PAIRS and all(type(w.get('tid')) is int and w['tid'] > 0
        and type(w.get('handoffs')) is int and w['handoffs'] > 0 and
        type(w.get('begin_qpc')) is int and type(w.get('end_qpc')) is int and
        w['begin_qpc'] < w['end_qpc'] and str(w.get('created_100ns', '')).isdigit() for w in workers),
        'NOISE_REAL_HANDOFFS_OR_IDENTITIES_MISSING')


def validate_rejection(meta, actual_hash, native):
    apps.require(meta.get('status') == 'TRUNCATED' and type(meta.get('rows')) is int and
        0 < meta['rows'] <= 250000 and meta.get('import_completeness') == 'BOUNDED_PREFIX' and
        meta.get('input_sha256') == actual_hash, 'REPRODUCTION_NOT_ESTABLISHED')
    apps.require(native.get('switch_rows', 0) > 0 and native.get('ready_rows', 0) > 0 and
        native.get('switch_rows', 0) + native.get('ready_rows', 0) >= MIN_NOISE_ROWS and
        native.get('noise_tids_observed', 0) >= PAIRS and native.get('qpc_frequency_matches') is True,
        'NATIVE_NOISE_ATTRIBUTION_NOT_ESTABLISHED')


def validate_progress(progress, ready, previous=None, *, implementation=None):
    limit = MAX_PROGRESS_RECEIPTS
    if implementation is not None:
        limit = noise_policy(implementation)['progress_limit']
        validate_noise_policy(ready, implementation)
        validate_noise_policy(progress, implementation)
    workers = progress.get('workers')
    apps.require(progress.get('schema') == 'blackbox.scheduler-noise-progress/1' and
        progress.get('pid') == ready['pid'] and progress.get('created_100ns') == ready['created_100ns'] and
        progress.get('source_sha256') == ready['source_sha256'] and
        all(progress.get(key) == ready.get(key) for key in
            ('implementation', 'executable_sha256', 'expected_native_handles')) and
        type(progress.get('qpc_frequency_hz')) is int and progress['qpc_frequency_hz'] > 0 and
        progress['qpc_frequency_hz'] == ready['qpc_frequency_hz'] and
        type(progress.get('sequence')) is int and 1 <= progress['sequence'] <= limit and
        type(progress.get('qpc')) is int and type(progress.get('sample_begin_qpc')) is int and
        type(progress.get('sample_end_qpc')) is int and
        0 <= ready['begin_qpc'] <= progress['sample_begin_qpc'] <= progress['sample_end_qpc'] == progress['qpc'] and
        type(workers) is list and len(workers) == 2 * PAIRS and
        {w['tid'] for w in workers} == {w['tid'] for w in ready['workers']} and
        all(type(w.get('handoffs')) is int and 0 <= w['handoffs'] <= 2**63 - 1 for w in workers) and
        type(progress.get('total_handoffs')) is int and
        progress['total_handoffs'] == sum(w['handoffs'] for w in workers), 'NOISE_PROGRESS_IDENTITY_OR_COUNTS')
    if previous is not None:
        old = {w['tid']: w['handoffs'] for w in previous['workers']}
        apps.require(progress['sequence'] >= previous['sequence'] and progress['qpc'] >= previous['qpc'] and
            all(w['handoffs'] >= old[w['tid']] for w in workers), 'NOISE_PROGRESS_REGRESSED')
        apps.require((progress == previous if progress['sequence'] == previous['sequence'] else
            progress['sample_begin_qpc'] >= previous['sample_end_qpc']), 'NOISE_PROGRESS_SAMPLE_OVERLAP')


def validate_positive(result, meta):
    capabilities = result.get('capabilities')
    apps.require(result.get('status') == 'PASS' and type(capabilities) is dict and
        set(capabilities) == SEVENZIP_CAPABILITIES and all(v == 'PASS' for v in capabilities.values()) and
        meta.get('status') == 'DECODED' and type(meta.get('rows')) is int and meta['rows'] > 0 and
        meta.get('import_completeness') == 'ALL_EMITTED_RECORDS', 'FOCUSED_7ZIP_COMPLETE_ACCEPTANCE_FAILED')


def validate_workload_activity(first, last, clock):
    before = {w['tid']: w['handoffs'] for w in first['workers']}
    after = {w['tid']: w['handoffs'] for w in last['workers']}
    apps.require(all(type(snapshot.get(key)) is int for snapshot in (first, last)
        for key in ('sequence', 'sample_begin_qpc', 'sample_end_qpc', 'qpc_frequency_hz')) and
        all(type(clock.get(key)) is int for key in ('begin_qpc', 'end_qpc', 'qpc_frequency_hz')) and
        0 <= clock['begin_qpc'] < clock['end_qpc'] and clock['qpc_frequency_hz'] > 0 and
        first['qpc_frequency_hz'] == last['qpc_frequency_hz'] == clock['qpc_frequency_hz'] and
        first['sequence'] < last['sequence'] and
        clock['begin_qpc'] < first['sample_begin_qpc'] <= first['sample_end_qpc'] <=
        last['sample_begin_qpc'] <= last['sample_end_qpc'] < clock['end_qpc'] and
        len(before) == 2 * PAIRS and set(before) == set(after) and
        all(after[tid] > before[tid] for tid in before), 'NOISE_ALL_THREADS_ACTIVE_IN_WORKLOAD_NOT_ESTABLISHED')
    return {'threads_with_positive_handoff_delta': len(before),
            'handoffs_between_receipts': sum(after.values()) - sum(before.values()),
            'first_sample_begin_qpc': first['sample_begin_qpc'], 'first_sample_end_qpc': first['sample_end_qpc'],
            'last_sample_begin_qpc': last['sample_begin_qpc'], 'last_sample_end_qpc': last['sample_end_qpc']}


def workload_activity(noise, clock):
    paths = sorted(noise.output.glob('progress-????.json'))
    apps.require(len(paths) <= noise.policy['progress_limit'], 'NOISE_PROGRESS_FILE_BUDGET')
    selected = []; previous = None
    for path in paths:
        progress = read_json(path)
        validate_progress(progress, noise.ready, previous, implementation=noise.producer['implementation']); previous = progress
        if clock['begin_qpc'] < progress['sample_begin_qpc'] <= progress['sample_end_qpc'] < clock['end_qpc']:
            selected.append((path, progress))
    apps.require(len(selected) >= 2, 'NOISE_WORKLOAD_PROGRESS_INTERVAL_MISSING')
    first_path, first = selected[0]; last_path, last = selected[-1]
    result = validate_workload_activity(first, last, clock)
    return {**result, 'first_receipt_sha256': apps.file_hash(first_path),
            'last_receipt_sha256': apps.file_hash(last_path)}


def validate_original_source(diagnostic, actual_hash, actual_bytes):
    apps.require(diagnostic.get('schema') == 'blackbox.decoder-app-trace-diagnostic/1' and
        diagnostic.get('source_sha256') == actual_hash and
        type(diagnostic.get('source_bytes')) is int and diagnostic['source_bytes'] == actual_bytes and
        diagnostic.get('metadata_input_sha256_matches') is True,
        'DIAGNOSTIC_ORIGINAL_SOURCE_CHANGED')
    return {'source_sha256': actual_hash, 'source_bytes': actual_bytes,
            'metadata_input_sha256_matches': True}


def native_attribution(index, meta, oracle, deadline, target_pids=()):
    from blackbox_core.decoder_cpu import classify_cpu_sample
    workers = {w['tid']: w for w in oracle['workers']}
    result = {'switch_rows': 0, 'ready_rows': 0, 'noise_tids_observed': 0,
              'qpc_frequency_matches': meta.get('engine', {}).get('trace_counter_frequency_hz') == oracle['qpc_frequency_hz']}
    observed = set()
    def counts():
        return {'rows': 0, 'stacked_rows': 0, 'frames': 0, 'cpu_samples': 0,
                'cpu_samples_with_stacks': 0, 'derived_index_event_json_bytes': 0,
                'derived_index_frame_json_bytes': 0}
    known = {pid: {'counts': counts(), 'instances': set(), 'missing_instance': False}
             for pid in set(target_pids) | {oracle['pid']}}
    groups = {key: counts() for key in ('target_application', 'owned_noise', 'other', 'unattributed')}
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        apps.require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'DIAGNOSTIC_INDEX_INTEGRITY')
        apps.require(db.execute('SELECT count(*) FROM events').fetchone()[0] == meta['rows'], 'DIAGNOSTIC_INDEX_COUNT')
        for number, (data,) in enumerate(db.execute('SELECT data FROM events'), 1):
            if number % 512 == 0:
                apps.require(time.monotonic() < deadline, 'DIAGNOSTIC_NATIVE_SCAN_DEADLINE')
            row = json.loads(data); schedule = row.get('thread_schedule') or {}
            pid = row.get('pid'); frames = row.get('frames') or []
            if pid in known:
                item = known[pid]; bucket = item['counts']; instance = row.get('process_instance')
                if type(instance) is int and instance >= 0:
                    if len(item['instances']) < 2:
                        item['instances'].add(instance)
                else:
                    item['missing_instance'] = True
            else:
                bucket = groups['other' if type(pid) is int and pid > 0 else 'unattributed']
            cpu = classify_cpu_sample(row, 'etw') == 'PROCESS_SAMPLE'
            bucket['rows'] += 1; bucket['stacked_rows'] += bool(frames); bucket['frames'] += len(frames)
            bucket['cpu_samples'] += cpu; bucket['cpu_samples_with_stacks'] += cpu and bool(frames)
            bucket['derived_index_event_json_bytes'] += len(data.encode('utf-8'))
            bucket['derived_index_frame_json_bytes'] += len(json.dumps(frames, ensure_ascii=True,
                separators=(',', ':'), allow_nan=False).encode('utf-8'))
            if (schedule.get('schema') != 'blackbox.thread-schedule/1' or
                    schedule.get('source') != 'ETW_KERNEL_SCHEDULER' or
                    row.get('provider_guid', '').lower() != '9e814aad-3204-11d2-9a82-006008a86939'):
                continue
            parser = schedule.get('parser')
            if parser not in ('TRACEEVENT_CSWITCH', 'TRACEEVENT_READY_THREAD'):
                continue
            matched = False
            for key in ('old_thread', 'new_thread', 'ready_thread', 'waker_thread'):
                identity = schedule.get(key)
                if not isinstance(identity, dict):
                    continue
                worker = workers.get(identity.get('tid'))
                if (worker and identity.get('pid') == oracle['pid'] and
                    identity.get('attribution') == 'TRACELOG_THREAD_LIFETIME' and
                    type(identity.get('thread_instance')) is int and identity['thread_instance'] >= 0 and
                    type(identity.get('process_instance')) is int and identity['process_instance'] >= 0 and
                    worker['begin_qpc'] <= int(row['source_ticks']) <= worker['end_qpc']):
                    observed.add(identity['tid']); matched = True
            if matched:
                result['switch_rows' if parser == 'TRACEEVENT_CSWITCH' else 'ready_rows'] += 1
    result['noise_tids_observed'] = len(observed)
    ambiguous = []
    for pid, item in known.items():
        if len(item['instances']) != 1 or item['missing_instance']:
            ambiguous.append(pid); name = 'unattributed'
        else:
            name = 'owned_noise' if pid == oracle['pid'] else 'target_application'
        for key, value in item['counts'].items():
            groups[name][key] += value
    result['stack_attribution'] = {'groups': groups, 'ambiguous_known_pids': sorted(ambiguous),
        'scope': 'OWNED_PID_LIST_AND_SINGLE_TRACE_PROCESS_INDEX_NOT_CAUSAL_OR_CREATION_TIME_ATTESTATION',
        'byte_scope': 'DERIVED_INDEX_JSON_BYTES_NOT_ACTUAL_NATIVE_JSONL_BYTE_DISTRIBUTION'}
    return result


def validate_output_observation(value, meta):
    processes = value.get('processes')
    apps.require(value.get('schema') == 'blackbox.native-output-observation/1' and type(processes) is list and
        len(processes) == 1, 'ACTUAL_NATIVE_OUTPUT_OBSERVATION_MISSING')
    item = processes[0]
    apps.require(item.get('status') == 'OBSERVED' and item.get('helper_exit_code') == 0 and
        type(item.get('output_bytes')) is int and item['output_bytes'] > 0 and
        re.fullmatch(r'[a-f0-9]{64}', item.get('output_sha256', '')) and
        item.get('footer') == {'status': meta['status'], 'rows': meta['rows']},
        'ACTUAL_NATIVE_OUTPUT_OBSERVATION_UNCONFIRMED')
    return item


def validate_case_contract(expectation, assertion_observed, result, meta, actual_hash, native, output):
    apps.require(native.get('qpc_frequency_matches') is True, 'NATIVE_TRACE_COUNTER_FREQUENCY_MISMATCH')
    if expectation in ('ROW_BUDGET_NEGATIVE', 'OUTPUT_BUDGET_NEGATIVE', 'NATIVE_BUDGET_NEGATIVE'):
        apps.require(assertion_observed, 'EXPECTED_NATIVE_REJECTION_NOT_OBSERVED')
        apps.require(meta.get('status') == 'TRUNCATED' and type(meta.get('rows')) is int and
            0 < meta['rows'] <= 250000 and meta.get('import_completeness') == 'BOUNDED_PREFIX' and
            meta.get('input_sha256') == actual_hash, 'EXPECTED_NATIVE_PREFIX_NOT_ESTABLISHED')
        if expectation == 'ROW_BUDGET_NEGATIVE':
            apps.require(meta['rows'] == 250000, 'EXPECTED_NATIVE_ROW_LIMIT_NOT_REACHED')
        elif expectation == 'OUTPUT_BUDGET_NEGATIVE':
            apps.require(meta['rows'] < 250000 and output['output_bytes'] > 384 * 1024**2,
                         'EXPECTED_NATIVE_OUTPUT_LIMIT_NOT_REACHED')
        else:
            apps.require(meta['rows'] == 250000, 'EXPECTED_NATIVE_ROW_LIMIT_NOT_REACHED')
        if expectation != 'OUTPUT_BUDGET_NEGATIVE':
            validate_rejection(meta, actual_hash, native)
        return 'EXPECTED_' + expectation
    apps.require(expectation == 'COMPLETE_NATIVE_7ZIP' and not assertion_observed,
                 'COMPLETE_NATIVE_CASE_STILL_REJECTED')
    validate_positive(result, meta)
    apps.require(native['qpc_frequency_matches'], 'FOCUSED_TRACE_COUNTER_FREQUENCY_MISMATCH')
    return 'COMPLETE_7ZIP_ACCEPTANCE'


def seal_and_remove_large_evidence(root, work, source, index, proof):
    apps.require(proof['noise_cleanup']['status'] == 'COMPLETED' and
        proof['capture_cleanup']['status'] == 'STOPPED' and
        proof['native_output']['helper_exit_code'] == 0, 'EVIDENCE_REMOVAL_RESOURCE_CLEANUP_UNCONFIRMED')
    candidates = {'etl': source, 'index': index}
    expected = {}
    for name, path in candidates.items():
        info = path.lstat()
        apps.require(path.resolve().parent == work.resolve() and not path.is_symlink() and
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            not (getattr(info, 'st_file_attributes', 0) & 0x400) and
            (path.suffix.lower() == '.etl' if name == 'etl' else path.name == 'decoded.sqlite3'),
            'EVIDENCE_REMOVAL_NOT_OWNED_REGULAR_FILE')
        expected[name] = (info.st_dev, info.st_ino, info.st_size)
        apps.require(proof['evidence'][name] == {'sha256': apps.file_hash(path), 'bytes': info.st_size},
                     'EVIDENCE_REMOVAL_HASH_CHANGED')
    sealed = root / 'case-sealed.json'
    write_receipt(sealed, {'schema': 'blackbox.owned-evidence-seal/1', 'facts': proof})
    seal_hash = apps.file_hash(sealed)
    apps.require(read_json(sealed, 128 * 1024).get('facts') == proof and apps.file_hash(sealed) == seal_hash,
                 'EVIDENCE_SEAL_READBACK_FAILED')
    removed = []
    proof['evidence_retention'] = {'status': 'REMOVAL_NOT_COMPLETED', 'seal_sha256': seal_hash,
        'scope': 'ONLY_THIS_FRESH_OWNED_QA_CAPTURE_ETL_AND_CLOSED_INDEX', 'removed': removed}
    for name, path in candidates.items():
        info = path.lstat()
        apps.require((info.st_dev, info.st_ino, info.st_size) == expected[name] and
            not path.is_symlink() and apps.file_hash(path) == proof['evidence'][name]['sha256'] and
            apps.file_hash(sealed) == seal_hash, 'EVIDENCE_REMOVAL_IDENTITY_CHANGED')
        path.unlink(); apps.require(not path.exists() and not path.is_symlink(), 'EVIDENCE_REMOVAL_UNCONFIRMED')
        removed.append(name)
    proof['evidence_retention']['status'] = 'OWNED_QA_EVIDENCE_HASHED_THEN_REMOVED'


def collect_bounded_case_facts(proof, work, helper, clock):
    """Secondary diagnostics never replace the primary failure or certify cleanup."""
    facts = proof.setdefault('small_facts', {})
    errors = proof.setdefault('fact_errors', {})
    failure_path = work / 'workload-failure.json'
    try:
        if failure_path.is_file():
            failure = read_json(failure_path)
            apps.require(failure.get('schema') == 'blackbox.app-workload-failure/1',
                         'WORKLOAD_FAILURE_SCHEMA_UNRECOGNIZED')
            facts['workload_failure'] = apps.project_workload_failure(failure)
    except Exception as error:
        facts.setdefault('workload_failure', 'NOT_ESTABLISHED')
        errors['workload_failure'] = apps._qa_code(str(error))
    def scalar(value):
        if type(value) is bool or type(value) is int and abs(value) <= 2**63 - 1:
            return value
        if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_+.-]{1,96}', value):
            return value
        return 'NOT_ESTABLISHED'
    for key, filename, limit in (('summary', 'decoder-summary.json', 256 * 1024),
                                  ('workload', 'workload-oracle.json', 32768)):
        try:
            value = read_json(work / filename, limit)
            if key == 'summary':
                facts[key] = {name: scalar(value.get(name)) for name in ('status', 'rows', 'input_sha256',
                    'import_completeness', 'events_with_stacks', 'events_with_errors', 'bounded_events',
                    'decoder_reported_lost_events')}
            else:
                application = value.get('application') if type(value.get('application')) is dict else {}
                facts[key] = {name: scalar(value.get(name)) for name in
                              ('input_sha256', 'input_bytes', 'roundtrips_verified', 'requested_minimum_roundtrips', 'workload_policy',
                               'requested_process_timeout_seconds')}
                facts[key]['application_sha256'] = scalar(application.get('sha256'))
                entries = value.get('workloads')
                if type(entries) is list and len(entries) <= 6 and all(type(item) is dict for item in entries):
                    facts[key]['owned_processes'] = [{**{name: scalar(item.get(name)) for name in
                        ('pid', 'creation_time_filetime_ticks', 'owned_image_matches_requested', 'exit_code',
                         'role', 'cycle', 'configured_timeout_seconds')},
                        'elapsed_monitor_seconds': item.get('elapsed_monitor_seconds') if
                            type(item.get('elapsed_monitor_seconds')) in (int, float) and
                            0 <= item['elapsed_monitor_seconds'] <= 2**63 - 1 else 'NOT_ESTABLISHED'}
                        for item in entries]
                else:
                    facts[key]['owned_processes'] = 'NOT_ESTABLISHED'
                    errors['workload_processes'] = 'NOT_ESTABLISHED'
        except Exception as error:
            facts.setdefault(key, 'NOT_ESTABLISHED')
            errors[key] = apps._qa_code(str(error))
    facts['workload_qpc_bounds'] = {key: scalar(clock.get(key)) for key in
                                  ('begin_qpc', 'end_qpc', 'qpc_frequency_hz')}
    try:
        path = work / 'input.bin'
        apps.require(path.stat().st_size <= 8 * 1024**2, 'DIAGNOSTIC_INPUT_FACT_SIZE')
        facts['actual_input_file'] = {'bytes': path.stat().st_size, 'sha256': apps.file_hash(path)}
    except Exception as error:
        facts.setdefault('actual_input_file', 'NOT_ESTABLISHED')
        errors['input_file'] = apps._qa_code(str(error))
    for name, path in (('helper_sha256', helper), ('driver_sha256', Path(__file__)),
                       ('apps_sha256', Path(apps.__file__)), ('capture_sha256', ROOT / 'tools' / 'qa_schedule_capture.py')):
        if name not in facts:
            try:
                facts[name] = apps.file_hash(path)
            except Exception as error:
                facts[name] = 'NOT_ESTABLISHED'; errors[name] = apps._qa_code(str(error))


def validate_native_timing(ready, clock, *, complete=False, facts=None):
    facts = {} if facts is None else facts
    facts.update(status='NOT_ESTABLISHED', scope='NATIVE_QA_ADMISSION_QPC_NOT_HARD_OS_DEADLINE',
        ready_to_work_begin_limit_seconds=90, whole_workload_limit_seconds=65)
    frequency = clock.get('qpc_frequency_hz')
    apps.require(type(frequency) is int and 0 < frequency <= 2**63 - 1 and
        type(ready.get('qpc_frequency_hz')) is int and ready['qpc_frequency_hz'] == frequency and
        type(ready.get('begin_qpc')) is int and type(clock.get('begin_qpc')) is int and
        0 <= ready['begin_qpc'] <= clock['begin_qpc'] <= 2**63 - 1, 'NATIVE_QOS_CLOCK_NOT_ESTABLISHED')
    facts.update(qpc_frequency_hz=frequency, ready_qpc=ready['begin_qpc'], work_begin_qpc=clock['begin_qpc'],
        ready_to_work_begin_seconds=(clock['begin_qpc'] - ready['begin_qpc']) / frequency, status='REJECTED')
    apps.require(clock['begin_qpc'] - ready['begin_qpc'] <= 90 * frequency, 'NATIVE_QOS_READY_TO_WORK_EXCEEDED')
    facts['status'] = 'READY_TO_WORK_WITHIN_LIMIT'
    if complete:
        apps.require(type(clock.get('end_qpc')) is int and clock['begin_qpc'] < clock['end_qpc'] <= 2**63 - 1,
                     'NATIVE_QOS_CLOCK_NOT_ESTABLISHED')
        facts.update(work_end_qpc=clock['end_qpc'], whole_workload_seconds=(clock['end_qpc'] - clock['begin_qpc']) / frequency,
                     status='REJECTED')
        apps.require(clock['end_qpc'] - clock['begin_qpc'] <= 65 * frequency, 'NATIVE_QOS_WORKLOAD_EXCEEDED')
        facts['status'] = 'WITHIN_LIMITS'
    return facts


class BudgetCapture:
    """Stop noise at the workload boundary; always flush the owned WPR session."""
    def __init__(self, actual, noise, clock, cleanup, captures, end_counter, lifecycle):
        self.actual = actual; self.noise = noise; self.clock = clock
        self.cleanup = cleanup; self.captures = captures; self.end_counter = end_counter
        self.lifecycle = lifecycle; self.first_error = None; self.noise_stop_attempted = False

    @property
    def active(self):
        return self.actual.active

    def remember(self, error, phase):
        fact = bounded_failure(error, phase)
        if self.first_error is None:
            self.first_error = error
            self.lifecycle['primary_error'] = fact
        elif error is not self.first_error:
            errors = self.lifecycle.setdefault('secondary_errors', [])
            if len(errors) < 8:
                errors.append(fact)

    def stop_noise(self):
        if self.noise_stop_attempted or self.noise.cleanup.get('status') == 'COMPLETED':
            return
        self.noise_stop_attempted = True
        self.lifecycle['noise_stop_attempted'] = True
        try:
            self.noise.stop()
        except BaseException as error:
            self.remember(error, 'NOISE_STOP')

    def observe_workload_failure(self, owner, failure):
        existing = self.lifecycle.get('failure_scheduler_observation')
        if existing is not None:
            return existing
        frequency = self.clock.get('qpc_frequency_hz')
        observation = {'schema': 'blackbox.controlled-scheduler-failure/1',
            'scope': 'OBSERVATIONS_ONLY_NOT_STATE_WAIT_OR_CAUSE',
            'time_scope': 'TWO_SEQUENTIAL_NONATOMIC_POST_ASSERT_PRE_CLEANUP_SNAPSHOTS',
            'workload_status': 'INCOMPLETE_GUARD_FAILURE_BOUNDARY', 'errors': {},
            'qpc_frequency_hz': frequency if type(frequency) is int and 0 < frequency <= 2**63 - 1
                else 'NOT_ESTABLISHED'}
        self.lifecycle['failure_scheduler_observation'] = observation
        pending = sys.exc_info()[1]
        if pending is not None and self.first_error is None:
            self.remember(pending, 'APPLICATION')

        def mark(name):
            try:
                tick = self.end_counter()
                apps.require(type(tick) is int and 0 <= tick <= 2**63 - 1,
                             'FAILURE_OBSERVER_COUNTER_UNAVAILABLE')
                observation[name] = tick
            except Exception as error:
                observation[name] = 'NOT_ESTABLISHED'
                observation['errors'][name] = apps._qa_code(str(error))

        mark('failure_boundary_qpc')
        self.clock['failure_boundary_qpc'] = observation['failure_boundary_qpc']
        for label in ('target', 'noise'):
            mark(label + '_begin_qpc')
            try:
                if label == 'target':
                    process = owner.process
                    created = failure.get('creation_time_filetime_ticks')
                    apps.require(type(failure.get('pid')) is int and failure['pid'] == process.pid and
                        failure.get('owned_image_matches_requested') is True and
                        failure.get('image_identity_source') == 'OWNED_WINDOWS_PROCESS_HANDLE' and
                        isinstance(created, str) and re.fullmatch(r'[0-9]{1,20}', created),
                        'FAILURE_TARGET_OWNED_IDENTITY_NOT_ESTABLISHED')
                    result = apps.observe_owned_thread_priorities(process, created)
                else:
                    process = self.noise.owner.process
                    created = self.noise.identity['creation_time_filetime_ticks']
                    ready = self.noise.ready; workers = ready.get('workers')
                    apps.require(ready.get('pid') == process.pid and ready.get('created_100ns') == created and
                        type(workers) is list and len(workers) == 2 * PAIRS and all(type(worker) is dict and
                            type(worker.get('tid')) is int and 1 <= worker['tid'] <= 2**32 - 1 and
                            isinstance(worker.get('created_100ns'), str) and
                            re.fullmatch(r'[0-9]{1,20}', worker['created_100ns']) for worker in workers) and
                        len({worker['tid'] for worker in workers}) == 2 * PAIRS,
                        'FAILURE_NOISE_THREAD_IDENTITIES_NOT_ESTABLISHED')
                    result = apps.observe_owned_thread_priorities(process, created,
                        thread_births={worker['tid']: worker['created_100ns'] for worker in workers})
                apps.require(type(result) is dict, 'OWNED_PRIORITY_OBSERVER_RETURN_TYPE')
                observation[label] = result
            except Exception as error:
                observation[label] = {'status': 'UNKNOWN', 'reason_code': apps._qa_code(str(error))}
            mark(label + '_end_qpc')
        mark('snapshots_end_qpc')
        # The application guard has already failed. Release the noise before
        # target teardown can consume the remaining fixed child lifetime.
        self.stop_noise()
        mark('after_noise_stop_poll_begin_qpc')
        after = {'scope': 'AFTER_NOISE_STOP_BEFORE_TARGET_CLEANUP', 'state': 'UNKNOWN',
                 'exit_code': 'NOT_ESTABLISHED'}
        try:
            code = owner.process.poll()
            if code is None:
                after['state'] = 'RUNNING'
            elif type(code) is int and -(2**31) <= code <= 2**32 - 1:
                after.update(state='EXITED', exit_code=code)
        except Exception as error:
            after['reason_code'] = apps._qa_code(str(error))
        observation['target_after_noise_stop'] = after
        mark('after_noise_stop_poll_end_qpc')
        try:
            print('CONTROLLED_SCHEDULER_FAILURE_FACTS ' + json.dumps(observation, sort_keys=True), flush=True)
        except Exception as error:
            observation['errors']['stdout'] = apps._qa_code(str(error))
        return observation

    def stop(self):
        if self.first_error is not None:
            raise self.first_error
        try:
            self.clock['end_qpc'] = self.end_counter()
        except BaseException as error:
            self.remember(error, 'WORKLOAD_END_CLOCK')
        if self.noise.producer['implementation'] == 'NATIVE_WIN32':
            timing = self.lifecycle.setdefault('native_timing', {})
            try:
                validate_native_timing(self.noise.ready, self.clock, complete=True, facts=timing)
            except BaseException as error:
                self.remember(error, 'NATIVE_TIMING')
        self.stop_noise()
        result = None
        try:
            result = self.actual.stop()
            self.captures.append(result)
            apps.require(not self.actual.active, 'DIAGNOSTIC_WPR_STOP_UNCONFIRMED')
            self.cleanup.update(status='STOPPED', cleanup_required=False)
        except BaseException as error:
            self.cleanup.update(status='UNCONFIRMED', cleanup_required=True)
            self.remember(error, 'WPR_STOP')
        if self.first_error is not None:
            raise self.first_error
        return result

    def cancel(self):
        # apps.seven_zip calls this from its finally. Retain the triggering
        # exception even if cancellation or the first noise stop also fails.
        pending = sys.exc_info()[1]
        if self.first_error is None and pending is not None:
            self.remember(pending, 'APPLICATION')
        if self.noise.owner:
            self.stop_noise()
        result = None
        if self.actual.active:
            try:
                result = self.actual.cancel()
                apps.require(not self.actual.active, 'DIAGNOSTIC_WPR_CANCEL_UNCONFIRMED')
                self.cleanup.update(status='CANCELLED', cleanup_required=False)
            except BaseException as error:
                self.cleanup.update(status='UNCONFIRMED', cleanup_required=True)
                self.remember(error, 'WPR_CANCEL')
        if self.first_error is not None:
            raise self.first_error
        return result


def validate_workload_budget(workload, policy):
    seconds = apps.workload_policy_seconds(policy)
    apps.require(type(workload) is dict, 'CONTROLLED_WORKLOAD_BUDGET_NOT_OBSERVED')
    entries = workload.get('workloads')
    minimum = apps.validate_minimum_roundtrips(workload.get('requested_minimum_roundtrips'))
    apps.require(workload.get('workload_policy') == policy and
        type(workload.get('roundtrips_verified')) is int and
        minimum <= workload['roundtrips_verified'] <= 3 and
        type(workload.get('requested_process_timeout_seconds')) is int and
        workload['requested_process_timeout_seconds'] == seconds and type(entries) is list and
        len(entries) in (2, 4, 6) and len(entries) == 2 * workload['roundtrips_verified'] and all(type(item) is dict and
            type(item.get('pid')) is int and 1 <= item['pid'] <= 2**32 - 1 and
            type(item.get('configured_timeout_seconds')) is int and item['configured_timeout_seconds'] == seconds and
            type(item.get('elapsed_monitor_seconds')) in (int, float) and
            0 <= item['elapsed_monitor_seconds'] <= 2**63 - 1 and
            type(item.get('exit_code')) is int and item['exit_code'] == 0 and
            item.get('role') == ('COMPRESS' if number % 2 == 0 else 'EXTRACT') and
            type(item.get('cycle')) is int and item['cycle'] == number // 2
            for number, item in enumerate(entries)), 'CONTROLLED_WORKLOAD_BUDGET_NOT_OBSERVED')
    return {'workload_policy': policy, 'requested_process_timeout_seconds': seconds,
        'requested_minimum_roundtrips': minimum, 'roundtrips_verified': workload['roundtrips_verified'],
        'monitor_duration_scope': 'OBSERVED_MONITOR_DURATION_NOT_HARD_OS_DEADLINE',
        'workloads': [{key: item.get(key) for key in ('pid', 'role', 'cycle', 'exit_code',
                      'configured_timeout_seconds', 'elapsed_monitor_seconds')} for item in entries]}


def run_case(output, helper, source_sha, deadline, profile, producer, expectation, target_handoffs=0,
             *, native_module_encoding=None, minimum_roundtrips=1, minimum_prelude_seconds=0):
    apps.validate_minimum_roundtrips(minimum_roundtrips)
    apps.require(type(target_handoffs) is int and 0 <= target_handoffs <= 2**63 - 1 and
        type(minimum_prelude_seconds) is int and minimum_prelude_seconds in (0, PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS) and
        (minimum_prelude_seconds == 0 or producer['implementation'] == 'PYTHON_CTYPES_WIN32' and
         expectation == 'OUTPUT_BUDGET_NEGATIVE'), 'INVALID_CONTROLLED_STIMULUS_REQUEST')
    apps.require(minimum_prelude_seconds == (PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS
        if expectation == 'OUTPUT_BUDGET_NEGATIVE' else 0), 'INVALID_CONTROLLED_STIMULUS_REQUEST')
    identity = source_identity(source_sha)
    apps.require(identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD', 'DIAGNOSTIC_SOURCE_IDENTITY')
    output.mkdir(parents=True, exist_ok=False)
    work = output / '7zip'; work.mkdir()
    noise = NoiseOwner(output / 'noise', producer)
    workload_policy = 'CONTROLLED_NATIVE_60' if producer['implementation'] == 'NATIVE_WIN32' else 'ORDINARY_30'
    proof = {'schema': 'blackbox.native-budget-diagnostic/1', 'status': 'REPRODUCTION_NOT_ESTABLISHED',
        'source_identity': identity, 'historical_a80_cause': 'NOT_ESTABLISHED',
        'positive_application_acceptance': 'NOT_ESTABLISHED', 'synthetic_etw': False,
        'requested_profile': profile, 'expectation': expectation,
        'requested_workload_policy': workload_policy,
        'requested_process_timeout_seconds': apps.workload_policy_seconds(workload_policy),
        'requested_minimum_roundtrips': minimum_roundtrips,
        'requested_minimum_prelude_seconds': minimum_prelude_seconds,
        'requested_noise_policy': dict(noise.policy),
        'requested_native_module_encoding': native_module_encoding or 'DEFAULT',
        'noise_producer': {key: producer[key] for key in
            ('implementation', 'source_sha256', 'executable_sha256', 'expected_native_handles')},
        'evidence': {}}
    captures = []; original_factory = apps.start_schedule
    capture_cleanup = {'status': 'NOT_STARTED', 'cleanup_required': False}
    capture_lifecycle = {'secondary_errors': []}
    capture_profile = {}
    workload_clock = {}
    kernel = kernel_api()
    frequency = counter(kernel, 'QueryPerformanceFrequency')
    workload_clock['qpc_frequency_hz'] = frequency

    def factory(folder, *, profile='schedule'):
        apps.require(profile == proof['requested_profile'], 'DIAGNOSTIC_PROFILE_NOT_FORWARDED')
        capture_cleanup.update(status='START_REQUESTED', cleanup_required=True)
        actual = original_factory(folder, profile=profile)
        capture_cleanup.update(status='RECORDING', cleanup_required=True)
        capture = BudgetCapture(actual, noise, workload_clock, capture_cleanup, captures,
                                lambda: counter(kernel), capture_lifecycle)
        try:
            apps.require(actual.qa_profile == profile, 'DIAGNOSTIC_ACTUAL_PROFILE_MISMATCH')
            capture_profile.update(name=actual.qa_profile, entry=actual.profile_entry,
                                   xml_sha256=apps.file_hash(actual.profile_path))
            proof['capture_profile'] = dict(capture_profile)
            noise.start()
            if target_handoffs or minimum_prelude_seconds:
                noise.await_handoffs(target_handoffs, deadline, minimum_seconds=minimum_prelude_seconds)
            apps.require(noise.ready['qpc_frequency_hz'] == frequency, 'DIAGNOSTIC_NOISE_COUNTER_MISMATCH')
            workload_clock['begin_qpc'] = counter(kernel)
        except BaseException as error:
            capture.remember(error, 'NOISE_START_OR_PRELUDE')
            capture.cancel()  # Normal noise stop, then WPR cancel; rethrows the original.
            raise
        if producer['implementation'] == 'NATIVE_WIN32':
            timing = capture_lifecycle.setdefault('native_timing', {})
            try:
                validate_native_timing(noise.ready, workload_clock, facts=timing)
            except BaseException as error:
                capture.remember(error, 'NATIVE_TIMING')
                capture.cancel()
                raise
        return capture

    try:
        apps.start_schedule = factory
        expected_assertion_observed = False
        result = None
        try:
            options = {'minimum_roundtrips': minimum_roundtrips}
            if native_module_encoding is not None:
                options['native_module_encoding'] = native_module_encoding
            if workload_policy != 'ORDINARY_30':
                options['workload_policy'] = workload_policy
            result = apps.seven_zip(work, helper, profile=profile, **options)
        except AssertionError as error:
            if str(error) != EXPECTED_REASON:
                raise
            expected_assertion_observed = True
        finally:
            apps.start_schedule = original_factory
        collect_bounded_case_facts(proof, work, helper, workload_clock)
        apps.require(len(captures) == 1, 'DIAGNOSTIC_CAPTURE_METADATA_NOT_AVAILABLE')
        meta_path = work / 'decoder-summary.json'; index = work / 'decoded.sqlite3'
        source = work / captures[0]['path']; meta = read_json(meta_path, 256 * 1024)
        oracle_path = work / 'workload-oracle.json'; workload = read_json(oracle_path)
        index_hash = apps.file_hash(index); source_hash = apps.file_hash(source)
        diagnostic_path = work / 'decoder-diagnostic.json'
        diagnostic = read_json(diagnostic_path)
        observation_path = work / 'native-output-observation.json'
        observation = read_json(observation_path)
        proof.update(decoder_status=meta['status'], rows=meta['rows'], noise_cleanup=noise.cleanup,
                     decoder_reported_lost_events=meta.get('decoder_reported_lost_events'),
                     actual_native_module_encoding=apps.observed_module_encoding(meta))
        proof['native_output_observation'] = observation
        proof['decoder_diagnostic'] = diagnostic
        roundtrips = workload.get('roundtrips_verified'); workloads = workload.get('workloads')
        proof['roundtrips_verified'] = roundtrips
        apps.require(type(workload.get('requested_minimum_roundtrips')) is int and
            workload['requested_minimum_roundtrips'] == minimum_roundtrips,
            'CONTROLLED_MINIMUM_ROUNDTRIPS_NOT_FORWARDED')
        native = native_attribution(index, meta, noise.oracle, deadline,
                                    [p['pid'] for p in workloads])
        proof['native_attribution'] = native
        proof['expected_assertion_observed'] = expected_assertion_observed
        if result is not None:
            proof['capabilities'] = result.get('capabilities')
        else:
            proof['capabilities_assessment'] = 'NOT_EVALUATED_FULL_DECODE_REQUIRED; PREFIX_COUNTS_ARE_NOT_PASS'
        apps.require(type(roundtrips) is int and minimum_roundtrips <= roundtrips <= 3 and type(workloads) is list
            and len(workloads) == 2 * roundtrips and all(p.get('exit_code') == 0 and
            p.get('owned_image_matches_requested') is True for p in workloads) and
            any(p.get('cpu_seconds_observed', 0) > 0 for p in workloads), 'DIAGNOSTIC_REAL_7ZIP_WORKLOAD_MISSING')
        input_hash = apps.file_hash(work / 'input.bin')
        apps.require(workload.get('input_sha256') == input_hash and workload.get('input_bytes') == 8 * 1024**2 and
            all(apps.file_hash(work / f'roundtrip-{n}' / 'input.bin') == input_hash for n in range(roundtrips)),
            'DIAGNOSTIC_ROUNDTRIP_HASH_MISMATCH')
        apps.require(workload_clock['begin_qpc'] < workload_clock['end_qpc'] and
            all(w['begin_qpc'] <= workload_clock['begin_qpc'] < workload_clock['end_qpc'] <= w['end_qpc']
                for w in noise.oracle['workers']), 'NOISE_THREADS_DID_NOT_COVER_ENTIRE_WORKLOAD')
        activity = workload_activity(noise, workload_clock)
        files = {'etl': source, 'index': index, 'decoder_summary': meta_path,
            'decoder_diagnostic': diagnostic_path, 'workload_oracle': oracle_path,
            'native_output_observation': observation_path,
            'noise_ready': noise.output / 'ready.json', 'noise_oracle': noise.output / 'oracle.json'}
        hashes = {name: {'sha256': apps.file_hash(path), 'bytes': path.stat().st_size} for name, path in files.items()}
        live_bytes = sum(p.stat().st_size for p in output.parent.rglob('*') if p.is_file())
        proof['measured_live_qa_bytes_before_removal'] = live_bytes
        apps.require(apps.file_hash(source) == source_hash and apps.file_hash(index) == index_hash and
            live_bytes <= MAX_OUTPUT,
            'DIAGNOSTIC_SOURCE_CHANGED_OR_OUTPUT_BUDGET')
        from tools.qa_schedule_capture import profile_definition
        profile_relative = profile_definition(profile)[0]
        profile_path = ROOT / 'tools' / profile_relative
        apps.require(apps.file_hash(profile_path) == capture_profile['xml_sha256'], 'DIAGNOSTIC_PROFILE_CHANGED')
        final_identity = source_identity(source_sha)
        apps.require(final_identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD',
                     'DIAGNOSTIC_FINAL_SOURCE_IDENTITY')
        proof.update(decoder_status=meta['status'],
            rows=meta['rows'], native_attribution=native, noise_cleanup=noise.cleanup,
            roundtrips_verified=roundtrips, decoder_reported_lost_events=meta.get('decoder_reported_lost_events'),
            evidence=hashes, final_source_identity=final_identity, capture_profile=capture_profile,
            input_sha256=input_hash, input_bytes=workload['input_bytes'],
            application_sha256=workload['application']['sha256'], native_image=workload['application']['native_image'],
            noise_workload_coverage={**workload_clock, 'qpc_frequency_hz': frequency,
                                     'all_16_threads_bracket': True, **activity},
            helper_sha256=apps.file_hash(helper),
            script_hashes={'driver': apps.file_hash(Path(__file__)), 'apps': apps.file_hash(Path(apps.__file__)),
                           'capture': apps.file_hash(ROOT / 'tools' / 'qa_schedule_capture.py')},
            owned_processes=[{'pid': p['pid'], 'created_100ns': p['creation_time_filetime_ticks'],
                              'owned_image_matches_requested': p['owned_image_matches_requested']} for p in workloads])
        proof.update(capture_cleanup=dict(capture_cleanup), noise_cleanup=noise.cleanup,
                     noise_handoffs=sum(w['handoffs'] for w in noise.oracle['workers']), prelude=noise.prelude)
        apps.require(noise.cleanup.get('status') == 'COMPLETED' and capture_cleanup['status'] == 'STOPPED',
                     'DIAGNOSTIC_CAPTURE_OR_OWNER_UNCONFIRMED')
        proof['original_source_receipt'] = validate_original_source(diagnostic, source_hash, source.stat().st_size)
        proof['workload_budget'] = validate_workload_budget(workload, workload_policy)
        proof['noise_policy_receipts'] = dict(noise.policy_receipts)
        if producer['implementation'] == 'NATIVE_WIN32':
            proof['native_timing'] = dict(capture_lifecycle['native_timing'])
        proof['native_output'] = validate_output_observation(observation, meta)
        apps.require(proof['actual_native_module_encoding'] ==
            ('INLINE_V1' if native_module_encoding == 'INLINE_V1' else 'PER_EVENT_MODULES_V1'),
            'REQUESTED_NATIVE_MODULE_ENCODING_NOT_OBSERVED')
        decision = validate_case_contract(expectation, expected_assertion_observed, result, meta,
                                         source_hash, native, proof['native_output'])
        if expectation == 'COMPLETE_NATIVE_7ZIP':
            proof['positive_application_acceptance'] = 'ALL_EIGHT_ORACLES_PASS'
        proof['admission_decision'] = decision
        seal_and_remove_large_evidence(output, work, source, index, proof)
        proof['status'] = decision
    except BaseException as error:
        proof.update(status='REPRODUCTION_NOT_ESTABLISHED', error_type=type(error).__name__,
                     reason_code=apps._qa_code(str(error)))
    finally:
        apps.start_schedule = original_factory
        proof['capture_cleanup'] = capture_cleanup
        proof['capture_lifecycle'] = capture_lifecycle
        proof['prelude'] = dict(noise.prelude)
        proof['noise_policy_receipts'] = dict(noise.policy_receipts)
        if 'native_timing' in capture_lifecycle:
            proof['native_timing'] = dict(capture_lifecycle['native_timing'])
        if capture_cleanup['cleanup_required']:
            proof.update(status='REPRODUCTION_NOT_ESTABLISHED', cleanup_required=True)
        if noise.cleanup.get('status') != 'COMPLETED':
            try:
                noise.abort()
            except BaseException:
                noise.cleanup = {'status': 'UNCONFIRMED', 'cleanup_required': True}
        proof['noise_cleanup'] = noise.cleanup
        collect_noise_stop_observation(noise.output, noise.stop_observation)
        noise.stop_observation['watchdog_error_codes'] = [apps._qa_code(value) for value in noise.errors[:32]]
        proof['noise_stop_observation'] = noise.stop_observation
        proof['capture_profile'] = dict(capture_profile) if capture_profile else {'status': 'NOT_ESTABLISHED'}
        proof.setdefault('noise_workload_qpc_bounds', {key: workload_clock.get(key, 'NOT_ESTABLISHED') for key in
                         ('begin_qpc', 'end_qpc', 'qpc_frequency_hz')})
        if noise.cleanup.get('status') == 'COMPLETED':
            proof['noise_handoffs'] = sum(w['handoffs'] for w in noise.oracle['workers'])
            proof['prelude'] = noise.prelude
        collect_bounded_case_facts(proof, work, helper, workload_clock)
        for key, filename in (('native_output_observation', 'native-output-observation.json'),
                              ('decoder_diagnostic', 'decoder-diagnostic.json')):
            path = work / filename
            try:
                if key not in proof and path.is_file():
                    proof[key] = read_json(path)
            except Exception as error:
                proof.setdefault('fact_errors', {})[key] = apps._qa_code(str(error))
        # Preserve every already available owned fact even if admission or an
        # earlier reader failed; never replace a sealed, removed-file hash.
        available = {'index': work / 'decoded.sqlite3', 'decoder_summary': work / 'decoder-summary.json',
            'decoder_diagnostic': work / 'decoder-diagnostic.json', 'native_output_observation': work / 'native-output-observation.json',
            'workload_oracle': work / 'workload-oracle.json', 'noise_ready': noise.output / 'ready.json',
            'noise_oracle': noise.output / 'oracle.json'}
        if captures:
            available['etl'] = work / captures[0]['path']
        for name, path in available.items():
            try:
                if name not in proof['evidence'] and path.is_file():
                    apps.require(path.stat().st_size <= 768 * 1024**2, 'FAILURE_FACT_SIZE_BUDGET')
                    proof['evidence'][name] = {'sha256': apps.file_hash(path), 'bytes': path.stat().st_size}
            except Exception as error:
                proof.setdefault('fact_errors', {})[name] = apps._qa_code(str(error))
        for key in ('native_attribution', 'native_output', 'original_source_receipt', 'noise_workload_coverage', 'owned_processes',
                    'input_sha256', 'input_bytes', 'application_sha256', 'native_image', 'helper_sha256',
                    'script_hashes', 'final_source_identity'):
            if key not in proof:
                proof[key] = 'NOT_ESTABLISHED'
                proof.setdefault('fact_errors', {}).setdefault(key, 'NOT_ESTABLISHED_DEPENDENT_FACT_UNAVAILABLE')
        try:
            apps.write_json(output / 'budget-diagnostic.json', proof)
        except Exception as error:
            proof.update(status='REPRODUCTION_NOT_ESTABLISHED', evidence_write_error=apps._qa_code(str(error)))
        print('CONTROLLED_NATIVE_CASE_FACTS ' + json.dumps(proof, sort_keys=True), flush=True)
    return proof


def validate_comparison(first, second, *, positive=True):
    apps.require(first.get('status') in ('EXPECTED_ROW_BUDGET_NEGATIVE', 'EXPECTED_NATIVE_BUDGET_NEGATIVE') and
        second.get('status') == ('COMPLETE_7ZIP_ACCEPTANCE' if positive else 'EXPECTED_OUTPUT_BUDGET_NEGATIVE'),
        'CONTROLLED_PROFILE_A_B_NOT_ESTABLISHED')
    policy = 'CONTROLLED_NATIVE_60' if positive else 'ORDINARY_30'
    seconds = apps.workload_policy_seconds(policy)
    implementation = 'NATIVE_WIN32' if positive else 'PYTHON_CTYPES_WIN32'
    expected_noise_policy = noise_policy(implementation)
    for case in (first, second):
        apps.require(case.get('requested_workload_policy') == policy and
            case.get('requested_process_timeout_seconds') == seconds, 'CONTROLLED_PAIR_WORKLOAD_POLICY_MISMATCH')
        validate_workload_budget(case.get('workload_budget', {}), policy)
        apps.require(type(case.get('requested_minimum_roundtrips')) is int and
            case['requested_minimum_roundtrips'] == case['workload_budget']['requested_minimum_roundtrips'] and
            type(case.get('roundtrips_verified')) is int and
            case['roundtrips_verified'] == case['workload_budget']['roundtrips_verified'],
            'CONTROLLED_PAIR_ROUNDTRIP_RECEIPT_MISMATCH')
        validate_requested_noise_policy(case.get('requested_noise_policy'), implementation)
        receipts = case.get('noise_policy_receipts', {})
        for phase in ('ready', 'oracle'):
            validate_noise_policy(receipts.get(phase), implementation)
        if positive:
            timing = case.get('native_timing', {})
            apps.require(type(timing) is dict, 'NATIVE_QOS_CLOCK_NOT_ESTABLISHED')
            validate_native_timing({'begin_qpc': timing.get('ready_qpc'),
                'qpc_frequency_hz': timing.get('qpc_frequency_hz')},
                {'begin_qpc': timing.get('work_begin_qpc'), 'end_qpc': timing.get('work_end_qpc'),
                 'qpc_frequency_hz': timing.get('qpc_frequency_hz')}, complete=True)
    minimum_prelude = 0 if positive else PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS
    maximum_prelude = NATIVE_PRELUDE_SECONDS if positive else PRELUDE_SECONDS
    apps.require(first.get('requested_minimum_roundtrips') == 1 and
        second.get('requested_minimum_roundtrips') == first['roundtrips_verified'] and
        type(first.get('requested_minimum_prelude_seconds')) is int and first['requested_minimum_prelude_seconds'] == 0 and
        type(second.get('requested_minimum_prelude_seconds')) is int and
        second['requested_minimum_prelude_seconds'] == minimum_prelude,
        'CONTROLLED_PAIR_STIMULUS_REQUEST_MISMATCH')
    first_prelude = first.get('prelude', {})
    apps.require(type(first_prelude.get('target_handoffs')) is int and first_prelude['target_handoffs'] == 0 and
        type(first_prelude.get('requested_minimum_seconds')) is int and first_prelude['requested_minimum_seconds'] == 0 and
        type(first_prelude.get('wait_seconds')) is int and first_prelude['wait_seconds'] == 0 and
        first_prelude.get('status') == 'NOT_REQUIRED', 'CONTROLLED_FIRST_PRELUDE_REQUEST_MISMATCH')
    for key in ('input_sha256', 'input_bytes', 'application_sha256', 'native_image', 'helper_sha256',
                'script_hashes', 'noise_producer'):
        apps.require(first.get(key) == second.get(key) and first.get(key) is not None, 'CONTROLLED_A_B_SOURCE_CHANGED')
    apps.require(first['source_identity']['actual_source_sha'] == second['source_identity']['actual_source_sha'] and
        first['source_identity']['source_tree_sha'] == second['source_identity']['source_tree_sha'] and
        first['capture_profile']['name'] == 'schedule' and second['capture_profile']['name'] == 'cpu_file' and
        first['capture_profile']['xml_sha256'] != second['capture_profile']['xml_sha256'] and
        type(first.get('noise_handoffs')) is int and type(second.get('noise_handoffs')) is int and
        second['noise_handoffs'] >= first['noise_handoffs'] > 0 and
        second['roundtrips_verified'] >= first['roundtrips_verified'] > 0 and
        type(second['prelude'].get('target_handoffs')) is int and
        second['prelude']['target_handoffs'] == first['noise_handoffs'] and
        type(second['prelude'].get('observed_handoffs')) is int and
        second['prelude']['observed_handoffs'] >= first['noise_handoffs'] and
        second['prelude'].get('status') == 'COMPLETED' and
        type(second['prelude'].get('requested_minimum_seconds')) is int and
        second['prelude']['requested_minimum_seconds'] == minimum_prelude and
        type(second['prelude'].get('wait_seconds')) in (int, float) and
        minimum_prelude <= second['prelude']['wait_seconds'] <= maximum_prelude and
        all(case['noise_cleanup']['status'] == 'COMPLETED' and case['capture_cleanup']['status'] == 'STOPPED'
            and case['noise_workload_coverage']['all_16_threads_bracket'] is True
            and case['noise_workload_coverage']['threads_with_positive_handoff_delta'] == 2 * PAIRS
            for case in (first, second)), 'CONTROLLED_A_B_NOISE_OR_CLEANUP_NOT_COMPARABLE')
    apps.require(first['actual_native_module_encoding'] == 'PER_EVENT_MODULES_V1' and
        second['actual_native_module_encoding'] == ('PER_EVENT_MODULES_V1' if positive else 'INLINE_V1'),
        'CONTROLLED_PAIR_TRANSPORT_NOT_ESTABLISHED')
    return {'workload_policy': policy, 'noise_policy_equal': True, 'noise_policy': expected_noise_policy,
            'second_requested_minimum_roundtrips': second['requested_minimum_roundtrips'],
            'second_observed_roundtrips': second['roundtrips_verified'],
            'second_minimum_prelude_seconds': minimum_prelude,
            'second_observed_prelude_seconds': second['prelude']['wait_seconds'],
            'second_maximum_prelude_seconds': maximum_prelude,
            'native_timing_limits': {'ready_to_work_begin_seconds': 90, 'whole_workload_seconds': 65}
                if positive else 'NOT_APPLICABLE_PYTHON_POLICY'}


def diagnostic_output_root(path, *, prepared=False):
    """Adopt only the fresh same-job build directory, never old case output."""
    apps.require(type(prepared) is bool, 'DIAGNOSTIC_PREPARED_MODE_INVALID')
    output = Path(path).absolute()
    if not prepared:
        output.mkdir(parents=True, exist_ok=False)
    else:
        apps.require('..' not in output.parts, 'DIAGNOSTIC_PREPARED_OUTPUT_PATH')
        try:
            relative = output.relative_to(ROOT)
        except ValueError:
            raise AssertionError('DIAGNOSTIC_PREPARED_OUTPUT_OUTSIDE_CHECKOUT') from None
        directories = [ROOT]
        for component in relative.parts:
            directories.append(directories[-1] / component)
        directories.append(output / 'native-build')
        for directory in directories:
            info = directory.lstat()
            apps.require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                not getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400),
                'DIAGNOSTIC_PREPARED_OUTPUT_NOT_REGULAR_DIRECTORY')
        with os.scandir(output) as entries:
            first = next(entries, None)
            second = next(entries, None)
            apps.require(first is not None and first.name == 'native-build' and second is None,
                         'DIAGNOSTIC_PREPARED_OUTPUT_NOT_FRESH')
    return output.resolve(strict=True)


def prepared_budget_deadline(started, elapsed):
    """Charge the earlier build to the same finite 660s active-work budget."""
    apps.require(type(started) in (int, float) and math.isfinite(started) and 0 <= started <= 2**63 - 1 and
        type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 90,
        'DIAGNOSTIC_PREPARED_ELAPSED_INVALID')
    return started + CONTROLLED_SECONDS - elapsed


def validate_prepared_recheck(initial, final):
    """A later read must preserve the externally anchored preparation facts."""
    facts = []
    for record in (initial, final):
        apps.require(type(record) is dict and type(record.get('prepared_validation')) is dict and
            record['prepared_validation'].get('status') == 'VERIFIED_SAME_JOB_BUILD_FILES',
            'DIAGNOSTIC_PREPARED_FINAL_VALIDATION_MISSING')
        prepared_budget_deadline(0, record.get('prepared_build_elapsed_seconds'))
        facts.append(json.dumps({key: record[key] for key in (
            'prepared_validation', 'prepared_build_elapsed_seconds')}, sort_keys=True, allow_nan=False))
    apps.require(facts[0] == facts[1], 'DIAGNOSTIC_PREPARED_CHANGED_AT_END')
    return dict(final['prepared_validation'])


def run_diagnostic(args):
    started = time.monotonic(); deadline = started + CONTROLLED_SECONDS
    prepaid_build_elapsed = 0
    require_hosted_windows()
    output = diagnostic_output_root(args.output, prepared=args.prepared_native_build)
    proof = {'schema': 'blackbox.native-budget-acceptance/2', 'status': 'REPRODUCTION_NOT_ESTABLISHED',
        'historical_a80_cause': 'NOT_ESTABLISHED', 'previous_7f45_result': 'FAILED_FOCUSED_PROFILE_STILL_TRUNCATED',
        'evidence_footprint_scope': 'LIVE_OWNED_QA_TREE; EXISTING_PRODUCTION_PRIVATE_IMPORT_BUDGET_IS_SEPARATE',
        'subwindow_delta_scope': 'REPORT_ONLY; UNEQUAL_QPC_WINDOWS_ARE_NOT_A_CAUSAL_RATE_COMPARISON',
        'python_pair_transport_scope': 'COMPACT_ROW_NEGATIVE_AND_EXPLICIT_INLINE_BYTE_NEGATIVE; NOT_PROFILE_CAUSAL_COMPARISON',
        'native_pair_transport_scope': 'BOTH_DEFAULT_COMPACT_PER_EVENT_MODULES_V1',
        'diagnostic_budget_seconds': CONTROLLED_SECONDS,
        'workload_budget_scope': 'SEVENZIP_ORDINARY_AND_PYTHON_30; CONTROLLED_NATIVE_PAIR_60; NOT_HARD_OS_COMPLETION_DEADLINE',
        'cases': {}}
    try:
        helper = args.helper.resolve(strict=True)
        python = {'implementation': 'PYTHON_CTYPES_WIN32', 'executable': str(Path(sys.executable).resolve()),
            'source_sha256': apps.file_hash(Path(__file__)), 'executable_sha256': apps.file_hash(Path(sys.executable)),
            'expected_native_handles': 16}
        if args.prepared_native_build:
            from tools.qa_decoder_noise_fixture import load_prepared_native_noise
            native = load_prepared_native_noise(output / 'native-build', args.source_sha,
                expected_manifest_sha256=args.prepared_build_sha256)
            elapsed = native['prepared_build_elapsed_seconds']
            deadline = prepared_budget_deadline(started, elapsed)
            prepaid_build_elapsed = elapsed
            validation = native.get('prepared_validation')
            apps.require(type(validation) is dict and validation.get('status') == 'VERIFIED_SAME_JOB_BUILD_FILES',
                         'DIAGNOSTIC_PREPARED_VALIDATION_MISSING')
            proof['prepared_native_build'] = validation
            proof['expected_prepared_manifest_sha256'] = args.prepared_build_sha256
            proof['prepared_build_elapsed_debit_seconds'] = prepaid_build_elapsed
            proof['native_build_mode'] = 'SAME_JOB_PREPARED_BUILD_REVALIDATED_NO_FALLBACK'
        else:
            from tools.qa_decoder_noise_fixture import build_native_noise
            native = build_native_noise(output / 'native-build', args.source_sha)
            proof['native_build_mode'] = 'BUILT_IN_CONTROLLED_TOOL'
        max_live = 0
        for label, producer, positive in (('python', python, False), ('native', native, True)):
            live = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
            max_live = max(max_live, live)
            apps.require(live <= MAX_OUTPUT and time.monotonic() < deadline, 'CONTROLLED_LIVE_OUTPUT_OR_DEADLINE')
            first = run_case(output / (label + '-schedule'), helper, args.source_sha, deadline,
                'schedule', producer, 'NATIVE_BUDGET_NEGATIVE' if positive else 'ROW_BUDGET_NEGATIVE')
            proof['cases'][label + '_schedule'] = first
            max_live = max(max_live, first.get('measured_live_qa_bytes_before_removal', 0))
            apps.require(first['status'] in ('EXPECTED_ROW_BUDGET_NEGATIVE', 'EXPECTED_NATIVE_BUDGET_NEGATIVE'),
                         'CONTROLLED_SCHEDULE_REJECTION_NOT_ESTABLISHED')
            apps.require(time.monotonic() < deadline, 'CONTROLLED_A_B_DEADLINE')
            second = run_case(output / (label + '-cpu-file'), helper, args.source_sha, deadline,
                'cpu_file', producer, 'COMPLETE_NATIVE_7ZIP' if positive else 'OUTPUT_BUDGET_NEGATIVE',
                first['noise_handoffs'], native_module_encoding=None if positive else 'INLINE_V1',
                minimum_roundtrips=first['roundtrips_verified'],
                minimum_prelude_seconds=0 if positive else PYTHON_BYTE_MINIMUM_PRELUDE_SECONDS)
            proof['cases'][label + '_cpu_file'] = second
            max_live = max(max_live, second.get('measured_live_qa_bytes_before_removal', 0))
            proof.setdefault('pair_policy_comparisons', {})[label] = validate_comparison(first, second, positive=positive)
            live = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
            max_live = max(max_live, live)
            apps.require(live <= MAX_OUTPUT and time.monotonic() < deadline, 'CONTROLLED_LIVE_OUTPUT_OR_DEADLINE')
        if args.prepared_native_build:
            final_native = load_prepared_native_noise(output / 'native-build', args.source_sha,
                expected_manifest_sha256=args.prepared_build_sha256)
            proof['prepared_native_build_final'] = validate_prepared_recheck(native, final_native)
            live = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
            max_live = max(max_live, live)
            apps.require(live <= MAX_OUTPUT and time.monotonic() < deadline, 'CONTROLLED_FINAL_PREPARED_DEADLINE_OR_BUDGET')
        proof.update(status='CONTROLLED_NEGATIVE_BUDGETS_AND_NATIVE_A_B_VERIFIED',
                     max_measured_live_qa_bytes=max_live)
    except BaseException as error:
        proof.update(status='REPRODUCTION_NOT_ESTABLISHED', error_type=type(error).__name__,
                     reason_code=apps._qa_code(str(error)))
    finally:
        elapsed = time.monotonic() - started
        proof['observed_elapsed_until_final_report_seconds'] = elapsed if 0 <= elapsed <= 2**63 - 1 else 'NOT_ESTABLISHED'
        proof['observed_elapsed_scope'] = 'BEFORE_JSON_WRITE_AND_STDOUT_NOT_HARD_OS'
        active_elapsed = elapsed + prepaid_build_elapsed
        proof['observed_compile_and_controlled_active_seconds'] = active_elapsed if 0 <= active_elapsed <= 2**63 - 1 else 'NOT_ESTABLISHED'
        proof['active_elapsed_scope'] = 'COMPILE_PLUS_CONTROLLED_INTERVAL_EXCLUDES_INTERVENING_ORDINARY_TRIALS_AND_NEW_SEAL_PUBLICATION_AND_STEP_OUTPUT_NOT_HARD_OS'
        apps.write_json(output / 'budget-diagnostic.json', proof)
        print('CONTROLLED_NATIVE_BUDGET_DIAGNOSTIC ' + json.dumps(proof, sort_keys=True), flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
                stream.write('\n- Controlled negative budgets and native A/B ' + json.dumps(proof, sort_keys=True) + '\n')
    return 0 if proof['status'] == 'CONTROLLED_NEGATIVE_BUDGETS_AND_NATIVE_A_B_VERIFIED' else 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--noise-child', action='store_true')
    parser.add_argument('--prepared-native-build', action='store_true')
    parser.add_argument('--prepared-build-sha256')
    args = parser.parse_args(argv)
    if args.noise_child:
        if (args.helper is not None or args.source_sha is not None or args.prepared_native_build
                or args.prepared_build_sha256 is not None):
            parser.error('noise child accepts only its own output directory')
    elif args.helper is None or args.source_sha is None:
        parser.error('parent requires --helper and --source-sha')
    elif args.prepared_native_build:
        if not re.fullmatch(r'[a-f0-9]{64}', args.prepared_build_sha256 or ''):
            parser.error('prepared build requires the prior step manifest sha256')
    elif args.prepared_build_sha256 is not None:
        parser.error('prepared manifest sha256 requires --prepared-native-build')
    return args


if __name__ == '__main__':
    arguments = parse_args()
    raise SystemExit(noise_child(arguments.output) if arguments.noise_child else run_diagnostic(arguments))
