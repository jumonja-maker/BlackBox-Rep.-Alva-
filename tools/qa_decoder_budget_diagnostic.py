"""CI-only native A/B: a rejected scheduler prefix and complete focused 7-Zip.

The historical a80 release trace is unavailable: its cause remains unknown.
All capture/decode/workload operations delegate to the existing real 7-Zip QA.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import sqlite3
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
MAX_PROGRESS_RECEIPTS = 281
EXPECTED_REASON = 'APP_TRACE_NOT_COMPLETELY_DECODED'
SEVENZIP_CAPABILITIES = frozenset({
    'compression_extraction_hash_roundtrip', 'owned_native_image_identity', 'cpu_counters',
    'etw_cpu_samples', 'etw_cpu_stacks', 'etw_file_operations', 'etw_threads', 'pid_lifetime_attribution',
})


def read_json(path, limit=32768):
    apps.require(0 < path.stat().st_size <= limit, 'DIAGNOSTIC_RECEIPT_SIZE')
    value = json.loads(path.read_text(encoding='utf-8'))
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
             'source_sha256': apps.file_hash(Path(__file__)), 'pairs': PAIRS}

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
    def __init__(self, output):
        self.output = output; self.owner = None; self.log = None; self.errors = []
        self.watcher_stop = threading.Event(); self.watcher = None
        self.started = None; self.max_rss = 0; self.cleanup = {'status': 'NOT_ESTABLISHED'}
        self.prelude = {'target_handoffs': 0, 'wait_seconds': 0}

    def start(self):
        import psutil
        self.log = (self.output.parent / 'noise.log').open('xb')
        self.owner = apps.OwnedProcess([sys.executable, str(Path(__file__).resolve()),
            '--noise-child', '--output', str(self.output)], stdout=self.log, stderr=self.log,
            detach_console=True)
        self.started = time.monotonic()
        self.identity = apps.owned_process_identity(self.owner.process, Path(sys.executable).resolve())
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
                    apps.require(time.monotonic() - self.started <= NOISE_SECONDS + 15, 'NOISE_OWNER_DEADLINE')
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
        apps.require(ready.get('status') == 'READY' and ready.get('pid') == self.owner.process.pid and
                     ready.get('created_100ns') == self.identity['creation_time_filetime_ticks'] and
                     ready.get('source_sha256') == apps.file_hash(Path(__file__)), 'NOISE_IDENTITY_MISMATCH')

    def await_handoffs(self, target, whole_deadline):
        started = time.monotonic(); deadline = min(started + PRELUDE_SECONDS, whole_deadline)
        previous = None
        while time.monotonic() < deadline:
            apps.require(not self.errors and self.owner.process.poll() is None, 'NOISE_PRELUDE_OWNER_FAILED')
            paths = sorted(self.output.glob('progress-????.json'))
            apps.require(len(paths) <= MAX_PROGRESS_RECEIPTS, 'NOISE_PROGRESS_FILE_BUDGET')
            if paths:
                path = paths[-1]; progress = read_json(path)
                validate_progress(progress, self.ready, previous)
                previous = progress
                if progress['total_handoffs'] >= target:
                    self.prelude = {'target_handoffs': target, 'observed_handoffs': progress['total_handoffs'],
                        'wait_seconds': time.monotonic() - started, 'sequence': progress['sequence'],
                        'receipt_sha256': apps.file_hash(path), 'receipt_bytes': path.stat().st_size}
                    return
            time.sleep(.02)
        raise AssertionError('COMPARABLE_NOISE_PRELUDE_NOT_ESTABLISHED')

    def stop(self):
        if self.cleanup.get('status') == 'COMPLETED':
            return
        apps.require(self.owner is not None, 'NOISE_OWNER_MISSING')
        (self.output / 'stop.request').touch(exist_ok=False)
        apps.require(self.owner.process.wait(timeout=8) == 0, 'NOISE_EXIT_NOT_CONFIRMED')
        self.watcher_stop.set(); self.watcher.join(timeout=2)
        apps.require(not self.watcher.is_alive() and not self.errors, 'NOISE_WATCHDOG_NOT_CLOSED')
        self.oracle = read_json(self.output / 'oracle.json')
        validate_noise_oracle(self.oracle, self.owner.process.pid,
                              self.identity['creation_time_filetime_ticks'])
        apps.require(self.oracle.get('source_sha256') == self.ready['source_sha256'] and
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
                        'all_threads_joined': True, 'native_handles_closed': 2 * PAIRS,
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


def validate_noise_oracle(oracle, pid, created):
    workers = oracle.get('workers')
    apps.require(oracle.get('schema') == 'blackbox.scheduler-noise/1' and oracle.get('status') == 'COMPLETED'
        and oracle.get('pid') == pid and oracle.get('created_100ns') == created
        and oracle.get('pairs') == PAIRS and oracle.get('stop_requested') is True
        and oracle.get('all_threads_joined') is True and oracle.get('native_handles_created') == 2 * PAIRS
        and oracle.get('native_handles_closed') == 2 * PAIRS and oracle.get('cleanup_required') is False
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


def validate_progress(progress, ready, previous=None):
    workers = progress.get('workers')
    apps.require(progress.get('schema') == 'blackbox.scheduler-noise-progress/1' and
        progress.get('pid') == ready['pid'] and progress.get('created_100ns') == ready['created_100ns'] and
        progress.get('source_sha256') == ready['source_sha256'] and
        type(progress.get('qpc_frequency_hz')) is int and progress['qpc_frequency_hz'] > 0 and
        progress['qpc_frequency_hz'] == ready['qpc_frequency_hz'] and
        type(progress.get('sequence')) is int and 1 <= progress['sequence'] <= MAX_PROGRESS_RECEIPTS and
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
    apps.require(len(paths) <= MAX_PROGRESS_RECEIPTS, 'NOISE_PROGRESS_FILE_BUDGET')
    selected = []; previous = None
    for path in paths:
        progress = read_json(path)
        validate_progress(progress, noise.ready, previous); previous = progress
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


def native_attribution(index, meta, oracle, deadline):
    workers = {w['tid']: w for w in oracle['workers']}
    result = {'switch_rows': 0, 'ready_rows': 0, 'noise_tids_observed': 0,
              'qpc_frequency_matches': meta.get('engine', {}).get('trace_counter_frequency_hz') == oracle['qpc_frequency_hz']}
    observed = set()
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        apps.require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'DIAGNOSTIC_INDEX_INTEGRITY')
        apps.require(db.execute('SELECT count(*) FROM events').fetchone()[0] == meta['rows'], 'DIAGNOSTIC_INDEX_COUNT')
        for number, (data,) in enumerate(db.execute('SELECT data FROM events'), 1):
            if number % 512 == 0:
                apps.require(time.monotonic() < deadline, 'DIAGNOSTIC_NATIVE_SCAN_DEADLINE')
            row = json.loads(data); schedule = row.get('thread_schedule') or {}
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
    return result


def run_case(output, helper, source_sha, deadline, profile, target_handoffs=0):
    identity = source_identity(source_sha)
    apps.require(identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD', 'DIAGNOSTIC_SOURCE_IDENTITY')
    output.mkdir(parents=True, exist_ok=False)
    work = output / '7zip'; work.mkdir()
    noise = NoiseOwner(output / 'noise')
    proof = {'schema': 'blackbox.native-budget-diagnostic/1', 'status': 'REPRODUCTION_NOT_ESTABLISHED',
        'source_identity': identity, 'historical_a80_cause': 'NOT_ESTABLISHED',
        'positive_application_acceptance': 'NOT_ESTABLISHED', 'synthetic_etw': False,
        'requested_profile': profile}
    captures = []; original_factory = apps.start_schedule
    capture_cleanup = {'status': 'NOT_STARTED', 'cleanup_required': False}
    capture_profile = {}
    workload_clock = {}
    kernel = kernel_api()
    frequency = counter(kernel, 'QueryPerformanceFrequency')
    workload_clock['qpc_frequency_hz'] = frequency

    class Capture:
        def __init__(self, actual):
            self.actual = actual
        @property
        def active(self):
            return self.actual.active
        def stop(self):
            workload_clock['end_qpc'] = counter(kernel)
            result = self.actual.stop(); captures.append(result)
            capture_cleanup.update(status='STOPPED', cleanup_required=False)
            noise.stop()
            return result
        def cancel(self):
            try:
                result = self.actual.cancel()
                apps.require(not self.actual.active, 'DIAGNOSTIC_WPR_CANCEL_UNCONFIRMED')
                capture_cleanup.update(status='CANCELLED', cleanup_required=False)
                return result
            except BaseException:
                capture_cleanup.update(status='UNCONFIRMED', cleanup_required=True)
                raise
            finally:
                if noise.owner:
                    noise.stop()

    def factory(folder, *, profile='schedule'):
        apps.require(profile == proof['requested_profile'], 'DIAGNOSTIC_PROFILE_NOT_FORWARDED')
        capture_cleanup.update(status='START_REQUESTED', cleanup_required=True)
        actual = original_factory(folder, profile=profile)
        capture_cleanup.update(status='RECORDING', cleanup_required=True)
        try:
            apps.require(actual.qa_profile == profile, 'DIAGNOSTIC_ACTUAL_PROFILE_MISMATCH')
            capture_profile.update(name=actual.qa_profile, entry=actual.profile_entry,
                                   xml_sha256=apps.file_hash(actual.profile_path))
            noise.start()
            if target_handoffs:
                noise.await_handoffs(target_handoffs, deadline)
            apps.require(noise.ready['qpc_frequency_hz'] == frequency, 'DIAGNOSTIC_NOISE_COUNTER_MISMATCH')
            workload_clock['begin_qpc'] = counter(kernel)
        except BaseException:
            try:
                actual.cancel()
                apps.require(not actual.active, 'DIAGNOSTIC_WPR_CANCEL_UNCONFIRMED')
                capture_cleanup.update(status='CANCELLED', cleanup_required=False)
            except BaseException:
                capture_cleanup.update(status='UNCONFIRMED', cleanup_required=True)
                raise
            raise
        return Capture(actual)

    try:
        apps.start_schedule = factory
        expected_assertion_observed = False
        result = None
        try:
            result = apps.seven_zip(work, helper, profile=profile)
        except AssertionError as error:
            apps.require(str(error) == EXPECTED_REASON, 'DIAGNOSTIC_UNEXPECTED_ACCEPTANCE_ERROR')
            expected_assertion_observed = True
        finally:
            apps.start_schedule = original_factory
        apps.require(len(captures) == 1 and noise.cleanup.get('status') == 'COMPLETED',
                     'DIAGNOSTIC_CAPTURE_OR_OWNER_UNCONFIRMED')
        meta_path = work / 'decoder-summary.json'; index = work / 'decoded.sqlite3'
        source = work / captures[0]['path']; meta = read_json(meta_path, 256 * 1024)
        oracle_path = work / 'workload-oracle.json'; workload = read_json(oracle_path)
        index_hash = apps.file_hash(index); source_hash = apps.file_hash(source)
        diagnostic_path = work / 'decoder-diagnostic.json'
        diagnostic = read_json(diagnostic_path)
        proof.update(decoder_status=meta['status'], rows=meta['rows'], noise_cleanup=noise.cleanup,
                     decoder_reported_lost_events=meta.get('decoder_reported_lost_events'))
        proof['original_source_receipt'] = validate_original_source(diagnostic, source_hash, source.stat().st_size)
        native = native_attribution(index, meta, noise.oracle, deadline)
        proof['native_attribution'] = native
        proof['expected_assertion_observed'] = expected_assertion_observed
        if profile == 'schedule':
            apps.require(expected_assertion_observed, 'REPRODUCTION_NOT_ESTABLISHED')
            validate_rejection(meta, source_hash, native)
        else:
            apps.require(not expected_assertion_observed, 'FOCUSED_PROFILE_STILL_TRUNCATED')
            validate_positive(result, meta)
            apps.require(native['qpc_frequency_matches'], 'FOCUSED_TRACE_COUNTER_FREQUENCY_MISMATCH')
        roundtrips = workload.get('roundtrips_verified'); workloads = workload.get('workloads')
        apps.require(type(roundtrips) is int and 1 <= roundtrips <= 3 and type(workloads) is list
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
            'noise_ready': noise.output / 'ready.json', 'noise_oracle': noise.output / 'oracle.json'}
        hashes = {name: {'sha256': apps.file_hash(path), 'bytes': path.stat().st_size} for name, path in files.items()}
        apps.require(apps.file_hash(source) == source_hash and apps.file_hash(index) == index_hash and
            sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) <= MAX_OUTPUT,
            'DIAGNOSTIC_SOURCE_CHANGED_OR_OUTPUT_BUDGET')
        from tools.qa_schedule_capture import profile_definition
        profile_relative = profile_definition(profile)[0]
        profile_path = ROOT / 'tools' / profile_relative
        apps.require(apps.file_hash(profile_path) == capture_profile['xml_sha256'], 'DIAGNOSTIC_PROFILE_CHANGED')
        final_identity = source_identity(source_sha)
        apps.require(final_identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD',
                     'DIAGNOSTIC_FINAL_SOURCE_IDENTITY')
        proof.update(status='EXPECTED_NATIVE_BUDGET_REJECTION' if profile == 'schedule' else 'COMPLETE_7ZIP_ACCEPTANCE',
            decoder_status=meta['status'],
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
        if profile == 'cpu_file':
            proof.update(positive_application_acceptance='ALL_EIGHT_ORACLES_PASS', capabilities=result['capabilities'])
    except BaseException as error:
        proof.update(error_type=type(error).__name__, reason_code=apps._qa_code(str(error)))
    finally:
        apps.start_schedule = original_factory
        proof['capture_cleanup'] = capture_cleanup
        if capture_cleanup['cleanup_required']:
            proof.update(status='REPRODUCTION_NOT_ESTABLISHED', cleanup_required=True)
        if noise.cleanup.get('status') != 'COMPLETED':
            try:
                noise.abort()
            except BaseException:
                noise.cleanup = {'status': 'UNCONFIRMED', 'cleanup_required': True}
        proof['noise_cleanup'] = noise.cleanup
        if noise.cleanup.get('status') == 'COMPLETED':
            proof['noise_handoffs'] = sum(w['handoffs'] for w in noise.oracle['workers'])
            proof['prelude'] = noise.prelude
        apps.write_json(output / 'budget-diagnostic.json', proof)
    return proof


def validate_comparison(first, second):
    apps.require(first.get('status') == 'EXPECTED_NATIVE_BUDGET_REJECTION' and
        second.get('status') == 'COMPLETE_7ZIP_ACCEPTANCE', 'CONTROLLED_PROFILE_A_B_NOT_ESTABLISHED')
    for key in ('input_sha256', 'input_bytes', 'application_sha256', 'native_image', 'helper_sha256', 'script_hashes'):
        apps.require(first.get(key) == second.get(key) and first.get(key) is not None, 'CONTROLLED_A_B_SOURCE_CHANGED')
    apps.require(first['source_identity']['actual_source_sha'] == second['source_identity']['actual_source_sha'] and
        first['source_identity']['source_tree_sha'] == second['source_identity']['source_tree_sha'] and
        first['capture_profile']['name'] == 'schedule' and second['capture_profile']['name'] == 'cpu_file' and
        first['capture_profile']['xml_sha256'] != second['capture_profile']['xml_sha256'] and
        type(first.get('noise_handoffs')) is int and type(second.get('noise_handoffs')) is int and
        second['noise_handoffs'] >= first['noise_handoffs'] > 0 and
        second['roundtrips_verified'] >= first['roundtrips_verified'] > 0 and
        second['prelude']['target_handoffs'] == first['noise_handoffs'] and
        second['prelude']['observed_handoffs'] >= first['noise_handoffs'] and
        0 <= second['prelude']['wait_seconds'] <= PRELUDE_SECONDS and
        all(case['noise_cleanup']['status'] == 'COMPLETED' and case['capture_cleanup']['status'] == 'STOPPED'
            and case['noise_workload_coverage']['all_16_threads_bracket'] is True
            and case['noise_workload_coverage']['threads_with_positive_handoff_delta'] == 2 * PAIRS
            for case in (first, second)), 'CONTROLLED_A_B_NOISE_OR_CLEANUP_NOT_COMPARABLE')


def run_diagnostic(args):
    deadline = time.monotonic() + 300
    require_hosted_windows()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    proof = {'schema': 'blackbox.native-budget-profile-ab/1', 'status': 'REPRODUCTION_NOT_ESTABLISHED',
             'historical_a80_cause': 'NOT_ESTABLISHED', 'cases': {}}
    try:
        helper = args.helper.resolve(strict=True)
        first = run_case(output / 'a-schedule', helper, args.source_sha, deadline, 'schedule')
        proof['cases']['A'] = first
        apps.require(first['status'] == 'EXPECTED_NATIVE_BUDGET_REJECTION', 'CONTROLLED_A_REJECTION_NOT_ESTABLISHED')
        apps.require(time.monotonic() < deadline, 'CONTROLLED_A_B_DEADLINE')
        second = run_case(output / 'b-cpu-file', helper, args.source_sha, deadline, 'cpu_file', first['noise_handoffs'])
        proof['cases']['B'] = second
        validate_comparison(first, second)
        apps.require(time.monotonic() < deadline, 'CONTROLLED_A_B_DEADLINE')
        apps.require(sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) <= MAX_OUTPUT,
                     'CONTROLLED_A_B_COMBINED_OUTPUT_BUDGET')
        proof['status'] = 'CONTROLLED_PROFILE_A_B_VERIFIED'
    except BaseException as error:
        proof.update(error_type=type(error).__name__, reason_code=apps._qa_code(str(error)))
    finally:
        apps.write_json(output / 'budget-diagnostic.json', proof)
        print('CONTROLLED_NATIVE_BUDGET_DIAGNOSTIC ' + json.dumps(proof, sort_keys=True), flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
                stream.write('\n- Controlled native profile A/B ' + json.dumps(proof, sort_keys=True) + '\n')
    return 0 if proof['status'] == 'CONTROLLED_PROFILE_A_B_VERIFIED' else 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--noise-child', action='store_true')
    args = parser.parse_args(argv)
    if args.noise_child:
        if args.helper is not None or args.source_sha is not None:
            parser.error('noise child accepts only its own output directory')
    elif args.helper is None or args.source_sha is None:
        parser.error('parent requires --helper and --source-sha')
    return args


if __name__ == '__main__':
    arguments = parse_args()
    raise SystemExit(noise_child(arguments.output) if arguments.noise_child else run_diagnostic(arguments))
