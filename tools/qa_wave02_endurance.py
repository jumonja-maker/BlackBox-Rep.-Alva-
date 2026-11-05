"""One actual hosted-Windows hour per R50 profile, in parallel owned runs.

This QA-only owner drives the existing ResearchSession, never another recorder.
An hour means >=3600 seconds between persisted samples in EACH profile. It is
not GUI, eight-hour, physical Windows 10/11, leak-proof or causal acceptance.
All compilation and execution is refused outside GitHub-hosted Windows x64.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from tools.qa_deep_inspection import file_hash, require, require_hosted_windows, save
from tools.qa_github_endurance import verify_sampling_coverage
from tools.qa_wave02_fixture import WaveProbe, build

PROFILES = ('STANDARD', 'INCIDENT_BURST')
MAX_RSS = 512 * 1024**2
MAX_RSS_GROWTH = 128 * 1024**2
MAX_SESSION_BYTES = 128 * 1024**2
MAX_OUTPUT_BYTES = 192 * 1024**2
MAX_PROFILE_LOG_BYTES = 2 * 1024**2
BURST_PERIOD_SECONDS = 300


def source_proof(expected):
    require_hosted_windows()
    require(type(expected) is str and len(expected) == 40 and
            all(c in '0123456789abcdef' for c in expected), 'WAVE02_EXACT_SOURCE_SHA_REQUIRED')
    from blackbox_universal.provenance import source_identity
    proof = source_identity(expected)
    require(proof.get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD' and
            proof.get('actual_source_sha') == expected, 'WAVE02_ENDURANCE_CHECKOUT_MISMATCH')
    return proof


def command(session, operation, **arguments):
    return session.command({'op': operation, 'args': arguments,
                            'issued_ns': time.monotonic_ns()})


def directory_bytes(root):
    """Bounded inspection of our fresh QA directory; no deletion or quota claim."""
    total = count = 0
    for directory, children, files in os.walk(root, followlinks=False):
        require(len(children) <= 64, 'WAVE02_ENDURANCE_DIRECTORY_BUDGET')
        for name in children + files:
            path = Path(directory) / name
            require(not path.is_symlink(), 'WAVE02_ENDURANCE_UNEXPECTED_SYMLINK')
        for name in files:
            count += 1
            require(count <= 512, 'WAVE02_ENDURANCE_FILE_COUNT_BUDGET')
            # A real writer may finish and unlink its WAL between enumeration
            # and stat. This sampled total is never labelled a hard quota.
            try:
                total += (Path(directory) / name).stat().st_size
            except FileNotFoundError:
                pass
    return total


def read_json(path, maximum=256 * 1024):
    require(not path.is_symlink() and path.stat().st_size <= maximum,
            'WAVE02_ENDURANCE_JSON_BUDGET')
    result = json.loads(path.read_text(encoding='utf-8'))
    require(type(result) is dict, 'WAVE02_ENDURANCE_JSON_SHAPE')
    return result


def open_readonly(path):
    require(path.is_file() and not path.is_symlink(), 'WAVE02_ENDURANCE_DATABASE_MISSING')
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA cache_size=-2048')
    return db


def actual_progress(folder):
    with closing(open_readonly(folder / 'session.sqlite3')) as db:
        count, first, last, low, high = db.execute(
            'SELECT count(*),min(elapsed_ms),max(elapsed_ms),min(seq),max(seq) FROM samples').fetchone()
    require(type(count) is int and count >= 0 and (not count or low == 1 and high == count),
            'WAVE02_ENDURANCE_BASE_SEQUENCE_INCOMPLETE')
    return {'count': count, 'first_ms': first, 'last_ms': last,
            'span_seconds': (last - first) / 1000 if count else 0.}


def artifactless_profile_facts(result):
    """Project finite observed facts, never child paths or arbitrary payloads.

    This is evidence transport, not another acceptance oracle. The parent's
    original source/hash/span/Job checks and the child's SQL/native assertions
    remain mandatory. Missing or ill-typed facts stay explicitly unavailable.
    """
    unavailable = []

    def mapping(value):
        return value if type(value) is dict else {}

    def integer(value, field, maximum=2**63 - 1):
        if type(value) is int and 0 <= value <= maximum:
            return value
        unavailable.append(field)
        return None

    def number(value, field):
        if type(value) in (int, float) and 0 <= value <= 2**63 - 1 and math.isfinite(value):
            return value
        unavailable.append(field)
        return None

    def boolean(value, field):
        if type(value) is bool:
            return value
        unavailable.append(field)
        return None

    def enum(value, choices, field):
        if type(value) is str and value in choices:
            return value
        unavailable.append(field)
        return 'NOT_ESTABLISHED'

    result = mapping(result)
    saved = mapping(result.get('saved'))
    finalization = mapping(saved.get('database_finalization'))
    detail = mapping(saved.get('detail_threads'))
    recorder = mapping(result.get('recorder_cleanup'))
    stop = mapping(result.get('stop'))
    target = mapping(result.get('target_cleanup'))
    oracle = mapping(target.get('oracle'))
    facts = {'schema': 'blackbox.wave02.endurance-artifactless-facts/1',
        'scope': 'OBSERVED_READONLY_SQL_AND_HELD_RESOURCE_FACTS; NOT_NEW_ACCEPTANCE_OR_CAUSAL_PROOF',
        'database_finalization': {
            **{key: integer(finalization.get(key), 'database_finalization.' + key, 4)
               for key in ('database_count', 'integrity_ok_databases', 'nonempty_wal_files')},
            'schema1_exit_code': enum(finalization.get('schema1_exit_code'), ('COMPLETED',), 'schema1_exit_code'),
            'schema2_status': enum(finalization.get('schema2_status'), ('CLOSED',), 'schema2_status'),
            'schema2_exit_code': enum(finalization.get('schema2_exit_code'), ('COMPLETED',), 'schema2_exit_code'),
            'schema2_writer_dropped_commands': integer(finalization.get('schema2_writer_dropped_commands'),
                                                       'schema2_writer_dropped_commands'),
            'research_state': enum(finalization.get('research_state'), ('COMPLETED',), 'research_state'),
            'recording_resources_closed': boolean(finalization.get('recording_resources_closed'),
                                                  'recording_resources_closed'),
            'finalization_error_count': integer(finalization.get('finalization_error_count'),
                                                 'finalization_error_count', 256)},
        'saved_measurements': {
            **{key: integer(saved.get(key), key, 10_000_000) for key in
               ('schema2_standard_samples', 'schema2_detail_samples', 'incident_count',
                'burst_starts', 'burst_ttl_stops', 'manual_incident_refs')},
            **{key: number(saved.get(key), key) for key in
               ('recorded_peak_cpu_one_cpu_percent', 'recorded_rss_range_bytes', 'recorded_write_bytes_delta')}},
        'detail_threads': {key: integer(detail.get(key), 'detail_threads.' + key, 256)
                           for key in ('owner_count', 'live_thread_count', 'error_count')},
        'recorder_cleanup': {
            **{key: boolean(recorder.get(key), 'recorder_cleanup.' + key) for key in
               ('recording_resources_closed', 'optional_jobs_cleanup_required',
                'writer_thread_alive', 'journal_thread_alive')},
            'pending_owned_process_owners': integer(recorder.get('pending_owned_process_owners'),
                                                     'pending_owned_process_owners', 256)},
        'stop': {'state': enum(stop.get('state'), ('COMPLETED',), 'stop.state'),
                 'base_recording_state': enum(stop.get('base_recording_state'), ('COMPLETED',), 'stop.base_recording_state'),
                 'cleanup_required': boolean(stop.get('cleanup_required'), 'stop.cleanup_required'),
                 'error_count': integer(len(stop['errors']) if type(stop.get('errors')) is list else None,
                                        'stop.error_count', 256)},
        'target_cleanup': {'status': enum(target.get('status'), ('COMPLETED',), 'target_cleanup.status'),
                           'exit_code': integer(target.get('exit_code'), 'target_cleanup.exit_code', 2**32 - 1),
                           'native_oracle_cleanup_complete': boolean(oracle.get('cleanup_complete'),
                                                                      'target_cleanup.native_oracle_cleanup_complete')}}
    trigger = saved.get('trigger_coverage')
    if result.get('profile') == 'STANDARD' and trigger is None:
        facts['trigger_coverage'] = {'status': 'NOT_REQUESTED_FOR_STANDARD'}
    else:
        trigger = mapping(trigger)
        codes = trigger.get('observed_codes')
        allowed = {'MANUAL_PROBLEM', 'CPU_SUSTAINED', 'RSS_GROWTH', 'IO_BURST'}
        if (type(codes) is not list or len(codes) > 4 or
                any(type(value) is not str or value not in allowed for value in codes) or
                len(set(codes)) != len(codes)):
            unavailable.append('trigger_coverage.observed_codes')
            codes = None
        facts['trigger_coverage'] = {'observed_codes': codes,
            'incomplete_prehistory_count': integer(trigger.get('incomplete_prehistory_count'),
                                                   'trigger_coverage.incomplete_prehistory_count', 256)}
    facts['status'] = 'OBSERVED_FIXED_FACTS' if not unavailable else 'NOT_ESTABLISHED'
    facts['unavailable_fields'] = unavailable
    return facts


def policy(profile):
    return {'profile': profile, 'windows_enabled': False,
        'adaptive_throttle': True, 'incident_enabled': profile == 'INCIDENT_BURST',
        'max_session_mb': MAX_SESSION_BYTES // 1024**2,
        'burst_seconds': 10, 'burst_interval_ms': 500, 'session_seconds': 0,
        'incident': {'threshold': 20., 'min_duration_ms': 0,
            'pre_ms': 60000, 'post_ms': 2000, 'cooldown_ms': 1000,
            'growth_window_ms': 1000, 'memory_growth_bytes': 8*1024**2,
            'io_rate_bytes_s': 1024, 'max_incidents': 256,
            'max_buffer_samples': 16, 'max_buffer_bytes': 8192,
            'enabled_triggers': ['CPU_SUSTAINED', 'RSS_GROWTH', 'IO_BURST', 'MANUAL_PROBLEM']}}


class NativeController:
    """A single bounded oracle reader while the real sampler keeps progressing."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.thread = None
        self.result = self.error = None
        self.started = None
        self.completed = 0
        self.total_io_bytes = 0
        self.first = self.last = None

    def start(self):
        require(self.thread is None, 'WAVE02_ENDURANCE_CONCURRENT_FIXTURE_COMMAND')
        self.result = self.error = None
        self.started = time.monotonic()
        def work():
            try:
                self.fixture.send('burst')
                begun = self.fixture.receive('burst_begin', timeout=10)
                done = self.fixture.receive('burst_done', timeout=20)
                identity = self.fixture.ready
                require(all(q.get('pid') == identity['pid'] and
                        q.get('created_100ns') == identity['created_100ns'] for q in (begun, done)) and
                        done['worker_threads'] == 4 and done['worker_exit_verified'] is True and
                        done['allocated_bytes'] == 64*1024**2 and done['io_bytes'] > 0 and
                        done['start_qpc'] == begun['start_qpc'] and
                        done['end_qpc'] - begun['start_qpc'] >= identity['qpc_frequency'] * 6,
                        'WAVE02_ENDURANCE_ACTUAL_NATIVE_BURST_NOT_CONFIRMED')
                self.result = {'begin': begun, 'done': done}
            except BaseException as error:
                self.error = error
        self.thread = threading.Thread(target=work, name='wave02-endurance-control', daemon=True)
        self.thread.start()

    def poll(self):
        if self.thread is None:
            return
        require(time.monotonic() - self.started <= 35,
                'WAVE02_ENDURANCE_NATIVE_CONTROL_DEADLINE')
        if self.thread.is_alive():
            return
        self.thread.join(timeout=0)
        self.thread = None
        if self.error is not None:
            raise self.error
        require(self.result is not None, 'WAVE02_ENDURANCE_NATIVE_CONTROL_RESULT_MISSING')
        self.completed += 1
        self.total_io_bytes += self.result['done']['io_bytes']
        if self.first is None:
            self.first = self.result
        self.last = self.result

    def join(self):
        if self.thread is not None:
            self.thread.join(timeout=30)
            require(not self.thread.is_alive(), 'WAVE02_ENDURANCE_NATIVE_CONTROLLER_NOT_CLOSED')
            self.poll()


def inspect_live(session, captures, maxima):
    """Inspect actual owned writers; an enabled policy is not evidence of work."""
    from blackbox_core.optional_jobs import OwnedProcess
    p = session.probe
    require(p.active and p._store is not None and not p.last_error,
            'WAVE02_ENDURANCE_RECORDER_STOPPED_OR_FAILED')
    health = session.jobs.health()
    require(not health.get('cleanup_required') and not session.jobs.busy and
            not OwnedProcess.pending_cleanup(), 'WAVE02_ENDURANCE_PENDING_OPTIONAL_RESOURCE')
    require(not session.wpr and not session.runtime_trace and not p.window_capture,
            'WAVE02_ENDURANCE_UNREQUESTED_COLLECTOR')
    writer = p._store.v2
    require(writer is not None and writer.thread.is_alive() and not writer.failure and
            writer.dropped_commands == 0, 'WAVE02_ENDURANCE_SCHEMA2_WRITER_FAILURE')
    depth = writer._commands.qsize()
    require(depth <= writer._commands.maxsize, 'WAVE02_ENDURANCE_SCHEMA2_QUEUE_BUDGET')
    maxima['writer_queue_depth'] = max(maxima['writer_queue_depth'], depth)
    journal = p._store._journal
    if journal is not None:
        require(not journal.failed and journal._worker.is_alive() and
                journal.pending <= journal._tasks.maxsize, 'WAVE02_ENDURANCE_EVENT_WRITER_FAILURE')
        maxima['event_queue_depth'] = max(maxima['event_queue_depth'], journal.pending)
    detail = p.detailed_capture
    if session.capture_policy['profile'] == 'STANDARD':
        require(detail is None and session._burst_until is None and p.incident_capture is None,
                'WAVE02_ENDURANCE_STANDARD_STARTED_OPTIN_CAPTURE')
    else:
        capture = p.incident_capture
        require(capture is not None, 'WAVE02_ENDURANCE_INCIDENT_CAPTURE_NOT_STARTED')
        coverage = capture.coverage()
        require(coverage['retained_samples'] <= coverage['max_buffer_samples'] == 16 and
                coverage['accounted_buffer_bytes'] <= coverage['max_buffer_bytes'] == 8192 and
                coverage['raw_recording_deleted'] is False,
                'WAVE02_ENDURANCE_PREHISTORY_BUDGET_VIOLATION')
        maxima['ring_accounted_bytes'] = max(maxima['ring_accounted_bytes'], coverage['accounted_buffer_bytes'])
        maxima['ring_samples'] = max(maxima['ring_samples'], coverage['retained_samples'])
        if detail is not None:
            require(session._burst_until is not None and detail.thread is not None and
                    detail.thread.is_alive() and detail.error is None,
                    'WAVE02_ENDURANCE_BURST_DETAIL_OWNER_FAILED')
            if not any(q is detail for q in captures):
                captures.append(detail)
                require(len(captures) <= 256, 'WAVE02_ENDURANCE_DETAIL_OWNER_BUDGET')
        require(p._pending_detailed is None, 'WAVE02_ENDURANCE_DETAIL_STOP_PENDING')
    return health


def verify_saved(folder, profile, requested, expected_identity, executable_hash, captures):
    """Separate read-only SQL after normal stop; hash all source databases twice."""
    from blackbox_core.casebook import context
    paths = [folder / name for name in ('session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3')]
    if (folder / 'detail-v2.sqlite3').is_file():
        paths.append(folder / 'detail-v2.sqlite3')
    require(all(not (p.with_name(p.name + '-wal')).exists() or
                (p.with_name(p.name + '-wal')).stat().st_size == 0 for p in paths),
            'WAVE02_ENDURANCE_FINAL_WAL_NOT_CLOSED')
    nonempty_wals = sum((p.with_name(p.name + '-wal')).exists() and
                       (p.with_name(p.name + '-wal')).stat().st_size != 0 for p in paths)
    hashes = {p.name: file_hash(p) for p in paths}
    integrity_ok_databases = 0
    for path in paths:
        with closing(open_readonly(path)) as db:
            require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',),
                    'WAVE02_ENDURANCE_DATABASE_INTEGRITY_FAILED_' + path.name)
            integrity_ok_databases += 1
    progress = actual_progress(folder)
    with closing(open_readonly(folder / 'session.sqlite3')) as db:
        base_completion = db.execute('SELECT exit_code FROM metadata').fetchall()
        require(base_completion == [('COMPLETED',)],
                'WAVE02_ENDURANCE_BASE_NOT_COMPLETED')
        maximum_gap, nonpositive = db.execute('''SELECT max(gap),
            coalesce(sum(CASE WHEN gap<=0 THEN 1 ELSE 0 END),0) FROM
            (SELECT elapsed_ms-lag(elapsed_ms) OVER(ORDER BY seq) gap FROM samples)''').fetchone()
        counters = db.execute('''SELECT max(cpu_percent),min(rss_bytes),max(rss_bytes),
            max(write_bytes)-min(write_bytes),sum(CASE WHEN cpu_percent IS NULL OR
            rss_bytes IS NULL OR read_bytes IS NULL OR write_bytes IS NULL THEN 1 ELSE 0 END)
            FROM samples''').fetchone()
    measured = verify_sampling_coverage(count=progress['count'], span_seconds=progress['span_seconds'],
        max_gap_seconds=(maximum_gap or 0)/1000, nonpositive_gaps=nonpositive,
        requested_seconds=requested, boundary_tolerance_seconds=0, maximum_gap_seconds=30,
        minimum_count_interval_seconds=10, label='WAVE02_' + profile)
    require(counters[0] is not None and counters[0] >= 20 and counters[2]-counters[1] >= 32*1024**2 and
            counters[3] > 0 and counters[4] == 0, 'WAVE02_ENDURANCE_REAL_CPU_MEMORY_IO_NOT_SAMPLED')
    metadata = context(folder)
    run = metadata['experiment']['run_identity']
    require(run['identity_status'] == 'OS_OBSERVED_EXACT_FILETIME' and
            run['process_identity'] == expected_identity and
            run['image']['source_sha256'] == executable_hash and
            run['clock_domain']['source'] == 'BLACKBOX_LOCAL_MONOTONIC_NS',
            'WAVE02_ENDURANCE_SAVED_IDENTITY_IMAGE_OR_CLOCK_MISMATCH')
    health = metadata['capture_health']
    require(health['recording_resources_closed'] is True and not health['finalization_errors'] and
            metadata['state'] == 'COMPLETED', 'WAVE02_ENDURANCE_SAVED_CLEANUP_UNCONFIRMED')
    with closing(open_readonly(folder / 'session-v2.sqlite3')) as db:
        normalized_completion = db.execute('SELECT status,exit_code,writer_dropped_commands FROM sessions').fetchall()
        require(normalized_completion == [('CLOSED', 'COMPLETED', 0)], 'WAVE02_ENDURANCE_SCHEMA2_FINALIZATION_FAILED')
        base_count = db.execute("SELECT count(*) FROM samples WHERE series='STANDARD'").fetchone()[0]
        detail_count = db.execute("SELECT count(*) FROM samples WHERE series='DETAILED'").fetchone()[0]
        require(base_count == progress['count'], 'WAVE02_ENDURANCE_SCHEMA2_BASE_COUNT_MISMATCH')
        rows = db.execute('SELECT trigger_code,context_json,root_cause FROM incidents LIMIT 1001').fetchall()
        require(len(rows) <= 256 and all(q[2] == 'UNKNOWN' for q in rows),
                'WAVE02_ENDURANCE_INCIDENT_COUNT_OR_CAUSE_CONTRACT')
        incidents = [(q[0], json.loads(q[1])) for q in rows]
    with closing(open_readonly(folder / 'research.sqlite3')) as db:
        burst_starts = db.execute("SELECT count(*) FROM evidence WHERE kind='observer.burst_started'").fetchone()[0]
        stops = db.execute("SELECT data FROM evidence WHERE kind='observer.burst_stopped' LIMIT 257").fetchall()
        burst_stops = len(stops)
        ttl_only = all(json.loads(q[0]).get('reason') == 'TTL_EXPIRED' for q in stops)
        unavailable = db.execute("SELECT count(*) FROM evidence WHERE kind='observer.burst_unavailable'").fetchone()[0]
        manual_refs = db.execute("SELECT count(*) FROM evidence WHERE kind='user.problem_incident_request'").fetchone()[0]
    require(all(not q.thread.is_alive() and q.error is None for q in captures),
            'WAVE02_ENDURANCE_DETAIL_THREAD_OR_ERROR_NOT_CLOSED')
    detail_threads = {'owner_count': len(captures),
                      'live_thread_count': sum(q.thread.is_alive() for q in captures),
                      'error_count': sum(q.error is not None for q in captures)}
    coverage = health.get('incident_coverage')
    trigger_coverage = None
    if profile == 'STANDARD':
        require(not rows and not detail_count and not captures and burst_starts == burst_stops == 0 and
                coverage is None, 'WAVE02_ENDURANCE_STANDARD_RECORDED_OPTIN_CAPTURE')
    else:
        require(detail_count > 0 and len(captures) >= 10 and
                burst_starts == burst_stops == len(captures) and ttl_only and not unavailable and
                manual_refs >= 50 and coverage['capacity_evictions'] > 0 and
                coverage['byte_evictions'] > 0 and coverage['samples_not_retained'] == 0 and
                coverage['observed_samples'] == progress['count'] and not coverage['active'],
                'WAVE02_ENDURANCE_REAL_BURST_TTL_RETENTION_OR_MANUAL_COVERAGE_MISSING')
        codes = {code for code, _ in incidents}
        codes.update(k for _, value in incidents for k in value.get('secondary_signals', {}))
        required_codes = {'MANUAL_PROBLEM', 'CPU_SUSTAINED', 'RSS_GROWTH', 'IO_BURST'}
        incomplete_count = sum(value.get('capture_coverage', {}).get('prehistory_complete') is False
            and value['capture_coverage'].get('coverage_state') == 'INCOMPLETE'
            for _, value in incidents)
        trigger_coverage = {
            'observed_codes': sorted(required_codes & codes),
            'missing_codes': sorted(required_codes - codes),
            'incomplete_prehistory_count': incomplete_count,
            'incomplete_prehistory_observed': bool(incomplete_count)}
        print('WAVE02_ENDURANCE_TRIGGER_COVERAGE ' + json.dumps(trigger_coverage, sort_keys=True), flush=True)
        require({'MANUAL_PROBLEM', 'CPU_SUSTAINED', 'RSS_GROWTH', 'IO_BURST'} <= codes and
                any(value.get('capture_coverage', {}).get('prehistory_complete') is False
                    and value['capture_coverage'].get('coverage_state') == 'INCOMPLETE'
                    for _, value in incidents), 'WAVE02_ENDURANCE_MEASURED_TRIGGERS_OR_HONEST_LOSS_MISSING')
    require(all(file_hash(p) == hashes[p.name] for p in paths),
            'WAVE02_ENDURANCE_READONLY_VERIFICATION_CHANGED_SOURCE')
    return {'sampling_coverage': measured, 'database_sha256': hashes,
        'database_finalization': {'database_count': len(paths), 'integrity_ok_databases': integrity_ok_databases,
            'nonempty_wal_files': nonempty_wals, 'schema1_exit_code': base_completion[0][0],
            'schema2_status': normalized_completion[0][0], 'schema2_exit_code': normalized_completion[0][1],
            'schema2_writer_dropped_commands': normalized_completion[0][2], 'research_state': metadata['state'],
            'recording_resources_closed': health['recording_resources_closed'],
            'finalization_error_count': len(health['finalization_errors'])},
        'detail_threads': detail_threads, 'trigger_coverage': trigger_coverage,
        'schema2_standard_samples': base_count, 'schema2_detail_samples': detail_count,
        'incident_count': len(incidents), 'burst_starts': burst_starts, 'burst_ttl_stops': burst_stops,
        'manual_incident_refs': manual_refs, 'coverage': coverage,
        'recorded_peak_cpu_one_cpu_percent': counters[0], 'recorded_rss_range_bytes': counters[2]-counters[1],
        'recorded_write_bytes_delta': counters[3], 'readonly_original_hashes_unchanged': True}


def run_child(args):
    proof = {'schema': 'blackbox.wave02.endurance.profile/1', 'status': 'RUNNING',
        'profile': args.profile, 'source_identity': source_proof(args.source_sha),
        'requested_seconds': args.duration_seconds, 'scope': 'REAL_RESEARCHSESSION_OWNED_NATIVE_WORKLOAD',
        'physical_windows_10_11': 'NOT_TESTED', 'gui_endurance': 'NOT_TESTED',
        'eight_hour_acceptance': False, 'leak_absence_proven': False,
        'off_on_overhead_effect': 'NOT_ESTABLISHED', 'root_cause': 'UNKNOWN'}
    from blackbox_core.research_worker import ResearchSession
    from blackbox_core.deep_native import capture_identity
    from blackbox_core.optional_jobs import OwnedProcess
    import psutil
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = session = controller = None
    successful = False
    captures = []
    writer = journal = None
    maxima = {'writer_queue_depth': 0, 'event_queue_depth': 0,
              'ring_accounted_bytes': 0, 'ring_samples': 0, 'self_rss_bytes': 0,
              'self_threads': 0, 'target_rss_bytes': 0, 'recording_bytes': 0, 'output_bytes': 0,
              'tick_ms': 0., 'self_cpu_one_cpu_percent': 0., 'target_cpu_one_cpu_percent': 0.}
    proof['qa_guards'] = {'self_rss_bytes': MAX_RSS, 'post_warmup_rss_growth_bytes': MAX_RSS_GROWTH,
        'session_bytes': MAX_SESSION_BYTES, 'output_bytes': MAX_OUTPUT_BYTES,
        'semantics': 'MEASURED_QA_FAILURE_GUARDS_NOT_HARD_PRODUCT_QUOTAS'}
    try:
        executable = args.probe.resolve(strict=True)
        proof['executable_sha256'] = file_hash(executable)
        fixture = WaveProbe(executable, output / 'target')
        controller = NativeController(fixture)
        identity = capture_identity(fixture.process.pid)
        expected_identity = {'pid': identity.pid, 'created_100ns': identity.created_100ns}
        require(expected_identity == {k: fixture.ready[k] for k in ('pid', 'created_100ns')},
                'WAVE02_ENDURANCE_NATIVE_BIRTH_MISMATCH')
        proof['target_identity'] = expected_identity
        # CREATE_NEW permission/sharing oracles are deliberately executed once.
        file_done = fixture.command('file', 'file_done')
        require(file_done.get('ok') is True and file_done.get('acl_restored') is True,
                'WAVE02_ENDURANCE_INITIAL_NATIVE_FILE_OR_ACL_CLEANUP_FAILED')
        session = ResearchSession(output / 'sessions')
        command(session, 'attach', pid=identity.pid)
        command(session, 'configure', scenario='BB-WAVE-02-RISK-ENDURANCE', scenario_version='1',
                workload='owned-six-second-cpu-memory-file-burst-every-300s-v1',
                target_version=proof['executable_sha256'])
        command(session, 'capture_policy', policy=policy(args.profile))
        folder = Path(command(session, 'start')['folder']).resolve(strict=True)
        require(folder.is_relative_to((output / 'sessions').resolve()), 'WAVE02_ENDURANCE_SESSION_OUTSIDE_ROOT')
        proof['session'] = str(folder)
        proof['run_identity'] = session.context['run_identity']
        require(proof['run_identity']['identity_status'] == 'OS_OBSERVED_EXACT_FILETIME' and
                proof['run_identity']['process_identity'] == expected_identity and
                proof['run_identity']['image']['source_sha256'] == proof['executable_sha256'],
                'WAVE02_ENDURANCE_RUN_IDENTITY_NOT_CAPTURED')
        writer = session.probe._store.v2
        journal = session.probe._store._journal
        me, target = psutil.Process(), psutil.Process(identity.pid)
        cpu_start = me.cpu_times()
        me.cpu_percent(None); target.cpu_percent(None)
        started = time.monotonic()
        next_tick = next_check = next_log = started
        next_burst, next_marker = started + 20, started + 45
        first_sample_ms = None
        manual_count = state_checks = 0
        rss_warm = None
        minutes = []
        last_count = 0; last_advance = started
        finishing = False
        while True:
            now = time.monotonic()
            require(now-started <= args.duration_seconds + 180, 'WAVE02_ENDURANCE_CHILD_DEADLINE')
            require(fixture.process.poll() is None, 'WAVE02_ENDURANCE_TARGET_EXITED')
            controller.poll()
            if now >= next_tick:
                tick_started = time.monotonic()
                session.tick()
                maxima['tick_ms'] = max(maxima['tick_ms'], (time.monotonic()-tick_started)*1000)
                next_tick = time.monotonic() + session.interval_ms/1000
                require(1000 <= session.interval_ms <= 5000, 'WAVE02_ENDURANCE_UNEXPECTED_CADENCE')
                count = session.probe.total_samples
                if count > last_count:
                    last_count = count; last_advance = time.monotonic()
                require(time.monotonic()-last_advance <= 30, 'WAVE02_ENDURANCE_SAMPLES_NOT_PROGRESSING')
                if count:
                    if first_sample_ms is None:
                        first_sample_ms = session.probe.last_elapsed_ms
                    span = (session.probe.last_elapsed_ms-first_sample_ms)/1000
                    finishing = span >= args.duration_seconds
                inspect_live(session, captures, maxima)
            if not finishing and now >= next_burst and controller.thread is None:
                controller.start(); next_burst += BURST_PERIOD_SECONDS
            if not finishing and now >= next_marker and session.probe.total_samples:
                command(session, 'mark', note='owned hourly QA manual observation; cause unknown')
                manual_count += 1; next_marker += 60
            if now >= next_check:
                current = capture_identity(identity.pid)
                require(current.created_100ns == identity.created_100ns,
                        'WAVE02_ENDURANCE_TARGET_INSTANCE_CHANGED')
                if controller.thread is None:
                    state = fixture.command('state', timeout=5)
                    require(state['pid'] == identity.pid and state['created_100ns'] == identity.created_100ns and
                            state['qpc'] > fixture.ready['qpc'] and state['ui_waiting'] == 0 and
                            state['mutex_owned'] is False, 'WAVE02_ENDURANCE_NATIVE_STATE_MISMATCH')
                    state_checks += 1
                self_rss, target_rss = me.memory_info().rss, target.memory_info().rss
                self_cpu, target_cpu = me.cpu_percent(None), target.cpu_percent(None)
                maxima['self_rss_bytes'] = max(maxima['self_rss_bytes'], self_rss)
                maxima['target_rss_bytes'] = max(maxima['target_rss_bytes'], target_rss)
                maxima['self_threads'] = max(maxima['self_threads'], me.num_threads())
                maxima['self_cpu_one_cpu_percent'] = max(maxima['self_cpu_one_cpu_percent'], self_cpu)
                maxima['target_cpu_one_cpu_percent'] = max(maxima['target_cpu_one_cpu_percent'], target_cpu)
                require(self_rss <= MAX_RSS, 'WAVE02_ENDURANCE_SELF_RSS_GUARD')
                if now-started >= 60:
                    rss_warm = self_rss if rss_warm is None else min(rss_warm, self_rss)
                    require(self_rss-rss_warm <= MAX_RSS_GROWTH, 'WAVE02_ENDURANCE_POST_WARMUP_RSS_GROWTH')
                recording_bytes, output_bytes = directory_bytes(folder), directory_bytes(output)
                maxima['recording_bytes'] = max(maxima['recording_bytes'], recording_bytes)
                maxima['output_bytes'] = max(maxima['output_bytes'], output_bytes)
                require(recording_bytes <= MAX_SESSION_BYTES and output_bytes <= MAX_OUTPUT_BYTES,
                        'WAVE02_ENDURANCE_DISK_GUARD')
                actual = actual_progress(folder)
                require(actual['count'] == session.probe.total_samples,
                        'WAVE02_ENDURANCE_PRIMARY_COMMIT_COUNT_MISMATCH')
                save(output / 'progress.json', {'profile': args.profile, 'source_sha': args.source_sha,
                    'session': str(folder), 'pid': os.getpid(), 'sample_count': actual['count'],
                    'span_seconds': actual['span_seconds'], 'updated_monotonic': time.monotonic(),
                    'native_bursts': controller.completed, 'status': 'RUNNING'})
                next_check = time.monotonic()+5
            if now >= next_log:
                require(len(minutes) <= 66, 'WAVE02_ENDURANCE_METRIC_BUCKET_BUDGET')
                minutes.append({'elapsed_seconds': round(now-started, 3),
                    'samples': session.probe.total_samples, 'rss_bytes': me.memory_info().rss,
                    'threads': me.num_threads(), 'bursts': controller.completed,
                    'interval_ms': session.interval_ms})
                print('WAVE02_PROFILE_PROGRESS ' + json.dumps({'profile': args.profile,
                    **minutes[-1]}, sort_keys=True), flush=True)
                next_log = now+60
            if finishing and controller.thread is None and session._burst_until is None:
                require(args.profile == 'STANDARD' or session.probe.detailed_capture is None,
                        'WAVE02_ENDURANCE_DETAIL_OUTLIVED_TTL')
                break
            time.sleep(max(.02, min(.2, next_tick-time.monotonic())))
        require(controller.completed >= args.duration_seconds // BURST_PERIOD_SECONDS and
                manual_count >= 50 and state_checks >= 300,
                'WAVE02_ENDURANCE_PERIODIC_REAL_WORKLOAD_COVERAGE_TOO_LOW')
        controller.join()
        stopped = command(session, 'stop')
        require(stopped['cleanup_required'] is False and not stopped['errors'] and
                stopped['state'] == stopped['base_recording_state'] == 'COMPLETED' and
                session._recording_resources_closed() and not session.jobs.health().get('cleanup_required') and
                not OwnedProcess.pending_cleanup() and not writer.thread.is_alive() and
                (journal is None or not journal._worker.is_alive()),
                'WAVE02_ENDURANCE_RECORDER_CLEANUP_UNCONFIRMED')
        proof['recorder_cleanup'] = {'recording_resources_closed': session._recording_resources_closed(),
            'optional_jobs_cleanup_required': bool(session.jobs.health().get('cleanup_required')),
            'pending_owned_process_owners': len(OwnedProcess.pending_cleanup()),
            'writer_thread_alive': writer.thread.is_alive(),
            'journal_thread_alive': bool(journal is not None and journal._worker.is_alive())}
        proof['saved'] = verify_saved(folder, args.profile, args.duration_seconds,
            expected_identity, proof['executable_sha256'], captures)
        cpu_end = me.cpu_times()
        cpu_seconds = cpu_end.user + cpu_end.system - cpu_start.user - cpu_start.system
        elapsed = time.monotonic()-started
        require(math.isfinite(cpu_seconds) and cpu_seconds >= 0, 'WAVE02_ENDURANCE_SELF_CPU_INVALID')
        proof.update(measured_wall_seconds=elapsed, stop=stopped, maxima=maxima, minute_samples=minutes,
            periodic_native_bursts=controller.completed, native_burst_io_bytes=controller.total_io_bytes,
            first_native_burst=controller.first, last_native_burst=controller.last,
            manual_markers=manual_count, native_state_checks=state_checks,
            observer_cpu_seconds=cpu_seconds,
            observer_average_one_cpu_percent=100*cpu_seconds/elapsed,
            overhead_scope='QA_CHILD_PLUS_EXISTING_RECORDER_DETAIL_THREADS; NOT_GUI_OR_OFF_ON_EFFECT',
            sampled_rss_semantics='SAMPLED_WORKING_SET_NOT_HARD_MEMORY_LIMIT',
            thread_cleanup='ACTUAL_HELD_WRITER_DETAIL_AND_ORACLE_THREADS',
            retention='BOUNDED_RING_WITH_HONEST_LOSS; ORIGINAL_RECORDING_PRESERVED')
        proof['target_cleanup'] = fixture.close()
        require(proof['target_cleanup']['status'] == 'COMPLETED' and
                not OwnedProcess.pending_cleanup(), 'WAVE02_ENDURANCE_TARGET_OWNER_CLEANUP_UNCONFIRMED')
        fixture = None
        proof['final_source_identity'] = source_proof(args.source_sha)
        proof['status'] = 'PASS'
        successful = True
    except BaseException as error:
        proof.update(status='FAIL', error=type(error).__name__, reason=str(error)[:600])
        traceback.print_exc(limit=8)
    finally:
        cleanup_errors = []
        if controller is not None:
            try: controller.join()
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ': ' + str(error)[:180])
        if session is not None and (session.book is not None or session.probe.active):
            try: proof['failure_stop'] = session.stop('QA_FAILURE')
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ': ' + str(error)[:180])
        if fixture is not None:
            try: proof['failure_target_cleanup'] = fixture.close(kill=True)
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ': ' + str(error)[:180])
        if session is not None and (not session._recording_resources_closed() or
                session.jobs.health().get('cleanup_required')):
            cleanup_errors.append('RECORDER_RESOURCE_CLEANUP_UNCONFIRMED')
        if cleanup_errors:
            proof.update(status='FAIL', cleanup_errors=cleanup_errors, cleanup_required=True)
            successful = False
        save(output / 'result.json', proof)
        print('WAVE02_PROFILE_RECEIPT ' + json.dumps({'profile': args.profile, 'status': proof['status'],
            'result_sha256': file_hash(output / 'result.json'),
            'cleanup_required': bool(proof.get('cleanup_required'))}, sort_keys=True), flush=True)
    return 0 if successful else 1


def run_parent(args):
    from blackbox_core.optional_jobs import OwnedProcess
    proof = {'schema': 'blackbox.wave02.endurance/1', 'status': 'RUNNING',
        'source_identity': source_proof(args.source_sha), 'requested_seconds_per_profile': args.duration_seconds,
        'profiles': {}, 'free_standard_github_hosted_only': True,
        'concurrency': 'TWO_INDEPENDENT_OWNED_PROFILE_CHILDREN; SHARED_HOST_LOAD',
        'physical_windows_10_11': 'NOT_TESTED', 'gui_endurance': 'NOT_TESTED',
        'eight_hour_acceptance': False, 'leak_absence_proven': False,
        'root_cause': 'UNKNOWN', 'artifact_upload': False}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    owners = {}; logs = {}; watches = {}
    successful = False
    try:
        executable = build(output / 'native-build', args.source_sha)
        executable_hash = file_hash(executable)
        started = time.monotonic()
        for profile in PROFILES:
            child_root = output / profile.lower()
            log = (output / (profile.lower() + '.log')).open('xb')
            logs[profile] = log
            owner = OwnedProcess([sys.executable, '-u', str(Path(__file__).resolve()),
                '--child-profile', profile, '--output', str(child_root), '--probe', str(executable),
                '--source-sha', args.source_sha, '--duration-seconds', str(args.duration_seconds)],
                stdout=log, stderr=subprocess.STDOUT, detach_console=True)
            owners[profile] = owner
            watches[profile] = {'root': child_root, 'count': 0, 'last_advance': time.monotonic(),
                'launched': time.monotonic(), 'session': None, 'complete': False}
        next_log = next_check = started
        while not all(value['complete'] for value in watches.values()):
            now = time.monotonic()
            require(now-started <= args.duration_seconds+240, 'WAVE02_ENDURANCE_PARENT_DEADLINE')
            for profile, owner in owners.items():
                watch = watches[profile]
                if watch['complete']:
                    continue
                root = watch['root']
                if owner.process.poll() is not None:
                    require(owner.process.returncode == 0, 'WAVE02_ENDURANCE_CHILD_FAILED_' + profile)
                    result_path = root / 'result.json'
                    digest = file_hash(result_path)
                    result = read_json(result_path)
                    require(result.get('status') == 'PASS' and result.get('profile') == profile and
                            result.get('source_identity', {}).get('actual_source_sha') == args.source_sha and
                            result.get('source_identity', {}).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD' and
                            result.get('executable_sha256') == executable_hash and
                            result.get('requested_seconds') == args.duration_seconds and
                            result['saved']['sampling_coverage']['persisted_span_seconds'] >= args.duration_seconds and
                            result['saved']['sampling_coverage']['max_sample_gap_seconds'] <= 30,
                            'WAVE02_ENDURANCE_CHILD_RECEIPT_INVALID_' + profile)
                    folder = Path(result['session']).resolve(strict=True)
                    require(folder.is_relative_to((root / 'sessions').resolve()) and
                            all(file_hash(folder / name) == expected
                                for name, expected in result['saved']['database_sha256'].items()) and
                            file_hash(result_path) == digest, 'WAVE02_ENDURANCE_FINAL_SOURCE_HASH_CHANGED')
                    # Do not let the final kill boundary conceal a leaked descendant.
                    require(owner._job_empty(), 'WAVE02_ENDURANCE_CHILD_LEFT_OWNED_DESCENDANT')
                    owner.close(kill=False)
                    proof['profiles'][profile] = {'status': 'PASS', 'result_sha256': digest,
                        'sampling_coverage': result['saved']['sampling_coverage'],
                        'database_sha256': result['saved']['database_sha256'],
                        'target_identity': result['target_identity'], 'maxima': result['maxima'],
                        'observer_average_one_cpu_percent': result['observer_average_one_cpu_percent'],
                        'periodic_native_bursts': result['periodic_native_bursts'],
                        'manual_markers': result['manual_markers'],
                        'burst_ttl_stops': result['saved']['burst_ttl_stops'],
                        'coverage': result['saved']['coverage'], 'owned_job_cleanup': owner.cleanup_evidence,
                        'artifactless_facts': artifactless_profile_facts(result)}
                    watch['complete'] = True
                    continue
                if now >= next_check:
                    require((output / (profile.lower()+'.log')).stat().st_size <= MAX_PROFILE_LOG_BYTES,
                            'WAVE02_ENDURANCE_PROFILE_LOG_BUDGET')
                    path = root / 'progress.json'
                    if path.is_file():
                        progress = read_json(path, maximum=8192)
                        require(progress.get('source_sha') == args.source_sha and
                                progress.get('profile') == profile and progress.get('pid') == owner.process.pid,
                                'WAVE02_ENDURANCE_PROGRESS_IDENTITY_MISMATCH')
                        folder = Path(progress['session']).resolve(strict=True)
                        require(folder.is_relative_to((root / 'sessions').resolve()),
                                'WAVE02_ENDURANCE_PROGRESS_PATH_OUTSIDE_ROOT')
                        if watch['session'] is None:
                            watch['session'] = str(folder)
                        require(str(folder) == watch['session'], 'WAVE02_ENDURANCE_SESSION_SWITCHED')
                        # Read persisted rows ourselves: rewriting a heartbeat cannot fake progress.
                        current = actual_progress(folder)
                        require(current['count'] >= watch['count'], 'WAVE02_ENDURANCE_SAMPLE_COUNT_REGRESSED')
                        if current['count'] > watch['count']:
                            watch['count'] = current['count']; watch['last_advance'] = now
                        require(now-watch['last_advance'] <= 30,
                                'WAVE02_ENDURANCE_PERSISTED_PROGRESS_FROZEN_' + profile)
                        watch['span_seconds'] = current['span_seconds']
                    else:
                        require(now-watch['launched'] <= 90,
                                'WAVE02_ENDURANCE_CHILD_NOT_STARTED_' + profile)
            if now >= next_check:
                next_check = now+5
            if now >= next_log:
                print('WAVE02_ENDURANCE_PROGRESS ' + json.dumps({'elapsed_seconds': round(now-started, 3),
                    'profiles': {name: {'samples': value['count'], 'span_seconds': value.get('span_seconds'),
                        'complete': value['complete']} for name, value in watches.items()}}, sort_keys=True), flush=True)
                next_log = now+60
            time.sleep(1)
        require(not OwnedProcess.pending_cleanup(), 'WAVE02_ENDURANCE_PARENT_CLEANUP_PENDING')
        require(file_hash(executable) == executable_hash, 'WAVE02_ENDURANCE_FIXTURE_IMAGE_CHANGED')
        proof['final_source_identity'] = source_proof(args.source_sha)
        proof.update(status='PASS', wall_seconds=time.monotonic()-started,
            executable_sha256=executable_hash, owner_cleanup_confirmed=True)
        successful = True
    except BaseException as error:
        proof.update(status='FAIL', error=type(error).__name__, reason=str(error)[:600])
        traceback.print_exc(limit=8)
        # Failure logs are bounded diagnostic excerpts, never an invented successful receipt.
        for profile, log in logs.items():
            log.flush()
            path = output / (profile.lower()+'.log')
            try:
                with path.open('rb') as stream:
                    stream.seek(max(0, path.stat().st_size-16000))
                    print('WAVE02_FAILURE_LOG ' + profile + '\n' + stream.read(16000).decode('utf-8', 'replace'), flush=True)
            except OSError:
                pass
    finally:
        errors = []
        for profile, owner in owners.items():
            try:
                owner.close(kill=not watches[profile]['complete'])
                require(not owner.cleanup_required, 'WAVE02_ENDURANCE_PROFILE_JOB_CLEANUP_UNCONFIRMED')
            except BaseException as error:
                errors.append(profile + ': ' + type(error).__name__ + ': ' + str(error)[:180])
        for log in logs.values():
            log.close()
        if errors:
            proof.update(status='FAIL', cleanup_required=True, cleanup_errors=errors)
            successful = False
        save(output / 'result.json', proof)
        print('WAVE02_ENDURANCE_RECEIPT ' + json.dumps(proof, sort_keys=True, allow_nan=False), flush=True)
        print('WAVE02_ENDURANCE_RESULT_SHA256 ' + file_hash(output / 'result.json'), flush=True)
    return 0 if successful else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--duration-seconds', type=int, default=3600)
    parser.add_argument('--child-profile', dest='profile', choices=PROFILES)
    parser.add_argument('--probe', type=Path)
    args = parser.parse_args()
    require_hosted_windows()
    require(3600 <= args.duration_seconds <= 3900, 'WAVE02_ONE_REAL_HOUR_PER_PROFILE_REQUIRED')
    require(bool(args.profile) == bool(args.probe), 'WAVE02_ENDURANCE_CHILD_ARGUMENTS_REQUIRED')
    return run_child(args) if args.profile else run_parent(args)


if __name__ == '__main__':
    raise SystemExit(main())
