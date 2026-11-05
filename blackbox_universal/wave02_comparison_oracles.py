"""Independent comparison-export QA over actual, stopped recording folders.

Requires the approved R20 QA module through the eventual normal base merge.
Only its stdlib JSON parser/type-aware equality are reused; no product reader,
serializer, redactor, comparability function or validator is an oracle here.
Two export operations legitimately have different receipts and call clocks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import sqlite3
import stat

from .wave02_export_oracles import _parse_graph, _same_json_metadata


SCHEMA = 'blackbox.experiment-comparison.v1'
MAX_EXPORT_BYTES = 8 * 1024**2
MAX_SOURCE_BYTES = 2 * 1024**3
_FILES = ('session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3', 'detail-v2.sqlite3')
_DYNAMIC_CONTEXT = ('run_id', 'started_at_utc', 'started_monotonic_ns',
                    'deadline_utc', 'deadline_monotonic_ns')
_DYNAMIC_RECEIPT = ('run_id', 'started_at_utc', 'ended_at_utc', 'duration_ns')
# The existing RunContext wire format hashes this fixed descriptive string.
# This is a public schema constant, not an authorization grant or a redactor.
_AUTH_WIRE_BYTES = b'"NO_HELPER_OR_NATIVE_INTERVENTION_AUTHORITY"'
_AUTH_PUBLIC = {'redacted': 'SENSITIVE_PAYLOAD', 'serialized_bytes': len(_AUTH_WIRE_BYTES),
                'sha256': hashlib.sha256(_AUTH_WIRE_BYTES).hexdigest()}


def _require(value, reason):
    if not value:
        raise AssertionError('WAVE02_COMPARISON_ORACLE_' + reason)


def _hex(value, count=64):
    return type(value) is str and len(value) == count and all(q in '0123456789abcdef' for q in value)


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _file_snapshot(path, limit, *, keep=False):
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'FILE_TYPE_OR_SIZE')
    chunks, total, digest = [], 0, hashlib.sha256()
    with path.open('rb') as stream:
        _require(_stamp(os.fstat(stream.fileno())) == _stamp(before), 'FILE_CHANGED')
        while block := stream.read(65536):
            total += len(block)
            _require(total <= limit, 'FILE_TYPE_OR_SIZE')
            digest.update(block)
            if keep:
                chunks.append(block)
        after = os.fstat(stream.fileno())
    _require(_stamp(before) == _stamp(after) == _stamp(path.lstat())
             and total == before.st_size, 'FILE_CHANGED')
    return {'sha256': digest.hexdigest(), 'bytes': total, 'stamp': _stamp(before)}, b''.join(chunks)


def _protocol_id(kind, *parts):
    # Read the documented graph-v3 identifier protocol independently, without
    # importing the product stable_id implementation.
    raw = json.dumps(['3.0.0', kind, *parts], sort_keys=True, ensure_ascii=True,
                     allow_nan=False, separators=(',', ':'))
    return hashlib.sha256(raw.encode('ascii')).hexdigest()


def _sources(folder):
    folder = Path(folder)
    result, inventory = {}, {}
    for name in (*_FILES, *(name + '-wal' for name in _FILES)):
        path = folder / name
        if not path.exists():
            inventory[name] = None
            continue
        facts, _ = _file_snapshot(path, MAX_SOURCE_BYTES)
        inventory[name] = facts
        if name.endswith('-wal') and facts['bytes'] == 0:
            continue
        _require(facts['bytes'] > 0, 'EMPTY_SOURCE')
        result[name] = facts
    _require({'session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3'} <= set(result),
             'REAL_RECORDING_SOURCES_MISSING')
    return {'files': result, 'inventory': inventory}


def _recorded_context(folder):
    path = Path(folder) / 'research.sqlite3'
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
        _require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SOURCE_SQLITE_INTEGRITY')
        rows = db.execute("SELECT key,data FROM context WHERE key IN "
            "('experiment','state','capture_health','environment','capabilities','configuration_changed')").fetchall()
        _require({'experiment', 'state'} <= {q[0] for q in rows} and len(rows) <= 6, 'RECORDED_CONTEXT')
        meta = {key: _parse_graph(raw.encode('utf-8'), 'json') for key, raw in rows}
        _require(meta['state'] in ('COMPLETED', 'USER_STOPPED') and type(meta['experiment']) is dict,
                 'RECORDING_NOT_STOPPED')
        count = db.execute('SELECT count(*) FROM action_runs').fetchone()[0]
    finally:
        db.close()
    experiment = meta['experiment']
    warmups = experiment.get('warmup_count', 0)
    _require(type(warmups) is int and 0 <= warmups <= 10000, 'RECORDED_WARMUPS')
    return {'experiment': experiment, 'run': experiment.get('run_identity'),
            'repeats': max(0, count - warmups), 'metadata': meta}


def _controlled_comparable_contexts(contexts):
    """Known positive E2E preconditions, not a second comparability algorithm.

    Statistics remain checked by the existing native oracles. An export cannot
    declare this controlled pair COMPARABLE after losing its recorded workload,
    exact instance, local-clock, image or finalization conditions.
    """
    settings = []
    for role in ('before', 'after'):
        exp, run, meta = (contexts[role][key] for key in ('experiment', 'run', 'metadata'))
        _require(all(type(exp.get(key)) is str and bool(exp[key])
                     for key in ('scenario', 'workload', 'profile'))
                 and type(exp.get('interval_ms')) is int and exp['interval_ms'] > 0
                 and type(exp.get('capture_policy')) is dict and bool(exp['capture_policy']),
                 'RECORDED_COMPARABLE_CONFIGURATION')
        target, image, clock = (run.get(key) for key in ('process_identity', 'image', 'clock_domain'))
        _require(type(target) is dict and type(target.get('pid')) is int
                 and 1 <= target['pid'] <= 2**32 - 1
                 and type(target.get('created_100ns')) is int and 1 <= target['created_100ns'] < 2**64
                 and type(image) is dict and _hex(image.get('source_sha256'))
                 and type(image.get('source_size_bytes')) is int and image['source_size_bytes'] > 0
                 and image.get('content_integrity') == 'HASHED_STABLE_FILE'
                 and type(clock) is dict and clock.get('source') == 'BLACKBOX_LOCAL_MONOTONIC_NS'
                 and clock.get('cross_run_alignment') == 'NOT_ESTABLISHED'
                 and type(exp.get('origin_monotonic_ns')) is int and exp['origin_monotonic_ns'] > 0,
                 'RECORDED_INSTANCE_IMAGE_OR_CLOCK')
        health = meta.get('capture_health')
        _require(type(health) is dict and health.get('recording_resources_closed') is True
                 and health.get('finalization_errors') == [] and not meta.get('configuration_changed'),
                 'RECORDED_FINALIZATION')
        settings.append({
            **{key: exp.get(key) for key in ('scenario', 'workload', 'profile', 'interval_ms',
                'scenario_version', 'target_version', 'capture_policy')},
            'warmup_count': exp.get('warmup_count', 0),
            'image': image, 'recorder_version': run.get('recorder_version'),
            'recorder_build': run.get('recorder_build'), 'environment': meta.get('environment'),
            'privilege': (meta.get('capabilities') or {}).get('privilege'),
        })
    _require(_same_json_metadata(settings[0], settings[1]), 'RECORDED_CONFIGURATIONS_DIFFER')


class _ComparisonHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inside = self.finished = False
        self.seen = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        _require(not self.inside and not self.finished, 'HTML_NESTED_OR_EXTRA_TAG')
        if tag == 'pre' and ('id', 'blackbox-comparison-data') in attrs:
            _require(attrs == [('id', 'blackbox-comparison-data')], 'HTML_METADATA_ATTRIBUTES')
            self.seen += 1
            _require(self.seen == 1, 'HTML_DUPLICATE_METADATA')
            self.inside = True

    def handle_endtag(self, tag):
        if self.inside:
            _require(tag == 'pre', 'HTML_NESTED_OR_EXTRA_TAG')
            self.inside = False
            self.finished = True
        elif self.finished:
            _require(tag in ('html', 'body'), 'HTML_NESTED_OR_EXTRA_TAG')

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)
        elif self.finished:
            _require(not data.strip(), 'HTML_EXTRA_METADATA_TEXT')

    def handle_comment(self, _value):
        _require(not (self.inside or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def handle_decl(self, _value):
        _require(not (self.inside or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def handle_pi(self, _value):
        _require(not (self.inside or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def unknown_decl(self, _value):
        raise AssertionError('WAVE02_COMPARISON_ORACLE_HTML_UNKNOWN_DECLARATION')

    def metadata(self):
        _require(self.seen == 1 and self.finished and not self.inside, 'HTML_METADATA_MISSING_OR_UNCLOSED')
        return ''.join(self.parts)


def _parse(data, format):
    if format == 'html':
        try:
            parser = _ComparisonHTML()
            parser.feed(data.decode('utf-8'))
            parser.close()
            data = parser.metadata().encode('utf-8')
        except UnicodeError:
            raise AssertionError('WAVE02_COMPARISON_ORACLE_HTML_UTF8') from None
    return _parse_graph(data, 'json')


def _utc(raw):
    _require(type(raw) is str and 1 <= len(raw) <= 64, 'CALL_CLOCK')
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        raise AssertionError('WAVE02_COMPARISON_ORACLE_CALL_CLOCK') from None
    _require(value.tzinfo is not None and value.utcoffset() == timedelta(0), 'CALL_CLOCK')
    return value.astimezone(timezone.utc)


def _call_receipt(comparison, source_sets, contexts):
    call, receipt = comparison.get('run_context'), comparison.get('run_receipt')
    _require(type(call) is dict and type(receipt) is dict, 'CALL_RECEIPT_MISSING')
    _require(_hex(call.get('run_id'), 32) and receipt.get('run_id') == call['run_id']
             and type(call.get('contract_version')) is int and call['contract_version'] == 1
             and type(receipt.get('contract_version')) is int and receipt['contract_version'] == 1
             and call.get('operation') == receipt.get('operation') == 'research.compare'
             and receipt.get('tool_id') == 'blackbox.research.compare'
             and receipt.get('status') == 'COMPLETED' and receipt.get('execution_started') is True,
             'CALL_RECEIPT_IDENTITY')
    started, deadline = _utc(call.get('started_at_utc')), _utc(call.get('deadline_utc'))
    ended = _utc(receipt.get('ended_at_utc'))
    _require(receipt.get('started_at_utc') == call['started_at_utc']
             and deadline - started == timedelta(seconds=30) and started <= ended <= deadline
             and type(call.get('started_monotonic_ns')) is int and call['started_monotonic_ns'] > 0
             and type(call.get('deadline_monotonic_ns')) is int
             and call['deadline_monotonic_ns'] - call['started_monotonic_ns'] == 30 * 10**9
             and type(receipt.get('duration_ns')) is int and 0 <= receipt['duration_ns'] <= 30 * 10**9,
             'CALL_CLOCK_OR_DEADLINE')
    limits = {'timeout_seconds': 30, 'scope': 'EXISTING_COMPONENT_BUDGET'}
    expected_sources = [{'source_type': 'RESEARCH_SESSION', 'role': role,
                         'producer_authentication': 'NOT_ESTABLISHED'} for role in ('before', 'after')]
    _require(_same_json_metadata(call.get('limits'), limits)
             and _same_json_metadata(receipt.get('limits'), limits)
             and call.get('target') is None and call.get('parameters') == {}
             and call.get('clock_scope') == 'CALLING_PROCESS_MONOTONIC_NS'
             and _same_json_metadata(call.get('sources'), expected_sources)
             and _same_json_metadata(call.get('permissions'), {
                'level_at_request': 'READ_ONLY_LOCAL_EVIDENCE', 'confirmation_required': False,
                'authorization': _AUTH_PUBLIC}), 'CALL_STABLE_CONTEXT')
    source = receipt.get('source')
    _require(type(source) is dict and source.get('name') == 'LOCAL_EVIDENCE_COMPONENT'
             and source.get('verified') is False and source.get('producer_authentication') == 'NOT_ESTABLISHED'
             and source.get('verification_scope') == 'BYTE_CONSISTENCY_ONLY_NOT_PRODUCER_AUTHENTICATION',
             'RECEIPT_SOURCE_TRUST')
    bound = []
    for role in ('before', 'after'):
        run = contexts[role]['run']
        bound.append({'source_type': 'RESEARCH_INDEX', 'role': role, 'filename': 'research.sqlite3',
            'recording_run_id': run['run_id'], 'source_id': _protocol_id('recording-run', run['run_id']),
            'source_sha256': None, 'source_size_bytes': source_sets[role]['files']['research.sqlite3']['bytes'],
            'producer_authentication': 'NOT_ESTABLISHED'})
    _require(_same_json_metadata(source.get('sources'), bound)
             and _same_json_metadata(receipt.get('target'), {
                'identity': None, 'verified': False, 'scope': 'RECORDED_IDENTITY_NOT_LIVE_BINDING'})
             and _same_json_metadata(receipt.get('cleanup'), {
                'status': 'COMPLETED', 'confirmed': True,
                'scope': 'READ_ONLY_COMPARISON_HANDLES_CLOSED_NO_NATIVE_OWNER'})
             and _same_json_metadata(receipt.get('coverage'), {'completeness': 'UNKNOWN',
                'scope': 'RECORDED_COMPARISON', 'comparison_status': comparison['comparison_status']})
             and receipt.get('effects') == 'READ_ONLY_SOURCE; CREATE_NEW_RESULT_ONLY',
             'RECEIPT_SOURCE_BINDING_OR_CLEANUP')
    return {key: item for key, item in receipt.items() if key not in _DYNAMIC_RECEIPT}


def _validate(value, source_sets, contexts, expected_status):
    _require(type(value) is dict and value.get('schema') == SCHEMA
             and value.get('source_trust') == 'UNVERIFIED_IMPORT' and value.get('causal_link_proven') is False
             and value.get('privacy') == 'METADATA_ONLY_NO_MEMORY_OR_DUMP_BYTES', 'SCHEMA_OR_TRUST')
    comparison = value.get('comparison')
    _require(type(comparison) is dict and type(comparison.get('schema_version')) is int
             and comparison['schema_version'] == 2 and comparison.get('comparison_status') == expected_status
             and comparison.get('comparison') == 'OBSERVATION_ONLY'
             and comparison.get('source_trust') == 'UNVERIFIED_IMPORT'
             and comparison.get('speedup_proven') is False and comparison.get('causal_link_proven') is False
             and comparison.get('comparable_context') is (expected_status == 'COMPARABLE'), 'COMPARISON_STATUS_OR_CAUSE')
    comparable = comparison.get('comparability')
    _require(type(comparable) is dict and comparable.get('status') == expected_status
             and comparable.get('identity_merge_performed') is False
             and comparable.get('cross_run_clock_alignment') == 'NOT_ESTABLISHED'
             and comparable.get('file_trust') == 'UNVERIFIED_IMPORT'
             and comparable.get('speedup_proven') is False and comparable.get('causal_link_proven') is False,
             'COMPARABILITY_TRUST_OR_CLOCK')
    _require(type(value.get('sources')) is dict and set(value['sources']) == {'before', 'after'}, 'SOURCE_ROLES')
    for role in ('before', 'after'):
        run = contexts[role]['run']
        _require(type(run) is dict and _hex(run.get('run_id'), 32)
                 and _same_json_metadata(comparable.get('run_contexts', {}).get(role), run), 'RECORDED_RUN_BINDING')
        exported = value['sources'][role]
        _require(type(exported) is dict and set(exported) == set(source_sets[role]['files']), 'SOURCE_FILE_INVENTORY')
        for name, facts in source_sets[role]['files'].items():
            expected = {'source_id': _protocol_id('recording-file', name, facts['sha256'], facts['bytes']),
                'source_sha256': facts['sha256'], 'source_size_bytes': facts['bytes'],
                'producer_authentication': 'NOT_ESTABLISHED'}
            _require(_same_json_metadata(exported[name], expected), 'SOURCE_FILE_HASH_OR_SIZE')
        _require(type(comparison.get('experiments')) is dict
                 and comparison['experiments'].get(role, {}).get('repeats') == contexts[role]['repeats']
                 and type(comparison['experiments'][role]['repeats']) is int,
                 'RECORDED_REPEAT_COUNT')
        if expected_status == 'COMPARABLE':
            _require(contexts[role]['repeats'] >= 2 and run.get('identity_status') == 'OS_OBSERVED_EXACT_FILETIME'
                     and type(run.get('process_identity')) is dict
                     and type(run['process_identity'].get('pid')) is int
                     and type(run['process_identity'].get('created_100ns')) is int,
                     'COMPARABLE_REQUIRES_EXACT_REPEATED_RUNS')
    descriptor = comparison.get('tool_descriptor')
    _require(type(descriptor) is dict and descriptor.get('tool_id') == 'blackbox.research.compare'
             and type(descriptor.get('version')) is int and descriptor['version'] == 1
             and descriptor.get('operations') == ['research.compare']
             and descriptor.get('effects') == 'NO_NATIVE_INTERVENTION', 'DESCRIPTOR_OPERATION')
    if expected_status == 'COMPARABLE':
        _controlled_comparable_contexts(contexts)
        first, second = (contexts[role]['run'] for role in ('before', 'after'))
        _require(first['run_id'] != second['run_id']
                 and not _same_json_metadata(first['process_identity'], second['process_identity'])
                 and comparable.get('process_relation') == 'DISTINCT_EXACT_INSTANCES',
                 'TWO_DISTINCT_RECORDED_INSTANCES_REQUIRED')
    return _call_receipt(comparison, source_sets, contexts)


def _stable_payload(value):
    result, comparison = dict(value), dict(value['comparison'])
    comparison.pop('run_receipt')
    call = dict(comparison['run_context'])
    for key in _DYNAMIC_CONTEXT:
        call[key] = 'VALIDATED_SEPARATE_COMPARISON_CALL:' + key
    comparison['run_context'] = call
    result['comparison'] = comparison
    return result


def read_comparison_export(path, *, format, before, after, expected_status='COMPARABLE', json_reference=None):
    """Check actual byte/source identities and both separate operation receipts."""
    _require(format in ('json', 'html') and expected_status in ('COMPARABLE', 'NOT_COMPARABLE', 'INCONCLUSIVE'), 'FORMAT')
    _require(format != 'html' or type(json_reference) is dict, 'HTML_REQUIRES_JSON_REFERENCE')
    folders = {'before': Path(before), 'after': Path(after)}
    source_sets = {role: _sources(folder) for role, folder in folders.items()}
    contexts = {role: _recorded_context(folder) for role, folder in folders.items()}
    path = Path(path)
    facts, data = _file_snapshot(path, MAX_EXPORT_BYTES, keep=True)
    _require(facts['bytes'] > 0, 'EMPTY_EXPORT')
    value = _parse(data, format)
    receipt = _validate(value, source_sets, contexts, expected_status)
    if format == 'html':
        previous = _validate(json_reference, source_sets, contexts, expected_status)
        _require(value['comparison']['run_receipt']['run_id'] !=
                 json_reference['comparison']['run_receipt']['run_id'], 'SEPARATE_COMPARE_CALLS_REQUIRED')
        _require(_same_json_metadata(receipt, previous), 'STABLE_RECEIPT_CHANGED')
        _require(_same_json_metadata(_stable_payload(value), _stable_payload(json_reference)), 'HTML_JSON_METADATA_DIFFER')
    final, _ = _file_snapshot(path, MAX_EXPORT_BYTES)
    _require(final == facts and all(_sources(folder) == source_sets[role] for role, folder in folders.items()),
             'EXPORT_OR_RECORDING_CHANGED')
    return value, {'schema': SCHEMA, 'format': format, 'sha256': facts['sha256'], 'bytes': facts['bytes'],
        'comparison_status': expected_status, 'source_count': 2,
        'source_file_count': sum(len(q['files']) for q in source_sets.values()),
        'before_run_id': contexts['before']['run']['run_id'], 'after_run_id': contexts['after']['run']['run_id'],
        'operation_run_id': value['comparison']['run_receipt']['run_id'],
        'semantic_readback_verified': True, 'html_matches_json': format == 'html',
        'separate_call_receipt_verified': True, 'stable_receipt_verified': format == 'html',
        'only_normalized_context_keys': list(_DYNAMIC_CONTEXT),
        'producer_authentication': 'NOT_ESTABLISHED', 'export_bytes_unchanged': True,
        'recording_sources_unchanged': True, 'method': 'INDEPENDENT_STDLIB_COMPARISON_JSON_HTML'}
