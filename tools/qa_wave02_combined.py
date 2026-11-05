"""Co-ingest the real, already closed Wave02 branches into one saved case.

This adds a bounded cross-adapter view; it does not replace any full individual
native check, join the clocks of separate recordings, or attach to a dead target.
Only explicit Windows hosted QA calls this module. The SQLite oracle below uses
stdlib reads rather than the product index reader or validator.
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time


_GRAPH_SCHEMA = 'blackbox.investigation-graph/1'
_MAX_INDEX_BYTES = 128 * 1024**2
_MAX_RESULT_BYTES = 32 * 1024**2
_MAX_SOURCE_BYTES = 4 * 1024**3


def _require(condition, reason):
    if not condition:
        raise AssertionError('WAVE02_COMBINED_' + reason)


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _fingerprint(path, maximum=_MAX_SOURCE_BYTES):
    path = Path(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
             'SOURCE_TYPE_OR_SIZE')
    for suffix in ('-wal', '-journal'):
        sidecar = Path(str(path) + suffix)
        _require(not sidecar.is_symlink() and
                 (not sidecar.exists() or sidecar.stat().st_size == 0), 'SOURCE_ACTIVE_SIDECAR')
    count, digest = 0, hashlib.sha256()
    with path.open('rb') as stream:
        _require(_stamp(os.fstat(stream.fileno())) == _stamp(before), 'SOURCE_CHANGED')
        while block := stream.read(1024**2):
            count += len(block)
            _require(count <= maximum, 'SOURCE_TYPE_OR_SIZE')
            digest.update(block)
        after = os.fstat(stream.fileno())
    _require(count == before.st_size and
             _stamp(before) == _stamp(after) == _stamp(path.lstat()), 'SOURCE_CHANGED')
    return {'sha256': digest.hexdigest(), 'size_bytes': count, 'stamp': _stamp(before)}


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'SQLITE_DUPLICATE_JSON_KEY')
            result[key] = value
        return result

    def nonfinite(_raw):
        raise AssertionError('WAVE02_COMBINED_SQLITE_NONFINITE_JSON')

    def number(value):
        value = float(value)
        _require(math.isfinite(value), 'SQLITE_NONFINITE_JSON')
        return value

    _require(type(raw) is str and len(raw.encode('utf-8')) <= _MAX_RESULT_BYTES,
             'SQLITE_JSON_BUDGET')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=number)


def verify_saved_combined(path, public_case):
    """Read the persisted case and individual rows without a product reader.

    ``public_case`` comes from the independent JSON export parser for this case.
    Fixture tests of this oracle are not substitutes for real Windows evidence.
    """
    from blackbox_universal.wave02_export_oracles import _same_json_metadata
    path = Path(path)
    before = _fingerprint(path, _MAX_INDEX_BYTES)
    deadline = time.monotonic() + 30
    connection_closed = False
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_RESULT_BYTES + 65536)
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA cache_size=-4096')
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        _require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SQLITE_INTEGRITY')
        _require(db.execute('PRAGMA application_id').fetchone() == (0x42424933,) and
                 db.execute('PRAGMA user_version').fetchone() == (1,), 'SQLITE_SCHEMA')
        saved = db.execute('SELECT case_id,schema,content_json,content_sha256 '
                           'FROM investigation LIMIT 2').fetchall()
        _require(len(saved) == 1, 'SQLITE_CASE_COUNT')
        case_id, schema, raw, digest = saved[0]
        _require(schema == _GRAPH_SCHEMA and case_id == public_case['case_id'] and
                 type(raw) is str and len(raw) <= _MAX_RESULT_BYTES and
                 hashlib.sha256(raw.encode('ascii')).hexdigest() == digest,
                 'SQLITE_CONTENT_BINDING')
        recorded = _json(raw)
        _require(_same_json_metadata(recorded, public_case), 'SQLITE_EXPORT_METADATA_DIFFER')
        counts = {}
        for table, identifier, maximum in (('nodes', 'node_id', 10000), ('edges', 'edge_id', 20000)):
            expected = public_case[table]
            _require(type(expected) is list and len(expected) <= maximum, 'SQLITE_ROW_BUDGET')
            rows = db.execute('SELECT ' + identifier + ',record_json FROM ' + table +
                              ' ORDER BY ordinal LIMIT ?', (maximum + 1,))
            count = 0
            for count, (key, record) in enumerate(rows, 1):
                _require(count <= len(expected) and key == expected[count - 1][identifier] and
                         _same_json_metadata(_json(record), expected[count - 1]),
                         'SQLITE_GRAPH_ROW_DIFFER')
            _require(count == len(expected), 'SQLITE_GRAPH_ROW_COUNT')
            counts[table] = count
        # Endpoint columns are separately persisted navigation data, not just JSON.
        endpoints = db.execute('SELECT edge_id,from_node,to_node FROM edges ORDER BY ordinal')
        _require(all((identifier, first, second) == (edge['edge_id'], edge['from_node'], edge['to_node'])
                     for (identifier, first, second), edge in zip(endpoints, public_case['edges'])),
                 'SQLITE_EDGE_ENDPOINT_DIFFER')
        _require(time.monotonic() < deadline, 'SQLITE_READ_DEADLINE')
    finally:
        db.close()
        connection_closed = True
    _require(_fingerprint(path, _MAX_INDEX_BYTES) == before, 'SQLITE_CHANGED_DURING_READBACK')
    return {'sqlite_integrity': 'ok', 'case_id': public_case['case_id'],
            'source_count': len(public_case['sources']), 'node_count': counts['nodes'],
            'edge_count': counts['edges'], 'sha256': before['sha256'],
            'bytes': before['size_bytes'], 'source_manifests_and_graph_rows_verified': True,
            'readonly_connection_closed': connection_closed,
            'method': 'INDEPENDENT_STDLIB_SQLITE_ROWS_VS_PARSED_PUBLIC_EXPORT'}


def _manifest(paths, fingerprints):
    return sorted(({'role': role, 'sha256': fingerprints[label]['sha256'],
                    'size_bytes': fingerprints[label]['size_bytes']}
                   for role, label in paths.items()), key=lambda row: row['role'])


def _same_source_identity(first, second):
    keys = ('source_id', 'source_type', 'source_sha256', 'source_size_bytes',
            'source_file_count', 'content_manifest', 'selection', 'time_domain')
    return all(first.get(key) == second.get(key) for key in keys)


def _session_closed(main):
    # The existing full R50 acceptance requires actual v2 recordings. Keep that
    # requirement here; a legacy fallback cannot silently substitute this oracle.
    _require(main.name == 'session-v2.sqlite3', 'REAL_R50_V2_RECORDING_REQUIRED')
    with closing(sqlite3.connect(main.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        _require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SESSION_INTEGRITY')
        rows = db.execute('SELECT session_uuid,status,ended_monotonic_ns FROM sessions LIMIT 2').fetchall()
        _require(len(rows) == 1 and rows[0][1] == 'CLOSED' and type(rows[0][2]) is int,
                 'SESSION_STOP_NOT_PERSISTED')
        instances = db.execute('SELECT pid,creation_time FROM process_instances WHERE instance_id=1').fetchall()
        _require(len(instances) == 1, 'SESSION_ROOT_INSTANCE_REQUIRED')
    return rows[0][0], instances[0]


def _write_failure_receipt(save, path, proof, error):
    """A late I/O failure must neither retain PASS nor replace its own cause."""
    failure = {**proof, 'status': 'FAIL', 'error': type(error).__name__,
               'reason': str(error)[:2000]}
    if type(proof.get('public_receipt')) is dict:
        failure['public_receipt'] = {**proof['public_receipt'], 'status': 'FAIL'}
    try:
        save(path, failure)
    except BaseException as receipt_error:
        error.add_note('COMBINED_FAILURE_RECEIPT_WRITE_UNCONFIRMED:' + type(receipt_error).__name__)
    return failure


def check_combined(*, sources, individual_case, container_results, output, source_sha,
                   original_trace, producer_cleanup):
    from blackbox_core.investigation_v3 import create_investigation, load_investigation
    from blackbox_universal.provenance import source_identity
    from blackbox_universal.wave02_export_oracles import read_graph_export
    from tools.qa_deep_inspection import require_hosted_windows, save
    from tools.qa_wave02 import export_case, verify_case

    require_hosted_windows()
    _require(type(source_sha) is str and re.fullmatch(r'[0-9a-f]{40}', source_sha) and
             source_identity(source_sha)['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD',
             'EXACT_SOURCE_REQUIRED')
    _require(set(container_results) == {'R20', 'R30', 'R40', 'R50'} and
             all(value.get('status') == 'PASS' for value in container_results.values()),
             'ALL_INDIVIDUAL_NATIVE_BRANCHES_REQUIRED')
    _require(producer_cleanup['target']['status'] == 'COMPLETED' and
             producer_cleanup['helper']['status'] == 'COMPLETED' and
             producer_cleanup['capture']['status'] == 'CAPTURED' and
             container_results['R40']['crash_cleanup']['status'] == 'OWNED_CRASH_EXIT_VERIFIED',
             'PRIOR_PRODUCER_CLEANUP_NOT_CONFIRMED')
    folder = Path(output) / 'combined'; folder.mkdir(exist_ok=False)
    proof = {'status': 'FAIL', 'source_sha': source_sha}
    try:
        r20 = {item['source_type']: deepcopy(item) for item in sources}
        _require(len(sources) == len(r20) == 3 and set(r20) ==
                 {'TRACE_INDEX', 'DEEP_JOURNAL', 'EVENTS_JSONL'}, 'REAL_R20_INPUTS_REQUIRED')
        crash = container_results['R40']
        before_recording = container_results['R50']['before']
        session = Path(before_recording['folder'])
        main = session / 'session-v2.sqlite3'
        research = session / 'research.sqlite3'
        legacy = session / 'session.sqlite3'
        paths = {'original_etl': Path(original_trace),
                 'trace_index': Path(r20['TRACE_INDEX']['path']),
                 'deep_journal': Path(r20['DEEP_JOURNAL']['path']),
                 'application_jsonl': Path(r20['EVENTS_JSONL']['path']),
                 'minidump': Path(crash['private_dump_path']),
                 'local_image': Path(crash['local_image_path']),
                 'local_pdb': Path(crash['local_pdb_path']),
                 'session_main': main, 'session_research': research, 'session_legacy': legacy}
        fingerprints = {label: _fingerprint(path) for label, path in paths.items()}
        _require(fingerprints['original_etl']['sha256'] == container_results['R20']['trace_sha256'] and
                 fingerprints['original_etl']['size_bytes'] == container_results['R20']['trace_bytes'] and
                 fingerprints['trace_index']['sha256'] == container_results['R20']['index_sha256'] and
                 fingerprints['minidump']['sha256'] == crash['dump_sha256'] and
                 fingerprints['local_image']['sha256'] == crash['local_image_sha256'] and
                 fingerprints['local_pdb']['sha256'] == crash['local_pdb_sha256'] and
                 fingerprints['session_main']['sha256'] == before_recording['source_sha256'],
                 'REAL_BRANCH_SOURCE_DIGEST_CHANGED')
        session_uuid, recorded_instance = _session_closed(main)
        # Descriptor order reserves room for the rare, real adapters before the
        # unchanged whole-trace bounded view. Original individual full views and
        # their strict oracles have already run. No clocks or windows are edited.
        combined_sources = [r20['DEEP_JOURNAL'], r20['EVENTS_JSONL'],
            {'source_type': 'DUMP_METADATA', 'path': str(paths['minidump']),
             'image_path': str(paths['local_image']), 'pdb_path': str(paths['local_pdb'])},
            {'source_type': 'SESSION', 'path': str(session)}, r20['TRACE_INDEX']]
        index = folder / 'case.sqlite3'
        case = create_investigation(combined_sources, target_identity=None,
            scenario={'scenario': 'BB-WAVE-02-REAL-CROSS-ADAPTER-SAVED-EVIDENCE',
                      'process_scope': 'SEPARATE_EXACT_OWNED_NATIVE_BRANCHES',
                      'clock_relation': 'NOT_ESTABLISHED'},
            budget={'timeout_seconds': 120}, index_path=index)
        verify_case(case)
        _require(case['target_identity'] is None and len(case['sources']) == 5 and
                 len(case['nodes']) <= 10000 and len(case['edges']) <= 20000 and
                 case['coverage']['events_examined'] <= 250000, 'DEFAULT_BOUNDS_OR_TARGET_CHANGED')
        by_type = {item['source_type']: item for item in case['sources']}
        _require(len(by_type) == 5 and set(by_type) ==
                 {'TRACE_INDEX', 'DEEP_JOURNAL', 'EVENTS_JSONL', 'DUMP_METADATA', 'SESSION'},
                 'COMBINED_ADAPTER_MISSING')
        for original in individual_case['sources']:
            _require(_same_source_identity(by_type[original['source_type']], original),
                     'R20_SOURCE_IDENTITY_OR_SELECTION_CHANGED')
        expected_manifests = {
            'TRACE_INDEX': {'trace_index': 'trace_index'}, 'DEEP_JOURNAL': {'0': 'deep_journal'},
            'EVENTS_JSONL': {'0': 'application_jsonl'},
            'DUMP_METADATA': {'minidump': 'minidump', 'local_image': 'local_image', 'local_pdb': 'local_pdb'},
            'SESSION': {'session_main': 'session_main', 'research': 'session_research'}}
        for kind, roles in expected_manifests.items():
            source = by_type[kind]
            manifest = _manifest(roles, fingerprints)
            _require(source['content_manifest'] == manifest and
                     source['source_size_bytes'] == sum(item['size_bytes'] for item in manifest) and
                     source['source_file_count'] == len(manifest) and
                     source['provenance']['producer_authentication'] == 'NOT_ESTABLISHED' and
                     source['verification_class'] == 'UNVERIFIED_IMPORT', 'MANIFEST_OR_TRUST_CHANGED')
        _require(by_type['SESSION']['session_uuid'] == session_uuid and
                 by_type['SESSION']['research_session_clock_alignment'] == 'NOT_ESTABLISHED' and
                 by_type['TRACE_INDEX']['trace_input_sha256'] == fingerprints['original_etl']['sha256'] and
                 by_type['DUMP_METADATA']['live_process_binding'] == 'NOT_ESTABLISHED',
                 'FOREIGN_CLOCK_OR_LIVE_DUMP_BINDING_INVENTED')
        counts = Counter(node['observation_type'] for node in case['nodes'])
        source_counts = {kind: Counter(node['observation_type'] for node in case['nodes']
                          if node['source_identity'] == source['source_id'])
                         for kind, source in by_type.items()}
        _require(source_counts['DEEP_JOURNAL']['WAIT_INTERVAL'] > 0 and
                 source_counts['EVENTS_JSONL']['FILE_OPERATION'] > 0 and
                 source_counts['DUMP_METADATA']['STACK'] > 0 and
                 source_counts['DUMP_METADATA']['ERROR'] > 0 and
                 source_counts['SESSION']['INCIDENT'] > 0 and
                 sum(source_counts['TRACE_INDEX'].values()) > 0,
                 'REAL_WAIT_IO_STACK_ERROR_INCIDENT_OR_TRACE_MISSING')
        # The selected session root is source-local float-creation metadata, not
        # an exact live FILETIME or a claim that the separate targets were one.
        session_nodes = [node for node in case['nodes']
                         if node['source_identity'] == by_type['SESSION']['source_id']]
        _require(any((node.get('process_identity') or {}).get('kind') == 'SESSION_PROCESS' and
                     node['process_identity'].get('pid') == recorded_instance[0] and
                     node['process_identity'].get('creation_time') == recorded_instance[1] and
                     node['process_identity'].get('exact') is False for node in session_nodes),
                 'SESSION_SOURCE_LOCAL_INSTANCE_LOST')
        nodes = {node['node_id']: node for node in case['nodes']}
        forbidden_cross = [edge for edge in case['edges'] if edge['relation_type'] in
            {'EXACT_IDENTITY', 'BOUNDED_TIME_CORRELATION', 'OBSERVED_DEPENDENCY'} and
            nodes[edge['from_node']]['source_identity'] != nodes[edge['to_node']]['source_identity']]
        _require(not forbidden_cross, 'UNPROVEN_CROSS_SOURCE_IDENTITY_CLOCK_OR_CAUSE')
        crash_projection = case['crash_investigation']
        _require(crash_projection['summary']['recorded_exceptions'] == 1 and
                 crash_projection['summary']['unwound_callers'] >= 2 and
                 crash_projection['root_cause'] == 'UNKNOWN' and
                 crash_projection['privacy']['memory_contents_included'] is False and
                 crash_projection['privacy']['dump_bytes_included'] is False,
                 'CRASH_STACK_SOURCE_OR_PRIVACY_LOST')
        receipt = case['run_receipt']
        _require(receipt['cleanup']['confirmed'] is True and
                 receipt['cleanup']['scope'] == 'NORMALIZATION_SOURCE_READ_HANDLES_AND_OFFLINE_UNWIND',
                 'COMBINED_OFFLINE_CLEANUP_UNCONFIRMED')
        exports = export_case(case, folder)
        public_case, semantic = read_graph_export(folder / 'investigation.json',
                                                 format='json', expected_case=case)
        sqlite_readback = verify_saved_combined(index, public_case)
        reopened = load_investigation(index)
        _require(reopened['case_id'] == case['case_id'] and
                 {node['node_id'] for node in reopened['nodes']} == set(nodes) and
                 reopened['source_ids'] == case['source_ids'] and
                 reopened['file_trust'] == 'UNVERIFIED_IMPORT', 'PUBLIC_REOPEN_CHANGED_GRAPH')
        _require(all(_fingerprint(path) == fingerprints[label] for label, path in paths.items()),
                 'ORIGINAL_SOURCE_CHANGED_BY_COINGESTION_OR_EXPORT')
        branch_instances = {'R20_R30': container_results['R20']['fixture'],
                            'R40': crash['target'],
                            'R50': before_recording['run_identity']['process_identity']}
        identities = {kind: {key: value[key] for key in ('pid', 'created_100ns')}
                      for kind, value in branch_instances.items()}
        _require(all(type(identity['pid']) is int and 0 < identity['pid'] < 2**32 and
                     type(identity['created_100ns']) is int and identity['created_100ns'] > 0
                     for identity in identities.values()) and
                 len({(value['pid'], value['created_100ns']) for value in identities.values()}) == 3,
                 'SEPARATE_ACTUAL_PRODUCER_INSTANCES_REQUIRED')
        source_views = []
        for kind, source in sorted(by_type.items()):
            source_nodes = [node for node in case['nodes']
                            if node['source_identity'] == source['source_id']]
            domains = sorted({node['time_domain'] for node in source_nodes})
            _require(all(domain == 'UNKNOWN' or re.fullmatch(
                r'(?:TRACE_RELATIVE|NATIVE_CAPTURE|APP_SOURCE|MINIDUMP_RECORDED|'
                r'SESSION_MONOTONIC|RESEARCH_MONOTONIC|LEGACY_ELAPSED):[0-9a-f]{64}', domain)
                for domain in domains), 'UNEXPECTED_SOURCE_TIME_DOMAIN')
            source_views.append({'source_type': kind, 'source_id': source['source_id'],
                'selection': source['selection'], 'node_time_domains': domains,
                'process_identity_kinds': dict(sorted(Counter(
                    (node.get('process_identity') or {}).get('kind', 'UNRESOLVED')
                    for node in source_nodes).items()))})
        public = {'schema': 'blackbox.wave02.combined-e2e/1', 'status': 'PASS',
            'source_sha': source_sha, 'case_id': case['case_id'], 'source_count': len(by_type),
            'source_manifests': [{key: source[key] for key in
                ('source_id', 'source_type', 'source_sha256', 'source_size_bytes', 'content_manifest')}
                for source in case['sources']],
            'source_types': sorted(by_type), 'node_kind_counts': dict(sorted(counts.items())),
            'source_views': source_views, 'separate_native_producer_instances': identities,
            'producer_instance_scope': 'SEPARATE_NATIVE_ORACLES_NOT_IMPORTED_CLOCK_OR_LIVE_DUMP_AUTHORITY',
            'source_node_kind_counts': {kind: dict(sorted(value.items()))
                                      for kind, value in sorted(source_counts.items())},
            'node_count': len(case['nodes']), 'edge_count': len(case['edges']),
            'view': 'DEFAULT_BOUNDED_COINGESTION_RARE_ADAPTERS_THEN_UNCHANGED_TRACE_SELECTION',
            'individual_full_native_checks_preserved': True,
            'coverage': {key: case['coverage'][key] for key in
                ('events_examined', 'events_omitted', 'nodes_omitted', 'has_more',
                 'edges_omitted', 'display_graph_complete', 'evidence_completeness')},
            'common_live_target': 'NOT_ESTABLISHED', 'cross_source_clock_binding': 'NOT_ESTABLISHED',
            'unproven_strong_cross_source_edges': 0, 'producer_authentication': 'NOT_ESTABLISHED',
            'root_cause': 'UNKNOWN', 'memory_contents_included': False, 'dump_bytes_included': False,
            'session_main_role': main.name, 'optional_session_research_absent': False,
            'source_hashes_unchanged': True, 'original_source_file_count': len(paths),
            'sqlite_readback': sqlite_readback, 'public_reopen_verified': True,
            'independent_json_semantic_readback': semantic, 'exports': exports,
            'cleanup': {'source_read_connections_closed': True,
                        'offline_unwind_confirmed': True,
                        'r20_target_helper_capture_and_r40_crash_exit_verified': True,
                        'r50_session_closed_independently_read': True,
                        'scope': 'COMBINED_OFFLINE_READS_AND_RECORDED_SEPARATE_PRODUCER_GATES'},
            'physical_windows_10_11': 'NOT_TESTED', 'physical_secure_desktop': 'NOT_TESTED'}
        proof = {'status': 'PASS', 'case_index': str(index), 'public_receipt': public}
        save(folder / 'combined-qa.json', proof)
        fingerprint = _fingerprint(folder / 'combined-qa.json', 1024**2)
        public['receipt_sha256'] = fingerprint['sha256']
        public['receipt_bytes'] = fingerprint['size_bytes']
        print('WAVE02_COMBINED_E2E_RECEIPT ' + json.dumps(public, sort_keys=True), flush=True)
        return proof
    except BaseException as error:
        # Preserve failure, actual evidence paths and available diagnosis. Never
        # relabel a missing kind or exhausted bounded view as a completed chain.
        _write_failure_receipt(save, folder / 'combined-failure.json', proof, error)
        safe_reason = (str(error)[:2000] if isinstance(error, AssertionError) and
                       str(error).startswith('WAVE02_COMBINED_') else 'EXCEPTION_DETAIL_WITHHELD')
        try:
            print('WAVE02_COMBINED_E2E_RECEIPT ' + json.dumps({
                'schema': 'blackbox.wave02.combined-e2e/1', 'status': 'FAIL',
                'source_sha': source_sha, 'error': type(error).__name__,
                'reason': safe_reason}, sort_keys=True), flush=True)
        except BaseException as log_error:
            error.add_note('COMBINED_FAILURE_LOG_WRITE_UNCONFIRMED:' + type(log_error).__name__)
        raise
