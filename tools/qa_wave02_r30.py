"""Actual R30 scheduler/I/O provenance and explicit loss/identity controls."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3


def check_r30(case, index, ready, file_oracles, output):
    from blackbox_core.decoder_io import build_file_io_report, build_disk_io_report
    from blackbox_core.decoder_waits import build_wait_report
    from blackbox_core.delay_investigation import analyze_delay
    from blackbox_core.investigation_v3 import create_investigation
    from tools.qa_wave02 import export_case, trace_source, verify_case
    from tools.qa_deep_inspection import require, file_hash, save
    index, output = Path(index), Path(output)
    before = file_hash(index)
    selected = trace_source(index, ready['pid'])
    lifetime = selected['selection']['process_instance']
    files = build_file_io_report(index, pid=ready['pid'], process_instance=lifetime)
    require(files['operations'] and files['coverage']['typed_events'] > 0,
            'WAVE02_R30_ACTUAL_TYPED_FILE_OPERATIONS_REQUIRED')
    require(all(q['pid'] == ready['pid'] and q['process_instance'] in (lifetime, None)
                and q['win32_error'] is None and q['transferred_bytes'] is None
                and q['root_cause'] == 'UNKNOWN' for q in files['operations']),
            'WAVE02_R30_FILE_ATTRIBUTION_OR_ERROR_DOMAIN_OVERCLAIM')
    paired = [q for q in files['operations'] if q['quality'] == 'OBSERVED_REQUEST_PAIR']
    require(paired and all(q['elapsed_ms'] is not None and q['elapsed_ms'] >= 0
                          and len(q['source_event_ids']) == 2 for q in paired),
            'WAVE02_R30_REAL_FILE_REQUEST_BOUNDARIES_REQUIRED')
    disk = build_disk_io_report(index, pid=ready['pid'], process_instance=lifetime)
    require(all(q.get('queue_delay_ms') is None and q.get('device_service_ms') is None
                for q in disk['requests']), 'WAVE02_R30_INVENTED_DEVICE_QUEUE_OR_SERVICE_TIME')
    intervals = build_wait_report(index, pid=ready['pid'], process_instance=lifetime,
                                  tid=ready['ui_tid'])
    oracle = json.loads((output / 'target-A/oracle-records.json').read_text(encoding='utf-8'))
    entered = next(q for q in oracle if q['event'] == 'freeze_enter')
    exited = next(q for q in oracle if q['event'] == 'freeze_done')
    matched = []
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
        require(summary['engine']['trace_counter_frequency_hz'] == ready['qpc_frequency'],
                'WAVE02_R30_NATIVE_QPC_FREQUENCY_MISMATCH')
        for q in intervals['intervals']:
            if (q['tid'] != ready['ui_tid'] or q.get('off_cpu_ms') is None or
                    q['off_cpu_ms'] < 20 or len(q['source_event_ids']) < 2):
                continue
            first = json.loads(db.execute('SELECT data FROM events WHERE id=?',
                (q['source_event_ids'][0],)).fetchone()[0])
            last = json.loads(db.execute('SELECT data FROM events WHERE id=?',
                (q['source_event_ids'][-1],)).fetchone()[0])
            if entered['qpc'] <= int(first['source_ticks']) <= int(last['source_ticks']) <= exited['end_qpc']:
                matched.append(q)
    require(matched, 'WAVE02_R30_REAL_UI_WAIT_NOT_BOUND_TO_ORACLE_QPC')
    delays = analyze_delay(case)
    require(delays['findings'], 'WAVE02_R30_REAL_GRAPH_DELAY_FINDINGS_REQUIRED')
    nodes = {q['node_id'] for q in case['nodes']}
    for q in delays['findings']:
        require(q['source_nodes'] and set(q['source_nodes']) <= nodes and q['root_cause_proven'] is False,
                'WAVE02_R30_FINDING_LOST_SOURCE_OR_INVENTED_CAUSE')
    errors = [q for q in delays['findings'] if q['category'] == 'FILE_IO_ERROR']
    require({5, 32} <= {q['details'].get('win32_error') for q in errors},
            'WAVE02_R30_ACTUAL_APP_RECORDED_WIN32_ERRORS_MISSING')
    owners = [owner for q in delays['findings'] if q['category'] == 'WCT_CHAIN'
              for owner in q['details'].get('reported_owners', [])]
    require(any(q['pid'] == ready['pid'] and q['tid'] == ready['control_tid']
                and q['exact_instance'] is False for q in owners),
            'WAVE02_R30_OS_WCT_OWNER_MISSING_OR_FILETIME_INVENTED')
    irrelevant = build_file_io_report(index, pid=ready['pid'], process_instance=lifetime + 1000000)
    require(not irrelevant['operations'], 'WAVE02_R30_REUSED_PID_CROSSED_TRACE_LIFETIME')
    negative = output / 'R30-explicit-loss-control.sqlite3'
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(negative)) as target:
            source.backup(target)
            changed = json.loads(target.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            changed.update(status='TRUNCATED', decoder_reported_lost_events=1,
                           import_completeness='BOUNDED_PREFIX')
            target.execute("UPDATE metadata SET value=? WHERE key='summary'", (json.dumps(changed),))
            target.commit()
    lost = build_file_io_report(negative, pid=ready['pid'], process_instance=lifetime)
    require(lost['status'] == 'PARTIAL_EVIDENCE' and
            all(q['elapsed_ms'] is None and q['ntstatus'] is None for q in lost['operations']),
            'WAVE02_R30_INJECTED_LOSS_PROMOTED_TO_PRECISE_LATENCY_OR_STATUS')
    partial = create_investigation([{'source_type': 'TRACE_INDEX', 'path': str(negative),
        'selection': {'pid': ready['pid'], 'process_instance': lifetime}}],
        budget={'timeout_seconds': 120})
    require(partial['coverage']['evidence_completeness'] == 'INCOMPLETE_EVIDENCE',
            'WAVE02_R30_PARTIAL_SOURCE_BECAME_COMPLETE')
    require(file_hash(index) == before, 'WAVE02_R30_READERS_OR_NEGATIVE_CONTROL_CHANGED_ORIGINAL')
    folder = output / 'R30'; folder.mkdir()
    saved = deepcopy(case); saved['delay_investigation'] = delays
    from blackbox_core.investigation_graph_store import save_investigation
    save_investigation(saved, folder / 'case.sqlite3')
    exports = export_case(saved, folder)
    save(folder / 'file-operations.json', files)
    save(folder / 'disk-requests.json', disk)
    save(folder / 'wait-report.json', intervals)
    return {'status': 'PASS', 'case_index': str(folder / 'case.sqlite3'),
        'actual_file_pairs': len(paired), 'recorded_ntstatuses': sorted({q['ntstatus'] for q in paired if q['ntstatus'] is not None}),
        'disk_request_count': len(disk['requests']), 'disk_status': disk['status'],
        'disk_own_latency': 'OBSERVED_ONLY_FOR_MATCHED_REQUESTS' if disk['requests'] else 'NOT_OBSERVED_IN_THIS_CAPTURE',
        'actual_ui_wait_matches': len(matched), 'wct_owner_snapshot_count': len(owners),
        'app_recorded_errors': sorted({q['winerror'] for q in file_oracles if q['winerror']}),
        'source_hash_unchanged': True, 'exports': exports,
        'negative_controls': {'wrong_lifetime': 'NO_OPERATIONS', 'loss': 'PARTIAL_WITHOUT_DURATIONS',
            'kind': 'EXPLICIT_INDEX_METADATA_FAULT_COPY_NOT_OS_EVENT_LOSS'},
        'root_cause': 'UNKNOWN'}
