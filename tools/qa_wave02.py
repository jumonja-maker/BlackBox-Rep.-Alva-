"""Actual BB-WAVE-02 Windows evidence pipeline; no local execution or artifact transfer."""
from __future__ import annotations

import argparse
from contextlib import closing
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import sqlite3
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from tools.qa_deep_inspection import file_hash, require, require_hosted_windows, save
from tools.qa_wave02_fixture import WaveProbe, build
from tools.qa_wave02_scope import load_scope


def window_probe(ready):
    """Independent WM_NULL timeout with a verified own-window PID/TID."""
    user = C.WinDLL('user32', use_last_error=True, winmode=0x800)
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.GetWindowThreadProcessId.restype = W.DWORD
    user.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, C.c_size_t, C.c_ssize_t,
                                        W.UINT, W.UINT, C.POINTER(C.c_size_t)]
    user.SendMessageTimeoutW.restype = C.c_ssize_t
    pid = W.DWORD()
    tid = user.GetWindowThreadProcessId(ready['hwnd'], C.byref(pid))
    require(pid.value == ready['pid'] and tid == ready['ui_tid'],
            'WAVE02_WINDOW_EXACT_OWNED_PID_TID_REQUIRED')
    result = C.c_size_t()
    started = time.perf_counter_ns()
    C.set_last_error(0)
    ok = user.SendMessageTimeoutW(ready['hwnd'], 0, 0, 0, 0x1 | 0x2 | 0x20,
                                  200, C.byref(result))
    error = C.get_last_error()
    return {'responsive': bool(ok), 'winerror': 0 if ok else error,
            'duration_ns': time.perf_counter_ns() - started,
            'pid': pid.value, 'tid': tid, 'hwnd': ready['hwnd'],
            'method': 'INDEPENDENT_SEND_MESSAGE_TIMEOUT_WM_NULL'}


def oracle_events(probe, path):
    """Wrap real fixture results as unverified application statements, not ETW."""
    rows = [q for q in probe.records if q['event'] == 'file_operation']
    require(len(rows) == 3, 'WAVE02_THREE_ACTUAL_FILE_ORACLES_REQUIRED')
    frequency = probe.ready['qpc_frequency']
    records = []
    for sequence, observed in enumerate(rows, 1):
        require(observed['pid'] == probe.ready['pid'] and
                observed['created_100ns'] == probe.ready['created_100ns'] and
                observed['start_qpc'] <= observed['end_qpc'],
                'WAVE02_ORACLE_EXACT_PROCESS_AND_QPC_REQUIRED')
        records.append({'schema_version': 1, 'token': 'BLACKBOX_WAVE02_PUBLIC_ORACLE',
            'pid': observed['pid'], 'tid': observed['tid'], 'seq': sequence,
            'source_clock': 'OWNED_FIXTURE_QPC_NOT_IMPORTED_CLOCK_AUTHORITY',
            'source_ns': observed['end_qpc'] * 1000000000 // frequency,
            'kind': 'io.operation.end', 'operation_id': 'wave02-file-' + str(sequence),
            'parent_id': None, 'client_dropped': 0,
            'attributes': {'status': 'ERROR' if observed['winerror'] else 'COMPLETED',
                'error_code': observed['winerror'], 'winerror': observed['winerror'],
                'io_kind': 'CREATE_FILE' if observed['winerror'] else 'READ_WRITE',
                'role': observed['role'],
                'latency_ns': (observed['end_qpc'] - observed['start_qpc']) * 1000000000 // frequency,
                'process_created_100ns': observed['created_100ns'],
                'source_start_qpc': observed['start_qpc'], 'source_end_qpc': observed['end_qpc'],
                'source_qpc_frequency': frequency,
                'attribution': 'QA_WRAPPED_REAL_NATIVE_ORACLE_APPLICATION_STATEMENT',
                'private_secret': 'BLACKBOX_WAVE02_PRIVATE_SECRET_MUST_NOT_EXPORT'}})
    records.append({'schema_version': 1, 'token': 'BLACKBOX_WAVE02_PUBLIC_ORACLE',
        'pid': probe.ready['pid'], 'tid': probe.ready['control_tid'], 'seq': 4,
        'source_clock': 'OWNED_FIXTURE_QPC_NOT_IMPORTED_CLOCK_AUTHORITY',
        'source_ns': records[-1]['source_ns'], 'kind': 'blackbox.completed',
        'operation_id': 'wave02-file-complete', 'parent_id': None, 'client_dropped': 0,
        'attributes': {'status': 'COMPLETED', 'expected_operations': 3}})
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        for row in records:
            stream.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + '\n')
    return rows


def verify_case(case):
    from tools.qa_inv_common import graph_facts
    graph_facts(case)
    require(case.get('run_receipt', {}).get('operation') == 'investigation.create',
            'WAVE02_INVESTIGATION_REAL_RUN_RECEIPT_REQUIRED')
    require(case['run_receipt'].get('contract_version') == 1 and
            case['coverage'].get('evidence_completeness') in
            {'INCOMPLETE_EVIDENCE', 'UNKNOWN_CAPTURE_COMPLETENESS'},
            'WAVE02_CAPTURE_COMPLETENESS_MUST_NOT_BE_INVENTED')
    for source in case['sources']:
        require(source.get('source_size_bytes', 0) > 0 and
                len(source.get('source_sha256', '')) == 64 and
                source.get('provenance', {}).get('producer_authentication') == 'NOT_ESTABLISHED',
                'WAVE02_SOURCE_SIZE_HASH_AND_NONAUTHENTICATION_REQUIRED')
    require(all(h.get('root_cause_proven') is False for h in case['hypotheses']),
            'WAVE02_HYPOTHESIS_IS_NOT_AUTOMATIC_ROOT_CAUSE')


def export_case(case, output):
    from blackbox_core.investigation_v3 import export_investigation, load_investigation
    from blackbox_core.evidence_graph import validate_case
    result = {}
    for kind in ('json', 'html'):
        path = output / ('investigation.' + kind)
        receipt = export_investigation(case, path, format=kind)
        require(receipt['status'] == 'COMPLETED' and receipt.get('readback_verified') is True
                and receipt.get('run_receipt', {}).get('operation') == 'investigation.export'
                and receipt['sha256'] == file_hash(path), 'WAVE02_REAL_EXPORT_RECEIPT_READBACK_REQUIRED')
        raw = path.read_text(encoding='utf-8')
        require('BLACKBOX_WAVE02_PRIVATE_SECRET_MUST_NOT_EXPORT' not in raw and
                'BLACKBOX_WAVE02_DUMP_PRIVATE_CONTENT' not in raw and
                b'BLACKBOX_WAVE02_DUMP_PRIVATE_CONTENT'.hex() not in raw,
                'WAVE02_PRIVATE_PAYLOAD_ESCAPED_NORMAL_SHARE')
        if kind == 'json':
            independently_parsed = json.loads(raw)
            require(independently_parsed['case_id'] == case['case_id'] and
                    len(independently_parsed['nodes']) == len(case['nodes']),
                    'WAVE02_INDEPENDENT_JSON_READBACK_CHANGED_CASE')
            validate_case(independently_parsed)
            loaded = load_investigation(output / 'case.sqlite3')
            require(loaded['case_id'] == case['case_id'], 'WAVE02_PUBLIC_READBACK_FAILED')
        before = file_hash(path)
        try:
            export_investigation(case, path, format=kind)
        except (FileExistsError, ValueError):
            pass
        else:
            raise AssertionError('WAVE02_EXPORT_OVERWROTE_EXISTING_DESTINATION')
        require(file_hash(path) == before, 'WAVE02_EXISTING_EXPORT_CHANGED')
        result[kind] = {'sha256': before, 'bytes': path.stat().st_size,
                        'readback_verified': True, 'no_clobber_verified': True}
    return result


def trace_source(index, pid):
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        lifetimes = {json.loads(raw).get('process_instance') for raw, in
            db.execute('SELECT data FROM events WHERE pid=?', (pid,))}
    lifetimes.discard(None)
    require(len(lifetimes) == 1, 'WAVE02_EXACT_TRACE_PROCESS_LIFETIME_REQUIRED')
    return {'source_type': 'TRACE_INDEX', 'path': str(index),
            'selection': {'pid': pid, 'process_instance': next(iter(lifetimes))}}


def writer_failure(output, target):
    """An actual owned SQLite writer exhausts an explicit test disk budget."""
    from blackbox_core.contracts import ObserverError
    from blackbox_core.session_v2 import SessionV2Writer
    folder = output / 'writer-disk-budget-fault'; folder.mkdir()
    created = (target.created_100ns - 116444736000000000) / 10000000
    writer = SessionV2Writer(folder, pid=target.pid, created=created,
        name='OWNED_WAVE02_WRITER_FAULT', origin_ns=time.monotonic_ns(), max_bytes=1024)
    try:
        require(writer._ready.wait(5) and writer.failure is None,
                'WAVE02_REAL_WRITER_INITIALIZATION_FAILED_BEFORE_FAULT')
        writer.submit('event', {'kind': 'wave02.owned_writer_fault', 'time_ns': time.monotonic_ns()})
        try:
            writer.finish('COMPLETED')
        except ObserverError:
            require(writer.failure == 'V2_DISK_LIMIT', 'WAVE02_WRITER_FAULT_CAUSE_NOT_ESTABLISHED')
        else:
            raise AssertionError('WAVE02_WRITER_BUDGET_FAILURE_WAS_CALLED_COMPLETED')
        require(not writer.thread.is_alive(), 'WAVE02_FAILED_WRITER_OWNER_NOT_CLOSED')
        with closing(sqlite3.connect(writer.path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',),
                    'WAVE02_FAILED_WRITER_CORRUPTED_DATABASE')
            status, code = db.execute('SELECT status,exit_code FROM sessions').fetchone()
        require(status == 'CLOSED' and code == 'STORAGE_ERROR',
                'WAVE02_WRITER_FAILURE_PROMOTED_TO_COMPLETE')
        return {'status': 'PASS', 'fault': 'ACTUAL_EXPLICIT_DISK_BUDGET_EXHAUSTION',
            'writer_failure': writer.failure, 'session_status': status, 'exit_code': code,
            'writer_thread_exited': True, 'sqlite_integrity': 'ok'}
    finally:
        if writer.thread.is_alive():
            try: writer.finish('STORAGE_ERROR')
            except ObserverError: pass
            require(not writer.thread.is_alive(), 'WAVE02_WRITER_FAULT_CLEANUP_UNCONFIRMED')


def run(args):
    require_hosted_windows()
    from blackbox_universal.provenance import source_identity
    from blackbox_core.decoder_service import decode_file, helper_path
    from blackbox_core.deep_contracts import ActionRequest
    from blackbox_core.deep_service import InspectorService
    from blackbox_core.investigation_v3 import create_investigation
    from tools.qa_schedule_capture import OwnedScheduleCapture
    from tools.qa_r10_native import actual_token

    scope = load_scope(args.container)
    identity = source_identity(args.source_sha)
    require(identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD', 'WAVE02_SOURCE_HEAD_MISMATCH')
    require(helper_path().resolve(strict=True) == args.decoder.resolve(strict=True),
            'WAVE02_MUST_USE_PRODUCTION_DECODER_PATH')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    proof = {'status': 'RUNNING', 'schema': 'blackbox.wave02.native-qa/1',
        'source_identity': identity, 'scope': scope, 'container_results': {},
        'physical_windows_10_11': 'NOT_TESTED', 'physical_secure_desktop': 'NOT_TESTED',
        'positive_data': 'ACTUAL_OWNED_WINDOWS_PROCESSES_AND_ETW',
        'negative_format_controls': 'SEPARATE_UNVERIFIED_FAULT_INJECTION'}
    fixture = service = capture = None
    successful = False
    sources_before = {}
    def phase(name):
        proof['phase'] = name
        print('WAVE02_NATIVE_PHASE ' + name, flush=True)
    try:
        phase('BUILD_AND_START_OWNED_FIXTURE')
        executable = args.probe.resolve(strict=True) if args.probe else build(output / 'build', args.source_sha)
        capture_root = output / 'capture'; capture_root.mkdir()
        capture = OwnedScheduleCapture(capture_root)
        proof['capture_start'] = capture.start()
        fixture = WaveProbe(executable, output / 'target-A')
        proof['fixture_ready'] = fixture.ready
        service = InspectorService(output / 'journal', helper_executable=args.diagnostic_helper)
        launches = []
        original_launch = service.broker.launch
        def launch(arguments, *, elevated=False):
            owner = original_launch(arguments, elevated=elevated)
            launches.append({'pid': owner.pid, 'elevated': elevated})
            return owner
        service.broker.launch = launch
        phase('REAL_R10_SESSION_AND_EXACT_TARGET')
        opened = service.start_admin_session(confirmed=True)
        require(opened['status'] == 'COMPLETED', 'WAVE02_REAL_R10_LEASE_REQUIRED')
        status = service.session_status(refresh=True)
        helper_identity, deadline = status['helper_identity'], status['session_deadline_monotonic']
        token = actual_token(helper_identity['pid'])
        require(token['elevated'] is True and len(launches) == 1 and launches[0]['elevated'],
                'WAVE02_INDEPENDENT_ELEVATED_TOKEN_AND_ONE_RUNAS_REQUIRED')
        target = service.identity(fixture.process.pid)
        require(target.created_100ns == fixture.ready['created_100ns'], 'WAVE02_REAL_PROCESS_BIRTH_MISMATCH')
        require(service.bind_target(target, ['threads', 'modules', 'wait_chains'], confirmed=True)['status'] == 'COMPLETED',
                'WAVE02_EXPLICIT_R10_TARGET_SCOPE_REQUIRED')
        phase('REAL_UI_MUTEX_WAIT_AND_OS_WCT_OWNER')
        fixture.send('freeze'); frozen = fixture.receive('freeze_enter')
        ui_timeout = window_probe(fixture.ready)
        require(ui_timeout['responsive'] is False and ui_timeout['winerror'] in (0, 1460)
                and ui_timeout['duration_ns'] >= 100000000,
                'WAVE02_ACTUAL_OWNED_UI_TIMEOUT_REQUIRED')
        wct = service.execute(ActionRequest('wait_chains', target, {
            'tid': fixture.ready['ui_tid'],
            'thread_created_100ns': fixture.ready['ui_thread_created_100ns']}, False, 15))
        require(wct['status'] in ('COMPLETED', 'INCOMPLETE_EVIDENCE'), 'WAVE02_ACTUAL_WCT_ACTION_FAILED')
        rows = wct.get('data', {}).get('rows', [])
        proof['wait_observation'] = {'ui_timeout': ui_timeout, 'wct_status': wct['status'],
            'wct_error': wct.get('error'), 'rows': rows}
        owners = [node for row in rows for node in row.get('nodes', [])
                  if node.get('pid') == target.pid and node.get('tid') == fixture.ready['control_tid']]
        require(owners, 'WAVE02_WCT_DID_NOT_OBSERVE_ACTUAL_MUTEX_OWNER')
        fixture.send('release'); resumed = fixture.receive('freeze_done')
        require(resumed['wait_result'] == 0 and resumed['end_qpc'] >= frozen['qpc'],
                'WAVE02_ACTUAL_MUTEX_WAIT_AND_RELEASE_NOT_CONFIRMED')
        require(window_probe(fixture.ready)['responsive'] is True, 'WAVE02_OWNED_UI_DID_NOT_RECOVER')
        phase('ACTUAL_FILE_ERROR_AND_POSITIVE_ORACLES')
        file_done = fixture.command('file', 'file_done')
        require(file_done['ok'] and file_done['acl_restored'], 'WAVE02_ACTUAL_FILE_ORACLES_OR_ACL_RESTORE_FAILED')
        app_source = output / 'application-events.jsonl'
        file_oracles = oracle_events(fixture, app_source)
        require({q['role']: q['winerror'] for q in file_oracles} ==
                {'sharing_violation': 32, 'access_denied': 5, 'positive_read_write': 0},
                'WAVE02_ACTUAL_FILE_ERRORS_DIFFER_FROM_EXPECTED_FIXTURE')
        fixture_pid, fixture_ready = fixture.ready['pid'], dict(fixture.ready)
        phase('CONFIRMED_OWNED_FIXTURE_CAPTURE_AND_HELPER_EXIT')
        proof['target_cleanup'] = fixture.close(); fixture = None
        captured = capture.stop(); proof['capture_stop'] = captured
        require(captured.get('status') == 'CAPTURED' and not capture.active,
                'WAVE02_OWNED_NAMED_CAPTURE_STOP_NOT_CONFIRMED')
        trace = capture_root / captured['path']; capture = None
        require(0 < trace.stat().st_size <= 256 * 1024**2, 'WAVE02_ACTUAL_TRACE_SIZE_BUDGET')
        journal = service.journal.path
        live = service.session_status(refresh=True)
        require(live['helper_identity'] == helper_identity and
                abs(live['session_deadline_monotonic'] - deadline) < .001 and len(launches) == 1,
                'WAVE02_HELPER_ORIGINAL_LEASE_WAS_REPLACED_OR_RENEWED')
        proof['helper_cleanup'] = service.end_admin_session()
        require(proof['helper_cleanup']['status'] == 'COMPLETED', 'WAVE02_R10_CLEANUP_UNCONFIRMED')
        service.close(); service = None
        for path in (trace, journal, app_source): sources_before[str(path)] = file_hash(path)
        index = output / 'trace.sqlite3'
        phase('REAL_ETL_DECODE_AND_RUN_RECEIPT')
        decoded = decode_file(trace, index, timeout=180)
        proof['decode_result'] = {key: decoded.get(key) for key in ('status', 'rows', 'bounded_events',
            'events_with_errors', 'events_without_fields_or_schema', 'decoder_reported_lost_events',
            'import_completeness', 'input_sha256')}
        require(decoded['status'] == 'DECODED', 'WAVE02_ACTUAL_TRACE_IMPORT_INCOMPLETE')
        receipt = decoded.get('run_receipt', {})
        require(receipt.get('contract_version') == 1 and receipt.get('operation') == 'decoder.decode'
                and receipt.get('status') == decoded['status'] and receipt.get('cleanup', {}).get('confirmed') is True
                and receipt.get('coverage', {}).get('completeness') != 'COMPLETE',
                'WAVE02_DECODER_ACTUAL_RECEIPT_OR_CLEANUP_MISSING')
        sources_before[str(index)] = file_hash(index)
        sources = [trace_source(index, fixture_pid), {'source_type': 'DEEP_JOURNAL', 'path': str(journal)},
                   {'source_type': 'EVENTS_JSONL', 'path': str(app_source)}]
        phase('INVESTIGATION_PROVENANCE_ATOMIC_EXPORT_AND_READBACK')
        case = create_investigation(sources, target_identity=target.to_dict(),
            scenario={'scenario': 'BB-WAVE-02-OWNED-MUTEX-AND-FILE'},
            app_identity={'application_id': 'BLACKBOX_OWNED_WAVE02', 'version': '1',
                          'image_sha256': file_hash(executable)},
            budget={'timeout_seconds': 120}, index_path=output / 'case.sqlite3')
        verify_case(case)
        proof['exports'] = export_case(case, output)
        phase('REAL_CANCELLATION_CORRUPT_IMPORT_AND_WRITER_FAILURE')
        cancelled = threading.Event(); cancelled.set()
        cancelled_path = output / 'must-not-cancel.sqlite3'
        try:
            decode_file(trace, cancelled_path, cancel=cancelled)
        except InterruptedError as error:
            require(getattr(error, 'run_receipt', {}).get('status') == 'CANCELLED',
                    'WAVE02_CANCEL_FAILURE_RECEIPT_MISSING')
        else:
            raise AssertionError('WAVE02_CANCELLED_IMPORT_DID_NOT_CANCEL')
        require(not cancelled_path.exists(), 'WAVE02_CANCELLED_IMPORT_PUBLISHED_INDEX')
        corrupt = output / 'damaged.jsonl'; corrupt.write_bytes(b'{"unterminated":')
        corrupt_hash = file_hash(corrupt); broken_path = output / 'must-not-corrupt.sqlite3'
        try:
            decode_file(corrupt, broken_path)
        except ValueError as error:
            require(getattr(error, 'run_receipt', {}).get('status') == 'OPERATION_FAILED',
                    'WAVE02_CORRUPT_IMPORT_FAILURE_RECEIPT_MISSING')
        else:
            raise AssertionError('WAVE02_CORRUPT_IMPORT_WAS_ACCEPTED')
        require(not broken_path.exists() and file_hash(corrupt) == corrupt_hash,
                'WAVE02_CORRUPT_SOURCE_OR_PARTIAL_DESTINATION_CHANGED')
        proof['writer_fault'] = writer_failure(output, target)
        require(all(file_hash(Path(path)) == before for path, before in sources_before.items()),
                'WAVE02_USER_SOURCE_CHANGED_BY_ANALYSIS_OR_EXPORT')
        proof['container_results']['R20'] = {'status': 'PASS', 'case_id': case['case_id'],
            'source_count': len(case['sources']), 'source_hashes_unchanged': True,
            'trace_sha256': file_hash(trace), 'trace_bytes': trace.stat().st_size,
            'index_sha256': file_hash(index), 'rows': decoded['rows'],
            'decoder_receipt': receipt, 'investigation_receipt': case['run_receipt'],
            'coverage': case['coverage'], 'helper_identity': helper_identity,
            'independent_token': token, 'runas_count': len(launches),
            'fixture': fixture_ready, 'wct_owner': owners, 'ui_timeout': ui_timeout,
            'file_oracles': file_oracles, 'cancelled_no_publication': True,
            'corrupt_no_publication': True}
        proof['container_results']['R20']['source_ids'] = [q['source_id'] for q in case['sources']]
        proof['container_results']['R20']['source_sizes'] = [q['source_size_bytes'] for q in case['sources']]
        # Later stages are explicit requirements of their own tracked scope.
        # Missing modules or failed assertions fail the job; they are never skipped.
        if 'R30' in scope['required_containers']:
            from tools.qa_wave02_r30 import check_r30
            proof['container_results']['R30'] = check_r30(case, index, fixture_ready, file_oracles, output)
        if 'R40' in scope['required_containers']:
            from tools.qa_wave02_r40 import check_r40
            proof['container_results']['R40'] = check_r40(executable, output, args)
        if 'R50' in scope['required_containers']:
            from tools.qa_wave02_r50 import check_r50
            proof['container_results']['R50'] = check_r50(executable, output, args)
            from tools.qa_wave02_combined import check_combined
            proof['combined_e2e'] = check_combined(sources=sources, individual_case=case,
                container_results=proof['container_results'], output=output,
                source_sha=args.source_sha, original_trace=trace,
                producer_cleanup={'target': proof['target_cleanup'], 'helper': proof['helper_cleanup'],
                                  'capture': proof['capture_stop']})
            require(proof['combined_e2e'].get('status') == 'PASS',
                    'WAVE02_COMBINED_E2E_MUST_PASS')
        require(set(proof['container_results']) == set(scope['required_containers']) and
                all(q.get('status') == 'PASS' for q in proof['container_results'].values()),
                'WAVE02_REQUIRED_CONTAINER_NOT_PASSED')
        save(output / 'sources.json', {'source_sha': args.source_sha, 'scope': scope,
            'case_index': str(output / 'case.sqlite3'), 'sources': sources,
            'trace': str(trace), 'index': str(index), 'fixture': fixture_ready,
            'fixture_executable': str(executable), 'fixture_executable_sha256': file_hash(executable)})
        proof['status'] = 'PASS'; successful = True
    except BaseException as error:
        proof.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2000],
                     traceback=traceback.format_exc(limit=12))
        raise
    finally:
        cleanup_errors = []
        for label, owner in (('service', service), ('fixture', fixture), ('capture', capture)):
            if owner is None: continue
            try:
                if label == 'capture' and owner.active: owner.cancel()
                elif label == 'fixture': proof['failure_fixture_cleanup'] = owner.close(kill=not successful)
                elif label == 'service': proof['failure_helper_cleanup'] = owner.close()
            except BaseException as error:
                cleanup_errors.append({'owner': label, 'type': type(error).__name__, 'reason': str(error)[:700]})
        if cleanup_errors: proof.update(status='FAIL', cleanup_errors=cleanup_errors)
        save(output / 'wave02-native.json', proof)
        r20 = proof['container_results'].get('R20', {})
        print('WAVE02_NATIVE_RECEIPT ' + json.dumps({'status': proof['status'],
            'source_sha': args.source_sha, 'scope': scope,
            'phase': proof.get('phase'), 'decode_result': proof.get('decode_result'),
            'wait_observation': proof.get('wait_observation') if proof['status'] != 'PASS' else None,
            'container_statuses': {k: v.get('status') for k, v in proof['container_results'].items()},
            'r20': {key: r20.get(key) for key in ('case_id', 'source_count', 'source_ids',
                'source_sizes', 'source_hashes_unchanged', 'trace_sha256', 'trace_bytes',
                'index_sha256', 'rows', 'helper_identity', 'independent_token', 'runas_count',
                'cancelled_no_publication', 'corrupt_no_publication')},
            'exports': proof.get('exports'),
            'writer_fault': proof.get('writer_fault'),
            'combined_e2e': (proof.get('combined_e2e') or {}).get('public_receipt'),
            'receipt_sha256': file_hash(output / 'wave02-native.json'),
            'receipt_bytes': (output / 'wave02-native.json').stat().st_size,
            'error': proof.get('error'), 'reason': proof.get('reason'),
            'cleanup_errors': cleanup_errors}, sort_keys=True), flush=True)
        if cleanup_errors:
            raise RuntimeError('WAVE02_OWNED_CLEANUP_NOT_CONFIRMED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--decoder', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--diagnostic-helper', type=Path)
    parser.add_argument('--container', choices=('r20', 'r30', 'r40', 'full'))
    run(parser.parse_args())


if __name__ == '__main__':
    main()
