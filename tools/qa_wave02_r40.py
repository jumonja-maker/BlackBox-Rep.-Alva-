"""Owned real access violation, minidump/AMD64/PDB and negative R40 controls."""
from contextlib import closing
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import re
import struct
import threading
import time


def independent_exception(path):
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(32)
        signature, version, count, directory, _checksum, _stamp, _flags = struct.unpack('<6IQ', header)
        if signature != 0x504D444D or version & 0xffff != 0xA793 or not 0 < count <= 4096:
            raise AssertionError('R40_ORACLE_MINIDUMP_HEADER_INVALID')
        if not 32 <= directory <= size - count * 12:
            raise AssertionError('R40_ORACLE_MINIDUMP_DIRECTORY_INVALID')
        stream.seek(directory)
        entries = [struct.unpack('<III', stream.read(12)) for _ in range(count)]
        matches = [(length, offset) for kind, length, offset in entries if kind == 6]
        if len(matches) != 1 or matches[0][0] < 168 or matches[0][1] > size - matches[0][0]:
            raise AssertionError('R40_ORACLE_EXCEPTION_STREAM_REQUIRED')
        stream.seek(matches[0][1]); data = stream.read(168)
        return {'tid': struct.unpack_from('<I', data, 0)[0],
            'code': struct.unpack_from('<I', data, 8)[0],
            'address': struct.unpack_from('<Q', data, 24)[0],
            'stream_types': sorted(kind for kind, _, _ in entries)}


def private_marker_present(path):
    marker = b'BLACKBOX_WAVE02_DUMP_PRIVATE_CONTENT'
    tail = b''
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            if marker in tail + chunk: return True
            tail = chunk[-len(marker):]
    return False


def check_r40(executable, output, args):
    from blackbox_core.crash_events import query
    from blackbox_core.crash_investigation import project_crash_evidence
    from blackbox_core.deep_dump import inspect_dump
    from blackbox_core.investigation_v3 import create_investigation
    from tools.qa_wave02_fixture import WaveProbe
    from tools.qa_wave02 import export_case, verify_case
    from tools.qa_deep_inspection import require, file_hash, save
    output, executable = Path(output), Path(executable)
    folder = output / 'R40'; folder.mkdir()
    crashed = normal = None
    ok = False
    proof = {'status': 'RUNNING', 'scenario': 'ACTUAL_OWNED_ACCESS_VIOLATION_AND_NORMAL_EXIT',
             'physical_windows_10_11': 'NOT_TESTED', 'root_cause': 'UNKNOWN'}
    try:
        normal = WaveProbe(executable, folder / 'normal-target')
        normal_ready = normal.ready
        normal_cleanup = normal.close(); normal = None
        require(normal_cleanup['status'] == 'COMPLETED' and
                not (folder / 'normal-target/private-crash.dmp').exists(),
                'R40_NORMAL_EXIT_CREATED_CRASH_DUMP_OR_DID_NOT_EXIT')
        crashed = WaveProbe(executable, folder / 'crash-target')
        ready = dict(crashed.ready)
        require(ready['wer_policy'] in
                {'PER_PROCESS_NO_UI_NO_HEAP_NO_QUEUE_UPLOAD_REQUEST','FIXTURE_WER_SUPPRESSED'}
                and type(ready['wer_flags_hresult']) is int,
                'R40_ACTUAL_PROCESS_LOCAL_WER_CONFIGURATION_NOT_RECORDED')
        crashed.send('crash')
        oracle = crashed.receive('crash_dump', timeout=25)
        crashed.process.wait(timeout=30)
        require(oracle['dump_written'] and oracle['pid'] == ready['pid'] and
                oracle['created_100ns'] == ready['created_100ns'] and
                oracle['tid'] == ready['control_tid'] and oracle['exception_code'] == 0xC0000005,
                'R40_OWNED_NATIVE_AV_OR_DUMP_NOT_CONFIRMED')
        dump = crashed.dump
        proof['crash_cleanup'] = crashed.close(); crashed = None
        require(proof['crash_cleanup']['status'] == 'OWNED_CRASH_EXIT_VERIFIED',
                'R40_NATURAL_CRASH_EXIT_NOT_CONFIRMED')
        require(32 <= dump.stat().st_size <= 128 * 1024**2 and private_marker_present(dump),
                'R40_REAL_PRIVATE_DUMP_OR_CAPTURED_STACK_SENTINEL_MISSING')
        dump_hash = file_hash(dump)
        independent = independent_exception(dump)
        require(independent['tid'] == oracle['tid'] and independent['code'] == oracle['exception_code']
                and independent['address'] == oracle['exception_address'],
                'R40_PRODUCT_DUMP_METADATA_MUST_MATCH_INDEPENDENT_STREAM_ORACLE')
        pdb = executable.with_suffix('.pdb')
        require(pdb.is_file(), 'R40_OWNED_COMPILER_PDB_REQUIRED')
        metadata = inspect_dump(dump, image_path=executable, pdb_path=pdb, max_frames=32)
        data = metadata['data']; exception = data['exception']
        require(data['sha256'] == dump_hash and data['size_bytes'] == dump.stat().st_size
                and data['architecture'] == 'AMD64' and exception['tid'] == independent['tid']
                and exception['code'] == independent['code'] and exception['address'] == independent['address']
                and data['memory_contents_included'] is False and data['live_process_binding'] == 'NOT_ESTABLISHED',
                'R40_PRODUCT_EXCEPTION_HASH_PRIVACY_OR_BINDING_CHANGED')
        thread = next(q for q in data['stack_unwind']['threads'] if q['tid'] == ready['control_tid'])
        own = [q for q in thread['frames'] if q['module_binding'] == 'SAVED_RSDS_AND_PINNED_LOCAL_PE_MATCH']
        def fixed_code(value):
            if value is None:return None
            return value if type(value) is str and re.fullmatch(r'[A-Z0-9_]{1,160}',value) else 'NON_CODE_VALUE_WITHHELD'
        preview=[]
        for frame in thread['frames'][:8]:
            symbol=frame.get('symbol') or {}
            pc=frame.get('address')
            recorded_module=type(pc) is int and any(
                type(module.get('base_address')) is int and type(module.get('image_size')) is int and
                0<=module['base_address']<2**64 and 0<module['image_size']<=2**64-module['base_address'] and
                module['base_address']<=pc<module['base_address']+module['image_size']
                for module in data['modules'])
            role=('SELECTED_MATCHED_IMAGE' if frame.get('module_binding')=='SAVED_RSDS_AND_PINNED_LOCAL_PE_MATCH'
                else 'OTHER_RECORDED_DUMP_MODULE' if recorded_module else 'OUTSIDE_RECORDED_MODULES')
            preview.append({'origin':fixed_code(frame.get('origin')),
                'recorded_module_role':role,
                'module_binding':fixed_code(frame.get('module_binding')),
                'symbol_status':fixed_code(symbol.get('status')),
                'source_status':fixed_code(symbol.get('source_status')),
                'expected_function':next((name for name in
                    ('wave_crash_leaf','wave_crash_middle','wave_crash_entry')
                    if type(symbol.get('name')) is str and name in symbol['name']),None)})
        from blackbox_core import deep_native_win as native_win
        selected_metadata=next(q for q in data['threads'] if q['tid']==ready['control_tid'])
        image_metadata=thread.get('local_image_metadata') or {}
        image_hash=image_metadata.get('sha256')
        print('WAVE02_R40_UNWIND_DIAGNOSTICS '+json.dumps({
            'scope':'BOUNDED_STATUS_COUNTS_ONLY_NO_ADDRESSES_MEMORY_PATHS_OR_DUMP_BYTES',
            'inspection_status':fixed_code(metadata.get('status')),
            'unwind_status':fixed_code(data.get('stack_unwind_status')),
            'saved_thread_count':len(data['stack_unwind']['threads']),
            'exception_context_bytes_recorded':exception.get('context_bytes_recorded'),
            'required_amd64_context_bytes':C.sizeof(native_win.CONTEXT64),
            'exception_context_status':fixed_code(exception.get('context',{}).get('status')),
            'selected_context_status':fixed_code(selected_metadata.get('context',{}).get('status')),
            'selected_stack_bytes_recorded':selected_metadata.get('stack_bytes_recorded'),
            'first_frame_matches_recorded_exception_pc':bool(thread['frames']) and
                thread['frames'][0].get('address')==exception['address'],
            'selected_thread':{key:fixed_code(thread.get(key)) for key in
                ('status','method','context_source','reason','captured_memory_stop_reason')},
            'native_unwind_facts':{key:thread.get(key) if type(thread.get(key)) is bool else None
                for key in ('symbol_handler_callback_registered','function_table_for_context_available',
                            'dbghelp_module_base_matches_selected_image')},
            'memory_read_contract':fixed_code(thread.get('memory_read_contract')),
            'unwind_read_counters':{key:value if type(value) is int and 0<=value<2**63 else None
                for key in ('stackwalk_requests','symbol_handler_requests','successful_reads','failed_reads','copied_bytes',
                            'captured_memory_reads','local_image_metadata_reads','local_image_metadata_bytes')
                for value in [(thread.get('unwind_read_counters') or {}).get(key)]},
            'typed_local_image_metadata':{
                'source':fixed_code(image_metadata.get('source')),'scope':fixed_code(image_metadata.get('scope')),
                'sha256':image_hash if type(image_hash) is str and re.fullmatch(r'[0-9a-f]{64}',image_hash) else None,
                'runtime_function_count':image_metadata.get('runtime_function_count')
                    if type(image_metadata.get('runtime_function_count')) is int and
                        0<=image_metadata['runtime_function_count']<2**63 else None,
                'unwind_info_count':image_metadata.get('unwind_info_count')
                    if type(image_metadata.get('unwind_info_count')) is int and
                        0<=image_metadata['unwind_info_count']<2**63 else None,
                'memory_contents_included':image_metadata.get('memory_contents_included')
                    if type(image_metadata.get('memory_contents_included')) is bool else None},
            'failed_read_classes':{key:value if type(value) is int and 0<=value<2**63 else None
                for key in ('OUTSIDE_SELECTED_IMAGE_OR_INVALID_SIZE','AMBIGUOUS_METADATA_RANGE',
                            'IMAGE_GAP_OR_METADATA_CROSSING','WRITABLE_IMAGE_DATA',
                            'EXECUTABLE_IMAGE_CODE','READONLY_IMAGE_BYTES_OUTSIDE_TYPED_METADATA')
                for value in [(thread.get('failed_read_classes') or {}).get(key)]},
            'unwind_winerror':thread.get('unwind_winerror') if type(thread.get('unwind_winerror')) is int else None,
            'recorded_frame_count':len(thread['frames']),'matched_own_frame_count':len(own),
            'matched_unwound_callers':sum(q['origin']=='DBGHELP_UNWOUND_CALLER' for q in own),
            'frame_preview':preview,
            'offline_cleanup_confirmed':data.get('stack_unwind',{}).get('cleanup',{}).get('confirmed') is True
            },sort_keys=True),flush=True)
        require(len(own) >= 3 and sum(q['origin'] == 'DBGHELP_UNWOUND_CALLER' for q in own) >= 2,
                'R40_ACTUAL_OWNED_AMD64_CALL_CHAIN_NOT_UNWOUND')
        counters=thread['unwind_read_counters']
        require(image_metadata.get('source')=='LOCAL_PINNED_PE_UNWIND_METADATA' and
                image_metadata.get('scope')=='FILE_BACKED_HEADERS_RUNTIME_FUNCTION_AND_UNWIND_INFO_ONLY' and
                image_hash==file_hash(executable) and image_metadata.get('memory_contents_included') is False and
                image_metadata.get('runtime_function_count',0)>0 and image_metadata.get('unwind_info_count',0)>0,
                'R40_TYPED_LOCAL_UNWIND_METADATA_NOT_BOUND_TO_SELECTED_IMAGE')
        require(counters['captured_memory_reads']>0 and counters['local_image_metadata_reads']>0 and
                0<counters['local_image_metadata_bytes']<=counters['copied_bytes'] and
                counters['captured_memory_reads']+counters['local_image_metadata_reads']==counters['successful_reads'],
                'R40_CAPTURED_STACK_AND_TYPED_PE_METADATA_READ_COUNTS_NOT_CONFIRMED')
        names = {q.get('symbol', {}).get('name') for q in own}
        require(all(any(value and name in value for value in names) for name in
                    ('wave_crash_leaf', 'wave_crash_middle', 'wave_crash_entry')),
                'R40_MATCHED_OWN_PDB_CALLERS_REQUIRED')
        require(any(q.get('symbol', {}).get('source_status') == 'LOCAL_PDB_C13_LINE' for q in own),
                'R40_ACTUAL_MATCHED_PDB_SOURCE_LINE_REQUIRED')
        no_symbols = inspect_dump(dump, image_path=executable)
        require(all('symbol' not in q for row in no_symbols['data']['stack_unwind']['threads']
                    for q in row['frames']), 'R40_MISSING_SYMBOLS_WERE_INVENTED')
        cancelled = threading.Event(); cancelled.set()
        try: inspect_dump(dump, cancel_event=cancelled)
        except InterruptedError: pass
        else: raise AssertionError('R40_CANCELLED_DUMP_INSPECTION_DID_NOT_CANCEL')
        try: inspect_dump(dump, deadline=time.monotonic() - 1)
        except TimeoutError: pass
        else: raise AssertionError('R40_EXPIRED_DUMP_INSPECTION_DID_NOT_TIME_OUT')
        bad = folder / 'damaged.dmp'
        with dump.open('rb') as stream: bad.write_bytes(stream.read(32))
        try: inspect_dump(bad)
        except ValueError: pass
        else: raise AssertionError('R40_DAMAGED_DUMP_ACCEPTED')
        try: inspect_dump(dump, max_bytes=32)
        except ValueError: pass
        else: raise AssertionError('R40_EXCEEDED_DUMP_SIZE_POLICY_ACCEPTED')
        kernel=C.WinDLL('kernel32',use_last_error=True,winmode=0x800)
        kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
        kernel.CreateFileW.restype=W.HANDLE
        kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
        held=kernel.CreateFileW(str(dump),0x80000000,0,None,3,0x80,None)
        require(held and held!=C.c_void_p(-1).value,'R40_OWNED_EXCLUSIVE_DUMP_CONTROL_NOT_OPENED')
        try:
            try:inspect_dump(dump)
            except OSError as error:
                denied_error=getattr(error,'winerror',None)
                require(denied_error in (5,32),'R40_EXCLUSIVE_DUMP_DID_NOT_REPORT_ACTUAL_ACCESS_ERROR')
            else:raise AssertionError('R40_EXCLUSIVELY_LOCKED_DUMP_WAS_READ')
        finally:
            require(kernel.CloseHandle(held),'R40_EXCLUSIVE_DUMP_CONTROL_HANDLE_NOT_CLOSED')
        require(file_hash(dump)==dump_hash,'R40_DENIAL_CONTROL_CHANGED_PRIVATE_SOURCE')
        created = (ready['created_100ns'] - 116444736000000000) / 10000000
        events = query(ready['pid'], created, expected_created_100ns=ready['created_100ns'],
                       image_name=executable.name, deadline=time.monotonic() + 5)
        normal_created = (normal_ready['created_100ns'] - 116444736000000000) / 10000000
        normal_events = query(normal_ready['pid'],normal_created,
            expected_created_100ns=normal_ready['created_100ns'],image_name=executable.name,
            deadline=time.monotonic()+5)
        wrong_birth = query(ready['pid'],created,
            expected_created_100ns=ready['created_100ns']+1,image_name=executable.name,
            deadline=time.monotonic()+5)
        require(not any(q.get('process_instance_binding')=='MATCHED_RECORDED_CREATION_FILETIME'
                        for result in (normal_events,wrong_birth) for q in result['events']),
                'R40_NORMAL_EXIT_OR_WRONG_FILETIME_BECAME_CONFIRMED_TARGET_CRASH')
        require(all(q.get('target_pid') == ready['pid'] for q in events['events']),
                'R40_LOGGER_PID_WAS_CONFUSED_WITH_FAULTING_TARGET')
        for event in events['events']:
            require(event.get('root_cause') == 'UNKNOWN', 'R40_EVENTLOG_INVENTED_INTERNAL_ROOT_CAUSE')
        source = {'source_type': 'DUMP_METADATA', 'path': str(dump),
                  'image_path': str(executable), 'pdb_path': str(pdb)}
        sources = [source]
        if events['events'] or events.get('wer_candidates'):
            path = folder / 'queried-windows-events.jsonl'
            row = {'schema_version': 1, 'token': 'BLACKBOX_WAVE02_QUERIED_EVENTLOG',
                'pid': ready['pid'], 'tid': ready['control_tid'], 'seq': 1,
                'source_clock': 'QUERY_RECEIPT_TIME_NOT_EVENTLOG_EVENT_TIME',
                'source_ns': time.perf_counter_ns(), 'kind': 'crash.system_events',
                'operation_id': 'owned-eventlog-query', 'parent_id': None, 'client_dropped': 0,
                'attributes': events}
            path.write_text(json.dumps(row) + '\n', encoding='utf-8')
            sources.append({'source_type': 'EVENTS_JSONL', 'path': str(path)})
        case = create_investigation(sources, budget={'timeout_seconds': 120},
                                    index_path=folder / 'case.sqlite3')
        verify_case(case)
        projected = project_crash_evidence(case)
        require(case['crash_investigation']==projected and
                case['run_receipt']['cleanup']['confirmed'] is True and
                case['run_receipt']['cleanup']['scope']=='NORMALIZATION_SOURCE_READ_HANDLES_AND_OFFLINE_UNWIND',
                'R40_GRAPH_PROJECTION_OR_ACTUAL_OFFLINE_CLEANUP_RECEIPT_MISSING')
        compound=next(q for q in case['sources'] if q['source_type']=='DUMP_METADATA')
        roles={q['role']:q['sha256'] for q in compound['content_manifest']}
        require(roles=={'minidump':dump_hash,'local_image':file_hash(executable),'local_pdb':file_hash(pdb)},
                'R40_EXPLICIT_LOCAL_IMAGE_OR_PDB_NOT_BOUND_IN_COMPOUND_SOURCE')
        require(projected['summary']['recorded_exceptions'] == 1 and
                projected['summary']['unwound_callers'] >= 2 and projected['root_cause'] == 'UNKNOWN'
                and not projected['privacy']['memory_contents_included']
                and not projected['privacy']['dump_bytes_included'],
                'R40_REAL_GRAPH_EXCEPTION_STACK_OR_PRIVACY_LOST')
        exports = export_case(case, folder)
        require(file_hash(dump) == dump_hash, 'R40_DUMP_CHANGED_BY_INSPECTION_OR_EXPORT')
        proof.update(status='PASS', case_index=str(folder / 'case.sqlite3'),
            private_dump_path=str(dump),local_image_path=str(executable),local_pdb_path=str(pdb),
            case_id=case['case_id'], target=ready, native_crash_oracle=oracle,
            independent_exception=independent, dump_bytes=dump.stat().st_size,
            dump_sha256=dump_hash, private_marker_present_in_private_dump=True,
            own_frame_count=len(own), own_function_names=sorted(q for q in names if q),
            pdb_source_line_observed=True, local_image_sha256=file_hash(executable),
            local_pdb_sha256=file_hash(pdb), normal_exit_control=normal_cleanup,
            eventlog_status=events['status'], matched_event_count=len(events['events']),
            wer_candidate_count=len(events.get('wer_candidates', [])),
            eventlog_limitations=events['limitations'], public_exports=exports,
            wer_fixture_policy=ready['wer_policy'],wer_flags_hresult=ready['wer_flags_hresult'],
            normal_exit_eventlog_status=normal_events['status'],
            wrong_birth_eventlog_status=wrong_birth['status'],
            actual_dump_read_denial_winerror=denied_error,
            missing_symbols='NO_SYMBOL_NAME_INVENTED', dump_source_unchanged=True,
            negative_controls=['CANCELLED', 'TIMED_OUT', 'CORRUPT_INPUT', 'SIZE_BUDGET', 'NORMAL_EXIT',
                               'ACTUAL_OWNED_EXCLUSIVE_DUMP_READ_DENIAL'])
        print('WAVE02_R40_NATIVE_FACTS '+json.dumps({key:proof[key] for key in
            ('status','case_id','dump_bytes','dump_sha256','private_marker_present_in_private_dump',
             'own_frame_count','own_function_names','pdb_source_line_observed','local_image_sha256',
             'local_pdb_sha256','eventlog_status','matched_event_count','wer_candidate_count',
             'wer_fixture_policy','wer_flags_hresult','normal_exit_eventlog_status',
             'wrong_birth_eventlog_status','actual_dump_read_denial_winerror','dump_source_unchanged',
             'negative_controls','public_exports')},
            sort_keys=True),flush=True)
        ok = True
        return proof
    finally:
        for owner in (crashed, normal):
            if owner is not None: owner.close(kill=not ok)
        save(folder / 'crash-qa.json', proof)
