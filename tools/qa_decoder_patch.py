"""Native PE/PDB and optional real Windows WPR acceptance. No publication.

Linux validates real compiled symbol ranges against a linker map, combined
with EXPLICITLY SYNTHETIC trace metadata. --helper additionally requires an
owned native process/WPR roundtrip on a disposable Windows CI runner.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'src')]
from blackbox_core.decoder_native_symbols import load_native_symbols, resolve_event_stack
from blackbox_core.decoder_calltree import build_calltree, export_analysis
from blackbox_core.decoder_index import file_hash, read_index
from tools.qa_decoder_apps import observe_native_output, native_output_path, observed_module_encoding, _qa_code, owned_process_identity


def require(value, reason):
    if not value:
        raise AssertionError(reason)


NATIVE_QA_CAPTURE_SECONDS = 2


def require_complete_native_etl(meta, actual_input_sha256):
    """A partial prefix must never satisfy real Windows-native release acceptance."""
    require(type(meta) is dict, 'NATIVE_ETL_RESULT_MISSING')
    require(meta.get('status') == 'DECODED' and
            meta.get('import_completeness') == 'ALL_EMITTED_RECORDS',
            'NATIVE_ETL_DECODE_FAILED')
    require(meta.get('input_sha256') == actual_input_sha256,
            'NATIVE_ETL_SOURCE_HASH_MISMATCH')
    require(meta.get('decoder_reported_lost_events') == 0,
            'NATIVE_ETL_DECODER_REPORTED_LOST_EVENTS')


def strict_typed_event(text):
    """Independent stdlib comparison: key order ignored, scalar types retained."""
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'NATIVE_REFERENCE_DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    def constant(_value):
        raise AssertionError('NATIVE_REFERENCE_NONFINITE_JSON')
    require(len(text.encode('utf-8')) <= 6 * 262144, 'NATIVE_REFERENCE_RECORD_BUDGET')
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    nodes = [0]
    def canonical(item, depth=0):
        nodes[0] += 1
        require(depth <= 32 and nodes[0] <= 20000, 'NATIVE_REFERENCE_JSON_SHAPE_BUDGET')
        if item is None: return ('null',)
        if type(item) is bool: return ('bool', item)
        if type(item) is int: return ('int', item)
        if type(item) is float:
            require(math.isfinite(item), 'NATIVE_REFERENCE_NONFINITE_JSON')
            return ('float', item.hex())
        if type(item) is str: return ('string', item)
        if type(item) is list: return ('list', tuple(canonical(part, depth + 1) for part in item))
        require(type(item) is dict, 'NATIVE_REFERENCE_JSON_TYPE')
        return ('object', tuple((key, canonical(item[key], depth + 1)) for key in sorted(item)))
    require(type(value) is dict, 'NATIVE_REFERENCE_EVENT_TYPE')
    return value, canonical(value)


def compare_native_prefix(compact_index, legacy_index, compact_meta, legacy_meta, digest, *, seconds=180):
    """Legacy is only a reference prefix; it can never rescue primary TRUNCATED."""
    require_complete_native_etl(compact_meta, digest)
    require(legacy_meta.get('status') in ('DECODED', 'TRUNCATED') and
        legacy_meta.get('input_sha256') == digest and legacy_meta.get('decoder_reported_lost_events') == 0 and
        legacy_meta.get('import_completeness') ==
        ('BOUNDED_PREFIX' if legacy_meta['status'] == 'TRUNCATED' else 'ALL_EMITTED_RECORDS'),
        'NATIVE_LEGACY_REFERENCE_METADATA_UNCONFIRMED')
    deadline = time.monotonic() + seconds
    before = [file_hash(path) for path in (compact_index, legacy_index)]
    with closing(sqlite3.connect(compact_index.resolve().as_uri() + '?mode=ro', uri=True)) as first, \
            closing(sqlite3.connect(legacy_index.resolve().as_uri() + '?mode=ro', uri=True)) as second:
        for db in (first, second):
            db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
            require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'NATIVE_REFERENCE_INDEX_INTEGRITY')
        counts = [db.execute('SELECT count(*) FROM events').fetchone()[0] for db in (first, second)]
        require(counts == [compact_meta['rows'], legacy_meta['rows']] and 0 < counts[1] <= counts[0],
                'NATIVE_REFERENCE_ROW_COUNTS')
        require(legacy_meta['status'] != 'DECODED' or counts[0] == counts[1],
                'NATIVE_FULL_REFERENCE_ROW_COUNTS_DIFFER')
        compact_rows = first.execute('SELECT id,data FROM events ORDER BY id')
        matched = 0
        for legacy_id, legacy_data in second.execute('SELECT id,data FROM events ORDER BY id'):
            require(time.monotonic() < deadline, 'NATIVE_REFERENCE_COMPARE_DEADLINE')
            row = compact_rows.fetchone()
            require(row is not None and row[0] == legacy_id, 'NATIVE_REFERENCE_ORDINAL_MISMATCH')
            compact, compact_value = strict_typed_event(row[1]); legacy, legacy_value = strict_typed_event(legacy_data)
            require(compact.get('ordinal') == legacy.get('ordinal') == legacy_id and
                type(compact.get('source_index')) is str and compact['source_index'] == legacy.get('source_index'),
                'NATIVE_REFERENCE_SOURCE_INDEX_MISMATCH')
            require(compact_value == legacy_value, 'NATIVE_REFERENCE_PUBLIC_EVENT_MISMATCH')
            matched += 1
    require([file_hash(path) for path in (compact_index, legacy_index)] == before,
            'NATIVE_REFERENCE_ANALYSIS_CHANGED_INDEX')
    return {'status': 'MATCHED_ALL_EMITTED_LEGACY_PREFIX_ROWS', 'matched_prefix_rows': matched,
        'compact_full_rows': counts[0], 'legacy_rows': counts[1], 'legacy_status': legacy_meta['status'],
        'comparison_scope': 'ALL_ROWS_FULL_REFERENCE' if legacy_meta['status'] == 'DECODED' else 'EMITTED_LEGACY_PREFIX_ONLY',
        'legacy_unemitted_tail': 'NOT_COMPARED_NOT_CLAIMED', 'comparison': 'INDEPENDENT_STDLIB_STRICT_TYPED_JSON',
        'index_sha256': {'compact': before[0], 'legacy': before[1]}}


def native_index_diagnostics(index, fixture_pid, *, max_unique=4096, seconds=30):
    """Bounded derived counters, never an allocation of original native bytes."""
    require(type(max_unique) is int and 1 <= max_unique <= 4096, 'NATIVE_DIAGNOSTIC_DISTINCT_BUDGET')
    deadline = time.monotonic() + seconds
    def group():
        return {'rows': 0, 'stacked_rows': 0, 'frame_occurrences': 0, 'module_occurrences': 0,
            'derived_index_event_json_bytes': 0, 'derived_index_frame_json_bytes': 0,
            '_seen': {kind: set() for kind in ('frames', 'modules', 'stacks')}, '_capped': set()}
    groups = {name: group() for name in ('owned_native_fixture', 'other_processes', 'unattributed')}
    instances = set(); missing_instance = False; scanned = 0
    def signature(bucket, kind, value):
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
        fingerprint = hashlib.sha256(encoded).digest(); seen = bucket['_seen'][kind]
        if fingerprint not in seen:
            if len(seen) < max_unique: seen.add(fingerprint)
            else: bucket['_capped'].add(kind)
    with closing(sqlite3.connect(index.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        total = db.execute('SELECT count(*) FROM events').fetchone()[0]
        for data, in db.execute('SELECT data FROM events ORDER BY id'):
            if time.monotonic() >= deadline: break
            row = json.loads(data); pid = row.get('pid'); frames = row.get('frames') or []
            name = 'owned_native_fixture' if pid == fixture_pid else ('other_processes' if type(pid) is int and pid > 0 else 'unattributed')
            bucket = groups[name]; bucket['rows'] += 1; bucket['stacked_rows'] += bool(frames)
            bucket['frame_occurrences'] += len(frames)
            bucket['derived_index_event_json_bytes'] += len(data.encode('utf-8'))
            bucket['derived_index_frame_json_bytes'] += len(json.dumps(frames, ensure_ascii=True,
                separators=(',', ':'), allow_nan=False).encode('utf-8'))
            if pid == fixture_pid:
                instance = row.get('process_instance')
                if type(instance) is int and instance >= 0:
                    if len(instances) < 2: instances.add(instance)
                else: missing_instance = True
            if frames: signature(bucket, 'stacks', frames)
            for frame in frames:
                signature(bucket, 'frames', frame)
                if type(frame.get('module')) is dict:
                    bucket['module_occurrences'] += 1; signature(bucket, 'modules', frame['module'])
            scanned += 1
    ambiguous = missing_instance or len(instances) != 1
    if ambiguous:
        source = groups['owned_native_fixture']; target = groups['unattributed']
        for key, value in source.items():
            if not key.startswith('_'): target[key] += value
        for kind, seen in source['_seen'].items():
            for value in seen:
                if len(target['_seen'][kind]) < max_unique: target['_seen'][kind].add(value)
                elif value not in target['_seen'][kind]: target['_capped'].add(kind)
        target['_capped'].update(source['_capped']); groups['owned_native_fixture'] = group()
    for bucket in groups.values():
        seen = bucket.pop('_seen'); capped = bucket.pop('_capped')
        bucket['distinct_lower_bound'] = {kind: len(values) for kind, values in seen.items()}
        bucket['distinct_capped'] = sorted(capped)
    return {'status': 'COMPLETE' if scanned == total else 'BOUNDED_SCAN_PARTIAL', 'rows_scanned': scanned,
        'index_rows': total, 'groups': groups, 'fixture_process_instance_ambiguous': ambiguous,
        'distinct_cap_per_group_kind': max_unique,
        'scope': 'OWNED_PID_PLUS_SINGLE_TRACE_PROCESS_INDEX; NO_CAUSAL_CLAIM',
        'byte_scope': 'DERIVED_EXPANDED_INDEX_JSON_NOT_NATIVE_UTF8_DISTRIBUTION'}


def build_pair(output, *, busy=False):
    clang, linker = shutil.which('clang'), shutil.which('lld-link')
    require(clang and linker, 'NATIVE_QA_COMPILER_REQUIRED_NO_SYNTHETIC_SUBSTITUTE')
    source = ROOT/'tools/fixtures/NativeSymbolProbe/probe.c'
    obj, binary, symbols = output/'probe.obj', output/'probe.exe', output/'probe.pdb'
    options = ['-DBLACKBOX_QA_BUSY'] if busy else []
    subprocess.run([clang,'--target=x86_64-pc-windows-msvc','-g','-gcodeview','-O0',
                    *options,'-c',str(source),'-o',str(obj)], check=True, timeout=40)
    subprocess.run([linker,'/debug','/nodefaultlib','/entry:entry','/subsystem:console',
                    '/out:'+str(binary),'/pdb:'+str(symbols),'/map:'+str(output/'probe.map'),
                    str(obj)], check=True, timeout=40)
    return binary, symbols


def native_probe(output):
    binary,pdb = build_pair(output, busy=os.name=='nt')
    table = load_native_symbols(binary,pdb)
    linker_map = (output/'probe.map').read_text()
    required = {'blackbox_leaf','blackbox_parent','entry'}
    observed = {name for _,_,name in table.functions}
    require(required <= observed, 'REAL_PROCEDURE_NAMES_MISSING')
    for start,end,name in table.functions:
        require(name in linker_map and f'{0x140000000+start:016x}' in linker_map,
                'REAL_PDB_RANGE_DISAGREES_WITH_LINKER_MAP')
        require(table.lookup(start)['name']==name and table.lookup(end-1)['name']==name,
                'REAL_PROCEDURE_BOUNDS_UNREADABLE')
    start = next(a for a,b,n in table.functions if n=='blackbox_leaf')
    module = dict(schema='blackbox.trace-module/1',source='TRACEEVENT_NATIVE_LOAD_WINDOW',
        process_instance=1,module_file_index=1,image_base='0x140000000',
        image_size=table.pe['image_size'],image_timestamp=table.pe['image_timestamp'],
        load_time_ms=0.,unload_time_ms=10.,pdb_guid=table.pdb['guid'],pdb_age=table.pdb['age'],
        module_name='probe.exe')
    row = dict(type='event',ordinal=1,time_ms=1.,pid=123,tid=1,process_instance=1,
        provider='EXPLICIT_SYNTHETIC_TRACE_METADATA',name='native.symbol.QA',payload={},semantic=None,
        frames=[dict(address=hex(0x140000000+start+1),name='',rva=start+1,module=module)])
    derived = resolve_event_stack(row,binary,pdb)
    require(derived['frames'][0]['symbol']['name']=='blackbox_leaf', 'REAL_PDB_SYMBOL_NOT_RESOLVED')
    return binary,pdb,{'status':'PASS',
        'scope':'REAL_CLANG_LLD_PE_PDB_WITH_EXPLICITLY_SYNTHETIC_TRACE_METADATA',
        'symbol_table':table.summary(),'procedures':table.functions,'derived_report':derived}


def native_wpr(output,binary,pdb,helper,*,source_sha=None):
    from blackbox_core.trace_owner import TraceSupervisor, _read
    from blackbox_core.optional_jobs import OwnedProcess
    from blackbox_core.windows_research import privilege,wpr_tool
    from blackbox_core.decoder_service import decode_file
    from blackbox_universal.provenance import source_identity
    identity = source_identity(source_sha)
    if source_sha is not None:
        require(identity['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD', 'NATIVE_EXPECTED_SOURCE_HEAD_NOT_VERIFIED')
    require(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true',
            'NATIVE_ETW_ACCEPTANCE_ONLY_ON_DISPOSABLE_WINDOWS_CI')
    require(privilege()['mode']=='ADMINISTRATOR' and wpr_tool(), 'REAL_WPR_REQUIRED_FOR_ACCEPTANCE')
    capture=output/'wpr';capture.mkdir()
    # The system-wide CPU.Verbose profile can emit >384 MiB of JSONL during a
    # five-second sample on busy hosted Windows runners. Keep the exact same
    # real ETW provider/stack/PDB oracle and *full* DECODED requirement, but
    # bound the owned native fixture's sampling window to two seconds.
    # A TRUNCATED result still fails; never weaken the decoder's output limits.
    trace=TraceSupervisor(capture,seconds=NATIVE_QA_CAPTURE_SECONDS,
                          max_output_bytes=256*1024**2,profile="CPU.Verbose")
    owned=None; fixture_identity={'status':'NOT_ESTABLISHED'}
    try:
        trace.start();deadline=time.monotonic()+25
        while _read(trace.path).get('state')!='RECORDING':
            require(trace.active and time.monotonic()<deadline,'NATIVE_WPR_NEVER_READY')
            time.sleep(.05)
        owned=OwnedProcess([str(binary)])
        pid=owned.process.pid
        try:
            owned_identity=owned_process_identity(owned.process,binary)
            fixture_identity={'pid':pid,'created_100ns':owned_identity['creation_time_filetime_ticks'],
                              'owned_image_matches_requested':owned_identity['owned_image_matches_requested']}
        except Exception as error:
            fixture_identity={'pid':pid,'status':'NOT_ESTABLISHED','reason_code':_qa_code(str(error))}
        trace.process.wait(timeout=85)
        result=trace.poll();journal=_read(trace.path)
        require(result and result['status']=='COMPLETED', 'NATIVE_WPR_CAPTURE_FAILED')
        require(journal['policy']['profile']=='CPU.Verbose' and
                journal['start_result'].get('profile')=='CPU.Verbose', 'NATIVE_STACK_PROFILE_NOT_APPLIED')
        require(owned.process.poll() is None, 'OWNED_NATIVE_QA_TARGET_EXITED_EARLY')
    finally:
        if trace.active:trace.stop()
        # Explicit cleanup is restricted to the native fixture created above.
        if owned is not None:owned.close(kill=True)
    source=capture/journal['result']['path'];digest=file_hash(source)
    index=output/'native-etl.sqlite3'
    decoder_processes=[]

    class ObservedDecoderProcess(OwnedProcess):
        """Observe the real helper without substituting launch or decode results."""
        def __init__(self,*args,**kwargs):
            argv=args[0] if args else kwargs.get('args')
            self._qa_output=native_output_path(argv)
            self._qa_requested_encoding='INLINE_V1' if isinstance(argv,(list,tuple)) and len(argv)==4 and argv[-1]=='--inline-modules' else 'DEFAULT'
            super().__init__(*args,**kwargs)
            self._qa_log=Path(kwargs['stderr'].name) if hasattr(kwargs.get('stderr'),'name') else None

        def close(self,*args,**kwargs):
            try:
                return super().close(*args,**kwargs)
            finally:
                observed={'pid':self.process.pid,'exit_code':self.process.poll(),
                          'launch':'PRODUCTION_OWNED_PROCESS_DELEGATED_UNCHANGED',
                          'requested_native_module_encoding':self._qa_requested_encoding}
                try:
                    if self.process.poll() is not None and self._qa_output is not None and self._qa_output.is_file():
                        observed['native_output']=observe_native_output(self._qa_output)
                    if self._qa_log is not None and self._qa_log.is_file():
                        with self._qa_log.open('rb') as stream:
                            stream.seek(max(0,self._qa_log.stat().st_size-4096))
                            tail=stream.read(4096).decode('utf-8',errors='replace')
                            observed['console_machine_codes']=[_qa_code(part) for part in tail.splitlines()[-4:]]
                except Exception as error:
                    observed['console_capture_error_type']=type(error).__name__
                if len(decoder_processes)<4:
                    decoder_processes.append(observed)

    def fixed_metadata(value):
        if type(value) is not dict:
            return {'metadata_type':type(value).__name__}
        allowed=('schema','status','error','reason','format','rows','bounded_events','events_with_errors',
                 'events_without_fields_or_schema','events_with_stacks','decoder_reported_lost_events',
                 'import_completeness','input_sha256')
        bounded={key:(_qa_code(value[key]) if key in ('error','reason') else value[key][:1000]) if isinstance(value[key],str) else value[key]
                 for key in allowed if key in value and (value[key] is None or type(value[key]) in (str,int,bool))}
        reliability=value.get('reliability')
        if type(reliability) is dict:
            bounded['reliability']={key:reliability[key] for key in
                ('event_limit','record_limit_bytes','index_disk_limit_bytes','partial_index_published')
                if key in reliability and type(reliability[key]) in (int,bool)}
        bounded['actual_native_module_encoding']=observed_module_encoding(value)
        return bounded

    def emit_decode_diagnostics(meta,error=None):
        diagnostics={'label':'NATIVE_ETL_DECODE_FIXED_RESULT_METADATA','source_identity':source_identity(source_sha),
            'capture':{'bytes':source.stat().st_size,'sha256':digest,'profile':journal['policy']['profile'],
                       'status':journal['result'].get('status'),'guardian_exit_code':trace.process.returncode},
            'helper':{'name':helper.name,'sha256':file_hash(helper)},
            'decoder_result':fixed_metadata(meta or {}),'decoder_processes':decoder_processes,
            'native_fixture':fixture_identity,
            'index':{'exists':index.is_file()},'raw_trace_or_events_printed':False}
        if error is not None:
            diagnostics['error']={'type':type(error).__name__,'reason_code':_qa_code(str(error))}
        if index.is_file():
            diagnostics['index'].update(bytes=index.stat().st_size,sha256=file_hash(index))
            try:
                with closing(sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)) as db:
                    db.execute('PRAGMA query_only=ON')
                    row=db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()
                    if row is not None and len(row[0])<=65536:
                        diagnostics['index']['metadata']=fixed_metadata(json.loads(row[0]))
                diagnostics['index']['derived_diagnostics']=native_index_diagnostics(index,pid)
            except Exception as read_error:
                diagnostics['index']['metadata_read_error_type']=type(read_error).__name__
        print('NATIVE_ETL_DECODE_DIAGNOSTICS '+json.dumps(diagnostics,ensure_ascii=True),flush=True)
        try:
            (output/'native-decode-diagnostics.json').write_text(json.dumps(diagnostics,ensure_ascii=True,indent=2),encoding='utf-8')
        except OSError as write_error:
            print('NATIVE_ETL_DIAGNOSTIC_WRITE_FAILED '+type(write_error).__name__,flush=True)

    try:
        with patch('blackbox_core.decoder_service.helper_path',return_value=helper), \
             patch('blackbox_core.optional_jobs.OwnedProcess',ObservedDecoderProcess):
            meta=decode_file(source,index)
    except BaseException as error:
        try:
            emit_decode_diagnostics(None,error)
        except Exception as diagnostic_error:
            print('NATIVE_ETL_SECONDARY_DIAGNOSTIC_FAILED '+type(diagnostic_error).__name__,flush=True)
        raise
    try:
        emit_decode_diagnostics(meta)
    except Exception as diagnostic_error:
        print('NATIVE_ETL_SECONDARY_DIAGNOSTIC_FAILED '+type(diagnostic_error).__name__,flush=True)
    require_complete_native_etl(meta, digest)
    # A secondary old-transport prefix is only a losslessness reference. It
    # never substitutes for the full primary import required immediately above.
    legacy_index=output/'native-etl-inline-reference.sqlite3'
    reference={'schema':'blackbox.real-native-transport-reference/1','status':'FAILED',
               'source_sha256':digest,'source_identity':source_identity(source_sha)}
    try:
        with patch('blackbox_core.decoder_service.helper_path',return_value=helper), \
             patch('blackbox_core.optional_jobs.OwnedProcess',ObservedDecoderProcess):
            legacy_meta=decode_file(source,legacy_index,native_module_encoding='INLINE_V1')
        reference.update(primary_metadata=fixed_metadata(meta),legacy_metadata=fixed_metadata(legacy_meta),
                         decoder_processes=list(decoder_processes))
        require(len(decoder_processes)==2,'NATIVE_REFERENCE_HELPER_OBSERVATIONS_MISSING')
        for process, expected in zip(decoder_processes,(meta,legacy_meta)):
            observed=process.get('native_output') or {}
            require(process.get('exit_code')==0 and observed.get('status')=='OBSERVED' and
                observed.get('footer')=={'status':expected['status'],'rows':expected['rows']},
                'NATIVE_REFERENCE_HELPER_OUTPUT_UNCONFIRMED')
        require(observed_module_encoding(meta)=='PER_EVENT_MODULES_V1' and
                observed_module_encoding(legacy_meta)=='INLINE_V1','REAL_NATIVE_TRANSPORT_MODES_NOT_ESTABLISHED')
        comparison=compare_native_prefix(index,legacy_index,meta,legacy_meta,digest)
        require(file_hash(source)==digest,'REAL_NATIVE_REFERENCE_SOURCE_CHANGED')
        if source_sha is not None:
            require(source_identity(source_sha)['source_identity_status']=='VERIFIED_EXPECTED_HEAD',
                    'NATIVE_REFERENCE_SOURCE_HEAD_CHANGED')
        reference.update(comparison=comparison,status='MATCHED_ALL_EMITTED_LEGACY_PREFIX_ROWS')
    except BaseException as error:
        reference.update(status='FAILED',error_type=type(error).__name__,reason_code=_qa_code(str(error)))
        raise
    finally:
        print('REAL_NATIVE_TRANSPORT_REFERENCE '+json.dumps(reference,ensure_ascii=True),flush=True)
        try:
            (output/'native-transport-reference.json').write_text(json.dumps(reference,ensure_ascii=True,indent=2),encoding='utf-8')
        except OSError as write_error:
            print('NATIVE_REFERENCE_DIAGNOSTIC_WRITE_FAILED '+type(write_error).__name__,flush=True)
    rows_seen=bound_frames=resolved=0;example=None
    with closing(sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        for (data,) in db.execute('SELECT data FROM events WHERE pid=? AND has_stack=1',(pid,)):
            row=json.loads(data);rows_seen+=1
            matches=[f for f in row['frames'] if f.get('module',{}).get('module_name','').lower()=='probe.exe']
            bound_frames+=len(matches)
            if matches and example is None:
                proof=resolve_event_stack(row,binary,pdb,source_trace_sha256=digest)
                names={f['symbol']['name'] for f in proof['frames']}
                if names & {'blackbox_leaf','blackbox_parent','entry'}:
                    resolved=proof['resolved_frames'];example=proof
    evidence={'pid':pid,'stack_events':rows_seen,'bound_fixture_frames':bound_frames,
              'resolved_frames_in_example':resolved,'example':example,
              'source_trace_sha256':digest,'native_modules':meta.get('native_modules'),
              'capture_profile':journal['policy']['profile'],'transport_reference':reference['comparison']}
    (output/'real-native-etw.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    require(file_hash(source)==digest,'REAL_NATIVE_TRACE_MODIFIED')
    require(example is not None,'REAL_NATIVE_TRACE_PE_PDB_END_TO_END_NOT_CONFIRMED')
    # New acceptance is source-separated and uses genuine typed SampledProfile
    # records from this exact helper, never labels reconstructed by the test.
    before_index = file_hash(index)
    tree = build_calltree(index, source='etw', pid=pid, binary_path=binary, pdb_path=pdb)
    counts = tree['coverage']
    require(counts['samples_selected'] > 0 and
            counts['samples_missing_typed_classification'] == 0,
            'REAL_NATIVE_TYPED_CPU_SAMPLES_REQUIRED')
    require(counts['samples_represented'] + counts['samples_omitted_node_budget'] ==
            counts['samples_selected'], 'NATIVE_CPU_COUNT_NOT_CONSERVED')
    require(sum(n['self_samples'] for n in tree['nodes']) == counts['samples_represented'],
            'NATIVE_CPU_SELF_COUNT_NOT_CONSERVED')
    require(tree['symbolization']['frame_occurrences_resolved'] > 0,
            'REAL_NATIVE_CPU_TREE_SYMBOLS_NOT_CONFIRMED')
    require(any(n.get('derived_symbol') and n['derived_symbol']['symbol']['name'] in
                {'blackbox_leaf', 'blackbox_parent', 'entry'} for n in tree['nodes']),
            'REAL_NATIVE_CPU_TREE_FIXTURE_FUNCTION_MISSING')
    export_analysis(tree, output/'native-cpu-calltree.json')
    export_analysis(tree, output/'native-cpu-flame-view.html', html=True)
    with closing(sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        first = None
        for data, in db.execute("SELECT data FROM events WHERE pid=? AND provider=? AND name=? ORDER BY id",
                                (pid, 'Windows Kernel', 'PerfInfo/Sample')):
            item = json.loads(data); sample = item.get('cpu_sample') or {}
            if sample.get('executing_dpc') is False and sample.get('executing_isr') is False:
                first = item; break
    require(first is not None and first['process_instance'] is not None,
            'REAL_NATIVE_FILTER_ANCHOR_REQUIRED')
    filtered = build_calltree(index, source='etw', pid=pid,
        process_instance=first['process_instance'], tid=first['tid'],
        start_ms=first['time_ms'], end_ms=first['time_ms']+1)
    require(filtered['coverage']['samples_selected'] > 0,
            'REAL_NATIVE_THREAD_INTERVAL_FILTER_FAILED')
    export_analysis(filtered, output/'native-filtered-calltree.json')
    require(file_hash(index) == before_index, 'NATIVE_CPU_ANALYSIS_CHANGED_INDEX')
    evidence.update(native_cpu_tree=counts, native_cpu_symbols=tree['symbolization'],
                    native_filter=filtered['filters'], native_filter_coverage=filtered['coverage'])
    return {'status':'PASS','scope':'REAL_NATIVE_EXE_WPR_TRACE_PE_PDB_CPU_TREE',**evidence}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--helper',type=Path);parser.add_argument('--trace-index',type=Path)
    parser.add_argument('--source-sha')
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    report={'status':'RUNNING','source_sha':os.environ.get('GITHUB_SHA'),
            'network_symbol_lookup':False,'trace_to_session_alignment':'NOT_ESTABLISHED'}
    try:
        from blackbox_universal.provenance import source_identity
        report['source_identity']=source_identity(args.source_sha)
        report['source_sha_scope']='WORKFLOW_EVENT_ONLY; VERIFIED_HEAD_STATUS_IS_SOURCE_IDENTITY'
        if args.source_sha is not None:
            require(report['source_identity']['source_identity_status']=='VERIFIED_EXPECTED_HEAD',
                    'NATIVE_EXPECTED_SOURCE_HEAD_NOT_VERIFIED')
        binary,pdb,report['native_pair']=native_probe(output)
        if args.trace_index:
            before=file_hash(args.trace_index);tree=build_calltree(args.trace_index)
            require(tree['coverage']['samples_selected']>0,'REAL_CPU_SAMPLES_REQUIRED')
            export_analysis(tree,output/'cpu-calltree.json')
            export_analysis(tree,output/'cpu-flame-view.html',html=True)
            require(file_hash(args.trace_index)==before,'CALLTREE_CHANGED_INDEX')
            report['real_cpu_samples']=tree['coverage']
        if args.helper:
            report['native_trace']=native_wpr(output,binary,pdb,args.helper.resolve(strict=True),source_sha=args.source_sha)
        else:
            report['native_trace']={'status':'NOT_RUN','reason':'WINDOWS_HELPER_NOT_REQUESTED'}
        report['status']='PASS'
    except BaseException as exc:
        report.update(status='FAILED',error=type(exc).__name__,reason=str(exc)[:500]);raise
    finally:
        (output/'patch-qa.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('DECODER_PATCH_QA_PASS')


if __name__=='__main__':main()
