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


def require(value, reason):
    if not value:
        raise AssertionError(reason)


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


def native_wpr(output,binary,pdb,helper):
    from blackbox_core.trace_owner import TraceSupervisor, _read
    from blackbox_core.optional_jobs import OwnedProcess
    from blackbox_core.windows_research import privilege,wpr_tool
    from blackbox_core.decoder_service import decode_file
    require(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true',
            'NATIVE_ETW_ACCEPTANCE_ONLY_ON_DISPOSABLE_WINDOWS_CI')
    require(privilege()['mode']=='ADMINISTRATOR' and wpr_tool(), 'REAL_WPR_REQUIRED_FOR_ACCEPTANCE')
    capture=output/'wpr';capture.mkdir()
    trace=TraceSupervisor(capture,seconds=5,max_output_bytes=256*1024**2,profile="CPU.Verbose")
    owned=None
    try:
        trace.start();deadline=time.monotonic()+25
        while _read(trace.path).get('state')!='RECORDING':
            require(trace.active and time.monotonic()<deadline,'NATIVE_WPR_NEVER_READY')
            time.sleep(.05)
        owned=OwnedProcess([str(binary)])
        pid=owned.process.pid
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
    with patch('blackbox_core.decoder_service.helper_path',return_value=helper):
        meta=decode_file(source,index)
    require(meta['status']=='DECODED','NATIVE_ETL_DECODE_FAILED')
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
              'capture_profile':journal['policy']['profile']}
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
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    report={'status':'RUNNING','source_sha':os.environ.get('GITHUB_SHA'),
            'network_symbol_lookup':False,'trace_to_session_alignment':'NOT_ESTABLISHED'}
    try:
        binary,pdb,report['native_pair']=native_probe(output)
        if args.trace_index:
            before=file_hash(args.trace_index);tree=build_calltree(args.trace_index)
            require(tree['coverage']['samples_selected']>0,'REAL_CPU_SAMPLES_REQUIRED')
            export_analysis(tree,output/'cpu-calltree.json')
            export_analysis(tree,output/'cpu-flame-view.html',html=True)
            require(file_hash(args.trace_index)==before,'CALLTREE_CHANGED_INDEX')
            report['real_cpu_samples']=tree['coverage']
        if args.helper:
            report['native_trace']=native_wpr(output,binary,pdb,args.helper.resolve(strict=True))
        else:
            report['native_trace']={'status':'NOT_RUN','reason':'WINDOWS_HELPER_NOT_REQUESTED'}
        report['status']='PASS'
    except BaseException as exc:
        report.update(status='FAILED',error=type(exc).__name__,reason=str(exc)[:500]);raise
    finally:
        (output/'patch-qa.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('DECODER_PATCH_QA_PASS')


if __name__=='__main__':main()
