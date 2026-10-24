"""Allowlisted, disposable optional operations. No recording connection enters here.

The session owner commits returned evidence only after target revalidation. A
native call that never returns is confined to this disposable process, not the
base sampler or Qt. Paths are local explicit inputs, never shell commands.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import time

LIBRARY_OPERATIONS = frozenset({'library_query','library_register','library_scan','library_open',
    'library_compare','library_policy','library_retention','library_plan_trash',
    'library_apply_trash','library_restore','library_reconcile','library_plan_purge','library_apply_purge'})
OPERATIONS = LIBRARY_OPERATIONS | frozenset({'native', 'symbols', 'inspect_dump', 'inspect', 'prepare_client',
    'episode', 'evidence_page', 'export', 'compare', 'verify', 'recover', 'dump', 'processes','investigation','incident_card','events_query','export_recovery_scan','export_recover'})
TARGET_OPERATIONS = frozenset({'native', 'symbols', 'inspect', 'dump'})
MAX_RESULT_BYTES = 4 * 1024 * 1024


def validate_identity(pid, created):
    import psutil
    if type(pid) is not int or pid <= 0 or type(created) not in (int, float) or created <= 0:
        raise ValueError('INVALID_TARGET_IDENTITY')
    if abs(psutil.Process(pid).create_time() - created) > .000001:
        raise ValueError('TARGET_INSTANCE_CHANGED')


def execute(packet):
    op = packet['op']; a = packet.get('args', {})
    if op not in OPERATIONS or type(a) is not dict: raise ValueError('UNKNOWN_OPTIONAL_OPERATION')
    pid, created = packet.get('pid'), packet.get('created')
    if op in TARGET_OPERATIONS: validate_identity(pid, created)
    folder = Path(packet['folder']) if packet.get('folder') else None
    if op in LIBRARY_OPERATIONS:
        from .library_catalog import LibraryCatalog
        # The root is assigned by the session owner, never by an operation's args.
        catalog=LibraryCatalog(packet['library_root'])
        if op=='library_query':
            result=catalog.query(search=a.get('search',''),state=a.get('state','ALL'),after=a.get('after'),limit=a.get('limit',50))
            result['request_key']=a.get('request_key')
        elif op=='library_register':result={'entry':catalog.register(a['folder'])}
        elif op=='library_scan':result=catalog.scan(after=a.get('after',''),limit=a.get('limit',50))
        elif op=='library_open':result=catalog.open_entry(a['entry_id'])
        elif op=='library_compare':
            if a['before_id']==a['after_id']:raise ValueError('LIBRARY_SELECT_TWO_RECORDINGS')
            before=catalog.open_entry(a['before_id'],completed=True)
            after=catalog.open_entry(a['after_id'],completed=True)
            if before['has_research'] and after['has_research']:
                from .casebook import compare_cases
                comparison=compare_cases(before['folder'],after['folder'])
            else:
                from .report import compare
                comparison=compare(Path(before['folder']),Path(after['folder']))
            result={'before':before['entry'],'after':after['entry'],'comparison':comparison,
                'source_trust':'UNVERIFIED_IMPORT','source_observations_modified':False}
        elif op=='library_policy':result=catalog.policy(a.get('values'))
        elif op=='library_retention':result=catalog.retention_preview(limit=a.get('limit',50))
        elif op=='library_plan_trash':result=catalog.plan_trash(a['entry_ids'])
        elif op=='library_apply_trash':result=catalog.apply_trash(a['confirmation_token'])
        elif op=='library_restore':result=catalog.restore(a['entry_id'])
        elif op=='library_reconcile':result=catalog.reconcile()
        elif op=='library_plan_purge':result=catalog.plan_purge(a['entry_ids'])
        elif op=='library_apply_purge':result=catalog.apply_purge(a['confirmation_token'])
    elif op=='export_recovery_scan':
        from .export_recovery import scan_exports
        result=scan_exports(a['folder'])
    elif op=='export_recover':
        from .export_recovery import recover_export
        result=recover_export(a['journal'],action=a['action'],confirmed=a.get('confirmed',False))
    elif op=='investigation':
        from .investigation_v2 import investigate
        result=investigate(a.get('folder') or folder,start_ns=a.get('start_ns'),end_ns=a.get('end_ns'),after=a.get('after'),limit=a.get('limit',50),question=a.get('question','ALL'),sort_order=a.get('sort_order','TIME_ASC'),instance_id=a.get('instance_id',1))
        result['request_key']=a.get('request_key')
    elif op=='incident_card':
        from .investigation_v2 import incident_card
        result=incident_card(a.get('folder') or folder,a['incident_id'])
    elif op=='events_query':
        from .event_stream import event_page
        result=event_page(a.get('folder') or folder,after=a.get('after'),limit=a.get('limit',100),source=a.get('source','ALL'),severity=a.get('severity','ALL'),instance_id=a.get('instance_id',0),search=a.get('search',''),start_ms=a.get('start_ms'),end_ms=a.get('end_ms'))
        result['request_key']=a.get('request_key')
    elif op == 'native':
        import psutil
        from .windows_research import window_observations, wait_chain, enable_debug_privilege
        windows = window_observations(pid)
        tids = [r['tid'] for r in windows.get('windows', [])][:4]
        try:
            threads = sorted(psutil.Process(pid).threads(), key=lambda r:r.user_time+r.system_time, reverse=True)
            tids = list(dict.fromkeys(tids + [t.id for t in threads]))[:8]
        except psutil.Error: pass
        enable_debug_privilege()
        result = {'windows': windows, 'wait_chains': [wait_chain(t) for t in tids]}
    elif op == 'symbols':
        import psutil
        from .symbols import verify_symbols
        result = verify_symbols(psutil.Process(pid).exe(), a['pdb'])
    elif op == 'inspect_dump':
        from .symbols import inspect_dump
        artifacts = folder/'artifacts'; artifacts.mkdir(exist_ok=True)
        result = inspect_dump(a['dump'], artifacts, a.get('symbols'))
    elif op == 'dump':
        from uuid import uuid4
        from .windows_research import minidump
        artifacts = folder/'artifacts'; artifacts.mkdir(exist_ok=True)
        result = minidump(pid, artifacts/('snapshot-'+uuid4().hex+'.dmp'), full=bool(a.get('full', False)))
    elif op == 'inspect':
        from .preparation import inspect_target
        result = inspect_target(pid)
    elif op == 'prepare_client':
        from uuid import uuid4
        from .preparation import write_preparation
        result = write_preparation(folder/('preparation-'+uuid4().hex[:8]),
            Path(packet['event_path']), packet['event_token'])
    elif op == 'episode':
        from .casebook import episode
        result = episode(a.get('folder') or folder, int(a.get('start_ms', 0)), int(a.get('end_ms', packet.get('end_ms', 1))))
    elif op == 'evidence_page':
        from .casebook import evidence_page
        result = evidence_page(a.get('folder') or folder, start_ms=int(a['start_ms']), end_ms=int(a['end_ms']),
            after_id=int(a.get('after_id', 0)), before_id=a.get('before_id'))
    elif op == 'export':
        from .casebook import export_case
        # This worker has a hard owner-controlled deadline and termination boundary.
        result = export_case(a.get('folder') or folder, a['destination'], include_sensitive=bool(a.get('include_sensitive', False)))
    elif op == 'compare':
        from .casebook import compare_cases
        if (Path(a['before'])/'research.sqlite3').is_file() and (Path(a['after'])/'research.sqlite3').is_file():
            result = compare_cases(a['before'], a['after'])
        else:
            from .report import compare
            result = compare(Path(a['before']), Path(a['after']))
    elif op == 'verify':
        from .casebook import verify_package
        result = verify_package(a['path'])
    elif op == 'recover':
        from .casebook import recover_case
        result = recover_case(a['folder'], a['destination'])
    elif op == 'processes':
        from blackbox_universal.monitor import available_processes
        result = available_processes()
    if op in TARGET_OPERATIONS: validate_identity(pid, created)
    return result


def main(spec, destination):
    source = Path(spec); output = Path(destination)
    if source.is_symlink() or source.stat().st_size > 65536: raise ValueError('INVALID_OPERATION_PACKET')
    # Parent assigns the owned process tree to its Job Object before release.
    # Native tools cannot start in the spawn/assignment race.
    ready=source.parent/'ready';deadline=time.monotonic()+5
    while not ready.is_file():
        if time.monotonic()>=deadline:raise TimeoutError('OPERATION_OWNER_NOT_READY')
        time.sleep(.005)
    packet = json.loads(source.read_text(encoding='utf-8'))
    started = time.monotonic_ns()
    try: result = {'result': execute(packet), 'error': None}
    except Exception as exc:
        result = {'result': None, 'error': getattr(exc, 'code', None) or (type(exc).__name__+': '+str(exc))[:512]}
    result.update(started_ns=started, ended_ns=time.monotonic_ns(), pid=os.getpid())
    raw = json.dumps(result, ensure_ascii=True, allow_nan=False, default=lambda x:str(x) if isinstance(x, Path) else None).encode('ascii')
    if len(raw) > MAX_RESULT_BYTES:
        raw = json.dumps({'result': None, 'error': 'OPTIONAL_RESULT_BUDGET_EXCEEDED'}).encode('ascii')
    with output.open('xb') as stream: stream.write(raw)
    return 0


if __name__ == '__main__': raise SystemExit(main(*sys.argv[1:]))
