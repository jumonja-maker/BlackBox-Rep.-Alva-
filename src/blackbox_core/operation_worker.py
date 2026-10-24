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

OPERATIONS = frozenset({'native', 'symbols', 'inspect_dump', 'inspect', 'prepare_client',
    'episode', 'evidence_page', 'export', 'compare', 'verify', 'recover', 'dump', 'processes'})
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
    if op == 'native':
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
