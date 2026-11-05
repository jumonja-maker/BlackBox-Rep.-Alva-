"""Build one owned native scheduler fixture on a standard Windows CI runner.

This QA tool never executes the fixture or changes the production decoder.
No environment contents are printed or persisted in the receipt.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from blackbox_universal.provenance import source_identity
from blackbox_core.optional_jobs import OwnedProcess
from tools.qa_deep_inspection import compiler_environment, file_hash, require, require_hosted_windows, save
from tools.qa_decoder_apps import native_pe_identity, owned_process_identity

MAX_BUILD_SECONDS = 90
MAX_BUILD_LOG = 1024**2
MAX_BUILD_BYTES = 32 * 1024**2
MAX_JOB_DIAGNOSTIC_PIDS = 16
MAX_JOB_SNAPSHOTS = 4
_retained_build_resources = []
_COMPILE_GO = b'BLACKBOX_NATIVE_NOISE_BUILD_GO\n'
_COMPILER_OPT_OUT = {'VSCMD_SKIP_SENDTELEMETRY': '1', 'VCToolsTelemetryOptOut': '1'}


def _compiler_worker_environment(inherited):
    """Configure only these fixed opt-outs, preserving all other entries."""
    policy_names = {name.casefold() for name in _COMPILER_OPT_OUT}
    environment = {name: value for name, value in inherited.items() if name.casefold() not in policy_names}
    environment.update(_COMPILER_OPT_OUT)
    return environment


def _require_compiler_policy(environment):
    # Windows environment keys are case insensitive. Reject ambiguous duplicate
    # spellings instead of relying on subprocess or vcvars ordering to pick one.
    for name, expected in _COMPILER_OPT_OUT.items():
        values = [value for key, value in environment.items() if key.casefold() == name.casefold()]
        require(values == [expected], 'NATIVE_NOISE_COMPILER_OPT_OUT_POLICY_UNCONFIRMED')


def _configured_compiler_environment(output):
    # SDK setup may consume/change initialization variables. Preserve its real
    # PATH/LIB/INCLUDE updates, then configure and validate the compiler child's
    # own fixed policy rather than assuming setup retained either variable.
    compiler, environment = compiler_environment(output)
    environment = _compiler_worker_environment(environment)
    _require_compiler_policy(environment)
    return compiler, environment


def _compile_command(compiler, output, source):
    # /Z7 keeps compiler debug records in the OBJ. The linker still produces a
    # real full PDB, without requiring the compiler's shared PDB write service.
    return [compiler, '/nologo', '/W4', '/O2', '/Z7', '/MT', '/DUNICODE', '/D_UNICODE',
            '/FI' + str(output / 'noise-identity.h'), '/Fe:' + str(output / 'scheduler-noise.exe'),
            '/Fo:' + str(output / 'noise.obj'), str(source),
            '/link', '/DEBUG:FULL', '/PDB:' + str(output / 'scheduler-noise.pdb'),
            '/INCREMENTAL:NO', 'bcrypt.lib']


def _await_compile_go():
    """No Git, compiler discovery or other child process may precede this gate."""
    import msvcrt
    kernel = C.WinDLL('kernel32', use_last_error=True, winmode=0x800)
    kernel.PeekNamedPipe.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.c_void_p,
                                   C.POINTER(W.DWORD), C.c_void_p]
    kernel.PeekNamedPipe.restype = W.BOOL
    descriptor = sys.stdin.fileno()
    handle = msvcrt.get_osfhandle(descriptor)
    data = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        available = W.DWORD(); C.set_last_error(0)
        if not kernel.PeekNamedPipe(handle, None, 0, None, C.byref(available), None):
            require(C.get_last_error() == 109 and bytes(data) == _COMPILE_GO,
                    'NATIVE_NOISE_COMPILER_GO_OR_EOF_INVALID')
            return
        if available.value:
            require(len(data) + available.value <= len(_COMPILE_GO), 'NATIVE_NOISE_COMPILER_GO_SIZE')
            block = os.read(descriptor, available.value)
            require(bool(block), 'NATIVE_NOISE_COMPILER_GO_EOF')
            data.extend(block)
            require(_COMPILE_GO.startswith(data), 'NATIVE_NOISE_COMPILER_GO_INVALID')
        time.sleep(.02)
    raise RuntimeError('NATIVE_NOISE_COMPILER_GO_DEADLINE')


def _compile_worker(request_path):
    require_hosted_windows()
    _require_compiler_policy(os.environ)  # Read-only: still no child before GO.
    _await_compile_go()
    # All subprocesses below now inherit the parent's already assigned Job.
    require(request_path.name == 'compiler-request.json' and not request_path.is_symlink(),
            'NATIVE_NOISE_COMPILER_REQUEST_PATH')
    request_path = request_path.resolve(strict=True)
    with request_path.open('rb') as stream:
        raw = stream.read(4097)
    require(0 < len(raw) <= 4096, 'NATIVE_NOISE_COMPILER_REQUEST_SIZE')
    request = json.loads(raw.decode('utf-8'))
    require(type(request) is dict and set(request) == {'schema', 'source_sha', 'source_sha256'}
            and request['schema'] == 'blackbox.native-noise-compiler-request/1'
            and isinstance(request['source_sha'], str) and re.fullmatch(r'[0-9a-f]{40}', request['source_sha'])
            and isinstance(request['source_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', request['source_sha256']),
            'NATIVE_NOISE_COMPILER_REQUEST_INVALID')
    source = ROOT / 'tools' / 'fixtures' / 'DecoderBudgetProbe' / 'noise.c'
    output = request_path.parent
    require(file_hash(source) == request['source_sha256'] and
            (output / 'noise-identity.h').read_text(encoding='ascii') ==
            '#define NOISE_SOURCE_SHA256 "' + request['source_sha256'] + '"\n' and
            source_identity(request['source_sha']).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'NATIVE_NOISE_COMPILER_SOURCE_MISMATCH')
    compiler, environment = _configured_compiler_environment(output)
    command = _compile_command(compiler, output, source)
    compiled = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                              stdout=sys.stdout.buffer, stderr=sys.stderr.buffer,
                              timeout=MAX_BUILD_SECONDS)
    require(file_hash(source) == request['source_sha256'] and
            source_identity(request['source_sha']).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'NATIVE_NOISE_COMPILER_SOURCE_CHANGED')
    return compiled.returncode


class _JobAccounting(C.Structure):
    _fields_ = [('times', C.c_int64 * 4), ('page_faults', W.DWORD),
                ('total_processes', W.DWORD), ('active_processes', W.DWORD), ('terminated', W.DWORD)]


def _job_accounting(kernel, handle):
    kernel.QueryInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]
    kernel.QueryInformationJobObject.restype = W.BOOL
    accounting = _JobAccounting()
    C.set_last_error(0)
    ok = kernel.QueryInformationJobObject(handle, 1, C.byref(accounting), C.sizeof(accounting), None)
    return ok, accounting, C.get_last_error() if not ok else 0


def _owned_job_pid(kernel, job, pid, retained_handles):
    """A PID-list entry alone is not proof of a process identity or membership."""
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.GetProcessId.argtypes = [W.HANDLE]; kernel.GetProcessId.restype = W.DWORD
    kernel.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)]
    kernel.IsProcessInJob.restype = W.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = W.BOOL
    kernel.GetProcessTimes.argtypes = [W.HANDLE, *([C.POINTER(W.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = W.BOOL
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetExitCodeProcess.restype = W.BOOL
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    row = {'pid': pid, 'identity_status': 'NOT_ESTABLISHED'}
    # QUERY_LIMITED_INFORMATION | SYNCHRONIZE, never termination or VM access.
    C.set_last_error(0)
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        row.update(identity_status='OPEN_UNAVAILABLE_EXIT_OR_ACCESS_UNKNOWN', winerror=C.get_last_error())
        return row
    retained_handles.append(handle)
    try:
        assigned = W.BOOL(); C.set_last_error(0)
        if kernel.GetProcessId(handle) != pid or not kernel.IsProcessInJob(handle, job, C.byref(assigned)) or not assigned.value:
            row.update(identity_status='PID_RACE_EXIT_OR_MEMBERSHIP_UNCONFIRMED', winerror=C.get_last_error())
            return row
        row.update(identity_status='HELD_HANDLE_CONFIRMED_IN_THIS_JOB', specific_job_membership_verified=True)
        # Identity reads follow membership proof and use this same held handle.
        name = C.create_unicode_buffer(32768); length = W.DWORD(len(name)); C.set_last_error(0)
        if kernel.QueryFullProcessImageNameW(handle, 0, name, C.byref(length)):
            basename = Path(name.value).name
            row['image_basename'] = basename if re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', basename) else '<nonstandard-name>'
        else:
            row['image_query_winerror'] = C.get_last_error()
        created = W.FILETIME(); exited = W.FILETIME(); kt = W.FILETIME(); ut = W.FILETIME(); C.set_last_error(0)
        if kernel.GetProcessTimes(handle, C.byref(created), C.byref(exited), C.byref(kt), C.byref(ut)):
            row['created_100ns'] = str((created.dwHighDateTime << 32) | created.dwLowDateTime)
            row['exited_100ns'] = str((exited.dwHighDateTime << 32) | exited.dwLowDateTime)
        else:
            row['times_query_winerror'] = C.get_last_error()
        C.set_last_error(0)
        state = kernel.WaitForSingleObject(handle, 0)
        row['exit_state'] = {0: 'EXITED', 258: 'ACTIVE_AT_QUERY'}.get(state, 'WAIT_UNCONFIRMED')
        if state not in (0, 258):
            row['wait_result'] = state
            row['wait_winerror'] = C.get_last_error()
        if state == 0:
            code = W.DWORD(); C.set_last_error(0)
            if kernel.GetExitCodeProcess(handle, C.byref(code)):
                row['exit_code'] = code.value
            else:
                row['exit_query_winerror'] = C.get_last_error()
        return row
    finally:
        # Retain any failed-close capability rather than silently discarding it.
        if kernel.CloseHandle(handle):
            retained_handles.remove(handle)


def _compiler_snapshot(owner, phase, observations):
    """Bounded observations of this Job only; list/identity queries are not atomic."""
    kernel = owner.kernel; handle = owner.job
    if not handle:
        observations.append({'phase': phase, 'status': 'NO_CURRENT_OWNED_JOB', 'processes': []})
        return  # A NULL Job query would inspect the ambient runner Job instead.
    if not hasattr(owner, '_noise_diagnostic_handles'):
        owner._noise_diagnostic_handles = []
    row = {'phase': phase, 'pid_list_and_identity_queries_atomic': False,
           'pid_limit': MAX_JOB_DIAGNOSTIC_PIDS, 'processes': []}
    ok, accounting, error = _job_accounting(kernel, handle)
    row['accounting'] = ({'status': 'OBSERVED', 'active_processes': accounting.active_processes,
                          'total_processes': accounting.total_processes, 'terminated_processes': accounting.terminated}
                         if ok else {'status': 'NOT_ESTABLISHED', 'winerror': error})

    class ProcessList(C.Structure):
        _fields_ = [('assigned', W.DWORD), ('listed', W.DWORD),
                    ('pids', C.c_size_t * MAX_JOB_DIAGNOSTIC_PIDS)]

    pids = ProcessList(); C.set_last_error(0)
    ok = kernel.QueryInformationJobObject(handle, 3, C.byref(pids), C.sizeof(pids), None)
    error = C.get_last_error() if not ok else 0
    row.update(pid_list_query_winerror=error, assigned_processes=pids.assigned,
               listed_processes=pids.listed, pid_list_complete=bool(ok and pids.assigned == pids.listed
                                                                 and pids.listed <= MAX_JOB_DIAGNOSTIC_PIDS))
    if (ok or error == 234) and pids.listed <= MAX_JOB_DIAGNOSTIC_PIDS:
        for pid in pids.pids[:pids.listed]:
            if 0 < pid <= 0xffffffff:
                row['processes'].append(_owned_job_pid(kernel, handle, pid, owner._noise_diagnostic_handles))
    row['query_handles_closed_verified'] = not owner._noise_diagnostic_handles
    if len(observations) == MAX_JOB_SNAPSHOTS:
        del observations[1]  # Keep the first observation and the latest three.
    observations.append(row)


def _close_owner_with_checked_handles(owner):
    """Delegate all owner bookkeeping while checking its real handle closes."""
    kernel = owner.kernel
    real_close = kernel.CloseHandle

    def checked_close(candidate):
        result = real_close(candidate)
        require(result, 'NATIVE_NOISE_COMPILER_JOB_CLOSE_FAILED')
        return result

    kernel.CloseHandle = checked_close
    try:
        owner.close(kill=False)
    finally:
        kernel.CloseHandle = real_close


def _stop_completed_compiler_job(owner, *, build_deadline, observations):
    """Stop this dedicated SDK Job after the caller validates completed output."""
    receipt = {'status': 'NOT_STARTED',
               'method': 'PLANNED_OWNED_SDK_BACKGROUND_SHUTDOWN_AFTER_SUCCESSFUL_COMPILATION',
               'termination_requested': False, 'termination_succeeded': None,
               'active_job_processes_before_stop': None, 'active_job_processes_after_stop': None,
               'natural_background_exit_claimed': False}
    try:
        process = getattr(owner, 'process', None)
        require(process is not None and process.poll() == 0, 'NATIVE_NOISE_COMPILER_SUCCESS_REQUIRED_FOR_PLANNED_STOP')
        kernel = owner.kernel; handle = owner.job
        require(handle, 'NATIVE_NOISE_COMPILER_JOB_MISSING')
        stop_deadline = min(time.monotonic() + 2, build_deadline)
        _compiler_snapshot(owner, 'BEFORE_PLANNED_SHUTDOWN', observations)
        require(not owner._noise_diagnostic_handles, 'NATIVE_NOISE_COMPILER_DIAGNOSTIC_HANDLE_CLOSE_UNCONFIRMED')
        require(time.monotonic() < stop_deadline, 'NATIVE_NOISE_COMPILER_PLANNED_STOP_DEADLINE')
        ok, accounting, error = _job_accounting(kernel, handle)
        receipt['last_job_query_winerror'] = error
        require(ok, 'NATIVE_NOISE_COMPILER_JOB_QUERY_UNCONFIRMED')
        receipt['active_job_processes_before_stop'] = accounting.active_processes
        receipt['status'] = 'PLANNED_SHUTDOWN_IN_PROGRESS'
        if accounting.active_processes:
            receipt['termination_requested'] = True
            receipt['termination_succeeded'] = bool(kernel.TerminateJobObject(handle, 1))
            require(receipt['termination_succeeded'], 'NATIVE_NOISE_COMPILER_PLANNED_STOP_UNCONFIRMED')
        while True:
            require(time.monotonic() < stop_deadline, 'NATIVE_NOISE_COMPILER_PLANNED_STOP_DEADLINE')
            ok, accounting, error = _job_accounting(kernel, handle)
            receipt['last_job_query_winerror'] = error
            require(ok, 'NATIVE_NOISE_COMPILER_JOB_QUERY_UNCONFIRMED')
            receipt['active_job_processes_after_stop'] = accounting.active_processes
            if accounting.active_processes == 0:
                break
            time.sleep(.02)
        _compiler_snapshot(owner, 'PLANNED_SHUTDOWN_EMPTY', observations)
        require(not owner._noise_diagnostic_handles, 'NATIVE_NOISE_COMPILER_DIAGNOSTIC_HANDLES_REMAIN')
        require(time.monotonic() < stop_deadline, 'NATIVE_NOISE_COMPILER_PLANNED_STOP_DEADLINE')
        receipt['status'] = 'COMPLETED'
        return receipt
    except BaseException as error:
        receipt['status'] = 'FAILED'
        error.compiler_planned_shutdown = receipt
        raise


def _close_compiler(owner, *, force, observations, build_deadline):
    """Observe actual exit and empty Job before its close can hide descendants."""
    kernel = owner.kernel
    handle = owner.job
    require(handle, 'NATIVE_NOISE_COMPILER_JOB_MISSING')
    _compiler_snapshot(owner, 'BEFORE_FORCE_TERMINATE' if force else 'NORMAL_CLOSE_BEGIN', observations)
    if not force:
        require(not owner._noise_diagnostic_handles, 'NATIVE_NOISE_COMPILER_DIAGNOSTIC_HANDLE_CLOSE_UNCONFIRMED')
    if force:
        require(kernel.TerminateJobObject(handle, 1), 'NATIVE_NOISE_COMPILER_TERMINATION_UNCONFIRMED')
    process = getattr(owner, 'process', None)
    if process is not None:
        process.wait(timeout=3 if force else max(.001, min(3, build_deadline - time.monotonic())))
    deadline = min(time.monotonic() + 2, build_deadline) if not force else time.monotonic() + 2
    while True:
        ok, accounting, _ = _job_accounting(kernel, handle)
        require(ok, 'NATIVE_NOISE_COMPILER_JOB_QUERY_UNCONFIRMED')
        if accounting.active_processes == 0:
            break
        if time.monotonic() >= deadline:
            _compiler_snapshot(owner, 'DESCENDANTS_REMAIN', observations)
            raise RuntimeError('NATIVE_NOISE_COMPILER_DESCENDANTS_REMAIN')
        time.sleep(.02)
    _compiler_snapshot(owner, 'EMPTY_BEFORE_CLOSE', observations)
    if force:
        for diagnostic_handle in tuple(owner._noise_diagnostic_handles):
            if kernel.CloseHandle(diagnostic_handle):
                owner._noise_diagnostic_handles.remove(diagnostic_handle)
    require(not owner._noise_diagnostic_handles, 'NATIVE_NOISE_COMPILER_DIAGNOSTIC_HANDLES_REMAIN')
    # Delegate the owner's own cleanup, including future registry/resources,
    # but stop its close immediately if the real CloseHandle reports failure.
    _close_owner_with_checked_handles(owner)
    kernel.GetHandleInformation.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetHandleInformation.restype = W.BOOL
    flags = W.DWORD(); C.set_last_error(0)
    alive = kernel.GetHandleInformation(handle, C.byref(flags))
    require(not alive and C.get_last_error() == 6, 'NATIVE_NOISE_COMPILER_JOB_CLOSE_UNCONFIRMED')
    return {'status': 'FORCED_CLOSED' if force else 'COMPLETED',
            'process_exit_code': process.returncode if process is not None else None,
            'process_created': process is not None, 'active_job_processes_before_close': 0,
            'observed_job_processes': accounting.total_processes,
            'job_handle_closed_verified': True, 'diagnostic_query_handles_closed_verified': True,
            'cleanup_required': False,
            'scope': 'COMPILER_LEADER_EXIT_AND_OWNED_JOB_OBJECT'}


def _compiler_tail(log_path, output):
    try:
        with log_path.open('rb') as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 4000))
            text = stream.read(4000).decode('utf-8', errors='replace')
        text = text.replace(str(output), '<native-build>').replace(str(ROOT), '<repository>')
        # Compiler/discovery diagnostics may contain other Windows paths. Never
        # print raw absolute paths, environment values or a whole unbounded log.
        text = re.sub(r'(?i)(?:[a-z]:[\\/]|\\\\)[^\r\n"]*', '<path>', text)
        return ''.join(char if char.isprintable() or char in '\n\t' else '?' for char in text)[-4000:]
    except OSError:
        return '<compiler-log-unavailable>'


def _built_pdb(path):
    size = path.stat().st_size
    require(32 < size <= MAX_BUILD_BYTES, 'NATIVE_NOISE_PDB_SIZE_INVALID')
    with path.open('rb') as stream:
        require(stream.read(32) == b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00',
                'NATIVE_NOISE_PDB_MSF7_SIGNATURE_MISSING')
    return {'container': 'MSF7', 'bytes': size, 'sha256': file_hash(path),
            'verification_scope': 'CONTAINER_SIGNATURE_SIZE_AND_SHA256_ONLY'}


def build_native_noise(output: Path, source_sha: str) -> dict:
    build_deadline = time.monotonic() + MAX_BUILD_SECONDS
    require_hosted_windows()
    require(isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}', source_sha),
            'NATIVE_NOISE_EXACT_SOURCE_SHA_REQUIRED')
    identity = source_identity(source_sha)
    require(identity.get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'NATIVE_NOISE_BUILD_SOURCE_MISMATCH')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'tools' / 'fixtures' / 'DecoderBudgetProbe' / 'noise.c'
    digest = file_hash(source)
    identity_header = output / 'noise-identity.h'
    identity_header.write_text('#define NOISE_SOURCE_SHA256 "' + digest + '"\n', encoding='ascii')
    executable = output / 'scheduler-noise.exe'
    request_path = output / 'compiler-request.json'
    save(request_path, {'schema': 'blackbox.native-noise-compiler-request/1',
                       'source_sha': source_sha, 'source_sha256': digest})
    command = [sys.executable, str(Path(__file__).resolve()), '--compile-worker', str(request_path)]
    log_path = output / 'compiler.log'
    stream = log_path.open('xb')
    owner = None
    closed = False
    cleanup = {'status': 'NOT_ESTABLISHED', 'cleanup_required': True}
    observations = []
    opt_out_policy = {'request_status': 'NOT_REQUESTED', 'worker_verification_status': 'NOT_ESTABLISHED'}
    planned_shutdown = {'status': 'NOT_REQUESTED'}
    completed_output_proof = {'status': 'NOT_ESTABLISHED', 'post_shutdown_revalidated': False}
    try:
        require(time.monotonic() < build_deadline, 'NATIVE_NOISE_COMPILER_DEADLINE')
        environment = _compiler_worker_environment(os.environ)
        _require_compiler_policy(environment)
        opt_out_policy['request_status'] = 'FIXED_ENVIRONMENT_REQUESTED'
        owner = OwnedProcess(command, stdin=subprocess.PIPE, stdout=stream, stderr=stream,
                             detach_console=True, env=environment)
        owned_process_identity(owner.process, Path(sys.executable).resolve())
        owner.kernel.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)]
        owner.kernel.IsProcessInJob.restype = W.BOOL
        assigned = W.BOOL()
        require(owner.job and owner.kernel.IsProcessInJob(int(owner.process._handle), owner.job,
                C.byref(assigned)) and assigned.value, 'NATIVE_NOISE_COMPILER_JOB_ASSIGNMENT_UNCONFIRMED')
        # The worker cannot start even Git/discovery before this private token.
        owner.process.stdin.write(_COMPILE_GO)
        owner.process.stdin.flush()
        owner.process.stdin.close()
        while owner.process.poll() is None:
            require(time.monotonic() < build_deadline, 'NATIVE_NOISE_COMPILER_DEADLINE')
            require(log_path.stat().st_size <= MAX_BUILD_LOG, 'NATIVE_NOISE_COMPILER_LOG_BUDGET')
            require(sum(path.stat().st_size for path in output.rglob('*') if path.is_file()) <= MAX_BUILD_BYTES,
                    'NATIVE_NOISE_COMPILER_OUTPUT_BUDGET')
            time.sleep(.05)
        code = owner.process.wait(timeout=3)
        require(log_path.stat().st_size <= MAX_BUILD_LOG and
                sum(path.stat().st_size for path in output.rglob('*') if path.is_file()) <= MAX_BUILD_BYTES,
                'NATIVE_NOISE_FINAL_BUILD_BUDGET')
        require(code == 0 and executable.is_file(), 'NATIVE_NOISE_COMPILATION_FAILED')
        native = native_pe_identity(executable)
        require(native['machine'] == '0x8664', 'NATIVE_NOISE_COMPILER_NOT_X64')
        require(file_hash(source) == digest and
                source_identity(source_sha).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
                'NATIVE_NOISE_BUILD_SOURCE_CHANGED')
        # A zero worker exit follows both policy checks and its final source
        # guards. This verifies propagation, not that MSVC honours every knob.
        opt_out_policy['worker_verification_status'] = 'WORKER_AND_COMPILER_ENVIRONMENT_VERIFIED'
        pdb = _built_pdb(output / 'scheduler-noise.pdb')
        executable_digest = file_hash(executable)
        require(time.monotonic() < build_deadline, 'NATIVE_NOISE_COMPILER_DEADLINE')
        completed_output_proof.update(status='VERIFIED_BEFORE_PLANNED_STOP', source_sha256=digest,
                                      executable_sha256=executable_digest, native_image=native, native_pdb=pdb)
        # The worker and its cl/link invocation have completed successfully.
        # SDK background work has an explicit owned-Job stop lifecycle; its
        # natural exit is never an acceptance claim or a process-name exception.
        planned_shutdown = _stop_completed_compiler_job(owner, build_deadline=build_deadline,
                                                        observations=observations)
        cleanup = _close_compiler(owner, force=False, observations=observations, build_deadline=build_deadline)
        closed = True
        stream.close()
        require(file_hash(executable) == executable_digest and
                _built_pdb(output / 'scheduler-noise.pdb') == pdb and file_hash(source) == digest and
                source_identity(source_sha).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
                'NATIVE_NOISE_COMPLETED_BUILD_OUTPUT_CHANGED')
        require(log_path.stat().st_size <= MAX_BUILD_LOG and
                sum(path.stat().st_size for path in output.rglob('*') if path.is_file()) <= MAX_BUILD_BYTES,
                'NATIVE_NOISE_FINAL_BUILD_BUDGET')
        require(time.monotonic() < build_deadline, 'NATIVE_NOISE_COMPILER_DEADLINE')
        completed_output_proof['post_shutdown_revalidated'] = True
        result = {'schema': 'blackbox.native-noise-build/1', 'status': 'PASS',
                  'executable': str(executable), 'source_sha256': digest,
                  'executable_sha256': executable_digest, 'implementation': 'NATIVE_WIN32',
                  'expected_native_handles': 32, 'event_handles': 16, 'thread_handles': 16,
                  'source_identity': identity, 'native_image': native, 'native_pdb': pdb, 'cleanup': cleanup,
                  'compiler_job_observations': observations,
                  'compiler_opt_out_policy': opt_out_policy,
                  'compiler_planned_shutdown': planned_shutdown,
                  'completed_output_proof': completed_output_proof,
                  'compiler_job_assignment_verified_before_go': True}
        save(output / 'build.json', result)
        print('NATIVE_NOISE_FIXTURE_BUILD ' + json.dumps({key: result[key] for key in (
            'schema', 'status', 'source_sha256', 'executable_sha256', 'implementation',
            'expected_native_handles', 'source_identity', 'native_image', 'native_pdb', 'cleanup',
            'compiler_job_observations', 'compiler_opt_out_policy', 'compiler_planned_shutdown',
            'completed_output_proof')}, sort_keys=True), flush=True)
        return result
    except BaseException as error:
        planned_shutdown = getattr(error, 'compiler_planned_shutdown', planned_shutdown)
        # Newer owners preserve a failed constructor's cleanup capability on
        # the exception, before this function's assignment could have occurred.
        if owner is None and isinstance(getattr(error, 'owner', None), OwnedProcess):
            owner = error.owner
        if owner is not None and not closed:
            pipe_closed = True
            process = getattr(owner, 'process', None)
            pipe = getattr(process, 'stdin', None)
            try:
                if pipe is not None and not pipe.closed:
                    pipe.close()
            except OSError:
                pipe_closed = bool(pipe.closed)
            try:
                cleanup = _close_compiler(owner, force=True, observations=observations, build_deadline=build_deadline)
                require(pipe_closed, 'NATIVE_NOISE_COMPILER_INPUT_CLOSE_UNCONFIRMED')
                closed = True
            except BaseException as cleanup_error:
                cleanup = {'status': 'RECOVERY_UNCONFIRMED', 'cleanup_required': True,
                           'error_type': type(cleanup_error).__name__}
                # Do not discard the actual ownership capability or its open log.
                _retained_build_resources.append((owner, stream))
                error.owner = owner
                error.cleanup_required = True
        if owner is None or closed:
            try:
                stream.close()
            except OSError:
                cleanup = {'status': 'RECOVERY_UNCONFIRMED', 'cleanup_required': True,
                           'log_handle_closed_verified': False}
                _retained_build_resources.append((owner, stream))
                error.cleanup_required = True
        reason = str(error)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'UNCLASSIFIED_BUILD_FAILURE'
        failure = {'schema': 'blackbox.native-noise-build/1', 'status': 'FAILED',
                   'error_type': type(error).__name__, 'reason': reason, 'cleanup': cleanup,
                   'source_sha256': digest, 'source_identity': identity,
                   'compiler_job_observations': observations,
                   'compiler_opt_out_policy': opt_out_policy,
                   'compiler_planned_shutdown': planned_shutdown,
                   'completed_output_proof': completed_output_proof,
                   'compiler_exit_code': getattr(getattr(owner, 'process', None), 'returncode', None),
                   'compiler_diagnostics_tail': _compiler_tail(log_path, output)}
        # Print the final cleanup receipt even if persisting it subsequently
        # fails. The original failure remains the exception propagated to QA.
        print('NATIVE_NOISE_FIXTURE_BUILD_FAILED ' + json.dumps(failure, sort_keys=True), flush=True)
        try:
            save(output / 'build-failure.json', failure)
        except OSError:
            print('NATIVE_NOISE_BUILD_FAILURE_RECEIPT_WRITE_FAILED', flush=True)
        raise


if __name__ == '__main__':
    require(len(sys.argv) == 3 and sys.argv[1] == '--compile-worker', 'NATIVE_NOISE_BUILD_WORKER_ARGUMENTS')
    raise SystemExit(_compile_worker(Path(sys.argv[2])))
