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
_retained_build_resources = []
_COMPILE_GO = b'BLACKBOX_NATIVE_NOISE_BUILD_GO\n'


def _compile_command(compiler, output, source):
    return [compiler, '/nologo', '/W4', '/O2', '/Zi', '/MT', '/DUNICODE', '/D_UNICODE',
            '/FI' + str(output / 'noise-identity.h'), '/Fe:' + str(output / 'scheduler-noise.exe'),
            '/Fo:' + str(output / 'noise.obj'), '/Fd:' + str(output / 'compiler.pdb'), str(source),
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
    compiler, environment = compiler_environment(output)
    command = _compile_command(compiler, output, source)
    compiled = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                              stdout=sys.stdout.buffer, stderr=sys.stderr.buffer,
                              timeout=MAX_BUILD_SECONDS)
    require(file_hash(source) == request['source_sha256'] and
            source_identity(request['source_sha']).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'NATIVE_NOISE_COMPILER_SOURCE_CHANGED')
    return compiled.returncode


def _close_compiler(owner, *, force):
    """Observe actual exit and empty Job before its close can hide descendants."""
    kernel = owner.kernel
    handle = owner.job
    require(handle, 'NATIVE_NOISE_COMPILER_JOB_MISSING')
    if force:
        require(kernel.TerminateJobObject(handle, 1), 'NATIVE_NOISE_COMPILER_TERMINATION_UNCONFIRMED')
    owner.process.wait(timeout=3)

    class Accounting(C.Structure):
        _fields_ = [('times', C.c_int64 * 4), ('page_faults', W.DWORD),
                    ('total_processes', W.DWORD), ('active_processes', W.DWORD), ('terminated', W.DWORD)]

    kernel.QueryInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]
    kernel.QueryInformationJobObject.restype = W.BOOL
    deadline = time.monotonic() + 2
    while True:
        accounting = Accounting()
        require(kernel.QueryInformationJobObject(handle, 1, C.byref(accounting),
                C.sizeof(accounting), None), 'NATIVE_NOISE_COMPILER_JOB_QUERY_UNCONFIRMED')
        if accounting.active_processes == 0:
            break
        require(time.monotonic() < deadline, 'NATIVE_NOISE_COMPILER_DESCENDANTS_REMAIN')
        time.sleep(.02)
    owner.close(kill=False)
    kernel.GetHandleInformation.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetHandleInformation.restype = W.BOOL
    flags = W.DWORD(); C.set_last_error(0)
    alive = kernel.GetHandleInformation(handle, C.byref(flags))
    require(not alive and C.get_last_error() == 6, 'NATIVE_NOISE_COMPILER_JOB_CLOSE_UNCONFIRMED')
    return {'status': 'FORCED_CLOSED' if force else 'COMPLETED',
            'process_exit_code': owner.process.returncode, 'active_job_processes_before_close': 0,
            'observed_job_processes': accounting.total_processes,
            'job_handle_closed_verified': True, 'cleanup_required': False,
            'scope': 'COMPILER_LEADER_EXIT_AND_OWNED_JOB_OBJECT'}


def build_native_noise(output: Path, source_sha: str) -> dict:
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
    try:
        owner = OwnedProcess(command, stdin=subprocess.PIPE, stdout=stream, stderr=stream,
                             detach_console=True)
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
        deadline = time.monotonic() + MAX_BUILD_SECONDS
        while owner.process.poll() is None:
            require(time.monotonic() < deadline, 'NATIVE_NOISE_COMPILER_DEADLINE')
            require(log_path.stat().st_size <= MAX_BUILD_LOG, 'NATIVE_NOISE_COMPILER_LOG_BUDGET')
            require(sum(path.stat().st_size for path in output.rglob('*') if path.is_file()) <= MAX_BUILD_BYTES,
                    'NATIVE_NOISE_COMPILER_OUTPUT_BUDGET')
            time.sleep(.05)
        code = owner.process.wait(timeout=3)
        cleanup = _close_compiler(owner, force=False)
        closed = True
        stream.close()
        require(log_path.stat().st_size <= MAX_BUILD_LOG and
                sum(path.stat().st_size for path in output.rglob('*') if path.is_file()) <= MAX_BUILD_BYTES,
                'NATIVE_NOISE_FINAL_BUILD_BUDGET')
        if code != 0:
            diagnostics = log_path.read_text(encoding='utf-8', errors='replace')[-4000:]
            diagnostics = diagnostics.replace(str(output), '<native-build>').replace(str(ROOT), '<repository>')
            print('NATIVE_NOISE_COMPILER_FAILURE ' + json.dumps({'exit_code': code, 'diagnostics': diagnostics}), flush=True)
        require(code == 0 and executable.is_file(), 'NATIVE_NOISE_COMPILATION_FAILED')
        native = native_pe_identity(executable)
        require(native['machine'] == '0x8664', 'NATIVE_NOISE_COMPILER_NOT_X64')
        require(file_hash(source) == digest and
                source_identity(source_sha).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
                'NATIVE_NOISE_BUILD_SOURCE_CHANGED')
        result = {'schema': 'blackbox.native-noise-build/1', 'status': 'PASS',
                  'executable': str(executable), 'source_sha256': digest,
                  'executable_sha256': file_hash(executable), 'implementation': 'NATIVE_WIN32',
                  'expected_native_handles': 32, 'event_handles': 16, 'thread_handles': 16,
                  'source_identity': identity, 'native_image': native, 'cleanup': cleanup,
                  'compiler_job_assignment_verified_before_go': True}
        save(output / 'build.json', result)
        print('NATIVE_NOISE_FIXTURE_BUILD ' + json.dumps({key: result[key] for key in (
            'schema', 'status', 'source_sha256', 'executable_sha256', 'implementation',
            'expected_native_handles', 'source_identity', 'native_image', 'cleanup')}, sort_keys=True), flush=True)
        return result
    except BaseException as error:
        if owner is not None and not closed:
            pipe_closed = True
            try:
                if owner.process.stdin is not None and not owner.process.stdin.closed:
                    owner.process.stdin.close()
            except OSError:
                pipe_closed = bool(owner.process.stdin.closed)
            try:
                cleanup = _close_compiler(owner, force=True)
                require(pipe_closed, 'NATIVE_NOISE_COMPILER_INPUT_CLOSE_UNCONFIRMED')
                closed = True
            except BaseException:
                cleanup = {'status': 'RECOVERY_UNCONFIRMED', 'cleanup_required': True}
                # Do not discard the actual ownership capability or its open log.
                _retained_build_resources.append((owner, stream))
                error.owner = owner
                error.cleanup_required = True
        if owner is None or closed:
            stream.close()
        save(output / 'build-failure.json', {'schema': 'blackbox.native-noise-build/1',
             'status': 'FAILED', 'error_type': type(error).__name__, 'cleanup': cleanup,
             'source_sha256': digest, 'source_identity': identity})
        raise


if __name__ == '__main__':
    require(len(sys.argv) == 3 and sys.argv[1] == '--compile-worker', 'NATIVE_NOISE_BUILD_WORKER_ARGUMENTS')
    raise SystemExit(_compile_worker(Path(sys.argv[2])))
