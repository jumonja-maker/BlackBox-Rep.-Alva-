"""Actual hosted Windows compiled clients from source or frozen preparation.

Known failed Emit calls are client statements, never an OS lost-event count.
The frozen generator runs outside the checkout without Python on PATH.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
TOKEN = 'BLACKBOX_PUBLIC_SDK_QA_TOKEN_00001'

CS_FAILURE_PROGRAM = '''class Program {
  static int Main() {
    var bb = new BlackBoxEvents("blackbox-config.json");
    if (bb.Emit("oversized", attributes: new { payload = new string('x', 9000) })) return 10;
    if (bb.Emit("unsupported", attributes: new System.Action(() => {}))) return 11;
    return bb.Emit("blackbox.ready") ? 0 : 1;
  }
}
'''


def cpp_failure_program(event_path, token=TOKEN):
    filename = json.dumps(str(event_path), ensure_ascii=True)
    return ('#include "BlackBoxEvents.hpp"\nint main(){\n'
            '  BlackBoxEvents bb(L' + filename + ', "' + token + '");\n'
            '  if(bb.emit(std::string(9000, \'x\')))return 10;\n'
            '  HANDLE held=CreateFileW(L' + filename + ',GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);\n'
            '  if(held==INVALID_HANDLE_VALUE)return 11;\n'
            '  bool unexpected=bb.emit("share-denied");\n'
            '  if(!CloseHandle(held))return 12;\n'
            '  if(unexpected)return 13;\n'
            '  return bb.emit("blackbox.ready")?0:1;\n}\n')


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def hosted():
    require(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'SDK_QA_REQUIRES_GITHUB_HOSTED_WINDOWS')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare_main(argv):
    """Hidden app dispatch; this exact generator is also inside the frozen EXE."""
    hosted()
    parser = argparse.ArgumentParser()
    parser.add_argument('--qa-sdk-prepare', type=Path, required=True)
    parser.add_argument('--qa-commit-sha', required=True)
    args = parser.parse_args(argv)
    from blackbox_universal.provenance import source_identity
    from blackbox_core.preparation import write_preparation
    identity = source_identity(args.qa_commit_sha)
    require(identity.get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD', 'SDK_PREPARATION_SOURCE_MISMATCH')
    root = args.qa_sdk_prepare.resolve()
    root.mkdir(parents=True, exist_ok=False)
    files = {}
    for kind in ('cs', 'cpp'):
        folder = root / kind
        write_preparation(folder, folder / 'events.jsonl', TOKEN)
        files[kind] = {path.name: digest(path) for path in folder.iterdir() if path.is_file()}
    proof = {'status': 'PASS', 'source_sha': args.qa_commit_sha, 'source_identity': identity,
             'frozen': bool(getattr(sys, 'frozen', False)), 'files': files}
    (root / 'preparation-source.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
    return 0


def verify_event(path, pid, clock):
    """Independent file readback plus the actual incremental reader."""
    from blackbox_core.instrumentation import EventTail
    raw = Path(path).read_bytes()
    require(0 < len(raw) <= 8192 and len(raw.splitlines()) == 1, 'SDK_EXPECTED_ONE_RECOVERED_EVENT')
    value = json.loads(raw)
    require(value.get('schema_version') == 1 and value.get('pid') == pid and
            type(value.get('tid')) is int and value['tid'] > 0 and value.get('token') == TOKEN and
            value.get('seq') == 3 and value.get('client_dropped') == 2 and
            value.get('kind') == 'blackbox.ready' and value.get('source_clock') == clock,
            'SDK_COMPILED_DROP_RECOVERY_RECORD_MISMATCH')
    reader = EventTail(path, TOKEN, pid)
    rows = reader.poll()
    require(reader.ready and reader.invalid == 0 and reader.client_dropped == 2 and
            len(rows) == 1 and rows[0]['seq'] == 3, 'SDK_ACTUAL_READER_DID_NOT_PRESERVE_CLIENT_FAILURE_COUNT')
    return {'pid': pid, 'event_sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'seq': 3, 'client_failed_emit_calls': 2, 'actual_reader_ready': True,
            'source_clock': clock, 'os_loss': 'NOT_MEASURED', 'source_trust': 'APP_EVENTS_UNAUTHENTICATED'}


def run_client(command, folder, log_name, *, environment=None, timeout=120):
    with (folder / log_name).open('wb') as log:
        child = subprocess.Popen(command, cwd=folder, env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
            print('SDK_QA_CHILD_DEADLINE ' + log_name + ' FORCED_EXIT_FINALIZATION_UNCONFIRMED', flush=True)
            raise AssertionError('SDK_OWNED_BUILD_OR_CLIENT_DEADLINE') from None
    if code:
        print('SDK_QA_CHILD_FAILURE ' + log_name + '\n' +
              (folder / log_name).read_bytes()[-8000:].decode('utf-8', 'replace'), flush=True)
        error = folder / 'blackbox-sdk-qa-error.txt'
        if error.is_file():
            print('SDK_QA_PREPARATION_FAILURE ' + error.read_text(encoding='utf-8')[-8000:], flush=True)
    require(code == 0, 'SDK_COMPILED_CLIENT_OR_BUILD_FAILED_' + log_name)
    return child.pid


def main():
    hosted()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    from blackbox_universal.provenance import source_identity
    from tools.qa_deep_inspection import compiler_environment
    require(source_identity(args.source_sha).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'SDK_QA_CHECKOUT_MISMATCH')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    outside = output / 'outside-source'
    outside.mkdir()
    generated = output / 'generated'
    command = ([str(args.exe.resolve(strict=True))] if args.exe else [sys.executable, str(ROOT / 'app.py')])
    command += ['--qa-sdk-prepare', str(generated), '--qa-commit-sha', args.source_sha]
    environment = dict(os.environ)
    if args.exe:
        system = Path(os.environ['SystemRoot'])
        environment['PATH'] = os.pathsep.join((str(system / 'System32'), str(system)))
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)
    run_client(command, outside, 'preparation.log', environment=environment, timeout=60)
    proof = json.loads((generated / 'preparation-source.json').read_text(encoding='utf-8'))
    require(proof.get('status') == 'PASS' and proof.get('source_sha') == args.source_sha and
            proof.get('frozen') is bool(args.exe) and
            proof.get('source_identity', {}).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD',
            'SDK_ACTUAL_PREPARATION_RECEIPT_MISMATCH')
    for kind, files in proof['files'].items():
        require(all(digest(generated / kind / name) == expected for name, expected in files.items()),
                'SDK_GENERATED_FILE_CHANGED_BEFORE_COMPILATION')
    cs = generated / 'cs'
    (cs / 'Client.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>', encoding='utf-8')
    (cs / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>', encoding='utf-8')
    (cs / 'Program.cs').write_text(CS_FAILURE_PROGRAM, encoding='utf-8')
    run_client(['dotnet', 'build', 'Client.csproj', '--configuration', 'Release', '--output', 'out',
                '--verbosity', 'quiet', '--disable-build-servers', '-p:UseSharedCompilation=false', '-nodeReuse:false'],
               cs, 'compile.log')
    cs_pid = run_client(['dotnet', str(cs / 'out' / 'Client.dll')], cs, 'client.log', timeout=20)
    proof['csharp'] = verify_event(cs / 'events.jsonl', cs_pid, 'DOTNET_STOPWATCH')
    cpp = generated / 'cpp'
    (cpp / 'main.cpp').write_text(cpp_failure_program(cpp / 'events.jsonl'), encoding='utf-8')
    compiler_output = output / 'compiler-environment'
    compiler_output.mkdir()
    compiler, compiler_env = compiler_environment(compiler_output)
    executable = cpp / 'client.exe'
    run_client([compiler, '/nologo', '/EHsc', '/std:c++17', str(cpp / 'main.cpp'), '/Fe:' + str(executable)],
               cpp, 'compile.log', environment=compiler_env)
    cpp_pid = run_client([str(executable)], cpp, 'client.log', timeout=20)
    proof['cpp'] = verify_event(cpp / 'events.jsonl', cpp_pid, 'WIN32_GETTICKCOUNT64')
    require(all(digest(generated / kind / name) == expected for kind, files in proof['files'].items()
                for name, expected in files.items()), 'SDK_ORIGINAL_GENERATED_FILES_CHANGED')
    proof.update(exe_sha256=digest(args.exe) if args.exe else None,
                 scope='ACTUAL_COMPILED_GENERATED_CSHARP_CPP_CLIENT_FAILURE_RECOVERY', publication=False)
    (output / 'sdk-clients.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
    print('SDK_CLIENTS_RECEIPT ' + json.dumps(proof, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
