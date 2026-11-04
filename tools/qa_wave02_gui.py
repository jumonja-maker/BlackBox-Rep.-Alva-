"""Launch actual source/frozen BB-WAVE-02 Qt acceptance with exact-head evidence."""
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
from tools.qa_deep_inspection import require, require_hosted_windows
from tools.qa_wave02_scope import load_scope


def main():
    require_hosted_windows()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--exe', type=Path)
    parser.add_argument('--container', choices=('r20', 'r30', 'r40', 'full'))
    args = parser.parse_args()
    scope = load_scope(args.container)
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    work = output / 'outside-source'; work.mkdir()
    child_output = output / 'child'
    command = ([str(args.exe.resolve(strict=True))] if args.exe else
               [str(Path(sys.executable).resolve()), str(ROOT / 'app.py')])
    command += ['--wave02-e2e', str(child_output), '--wave02-evidence',
        str(args.evidence_root.resolve(strict=True)), '--wave02-container', scope['container'],
        '--qa-commit-sha', args.source_sha]
    environment = dict(os.environ)
    environment['QT_QPA_PLATFORM'] = 'offscreen'
    if args.exe:
        system_root = Path(os.environ['SystemRoot'])
        environment['PATH'] = str(system_root / 'System32') + ';' + str(system_root)
        environment.pop('PYTHONPATH', None)
    child_timeout = False
    with (output / 'child-console.log').open('wb') as log:
        child = subprocess.Popen(command, cwd=work, env=environment,
            stdout=log, stderr=subprocess.STDOUT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            child.wait(timeout=240)
        except subprocess.TimeoutExpired:
            child_timeout = True
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=10)
    result_file = child_output / 'wave02-gui.json'
    if result_file.is_file():
        proof = json.loads(result_file.read_text(encoding='utf-8'))
    else:
        proof = {'status': 'FAIL', 'reason': 'WAVE02_GUI_PROOF_NOT_WRITTEN'}
    summary = {'status': proof.get('status'), 'source_sha': args.source_sha,
        'container': scope['container'], 'frozen': bool(args.exe),
        'exit_code': child.returncode, 'reason': proof.get('reason'),
        'child_deadline_exceeded': child_timeout,
        'source_identity': proof.get('source_identity'), 'case_ids': proof.get('case_ids'),
        'sections': proof.get('sections'), 'cleanup': proof.get('cleanup'),
        'physical_windows_10_11': 'NOT_TESTED', 'physical_secure_desktop': 'NOT_TESTED'}
    if result_file.is_file():
        summary['receipt_sha256'] = hashlib.sha256(result_file.read_bytes()).hexdigest()
    if proof.get('status') != 'PASS':
        log = output / 'child-console.log'
        print('WAVE02_GUI_FAILURE_CONSOLE ' + log.read_bytes()[-4096:].decode(errors='replace'), flush=True)
    print('WAVE02_GUI_RECEIPT ' + json.dumps(summary, sort_keys=True), flush=True)
    require(not child_timeout and child.returncode == 0 and proof.get('status') == 'PASS',
            'WAVE02_ACTUAL_GUI_FAILED_' + str(proof.get('reason')))


if __name__ == '__main__':
    main()
