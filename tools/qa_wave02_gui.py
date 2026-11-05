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


def comparison_export_summary(item):
    """Comparison-specific scalar telemetry; no paths or arbitrary metadata."""
    semantic = item['independent_semantic_readback']
    require(item.get('case') == 'R50-comparison'
            and item.get('language') in ('EN', 'RU')
            and semantic.get('schema') == 'blackbox.experiment-comparison.v1'
            and semantic.get('format') in ('json', 'html')
            and semantic['format'] == item.get('format'), 'WAVE02_GUI_COMPARISON_SUMMARY_KIND')
    for key, length in (('sha256', 64), ('before_run_id', 32), ('after_run_id', 32), ('operation_run_id', 32)):
        value = semantic.get(key)
        require(type(value) is str and len(value) == length
                and all(q in '0123456789abcdef' for q in value), 'WAVE02_GUI_COMPARISON_SUMMARY_ID')
    require(semantic['sha256'] == item.get('sha256')
            and type(semantic.get('bytes')) is int and 0 < semantic['bytes'] <= 8 * 1024**2
            and semantic['bytes'] == item.get('bytes')
            and type(semantic.get('source_count')) is int and semantic['source_count'] == 2
            and type(semantic.get('source_file_count')) is int and 6 <= semantic['source_file_count'] <= 16
            and semantic.get('comparison_status') == 'COMPARABLE'
            and semantic.get('method') == 'INDEPENDENT_STDLIB_COMPARISON_JSON_HTML'
            and semantic.get('semantic_readback_verified') is True
            and semantic.get('separate_call_receipt_verified') is True
            and semantic.get('stable_receipt_verified') is (semantic['format'] == 'html')
            and semantic.get('html_matches_json') is (semantic['format'] == 'html')
            and semantic.get('export_bytes_unchanged') is True
            and semantic.get('recording_sources_unchanged') is True
            and semantic.get('producer_authentication') == 'NOT_ESTABLISHED'
            and item.get('independent_readback') is True, 'WAVE02_GUI_COMPARISON_SEMANTIC_SUMMARY')
    return {'report_kind': 'COMPARISON', 'format': semantic['format'], 'language': item['language'],
        **{key: semantic[key] for key in ('sha256', 'bytes', 'source_count', 'source_file_count',
            'before_run_id', 'after_run_id', 'operation_run_id', 'comparison_status')},
        'semantic_verified': True, 'separate_call_receipt_verified': True,
        'no_clobber_verified': item.get('no_clobber_verified')
            if type(item.get('no_clobber_verified')) is bool else None}


def semantic_export_summaries(proof):
    """R20 graph telemetry, with an explicit R50 comparison-schema branch."""
    exports = proof.get('exports', [])
    require(type(exports) is list and len(exports) <= 16, 'WAVE02_GUI_EXPORT_SUMMARY_BUDGET')
    require(proof.get('status') != 'PASS' or bool(exports), 'WAVE02_GUI_EXPORT_RECEIPTS_MISSING')
    result = []
    for item in exports:
        require(type(item) is dict, 'WAVE02_GUI_EXPORT_SUMMARY_SHAPE')
        semantic = item.get('independent_semantic_readback')
        require(type(semantic) is dict, 'WAVE02_GUI_SEMANTIC_EXPORT_RECEIPT_MISSING')
        if semantic.get('schema') == 'blackbox.experiment-comparison.v1':
            result.append(comparison_export_summary(item))
            continue
        kind, case_id, digest = semantic.get('format'), semantic.get('case_id'), semantic.get('sha256')
        require(kind in ('json', 'html') and kind == item.get('format')
                and type(case_id) is str and len(case_id) == 64
                and all(q in '0123456789abcdef' for q in case_id) and case_id == item.get('case_id')
                and type(digest) is str and len(digest) == 64
                and all(q in '0123456789abcdef' for q in digest) and digest == item.get('sha256'),
                'WAVE02_GUI_EXPORT_SUMMARY_IDENTITY')
        for key, lower, upper in (('source_count', 1, 64), ('node_count', 0, 10000),
                                  ('edge_count', 0, 20000), ('bytes', 1, 64 * 1024**2)):
            require(type(semantic.get(key)) is int and lower <= semantic[key] <= upper,
                    'WAVE02_GUI_EXPORT_SUMMARY_COUNTER')
        require(semantic['bytes'] == item.get('bytes') and item.get('independent_readback') is True
                and semantic.get('semantic_readback_verified') is True
                and semantic.get('export_bytes_unchanged') is True
                and semantic.get('html_matches_json') is (kind == 'html')
                and semantic.get('method') == 'INDEPENDENT_STDLIB_JSON_AND_HTML_PARSER'
                and semantic.get('producer_authentication') == 'NOT_ESTABLISHED',
                'WAVE02_GUI_EXPORT_SEMANTIC_RECEIPT_INVALID')
        result.append({'case_id': case_id, 'format': kind, 'sha256': digest,
            **{key: semantic[key] for key in ('source_count', 'node_count', 'edge_count', 'bytes')},
            'semantic_verified': True,
            'no_clobber_verified': item['no_clobber_verified']
                if type(item.get('no_clobber_verified')) is bool else None})
    return result


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
    requested_scale = os.environ.get('QT_SCALE_FACTOR', '1')
    require(requested_scale in ('1', '1.25', '1.5', '2'), 'WAVE02_GUI_SCALE_NOT_IN_QA_MATRIX')
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
    if proof.get('status') == 'PASS':
        require(proof.get('scale') == requested_scale, 'WAVE02_GUI_CHILD_SCALE_MISMATCH')
        require(type(proof.get('frozen')) is bool and proof['frozen'] == bool(args.exe),
                'WAVE02_GUI_CHILD_FROZEN_IDENTITY_MISMATCH')
    summary = {'status': proof.get('status'), 'source_sha': args.source_sha,
        'container': scope['container'], 'frozen': bool(args.exe),
        'actual_frozen': proof.get('frozen') if type(proof.get('frozen')) is bool else None,
        'requested_scale': requested_scale,
        'actual_scale': proof.get('scale') if proof.get('scale') in ('1', '1.25', '1.5', '2') else None,
        'dpi_scope': 'QT_SCALE_FACTOR_SIMULATION',
        'exit_code': child.returncode, 'reason': proof.get('reason'),
        'child_deadline_exceeded': child_timeout,
        'source_identity': proof.get('source_identity'), 'case_ids': proof.get('case_ids'),
        'sections': proof.get('sections'), 'cleanup': proof.get('cleanup'),
        'r50_new_gui_capture': proof.get('r50_new_gui_capture'),
        'r50_coverage_languages': proof.get('r50_coverage_languages'),
        'exports': proof.get('exports'),
        'semantic_exports': semantic_export_summaries(proof),
        'r40_raw_dump_route': proof.get('r40_raw_dump_route'),
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
