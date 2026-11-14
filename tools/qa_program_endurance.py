"""Artifactless exact-source admission/readback for explicit long recording QA."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
REQUIRED_SHORT_JOBS = {
    'Windows source contracts / a-c', 'Windows source contracts / d-h',
    'Windows source contracts / i-r', 'Windows source contracts / s-z',
    'Real Windows GUI / process / ETW integration', 'Windows portable exe',
    'Linux compatibility check (independent of Windows release)',
    'Exact-main complete QA gate (artifactless)', 'BB-WAVE-02 exact-source lifecycle scope',
    'BB-WAVE-02 one-hour Standard and Incident Burst lifecycle',
    'BB-WAVE-02 required containers and lifecycle gate',
}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def validate_upstream(run, jobs, *, expected_sha, run_id, repository):
    require(re.fullmatch(r'[0-9a-f]{40}', expected_sha or '') and type(run_id) is int and run_id > 0,
            'PROGRAM_ENDURANCE_EXPECTED_SOURCE_OR_RUN_INVALID')
    require(type(run.get('id')) is int and run.get('id') == run_id and
            type(run.get('run_attempt')) is int and run['run_attempt'] > 0 and run.get('head_sha') == expected_sha and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('path', '').split('@', 1)[0] == '.github/workflows/shell-qa.yml' and
            run.get('name') == 'BLACK.BOX Universal - independent Windows build and release' and
            run.get('head_repository', {}).get('full_name') == repository,
            'PROGRAM_ENDURANCE_FULL_CI_NOT_SUCCESSFUL_EXACT_SOURCE')
    selected = {}
    for job in jobs:
        name = job.get('name')
        if name in REQUIRED_SHORT_JOBS:
            require(name not in selected, 'PROGRAM_ENDURANCE_DUPLICATE_SHORT_JOB')
            require(type(job.get('id')) is int and job['id'] > 0 and
                    job.get('run_id') == run_id and job.get('head_sha') == expected_sha and
                    job.get('status') == 'completed' and job.get('conclusion') == 'success',
                    'PROGRAM_ENDURANCE_MANDATORY_SHORT_JOB_NOT_SUCCESSFUL:' + name)
            selected[name] = job.get('id')
    require(set(selected) == REQUIRED_SHORT_JOBS, 'PROGRAM_ENDURANCE_MANDATORY_SHORT_JOB_MISSING')
    return {'status': 'PASS', 'source_sha': expected_sha, 'upstream_run_id': run_id,
            'upstream_attempt': run.get('run_attempt'), 'upstream_url': run.get('html_url'),
            'successful_jobs': selected, 'published_release': False}


def validate_verdict(verdict, *, expected_sha, profile, requested):
    require((profile, requested) in (('STANDARD', 90), ('DETAILED', 90),
                                    ('STANDARD', 19800), ('DETAILED', 3600)),
            'PROGRAM_ENDURANCE_UNAPPROVED_PROFILE_DURATION')
    require(verdict.get('result') == 'PASS' and verdict.get('profile') == profile and
            verdict.get('requested_seconds') == requested and
            type(verdict.get('actual_seconds')) in (int, float) and math.isfinite(verdict['actual_seconds']) and
            verdict['actual_seconds'] >= requested and
            verdict.get('source', {}).get('actual_source_sha') == expected_sha and
            verdict.get('source', {}).get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD' and
            verdict.get('primary_exit_code') == 'COMPLETED' and verdict.get('research_state') == 'COMPLETED' and
            verdict.get('normalized_status') == 'CLOSED' and verdict.get('schema2_writer_errors') == 0 and
            verdict.get('invalid_source_links') == 0, 'PROGRAM_ENDURANCE_VERDICT_NOT_COMPLETE_EXACT_SOURCE')
    cleanup = verdict.get('gui_cleanup', {})
    require(cleanup.get('status') == 'COMPLETED' and cleanup.get('helper_alive') is False and
            cleanup.get('window_visible') is False and type(cleanup.get('running_qthreads')) is int and
            cleanup['running_qthreads'] == 0, 'PROGRAM_ENDURANCE_GUI_OWNERS_UNCONFIRMED')
    health = verdict.get('recording_capture_health', {})
    require(type(health) is dict and health.get('recording_resources_closed') is True and
            health.get('finalization_errors') == [], 'PROGRAM_ENDURANCE_RECORDING_OWNERS_UNCONFIRMED')
    for key in ('persisted_recording_coverage',) + (('detailed_recording_coverage',) if profile == 'DETAILED' else ()):
        coverage = verdict.get(key, {})
        require(type(coverage) is dict and coverage.get('requested_seconds') == requested and
                type(coverage.get('persisted_span_seconds')) in (int, float) and
                math.isfinite(coverage['persisted_span_seconds']) and
                coverage['persisted_span_seconds'] >= requested - 10 and
                type(coverage.get('persisted_samples')) is int and
                coverage['persisted_samples'] >= max(2, math.ceil(max(0, requested - 10) / 10) + 1) and
                coverage.get('nonincreasing_timestamps') == 0 and
                type(coverage.get('max_sample_gap_seconds')) in (int, float) and
                math.isfinite(coverage['max_sample_gap_seconds']) and
                0 < coverage['max_sample_gap_seconds'] <= 30,
                'PROGRAM_ENDURANCE_SAVED_SERIES_COVERAGE_MISSING:' + key)
    hashes = verdict.get('source_hashes_sha256', {})
    require(set(hashes) == {'session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3'} and
            all(re.fullmatch(r'[0-9a-f]{64}', value or '') for value in hashes.values()),
            'PROGRAM_ENDURANCE_SOURCE_HASHES_MISSING')
    return verdict


def api(path):
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
               'Authorization': 'Bearer ' + os.environ['GH_TOKEN']}
    with urlopen(Request('https://api.github.com/' + path, headers=headers), timeout=30) as response:
        raw = response.read(4 * 1024**2 + 1)
    require(len(raw) <= 4 * 1024**2, 'PROGRAM_ENDURANCE_CI_RESPONSE_BUDGET')
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha', required=True)
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--repository')
    parser.add_argument('--verdict', type=Path)
    parser.add_argument('--profile', choices=('STANDARD', 'DETAILED'))
    parser.add_argument('--requested-seconds', type=int)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'PROGRAM_ENDURANCE_REQUIRES_HOSTED_CI')
    require(args.expected_sha == os.environ.get('GITHUB_SHA') and re.fullmatch(r'[0-9a-f]{40}', args.expected_sha),
            'PROGRAM_ENDURANCE_WORKFLOW_HEAD_MISMATCH')
    from blackbox_universal.provenance import source_identity
    identity = source_identity(args.expected_sha)
    require(identity.get('source_identity_status') == 'VERIFIED_EXPECTED_HEAD', 'PROGRAM_ENDURANCE_CHECKOUT_MISMATCH')
    if args.verdict:
        require(args.verdict.is_file() and not args.verdict.is_symlink() and args.verdict.stat().st_size <= 256 * 1024,
                'PROGRAM_ENDURANCE_VERDICT_MISSING_OR_UNBOUNDED')
        raw = args.verdict.read_bytes()
        verdict = json.loads(raw)
        proof = {'source_sha': args.expected_sha, 'profile': args.profile, 'requested_seconds': args.requested_seconds,
                 'verdict_sha256': hashlib.sha256(raw).hexdigest(), 'verdict_bytes': len(raw), 'verdict': verdict,
                 'scope': 'BOUNDED_90_SECOND_PREFLIGHT' if args.requested_seconds == 90 else 'ACTUAL_SOURCE_GUI_RECORDING_ENDURANCE',
                 'physical_windows_10_11': 'NOT_TESTED', 'secure_desktop': 'NOT_TESTED', 'published_release': False}
        try:
            validate_verdict(verdict, expected_sha=args.expected_sha, profile=args.profile, requested=args.requested_seconds)
        except Exception as error:
            print('PROGRAM_ENDURANCE_RECEIPT ' + json.dumps({**proof, 'status': 'FAIL',
                  'validation_error': str(error)}, sort_keys=True), flush=True)
            raise
        print('PROGRAM_ENDURANCE_RECEIPT ' + json.dumps({**proof, 'status': 'PASS'}, sort_keys=True), flush=True)
        return 0
    require(args.run_id is not None and args.repository == os.environ.get('GITHUB_REPOSITORY') and
            re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository or ''),
            'PROGRAM_ENDURANCE_UPSTREAM_ARGUMENTS_INVALID')
    prefix = 'repos/' + args.repository + '/actions/runs/' + str(args.run_id)
    run = api(prefix)
    jobs = []
    for page in range(1, 5):
        rows = api(prefix + '/jobs?filter=latest&per_page=100&page=' + str(page)).get('jobs', [])
        jobs.extend(rows)
        if len(rows) < 100:
            break
    else:
        raise AssertionError('PROGRAM_ENDURANCE_UPSTREAM_JOB_BUDGET')
    proof = validate_upstream(run, jobs, expected_sha=args.expected_sha, run_id=args.run_id, repository=args.repository)
    print('PROGRAM_ENDURANCE_UPSTREAM ' + json.dumps({**proof, 'source_identity': identity}, sort_keys=True), flush=True)
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
        stream.write('verified_sha=' + args.expected_sha + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
