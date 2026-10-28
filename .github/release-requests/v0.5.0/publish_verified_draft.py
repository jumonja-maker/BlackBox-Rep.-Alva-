"""Complete the explicit owner-approved release after draft lookup failed.

Reuse the exact already-tested source/archive and existing uploaded draft.
Never rebuild, weaken a code-test gate, replace an asset, or touch an old tag.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = 'jumonja-maker/BlackBox-Rep.-Alva-'
SOURCE = '765156068a2d2f0171be4d048e74c7676feba143'
TREE = 'ceb71723118733641b32a0af052a1c2925064390'
RUN = 40692494930
RELEASE = 426702785
ZIP_SHA = '0d68cbb558e12b2f2a4839d2212a537cefd60d3250da31443b0fa75bf1eb6be1'
OLD_ZIP_SHA = '431a87c130e9895761fe083af3391e0a6fb08fa64337fac757e70ac9258e2f61'
REQUIRED_JOBS = {
    'Windows shell / read-only observer',
    'Linux compatibility check (independent of Windows release)',
    'Windows portable exe',
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def api(endpoint, *, method='GET', payload=None):
    command = ['gh', 'api', '--method', method, f'repos/{REPO}/{endpoint}']
    if payload is not None:
        command += ['--input', '-']
    response = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                              text=True, capture_output=True, check=True, timeout=60)
    return json.loads(response.stdout)


def validate_jobs(run, jobs):
    require(run['id'] == RUN and run['head_sha'] == SOURCE and
            run['head_branch'] == 'main' and run['event'] == 'workflow_dispatch' and
            run['status'] == 'completed', 'WRONG_OR_INCOMPLETE_ACCEPTANCE_RUN')
    selected = [j for j in jobs if j['name'] in REQUIRED_JOBS]
    require(len(selected) == 3 and {j['name'] for j in selected} == REQUIRED_JOBS,
            'MISSING_OR_DUPLICATE_REQUIRED_JOBS')
    require(all(j['status'] == 'completed' and j['conclusion'] == 'success' and
                j['head_sha'] == SOURCE and j['run_id'] == RUN for j in selected),
            'REQUIRED_CODE_OR_PORTABLE_GATE_FAILED')
    # The old run's publication step failed after upload. Its failure is kept
    # in the audit trail, never misrepresented as a passing workflow run.
    other = [j for j in jobs if j['name'] not in REQUIRED_JOBS]
    require(len(other) == 1 and other[0]['name'] ==
            'Publish verified BLACK.BOX v0.5.0 (exact approved main SHA)' and
            other[0]['status'] == 'completed' and other[0]['conclusion'] == 'failure',
            'UNEXPECTED_ACCEPTANCE_RUN_FAILURE')


def validate_draft(release, archive, notes):
    require(release['id'] == RELEASE and release['tag_name'] == 'v0.5.0' and
            release['target_commitish'] == SOURCE and release['draft'] is True and
            release['prerelease'] is False and
            release['author']['login'] == 'github-actions[bot]', 'WRONG_DRAFT_RELEASE')
    require(release['body'].strip() == notes.strip(), 'RELEASE_NOTES_CHANGED')
    assets = release['assets']
    names = {archive.name, archive.name + '.sha256'}
    require(len(assets) == 2 and {a['name'] for a in assets} == names,
            'UNEXPECTED_DRAFT_ASSETS')
    for item in assets:
        file = archive.parent / item['name']
        with file.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(item['state'] == 'uploaded' and item['size'] == file.stat().st_size and
                item['digest'] == 'sha256:' + checksum, 'DRAFT_ASSET_DIGEST_MISMATCH')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and
            os.environ.get('GITHUB_REF') == 'refs/heads/release/decoder-v0.5.0' and
            os.environ.get('GITHUB_ACTOR') == 'jumonja-maker', 'UNAUTHORIZED_RELEASE_CONTEXT')
    source = args.source.resolve(strict=True)
    archive = args.archive.resolve(strict=True)
    require(archive.name == 'BLACK.BOX-Universal-Windows.zip', 'WRONG_RELEASE_FILENAME')
    for rev, expected in [('HEAD', SOURCE), ('HEAD^{tree}', TREE)]:
        actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', rev],
                                         text=True).strip()
        require(actual == expected, 'RELEASE_SOURCE_MISMATCH')
    require(api('git/ref/heads/main')['object']['sha'] == SOURCE, 'MAIN_CHANGED')
    require(api(f'git/commits/{SOURCE}')['tree']['sha'] == TREE, 'SOURCE_TREE_CHANGED')
    run = api(f'actions/runs/{RUN}')
    jobs = api(f'actions/runs/{RUN}/jobs?per_page=100')['jobs']
    validate_jobs(run, jobs)
    evidence = Path('publish-proof'); evidence.mkdir(exist_ok=True)
    (evidence / 'acceptance-jobs.json').write_text(json.dumps(jobs, indent=2), encoding='utf-8')
    with archive.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == ZIP_SHA,
                'NOT_THE_ACCEPTED_PORTABLE_ARCHIVE')
    subprocess.run([sys.executable, str(source / 'tools/release_gate.py'),
                    '--archive', str(archive), '--source-sha', SOURCE, '--source-tree', TREE,
                    '--report', str((evidence / 'release-verification.json').resolve())],
                   check=True, timeout=120)
    draft = api(f'releases/{RELEASE}')
    validate_draft(draft, archive, (source / 'docs/RELEASE_v0.5.0.md').read_text(encoding='utf-8'))
    (evidence / 'verified-draft.json').write_text(json.dumps(draft, indent=2), encoding='utf-8')
    require(api('git/ref/heads/main')['object']['sha'] == SOURCE, 'MAIN_CHANGED_BEFORE_PUBLICATION')
    # Drafts without a published tag are addressed by immutable release ID.
    published = api(f'releases/{RELEASE}', method='PATCH',
                    payload={'draft': False, 'make_latest': 'true'})
    require(published['id'] == RELEASE and published['draft'] is False and
            published['tag_name'] == 'v0.5.0' and published['target_commitish'] == SOURCE,
            'PUBLICATION_NOT_CONFIRMED')
    tag = api('git/ref/tags/v0.5.0')['object']
    if tag['type'] == 'tag':
        tag = api('git/tags/' + tag['sha'])['object']
    require(tag['type'] == 'commit' and tag['sha'] == SOURCE, 'RELEASE_TAG_MISMATCH')
    require(api('releases/latest')['id'] == RELEASE, 'LATEST_RELEASE_NOT_CONFIRMED')
    old = api('releases/tags/v0.4.2')
    require(old['id'] == 424668017 and not old['draft'] and any(
        a['name'] == archive.name and a['digest'] == 'sha256:' + OLD_ZIP_SHA
        for a in old['assets']), 'OLD_RELEASE_NOT_PRESERVED')
    result = {'status': 'PUBLISHED_VERIFIED', 'release_id': RELEASE, 'tag': 'v0.5.0',
              'source_sha': SOURCE, 'source_tree': TREE, 'archive_sha256': ZIP_SHA,
              'code_qa_run': RUN, 'publication_run': os.environ['GITHUB_RUN_ID'],
              'previous_publication_error': 'DRAFT_LOOKUP_BY_UNPUBLISHED_TAG',
              'old_v042_preserved': True, 'url': published['html_url']}
    (evidence / 'publication-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (evidence / 'published-release.json').write_text(json.dumps(published, indent=2), encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
