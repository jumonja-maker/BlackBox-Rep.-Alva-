"""Complete an explicitly approved release by numeric draft ID, never by tag lookup.

The caller creates/uploads the draft only after full exact-SHA QA and offline
archive verification. This step rechecks every server digest and refuses to
replace an existing public release. No delete, force-tag or overwrite operation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.release_gate import VERSION


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def api(endpoint, *, method='GET', data=None):
    command = ['gh', 'api', endpoint, '--method', method,
               '-H', 'Accept: application/vnd.github+json']
    payload = None
    if data is not None:
        command += ['--input', '-']
        payload = json.dumps(data)
    result = subprocess.run(command, input=payload, text=True,
                            capture_output=True, timeout=90, check=True)
    return json.loads(result.stdout)


def releases(client, repo):
    result = []
    for page in range(1, 21):
        rows = client(f'repos/{repo}/releases?per_page=100&page={page}')
        require(isinstance(rows, list), 'INVALID_RELEASE_LIST')
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ValueError('RELEASE_LIST_BUDGET_EXCEEDED')


def require_main_and_tag(client, repo, sha, tag, *, absent=False):
    head = client(f'repos/{repo}/git/ref/heads/main')
    require(head.get('object', {}).get('sha') == sha, 'MAIN_MOVED')
    refs = client(f'repos/{repo}/git/matching-refs/tags/{tag}')
    require(isinstance(refs, list), 'INVALID_TAG_LIST')
    exact = [r for r in refs if r.get('ref') == 'refs/tags/'+tag]
    if absent:
        require(not exact, 'RELEASE_TAG_ALREADY_EXISTS')
    else:
        require(not exact or (len(exact) == 1 and
                exact[0].get('object', {}).get('type') == 'commit' and
                exact[0]['object'].get('sha') == sha), 'RELEASE_TAG_CONFLICT')


def preflight(client, repo, sha, tag):
    require_main_and_tag(client, repo, sha, tag, absent=True)
    require(not any(r.get('tag_name') == tag for r in releases(client, repo)),
            'RELEASE_OR_DRAFT_ALREADY_EXISTS')


def validate_draft(draft, sha, tag, archive):
    require(type(draft.get('id')) is int and draft['id'] > 0, 'INVALID_DRAFT_ID')
    require(draft.get('draft') is True and draft.get('prerelease') is False and
            draft.get('tag_name') == tag and draft.get('target_commitish') == sha,
            'DRAFT_IDENTITY_MISMATCH')
    paths = [Path(archive), Path(str(archive)+'.sha256')]
    assets = draft.get('assets', [])
    require(len(assets) == 2 and {a.get('name') for a in assets} == {p.name for p in paths},
            'DRAFT_ASSET_INVENTORY_MISMATCH')
    for path in paths:
        asset = next(a for a in assets if a['name'] == path.name)
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(asset.get('state') == 'uploaded' and
                asset.get('size') == path.stat().st_size and
                asset.get('digest') == 'sha256:'+checksum, 'DRAFT_ASSET_DIGEST_MISMATCH')
    return draft['id']


def publish(client, repo, sha, tag, archive):
    candidates = [r for r in releases(client, repo) if r.get('tag_name') == tag]
    require(len(candidates) == 1, 'DRAFT_NOT_UNIQUE')
    release_id = validate_draft(candidates[0], sha, tag, archive)
    # Read by returned immutable release ID: unpublished tags are not resolvable.
    draft = client(f'repos/{repo}/releases/{release_id}')
    require(validate_draft(draft, sha, tag, archive) == release_id, 'DRAFT_ID_CHANGED')
    require_main_and_tag(client, repo, sha, tag)
    result = client(f'repos/{repo}/releases/{release_id}', method='PATCH',
                    data={'draft':False, 'prerelease':False, 'make_latest':'true'})
    require(result.get('id') == release_id and result.get('draft') is False and
            result.get('prerelease') is False and result.get('tag_name') == tag and
            result.get('target_commitish') == sha and result.get('published_at'),
            'PUBLICATION_NOT_CONFIRMED')
    tag_ref = client(f'repos/{repo}/git/ref/tags/{tag}')
    require(tag_ref.get('object', {}).get('type') == 'commit' and
            tag_ref['object'].get('sha') == sha, 'PUBLISHED_TAG_SOURCE_MISMATCH')
    return {'status':'PUBLISHED', 'release_id':release_id, 'tag':tag,
            'source_sha':sha, 'url':result.get('html_url')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    sha = os.environ.get('GITHUB_SHA', '')
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)), 'INVALID_REPOSITORY')
    require(bool(re.fullmatch('[0-9a-f]{40}', sha)) and
            sha == os.environ.get('ACCEPTED_SHA') and
            os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
            os.environ.get('GITHUB_REF') == 'refs/heads/main', 'EXPLICIT_MAIN_APPROVAL_REQUIRED')
    tag = 'v'+VERSION
    if args.preflight:
        preflight(api, repo, sha, tag)
        print('UNUSED_RELEASE_TAG_CONFIRMED', tag)
    else:
        require(args.archive.name == 'BLACK.BOX-Universal-Windows.zip', 'INVALID_ARCHIVE_NAME')
        require(args.report is not None and not args.report.exists(), 'NEW_REPORT_REQUIRED')
        result = publish(api, repo, sha, tag, args.archive)
        with args.report.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
