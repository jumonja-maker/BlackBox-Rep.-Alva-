"""Publish v0.5.4 only from the successful main CI of owner-approved PR #27.

No GitHub Actions Artifacts, extra machines, manual runner, or force-tag.
GitHub Release assets are uploaded on the same ephemeral Windows runner as
the verified ZIP. Existing releases/tags are never replaced.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from blackbox_universal import __version__
from tools.publish_verified_draft import api, preflight, publish, require
from tools.release_gate import VERSION, verify_archive

TAG = 'v0.5.4'
CI_NAME = 'BLACK.BOX Universal - independent Windows build and release'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    args = parser.parse_args()
    repo = os.getenv('GITHUB_REPOSITORY', '')
    sha = os.getenv('GITHUB_SHA', '')
    require(os.getenv('GITHUB_ACTIONS') == 'true' and
            os.getenv('GITHUB_EVENT_NAME') == 'workflow_run' and
            os.getenv('GITHUB_REF') == 'refs/heads/main',
            'EXACT_OWNER_APPROVED_MAIN_RUN_REQUIRED')
    require(bool(re.fullmatch('[0-9a-f]{40}', sha)), 'INVALID_SOURCE_SHA')
    require(__version__ == VERSION == '0.5.4', 'VERSION_MISMATCH')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    run = event.get('workflow_run') or {}
    require(run.get('conclusion') == 'success' and
            run.get('event') == 'push' and
            run.get('name') == CI_NAME and
            run.get('head_branch') == 'main' and
            run.get('head_sha') == sha and
            (run.get('head_repository') or {}).get('full_name') == repo,
            'GREEN_SAME_SHA_MAIN_QA_REQUIRED')
    main_ref = api(f'repos/{repo}/git/ref/heads/main')
    pr = api(f'repos/{repo}/pulls/27')
    require(main_ref.get('object', {}).get('sha') == sha and
            pr.get('merged') is True and
            pr.get('merge_commit_sha') == sha,
            'EXACT_OWNER_APPROVED_PR27_MERGE_REQUIRED')
    require(args.archive.is_file() and
            args.archive.name == 'BLACK.BOX-Universal-Windows.zip',
            'RELEASE_ARCHIVE_MISSING')
    checksum = Path(str(args.archive) + '.sha256')
    require(checksum.is_file(), 'CHECKSUM_FILE_MISSING')
    with args.archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(checksum.read_text(encoding='utf-8-sig').strip() ==
            f'{digest}  {args.archive.name}', 'CHECKSUM_MISMATCH')
    tree_sha = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    require(verify_archive(args.archive, sha, tree_sha) is not None,
            'ZIP_INVENTORY_OR_PROVENANCE_INVALID')
    preflight(api, repo, sha, TAG)
    subprocess.run(['gh', 'release', 'create', TAG, str(args.archive),
                    str(checksum), '--draft', '--target', sha, '--title',
                    'BLACK.BOX Universal v0.5.4 — Evidence Graph & Guided Diagnostics',
                    '--notes-file', 'docs/RELEASE_v0.5.4.md'],
                   check=True, timeout=900)
    result = publish(api, repo, sha, TAG, args.archive)
    require(result['status'] == 'PUBLISHED', 'PUBLICATION_NOT_CONFIRMED')
    report = {'status':'PUBLISHED', 'source_sha':sha,
              'sha256':digest, 'upstream_ci_run':run.get('id'), 'release':result}
    print(json.dumps(report, indent=2))
    if os.getenv('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write('## BLACK.BOX v0.5.4 — verified release\n\n')
            stream.write(f'- Source SHA: {sha}\n')
            stream.write(f'- ZIP SHA-256: {digest}\n')
            stream.write(f"- Upstream CI run: {run.get('id')}\n")
            stream.write(f"- Official GitHub Release: {result.get('url')}\n")
            stream.write('- GitHub Actions Artifacts used: 0\n')

if __name__ == '__main__':
    main()
