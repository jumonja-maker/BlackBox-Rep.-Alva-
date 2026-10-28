"""One-shot, owner-authorized v0.5.0 integration. No network or publication here."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import subprocess

BASE = '963f27b1976770ba38608950ca4168eca2607a9f'
BASE_TREE = 'd8e45d3ce49862a8fe620b83451a370de2db57af'
MAIN = '36885efb5eef6552c06e7a2d9d0f3b2219a6c87d'
TREE = 'ceb71723118733641b32a0af052a1c2925064390'
COMPRESSED_SHA = '906c0b44ce296d3e9c3b5a4b1c2ad3896ac4a6950f20de602b3e574bb68ce6fc'
PATCH_SHA = 'e36d7de863eb014d07729b28bdf9707d9c646acddf7637b11ad4530aaf261d78'


def git(*args, data=None):
    return subprocess.run(['git', *args], input=data, check=True,
                          stdout=subprocess.PIPE).stdout.decode('utf-8').strip()


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def main():
    # Read and verify every payload byte BEFORE checking out the base which
    # intentionally removes this single-use request from the working tree.
    folder = Path(__file__).resolve().parent
    packed = b''.join((folder / f'v050.patch.gz.part{i:02}').read_bytes()
                      for i in range(7))
    require(len(packed) == 36960 and hashlib.sha256(packed).hexdigest() == COMPRESSED_SHA,
            'RELEASE_REQUEST_COMPRESSED_DIGEST_MISMATCH')
    patch = gzip.decompress(packed)
    require(len(patch) == 128142 and hashlib.sha256(patch).hexdigest() == PATCH_SHA,
            'RELEASE_REQUEST_PATCH_DIGEST_MISMATCH')
    request_head = git('rev-parse', 'HEAD')
    require(not git('status', '--porcelain', '--untracked-files=no'),
            'RELEASE_WORKSPACE_NOT_CLEAN')
    require(git('rev-parse', BASE + '^{tree}') == BASE_TREE, 'RELEASE_BASE_TREE_MISMATCH')
    git('checkout', '--detach', BASE)
    git('apply', '--index', '--whitespace=error-all', '-', data=patch)
    git('diff', '--cached', '--check')
    actual = git('write-tree')
    require(actual == TREE, 'RELEASE_FINAL_TREE_MISMATCH')
    git('diff', '--exit-code')
    record = {'version': '0.5.0', 'tree': actual, 'base': BASE,
              'expected_main': MAIN, 'request_head': request_head,
              'patch_sha256': PATCH_SHA, 'publication': 'NOT_STARTED'}
    print(json.dumps(record))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            for name, value in record.items():
                output.write(f'{name}={value}\n')


if __name__ == '__main__':
    main()
