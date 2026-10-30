"""Offline release artifact verification. This module never publishes or downloads."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

VERSION = '0.5.4'
PREFIX = 'BLACK.BOX-Universal/'
MAX_UNCOMPRESSED = 2 * 1024**3
REQUIRED = (
    'BLACK.BOX-Universal.exe', 'BLACK.BOX-Maintenance.exe',
    '.blackbox-portable.json', 'LICENSE', 'README.md', 'README.ru.md',
    'LICENSING.md', 'INVESTIGATION-LICENSE.txt',
    '_internal/blackbox-build.json', 'decoder/BLACK.BOX-Decoder.exe',
    'decoder/decoder-manifest.json', 'decoder/notices/TraceEvent-LICENSE.txt',
    'diagnostic/BLACK.BOX-Diagnostic.exe',
    'diagnostic/_internal/blackbox-build.json', 'DISTRIBUTION-INVENTORY.json',
)

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def digest(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024*1024), b''):
        h.update(block)
    return h.hexdigest()

def verify_archive(path, source_sha, source_tree):
    require(bool(re.fullmatch('[0-9a-f]{40}', source_sha or '')) and
            bool(re.fullmatch('[0-9a-f]{40}', source_tree or '')), 'INVALID_SOURCE_IDENTITY')
    path = Path(path)
    require(path.name == 'BLACK.BOX-Universal-Windows.zip' and path.is_file()
            and not path.is_symlink(), 'INVALID_RELEASE_ARCHIVE')
    with zipfile.ZipFile(path) as archive:
        records = archive.infolist()
        require(sum(i.file_size for i in records) <= MAX_UNCOMPRESSED, 'ARCHIVE_SIZE_LIMIT')
        members = {}
        for item in records:
            name = item.filename.replace('\\', '/')
            parts = PurePosixPath(name).parts
            require(name.startswith(PREFIX) and '..' not in parts and
                    all(':' not in part for part in parts) and
                    not stat.S_ISLNK(item.external_attr >> 16), 'UNSAFE_ARCHIVE_ENTRY')
            require(name.casefold() not in members, 'DUPLICATE_ARCHIVE_ENTRY')
            members[name.casefold()] = item
        def contents(relative, limit=1024*1024):
            item = members.get((PREFIX + relative).casefold())
            require(item is not None and not item.is_dir() and 0 < item.file_size <= limit,
                    'MISSING_OR_OVERSIZED_RELEASE_FILE:' + relative)
            return archive.read(item)
        for name in REQUIRED:
            item = members.get((PREFIX + name).casefold())
            require(item is not None and not item.is_dir() and item.file_size > 0,
                    'MISSING_REQUIRED_RELEASE_FILE:' + name)
        provenance = json.loads(contents('_internal/blackbox-build.json', 4096))
        require(provenance.get('schema_version') == 1 and
                provenance.get('source_sha') == source_sha and
                provenance.get('source_tree_sha') == source_tree and
                provenance.get('tracked_worktree_clean') is True, 'FROZEN_SOURCE_MISMATCH')
        require(provenance.get('version') == VERSION, 'FROZEN_VERSION_MISMATCH')
        diagnostic_provenance = json.loads(contents(
            'diagnostic/_internal/blackbox-build.json', 4096))
        require(diagnostic_provenance == provenance, 'DIAGNOSTIC_SOURCE_IDENTITY_MISMATCH')
        # The packaged inventory is constructed *after* all EXEs, third-party
        # notices and the helper are staged. Revalidate its complete exact
        # inventory against the final ZIP, rather than just the build folder.
        inventory = json.loads(contents('DISTRIBUTION-INVENTORY.json', 4*1024*1024))
        require(isinstance(inventory, dict) and
                inventory.get('schema') == 'blackbox.distribution-inventory/1' and
                inventory.get('inventoryExcludes') == ['DISTRIBUTION-INVENTORY.json'],
                'INVALID_DISTRIBUTION_INVENTORY')
        inventory_files = inventory.get('files')
        require(isinstance(inventory_files, list) and 1 <= len(inventory_files) <= 20000,
                'INVALID_DISTRIBUTION_FILE_LIST')
        inventoried = set()
        diagnostic_count = 0
        for row in inventory_files:
            require(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'},
                    'INVALID_DISTRIBUTION_FILE_RECORD')
            relative = row['path']
            require(type(relative) is str and relative not in ('', '.') and
                    not relative.startswith('/') and not relative.endswith('/') and
                    '\\' not in relative and ':' not in relative and
                    '..' not in PurePosixPath(relative).parts and
                    PurePosixPath(relative).as_posix() == relative and
                    type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_UNCOMPRESSED and
                    isinstance(row['sha256'], str) and
                    re.fullmatch('[0-9a-f]{64}', row['sha256']),
                    'INVALID_DISTRIBUTION_FILE_RECORD')
            key = (PREFIX + relative).casefold()
            require(key not in inventoried, 'DUPLICATE_DISTRIBUTION_INVENTORY_ENTRY')
            inventoried.add(key)
            item = members.get(key)
            require(item is not None and not item.is_dir() and
                    item.filename == PREFIX + relative,
                    'MISSING_DISTRIBUTION_FILE:' + relative)
            require(item.file_size == row['bytes'],
                    'DISTRIBUTION_FILE_SIZE_MISMATCH:' + relative)
            with archive.open(item) as stream:
                require(digest(stream) == row['sha256'],
                        'DISTRIBUTION_FILE_HASH_MISMATCH:' + relative)
            if relative.startswith('diagnostic/'):
                diagnostic_count += 1
        all_payload_files = {key for key, item in members.items()
                             if not item.is_dir() and
                             key != (PREFIX + 'DISTRIBUTION-INVENTORY.json').casefold()}
        require(inventoried == all_payload_files, 'DISTRIBUTION_FILE_LIST_MISMATCH')
        require(diagnostic_count >= 2, 'DIAGNOSTIC_PAYLOAD_INCOMPLETE')
        manifest = json.loads(contents('decoder/decoder-manifest.json'))
        require(manifest.get('rid') == 'win-x64' and manifest.get('self_contained') is True
                and manifest.get('traceevent_package') == '4.0.0', 'DECODER_BUILD_NOT_VERIFIED')
        files = manifest.get('files')
        require(isinstance(files, dict) and files and 'BLACK.BOX-Decoder.exe' in files,
                'INVALID_DECODER_INVENTORY')
        expected = set()
        for relative, wanted in files.items():
            require(isinstance(relative, str) and not relative.startswith(('/', '\\')) and
                    '\\' not in relative and '..' not in PurePosixPath(relative).parts and
                    ':' not in relative and isinstance(wanted, str) and
                    re.fullmatch('[0-9a-f]{64}', wanted), 'INVALID_DECODER_INVENTORY')
            key = (PREFIX + 'decoder/' + relative).casefold()
            require(key not in expected, 'DUPLICATE_DECODER_INVENTORY')
            expected.add(key)
            require(key in members, 'MISSING_DECODER_FILE:' + relative)
            with archive.open(members[key]) as stream:
                require(digest(stream) == wanted, 'DECODER_FILE_HASH_MISMATCH:' + relative)
        actual = {key for key, item in members.items()
                  if key.startswith((PREFIX + 'decoder/').casefold()) and not item.is_dir()
                  and key != (PREFIX + 'decoder/decoder-manifest.json').casefold()}
        require(actual == expected, 'DECODER_INVENTORY_MISMATCH')
        for name in ('README.md', 'README.ru.md'):
            text = contents(name).decode('utf-8')
            require(text.startswith('> ') and 'DonJeoJesky@outlook.com' in text.splitlines()[0],
                    'AUTHOR_MESSAGE_OR_CONTACT_MISSING')
    with path.open('rb') as stream:
        checksum = digest(stream)
    return {'status': 'VERIFIED_RELEASE_ARCHIVE', 'version': VERSION,
            'source_sha': source_sha, 'source_tree_sha': source_tree,
            'archive': path.name, 'bytes': path.stat().st_size, 'sha256': checksum,
            'decoder_files_verified': len(files),
            'diagnostic_files_verified': diagnostic_count,
            'distribution_files_verified': len(inventoried),
            'release_published': False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--source-tree', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = verify_archive(args.archive, args.source_sha, args.source_tree)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
    with Path(str(args.archive) + '.sha256').open('x', encoding='ascii') as stream:
        stream.write(report['sha256'] + '  ' + args.archive.name + '\n')
    print('RELEASE_ARCHIVE_VERIFIED', report['source_sha'], report['sha256'])

if __name__ == '__main__':
    main()
