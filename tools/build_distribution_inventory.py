"""Build-time inventory and concrete third-party notices for a portable folder.

This records files and installed build-environment metadata, not a claim that
all environment packages are bundled, a complete native SCA, or a legal audit.
Existing payload content and decoder notices are never rewritten.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
NOTICES = 'third_party_notices'
MANIFEST = 'DISTRIBUTION-INVENTORY.json'
PYSIDE_VERSION = '6.11.3'
PYTHON_FALLBACK_VERSION = '3.11.14'
QT_LICENSES = ('BSD-3-Clause.txt', 'GPL-2.0-only.txt', 'GPL-3.0-only.txt',
               'Qt-GPL-exception-1.0.txt', 'LGPL-3.0-only.txt')
BLOCK_BYTES = 1024 * 1024


def reject_link(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Linked/reparse payload or notice path is unsupported: '+str(path))
    return info


def file_digest(path):
    before = reject_link(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Non-regular inventory file: '+str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(BLOCK_BYTES), b''):
            digest.update(block)
    after = reject_link(path)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('File changed while creating inventory: '+str(path))
    return {'bytes':after.st_size, 'sha256':digest.hexdigest()}


def regular_files(root):
    reject_link(root)
    for child in sorted(root.iterdir(), key=lambda p:p.name):
        info = reject_link(child)
        if stat.S_ISDIR(info.st_mode):
            yield from regular_files(child)
        elif stat.S_ISREG(info.st_mode):
            yield child
        else:
            raise ValueError('Non-regular payload entry: '+str(child))


def license_record(path):
    """License texts only: do not copy Python code merely under licenses/."""
    value = Path(str(path))
    if value.suffix.lower() not in ('', '.txt', '.md', '.rst', '.lic'):
        return False
    name = value.name.casefold()
    return (any(name.startswith(term) for term in ('license', 'licence', 'copying', 'notice', 'copyright'))
            or any(part.casefold() in ('licenses', 'licences') for part in value.parts[:-1]))


def identifier(value):
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', value).strip('._-')[:100]
    return value or 'unnamed'


def installed_packages():
    return list(metadata.distributions())


def plan_notices(distributions, *, python_version, python_prefix, vendor_root):
    records = []
    copies = []
    found_pyside = False
    ordered = sorted(distributions, key=lambda d:(str(d.metadata.get('Name', '')).casefold(), str(d.version)))
    for index, distribution in enumerate(ordered):
        name = str(distribution.metadata.get('Name', 'unnamed'))
        version = str(distribution.version)
        canonical = re.sub(r'[-_.]+', '-', name).casefold()
        if canonical in ('pyside6', 'pyside6-addons', 'pyside6-essentials', 'shiboken6'):
            if version != PYSIDE_VERSION:
                raise ValueError('Vendored Qt notices require matching installed '+name+'=='+PYSIDE_VERSION)
            found_pyside |= canonical == 'pyside6'
        record = {'name':name, 'version':version,
            'metadataLicense':distribution.metadata.get('License'),
            'metadataLicenseExpression':distribution.metadata.get('License-Expression'),
            'scope':'installed_build_environment_not_proof_of_bundling', 'licenseFiles':[]}
        prefix = Path('python-packages')/(str(index).zfill(3)+'-'+identifier(name)+'-'+identifier(version))
        site = Path(distribution.locate_file('')).resolve()
        for entry in distribution.files or ():
            if not license_record(entry):
                continue
            relative = Path(str(entry))
            # RECORD entries may legally point to external Scripts; notices
            # are restricted to regular files inside this distribution root.
            if relative.is_absolute() or '..' in relative.parts:
                continue
            source = Path(distribution.locate_file(entry))
            if not source.is_file():
                continue
            if not source.resolve().is_relative_to(site):
                raise ValueError('Distribution notice escaped its install root')
            for candidate in (source, *source.parents):
                reject_link(candidate)
                if candidate == site:
                    break
            destination = prefix/relative
            copies.append((source, destination))
            record['licenseFiles'].append((Path(NOTICES)/destination).as_posix())
        record['licenseTextStatus'] = 'TEXT_COPIED' if record['licenseFiles'] else 'METADATA_ONLY_REVIEW_REQUIRED'
        records.append(record)
    if not found_pyside:
        raise ValueError('Installed PySide6=='+PYSIDE_VERSION+' is required to validate Qt notice provenance')
    for name in QT_LICENSES:
        source = vendor_root/('pyside-'+PYSIDE_VERSION)/name
        if not source.is_file() or file_digest(source)['bytes'] == 0:
            raise ValueError('Required vendored Qt notice unavailable: '+name)
        copies.append((source, Path('pyside-'+PYSIDE_VERSION)/name))
    python_source = None
    for name in ('LICENSE.txt', 'LICENSE'):
        candidate = python_prefix/name
        if candidate.is_file():
            if file_digest(candidate)['bytes'] == 0:
                raise ValueError('Installed Python license is empty')
            python_source = candidate
            python_kind = 'installed_python_license'
            break
    if python_source is None:
        if python_version != PYTHON_FALLBACK_VERSION:
            raise ValueError('Python license missing for '+python_version+'; refusing mismatched vendored license')
        python_source = vendor_root/('CPython-'+PYTHON_FALLBACK_VERSION+'-LICENSE.txt')
        if not python_source.is_file() or file_digest(python_source)['bytes'] == 0:
            raise ValueError('Pinned CPython license unavailable')
        python_kind = 'repository_vendored_exact_python_version'
    copies.append((python_source, Path('python-runtime')/'LICENSE.txt'))
    provenance = {'python':{'version':python_version, 'licenseSource':python_kind,
        'licenseFile':NOTICES+'/python-runtime/LICENSE.txt'},
        'qtNotices':{'source':'repository_vendored', 'validatedPySideVersion':PYSIDE_VERSION,
                    'files':[(Path(NOTICES)/('pyside-'+PYSIDE_VERSION)/name).as_posix() for name in QT_LICENSES]}}
    return records, copies, provenance


def create_inventory(payload, output=None, *, distributions=None, python_version=None,
                     python_prefix=None, vendor_root=None):
    payload = Path(payload)
    reject_link(payload)
    if not payload.is_dir():
        raise ValueError('Existing portable payload directory required')
    payload = payload.resolve()
    embedded = payload/MANIFEST
    output = Path(output).absolute() if output is not None else embedded
    if output != embedded and output.resolve().is_relative_to(payload):
        raise ValueError('External report must be outside payload or use '+MANIFEST)
    for path in (payload/NOTICES, embedded, output):
        if os.path.lexists(path):
            raise FileExistsError('Inventory/notice destination already exists: '+str(path))
    # Complete source validation before adding anything to the portable folder.
    list(regular_files(payload))
    records, copies, provenance = plan_notices(
        installed_packages() if distributions is None else distributions,
        python_version=python_version or platform.python_version(),
        python_prefix=Path(python_prefix or sys.base_prefix),
        vendor_root=Path(vendor_root or ROOT/'docs'/'vendor'))
    targets = set()
    for source, relative in copies:
        key = relative.as_posix().casefold()
        if key in targets:
            raise ValueError('Colliding notice filenames')
        targets.add(key)
        file_digest(source)
    created_files = []
    created_dirs = []
    try:
        notices = payload/NOTICES
        notices.mkdir(); created_dirs.append(notices)
        for source, relative in copies:
            destination = notices/relative
            missing = []
            parent = destination.parent
            while not parent.exists():
                missing.append(parent); parent = parent.parent
            for parent in reversed(missing):
                parent.mkdir(); created_dirs.append(parent)
            before = file_digest(source)
            with source.open('rb') as reader, destination.open('xb') as writer:
                created_files.append(destination)
                for block in iter(lambda:reader.read(BLOCK_BYTES), b''):
                    writer.write(block)
            if file_digest(destination) != before or file_digest(source) != before:
                raise ValueError('Notice source changed during copy')
        files = [{'path':path.relative_to(payload).as_posix(), **file_digest(path)}
                 for path in regular_files(payload)]
        result = {'schema':'blackbox.distribution-inventory/1',
            'scope':'portable_file_hashes_and_installed_build_environment',
            'licenseCoverageReviewRequired':True, 'allNativeDllLicensesCertified':False,
            'allEnvironmentPackagesDeclaredBundled':False,
            'limitations':['Not a complete native SCA or legal compliance certificate',
                           'Metadata and copied notices do not prove every binary redistribution condition'],
            'pythonImplementation':platform.python_implementation(),
            'environmentPackages':records, 'noticeProvenance':provenance,
            'inventoryExcludes':[MANIFEST], 'files':files}
        encoded = (json.dumps(result, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
        for path in (embedded,) if output == embedded else (embedded, output):
            with path.open('xb') as stream:
                created_files.append(path); stream.write(encoded)
        return result
    except BaseException:
        # Only remove files/directories created by this call, never pre-existing
        # decoder files or unrelated contents introduced while we were running.
        for path in reversed(created_files):
            try:path.unlink()
            except OSError:pass
        for path in reversed(created_dirs):
            try:path.rmdir()
            except OSError:pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    result = create_inventory(args.payload, args.output)
    print(json.dumps({'status':'PASS', 'files':len(result['files']),
        'environmentPackages':len(result['environmentPackages']),
        'licenseCoverageReviewRequired':True}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
