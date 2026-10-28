"""Portable build inventory proof, with explicit fake build-environment fixtures."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.build_distribution_inventory import (
    MANIFEST, NOTICES, QT_LICENSES, create_inventory, file_digest, reject_link,
)


class Distribution:
    def __init__(self, name, version, site, files=()):
        self.version, self.site, self.files = version, site, files
        self.metadata = {'Name':name, 'License':'fixture declared license',
                         'License-Expression':'BSD-3-Clause'}
    def locate_file(self, path):
        return self.site/path


class DistributionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root/'portable'; self.payload.mkdir()
        (self.payload/'BLACK.BOX.exe').write_bytes(b'MZ synthetic native file fixture\0'*5000)
        decoder = self.payload/'decoder'; decoder.mkdir()
        (decoder/'NOTICE.txt').write_text('Existing decoder notice, must remain unchanged')
        self.site = self.root/'site'; self.site.mkdir()
        self.license = self.site/'psutil.dist-info'/'LICENSE'; self.license.parent.mkdir()
        self.license.write_text('Actual fixture license file, not metadata substitution')
        self.vendor = self.root/'vendor'; qt = self.vendor/'pyside-6.11.3'; qt.mkdir(parents=True)
        for name in QT_LICENSES:(qt/name).write_text('Fixture vendored license: '+name)
        (self.vendor/'CPython-3.11.14-LICENSE.txt').write_text('Fixture exact CPython license')
        self.prefix = self.root/'python'; self.prefix.mkdir()
        self.distributions = [Distribution('PySide6','6.11.3',self.site),
            Distribution('psutil','7.2.2',self.site,[Path('psutil.dist-info/LICENSE')]),
            Distribution('PyInstaller','6.20.0',self.site)]
        self.kwargs = dict(distributions=self.distributions, python_version='3.11.14',
                           python_prefix=self.prefix, vendor_root=self.vendor)

    def snapshot(self):
        return {p.relative_to(self.payload).as_posix():p.read_bytes()
                for p in self.payload.rglob('*') if p.is_file()}

    def test_real_payload_hashes_copied_text_and_partial_coverage_are_explicit(self):
        before = self.snapshot(); output = self.root/'inventory.json'
        result = create_inventory(self.payload, output, **self.kwargs)
        self.assertEqual(json.loads(output.read_text()), result)
        self.assertEqual((self.payload/MANIFEST).read_bytes(), output.read_bytes())
        rows = {row['path']:row for row in result['files']}
        self.assertNotIn(MANIFEST, rows)
        for name, data in before.items():
            self.assertEqual((self.payload/name).read_bytes(), data)
        for name, row in rows.items():
            data = (self.payload/name).read_bytes()
            self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(row['bytes'],len(data))
        psutil = next(p for p in result['environmentPackages'] if p['name']=='psutil')
        self.assertEqual(psutil['metadataLicenseExpression'],'BSD-3-Clause')
        self.assertEqual((self.payload/psutil['licenseFiles'][0]).read_bytes(),self.license.read_bytes())
        self.assertTrue(result['licenseCoverageReviewRequired'])
        self.assertFalse(result['allNativeDllLicensesCertified'])
        self.assertFalse(result['allEnvironmentPackagesDeclaredBundled'])
        missing = next(p for p in result['environmentPackages'] if p['name']=='PyInstaller')
        self.assertEqual(missing['licenseTextStatus'],'METADATA_ONLY_REVIEW_REQUIRED')
        self.assertEqual(result['noticeProvenance']['python']['licenseSource'],
                         'repository_vendored_exact_python_version')

    def test_repeat_and_existing_destination_are_no_clobber(self):
        create_inventory(self.payload, **self.kwargs)
        before = self.snapshot()
        with self.assertRaises(FileExistsError):create_inventory(self.payload, **self.kwargs)
        self.assertEqual(self.snapshot(),before)
        output = self.root/'existing.json'; output.write_bytes(b'never replace')
        other = self.root/'another-payload'; other.mkdir()
        (other/'decoder-notice.txt').write_text('preserve')
        with self.assertRaises(FileExistsError):create_inventory(other, output, **self.kwargs)
        self.assertEqual(output.read_bytes(),b'never replace')
        self.assertEqual(list(other.iterdir()),[other/'decoder-notice.txt'])

    def test_mismatched_versions_refuse_fallback_but_actual_python_license_is_used(self):
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError,'matching installed'):
            create_inventory(self.payload, **{**self.kwargs,'distributions':[
                Distribution('PySide6','6.10.0',self.site)]})
        with self.assertRaisesRegex(ValueError,'mismatched vendored'):
            create_inventory(self.payload, **{**self.kwargs,'python_version':'3.12.14'})
        self.assertEqual(self.snapshot(),before)
        (self.prefix/'LICENSE.txt').write_text('Actual installed fixture Python license')
        result = create_inventory(self.payload, **{**self.kwargs,'python_version':'3.12.14'})
        self.assertEqual(result['noticeProvenance']['python']['licenseSource'],'installed_python_license')
        self.assertEqual((self.payload/NOTICES/'python-runtime'/'LICENSE.txt').read_text(),
                         'Actual installed fixture Python license')

    def test_failed_copy_rolls_back_only_new_inventory_content(self):
        before = self.snapshot()
        actual = Path.open
        def fail_destination(path, mode='r', *args, **kwargs):
            if mode == 'xb' and path.name == 'LGPL-3.0-only.txt':
                raise OSError('Controlled destination write failure')
            return actual(path, mode, *args, **kwargs)
        with patch('pathlib.Path.open', fail_destination):
            with self.assertRaisesRegex(OSError,'Controlled destination'):
                create_inventory(self.payload, **self.kwargs)
        self.assertEqual(self.snapshot(),before)
        self.assertFalse((self.payload/NOTICES).exists())
        self.assertFalse((self.payload/MANIFEST).exists())

    def test_reparse_or_link_cannot_be_inventory_bytes(self):
        # Pure metadata branch is portable even on Windows without symlink rights.
        class Reparse:
            st_mode = 0o100644
            st_file_attributes = 0x400
        with patch('pathlib.Path.lstat', return_value=Reparse()):
            with self.assertRaisesRegex(ValueError,'reparse'):
                reject_link(self.payload/'BLACK.BOX.exe')
        # A symlink's metadata is similarly refused without following its target.
        class Link:
            st_mode = 0o120777
            st_file_attributes = 0
        with patch('pathlib.Path.lstat', return_value=Link()):
            with self.assertRaisesRegex(ValueError,'Linked'):
                file_digest(self.payload/'BLACK.BOX.exe')
