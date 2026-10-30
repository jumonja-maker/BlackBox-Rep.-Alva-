"""Offline publication invariants; no real release or network access."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from tools.release_gate import verify_archive, PREFIX, REQUIRED, VERSION

class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'BLACK.BOX-Universal-Windows.zip'
        self.files = {PREFIX + n: b'fixture' for n in REQUIRED}
        for n in ('README.md', 'README.ru.md'):
            self.files[PREFIX+n] = b'> Feedback: DonJeoJesky@outlook.com\n'
        self.files[PREFIX+'_internal/blackbox-build.json'] = json.dumps({
            'schema_version': 1, 'source_sha': 'a'*40, 'source_tree_sha': 'b'*40,
            'tracked_worktree_clean': True, 'version': VERSION}).encode()
        decoder = {n[len(PREFIX+'decoder/'):]: hashlib.sha256(b).hexdigest()
                   for n,b in self.files.items() if n.startswith(PREFIX+'decoder/')
                   and not n.endswith('decoder-manifest.json')}
        self.files[PREFIX+'decoder/decoder-manifest.json'] = json.dumps({
            'rid':'win-x64','self_contained':True,'traceevent_package':'4.0.0',
            'files':decoder}).encode()
        self.files[PREFIX+'diagnostic/_internal/blackbox-build.json'] = self.files[
            PREFIX+'_internal/blackbox-build.json']
        self._inventory()

    def _inventory(self):
        index = PREFIX + 'DISTRIBUTION-INVENTORY.json'
        entries = [{'path': n[len(PREFIX):], 'bytes': len(b),
                    'sha256': hashlib.sha256(b).hexdigest()}
                   for n,b in self.files.items() if n != index]
        self.files[index] = json.dumps({
            'schema': 'blackbox.distribution-inventory/1',
            'inventoryExcludes': ['DISTRIBUTION-INVENTORY.json'],
            'files': entries,
        }).encode()
    def write(self):
        with zipfile.ZipFile(self.path,'w') as z:
            for n,b in self.files.items():z.writestr(n,b)
    def check(self):
        self.write()
        return verify_archive(self.path,'a'*40,'b'*40)
    def test_complete_archive_is_not_a_claim_of_publication(self):
        result=self.check()
        self.assertEqual(result['status'],'VERIFIED_RELEASE_ARCHIVE')
        self.assertFalse(result['release_published'])
    def test_wrong_embedded_version_is_refused(self):
        key=PREFIX+'_internal/blackbox-build.json'
        data=json.loads(self.files[key]);data['version']='0.5.0'
        self.files[key]=json.dumps(data).encode()
        self._inventory()
        with self.assertRaisesRegex(ValueError,'FROZEN_VERSION_MISMATCH'):self.check()
    def test_wrong_source_is_refused(self):
        self.write()
        with self.assertRaisesRegex(ValueError,'FROZEN_SOURCE_MISMATCH'):
            verify_archive(self.path,'c'*40,'b'*40)
    def test_tampered_helper_is_refused(self):
        self.files[PREFIX+'decoder/BLACK.BOX-Decoder.exe']=b'tampered'
        with self.assertRaisesRegex(ValueError,'DISTRIBUTION_FILE_(SIZE|HASH)_MISMATCH'):self.check()
    def test_missing_diagnostic_helper_is_refused(self):
        del self.files[PREFIX+'diagnostic/BLACK.BOX-Diagnostic.exe']
        self._inventory()
        with self.assertRaisesRegex(ValueError,'MISSING_REQUIRED_RELEASE_FILE'):
            self.check()

    def test_diagnostic_helper_modified_after_inventory_is_refused(self):
        self.files[PREFIX+'diagnostic/BLACK.BOX-Diagnostic.exe'] = b'tampered'
        with self.assertRaisesRegex(ValueError,'DISTRIBUTION_FILE_(SIZE|HASH)_MISMATCH'):
            self.check()

    def test_diagnostic_provenance_must_match_gui(self):
        key=PREFIX+'diagnostic/_internal/blackbox-build.json'
        payload=json.loads(self.files[key]);payload['source_sha']='c'*40
        self.files[key]=json.dumps(payload).encode()
        self._inventory()
        with self.assertRaisesRegex(ValueError,'DIAGNOSTIC_SOURCE_IDENTITY_MISMATCH'):
            self.check()

    def test_diagnostic_runtime_file_missing_or_changed_is_refused(self):
        key = PREFIX+'diagnostic/_internal/native-runtime.dll'
        self.files[key] = b'Native diagnostic fixture'
        self._inventory()
        del self.files[key]
        with self.assertRaisesRegex(ValueError,'MISSING_DISTRIBUTION_FILE'):
            self.check()
        self.files[key] = b'Tampered diagnostic runtime'
        with self.assertRaisesRegex(ValueError,'DISTRIBUTION_FILE_(SIZE|HASH)_MISMATCH'):
            self.check()

    def test_uninventoried_diagnostic_file_is_refused(self):
        self.files[PREFIX+'diagnostic/untracked-plugin.dll']=b'untracked'
        with self.assertRaisesRegex(ValueError,'DISTRIBUTION_FILE_LIST_MISMATCH'):
            self.check()

    def test_missing_distribution_inventory_is_refused(self):
        del self.files[PREFIX+'DISTRIBUTION-INVENTORY.json']
        with self.assertRaisesRegex(ValueError,'MISSING_REQUIRED_RELEASE_FILE'):
            self.check()

    def test_missing_license_is_refused(self):
        del self.files[PREFIX+'LICENSE']
        with self.assertRaisesRegex(ValueError,'MISSING_REQUIRED'):self.check()
    def test_extra_decoder_file_is_refused(self):
        self.files[PREFIX+'decoder/unreviewed.dll']=b'extra'
        with self.assertRaisesRegex(ValueError,'DISTRIBUTION_FILE_LIST_MISMATCH'):self.check()
    def test_unsafe_name_is_refused(self):
        self.files[PREFIX+'../unexpected']=b'bad'
        with self.assertRaisesRegex(ValueError,'UNSAFE_ARCHIVE'):self.check()
    def test_case_alias_duplicate_is_refused(self):
        self.files[PREFIX+'license']=b'alias'
        with self.assertRaisesRegex(ValueError,'DUPLICATE_ARCHIVE'):self.check()
    def test_author_contact_preserved(self):
        self.files[PREFIX+'README.md']=b'Other README'
        self._inventory()
        with self.assertRaisesRegex(ValueError,'AUTHOR_MESSAGE'):self.check()

if __name__=='__main__':unittest.main()
