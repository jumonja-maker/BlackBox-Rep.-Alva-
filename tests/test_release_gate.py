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
        with self.assertRaisesRegex(ValueError,'FROZEN_VERSION_MISMATCH'):self.check()
    def test_wrong_source_is_refused(self):
        self.write()
        with self.assertRaisesRegex(ValueError,'FROZEN_SOURCE_MISMATCH'):
            verify_archive(self.path,'c'*40,'b'*40)
    def test_tampered_helper_is_refused(self):
        self.files[PREFIX+'decoder/BLACK.BOX-Decoder.exe']=b'tampered'
        with self.assertRaisesRegex(ValueError,'HASH_MISMATCH'):self.check()
    def test_missing_license_is_refused(self):
        del self.files[PREFIX+'LICENSE']
        with self.assertRaisesRegex(ValueError,'MISSING_REQUIRED'):self.check()
    def test_extra_decoder_file_is_refused(self):
        self.files[PREFIX+'decoder/unreviewed.dll']=b'extra'
        with self.assertRaisesRegex(ValueError,'INVENTORY_MISMATCH'):self.check()
    def test_unsafe_name_is_refused(self):
        self.files[PREFIX+'../unexpected']=b'bad'
        with self.assertRaisesRegex(ValueError,'UNSAFE_ARCHIVE'):self.check()
    def test_case_alias_duplicate_is_refused(self):
        self.files[PREFIX+'license']=b'alias'
        with self.assertRaisesRegex(ValueError,'DUPLICATE_ARCHIVE'):self.check()
    def test_author_contact_preserved(self):
        self.files[PREFIX+'README.md']=b'Other README'
        with self.assertRaisesRegex(ValueError,'AUTHOR_MESSAGE'):self.check()

if __name__=='__main__':unittest.main()
