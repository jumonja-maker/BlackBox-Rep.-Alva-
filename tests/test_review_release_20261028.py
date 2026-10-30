"""No network: fail-closed publication by immutable draft ID and main identity."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from tools.publish_verified_draft import publish, preflight


class DraftPublicationReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name)/'BLACK.BOX-Universal-Windows.zip'
        self.archive.write_bytes(b'synthetic archive, not a real release')
        sidecar = Path(str(self.archive)+'.sha256'); sidecar.write_bytes(b'synthetic checksum')
        self.sha = 'a'*40; self.repo = 'owner/repo'; self.tag = 'v0.5.3'
        self.draft = {'id':123,'draft':True,'prerelease':False,'tag_name':self.tag,
                      'target_commitish':self.sha,'assets':[]}
        for p in (self.archive,sidecar):
            self.draft['assets'].append({'name':p.name,'state':'uploaded',
                'size':p.stat().st_size, 'digest':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()})
        self.main = self.sha;self.calls = [];self.extra_release = False;self.conflict = False

    def client(self, endpoint, *, method='GET', data=None):
        self.calls.append((endpoint, method, data))
        prefix='repos/'+self.repo
        if endpoint == prefix+'/git/ref/heads/main':
            return {'object':{'sha':self.main}}
        if endpoint.startswith(prefix+'/git/matching-refs/tags/'):
            return ([{'ref':'refs/tags/'+self.tag,'object':{'type':'commit','sha':'b'*40}}]
                    if self.conflict else [])
        if endpoint.startswith(prefix+'/releases?'):
            return [copy.deepcopy(self.draft)]*(2 if self.extra_release else 1)
        if endpoint == prefix+'/releases/123':
            result=copy.deepcopy(self.draft)
            if method == 'PATCH':
                self.assertEqual(data, {'draft':False,'prerelease':False,'make_latest':'true'})
                result.update(draft=False, published_at='fixture', html_url='fixture')
            return result
        if endpoint == prefix+'/git/ref/tags/'+self.tag:
            return {'object':{'type':'commit','sha':self.sha}}
        self.fail('Unexpected API route: '+endpoint)

    def run_publish(self):
        return publish(self.client,self.repo,self.sha,self.tag,self.archive)

    def assert_not_published(self):
        self.assertFalse(any(method=='PATCH' for _,method,_ in self.calls))

    def test_verified_draft_is_published_by_id_without_tag_release_lookup(self):
        result=self.run_publish();self.assertEqual(result['status'],'PUBLISHED')
        self.assertEqual(sum(m=='PATCH' for _,m,_ in self.calls),1)
        self.assertFalse(any('/releases/tags/' in path for path,_,_ in self.calls))

    def test_moved_main_blocks_publication(self):
        self.main='b'*40
        with self.assertRaisesRegex(ValueError,'MAIN_MOVED'):self.run_publish()
        self.assert_not_published()

    def test_wrong_asset_digest_blocks_publication(self):
        self.draft['assets'][0]['digest']='sha256:'+'b'*64
        with self.assertRaisesRegex(ValueError,'DIGEST_MISMATCH'):self.run_publish()
        self.assert_not_published()

    def test_public_release_is_never_replaced(self):
        self.draft['draft']=False
        with self.assertRaisesRegex(ValueError,'DRAFT_IDENTITY'):self.run_publish()
        self.assert_not_published()

    def test_duplicate_drafts_or_conflicting_tags_are_refused(self):
        self.extra_release=True
        with self.assertRaisesRegex(ValueError,'NOT_UNIQUE'):self.run_publish()
        self.extra_release=False;self.conflict=True
        with self.assertRaisesRegex(ValueError,'TAG_CONFLICT'):self.run_publish()
        self.assert_not_published()

    def test_preflight_checks_drafts_before_create(self):
        with self.assertRaisesRegex(ValueError,'DRAFT_ALREADY_EXISTS'):
            preflight(self.client,self.repo,self.sha,self.tag)
        self.assert_not_published()

    def test_source_version_is_consistent_and_screenshots_cannot_push_main(self):
        import tomllib
        from blackbox_universal import __version__
        from tools.release_gate import VERSION
        root=Path(__file__).resolve().parents[1]
        self.assertEqual(__version__,'0.5.3');self.assertEqual(VERSION,__version__)
        self.assertEqual(tomllib.loads((root/'pyproject.toml').read_text())['project']['version'],VERSION)
        workflow=(root/'.github/workflows/readme-screenshots.yml').read_text()
        self.assertNotIn('git push',workflow);self.assertNotIn('contents: write',workflow)
        self.assertNotIn('  push:',workflow);self.assertIn('workflow_dispatch:',workflow)


if __name__ == '__main__':unittest.main()
