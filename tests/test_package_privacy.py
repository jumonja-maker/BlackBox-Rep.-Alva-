from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile
from blackbox_core.research_worker import ResearchSession
from blackbox_core.casebook import export_case,_hash
from blackbox_core.package_privacy import redact

class ShareCopyPrivacyTests(unittest.TestCase):
    def test_paths_application_attributes_and_preview_are_explicitly_removed(self):
        data={'full_path':r'C:\private\secret.docx','note':'see /home/user/private.txt and https://private.example/a',
            'attributes':{'password':'private sentinel'},'preview':'memory sentinel','cpu_seconds':0,'missing':None}
        result=redact(data);text=json.dumps(result)
        self.assertNotIn('secret.docx',text);self.assertNotIn('private sentinel',text);self.assertNotIn('memory sentinel',text)
        self.assertEqual(result['cpu_seconds'],0);self.assertIsNone(result['missing'])
    def test_default_zip_has_no_raw_secret_in_sqlite_pages_and_original_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);s=ResearchSession(root/'sessions')
            s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'})
            secret='BB_PRIVATE_ATTRIBUTE_2cf098'
            s.book.put('application.sample',{'attributes':{'secret':secret},'preview':secret},source='APPLICATION_EVENT')
            s.tick();s.stop();folder=s.probe.session_folder
            original=_hash(folder/'research.sqlite3')
            output=root/'minimal.zip';result=export_case(folder,output)
            with zipfile.ZipFile(output) as archive:
                for name in archive.namelist():
                    self.assertNotIn(secret.encode(),archive.read(name),name)
                    self.assertNotIn(str(folder).encode(),archive.read(name),name)
            self.assertFalse(result['manifest']['privacy']['universal_secret_detection'])
            self.assertEqual(_hash(folder/'research.sqlite3'),original)
            full=root/'full.zip';export_case(folder,full,include_sensitive=True)
            with zipfile.ZipFile(full) as archive:self.assertIn(secret.encode(),archive.read('research.sqlite3'))
