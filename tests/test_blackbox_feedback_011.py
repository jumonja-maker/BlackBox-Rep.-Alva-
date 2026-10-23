"""BLACK.BOX 00 acceptance regressions: original 0.1.0 negative reproductions."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import math
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from blackbox_investigation import (InvestigationError, Policy, analyze,
                                    analyze_snapshot, compare_reports, analyze_session,
                                    load_session, to_html)
from blackbox_investigation.__main__ import main, _commit_export
from blackbox_investigation.optin_probe import observe_selected_process


def sample(ms, *, rss=100, uss=None, private=None):
    return dict(elapsed_ms=ms, rss_bytes=rss, uss_bytes=uss,
                private_bytes=private, cpu_percent=0, num_threads=1, children_count=0,
                read_bytes=0, write_bytes=0)


def fixture(root, count=1, exit_code='COMPLETED'):
    folder = Path(root) / 'session'
    folder.mkdir()
    db = sqlite3.connect(folder/'session.sqlite3')
    db.executescript('''CREATE TABLE metadata(schema_version INTEGER NOT NULL, session_id TEXT NOT NULL,
         pid INTEGER NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT, exit_code TEXT,
         probe TEXT NOT NULL);
         CREATE TABLE samples(seq INTEGER PRIMARY KEY,elapsed_ms INTEGER NOT NULL,
         rss_bytes INTEGER,cpu_percent REAL,num_threads INTEGER,read_bytes INTEGER,
         write_bytes INTEGER,children_count INTEGER);
         CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);''')
    db.execute("INSERT INTO metadata VALUES(1, 'genuine-local', 42, '2026-10-23', '2026-10-23', ?, 'psutil-read-only')",(exit_code,))
    db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ((i+1, i*1000, 1024, 0.0, 2, 0, 0, 0) for i in range(count)))
    db.commit()
    db.close()
    return folder


class BlockingRegressions(unittest.TestCase):
    def test_B01_caller_cannot_forge_observed_window_or_exit(self):
        for kind, origin in [('observed_window_unresponsive','EXTERNAL_OS_OBSERVATION'),
                             ('observed_process_exit','BLACKBOX_LIFECYCLE')]:
            with self.subTest(kind=kind), self.assertRaises(InvestigationError) as err:
                analyze([sample(0)], markers=[dict(elapsed_ms=0,kind=kind,source=origin)])
            self.assertEqual(err.exception.code, 'UNATTESTED_SYSTEM_EVENT')

    def test_B01_unverified_reports_do_not_create_system_facts(self):
        result=analyze([sample(0)],markers=[dict(elapsed_ms=0,kind='unverified_report',
                   source='EXTERNAL_UNVERIFIED',note='Window did not respond')])
        self.assertEqual(result['markers'][0]['verification'],'UNVERIFIED')
        self.assertNotIn('WINDOW_UNRESPONSIVE_OBSERVED',[f['code'] for f in result['findings']])
        self.assertFalse(result['provenance']['digest_is_attestation'])

    def test_B01_lifecycle_metadata_recorded_not_attested(self):
        with tempfile.TemporaryDirectory() as root:
            path=fixture(root,exit_code='PROCESS_EXITED')
            proof=analyze_session(path)
            hits=[f for f in proof['findings'] if f['code']=='PROCESS_EXIT_RECORDED']
            self.assertEqual(len(hits),1)
            self.assertEqual(hits[0]['facts'][0]['verification'],'RECORDED_NOT_ATTESTED')
            self.assertFalse(proof['provenance']['pid_creation_verified'])

    def test_B02_uss_private_are_separate(self):
        report=analyze([sample(0,uss=500),sample(1000,uss=600),sample(2000,uss=700)],
                       policy=Policy(rss_growth_alert_bytes=150))
        self.assertIsNone(report['timeline'][0]['private_bytes'])
        self.assertEqual(report['summary']['private_bytes']['count'],0)
        self.assertEqual(report['summary']['uss_bytes']['count'],3)
        self.assertEqual([f['facts'][0]['metric'] for f in report['findings'] if f['code']=='MEMORY_GROWTH_CANDIDATE'],['uss_bytes'])

    def test_B02_optional_probe_does_not_fallback_uss_to_private(self):
        class Proc:
            def create_time(self): return 42.0
            def oneshot(self):
                from contextlib import nullcontext
                return nullcontext()
            def memory_info(self):
                from types import SimpleNamespace
                return SimpleNamespace(rss=100)
            def io_counters(self):
                from types import SimpleNamespace
                return SimpleNamespace(read_bytes=0,write_bytes=0)
            def threads(self): return []
            def num_threads(self): return 1
            def memory_full_info(self):
                from types import SimpleNamespace
                return SimpleNamespace(uss=23)
            def children(self,recursive=True): return []
        class FakePsutil:
            AccessDenied=type('AccessDenied',(Exception,),{})
            NoSuchProcess=type('NoSuchProcess',(Exception,),{})
            ZombieProcess=type('ZombieProcess',(Exception,),{})
            Process=lambda self,pid: Proc()
        with patch.dict(sys.modules,{'psutil':FakePsutil()}):
            result=observe_selected_process(42,expected_created=42)
        self.assertIsNone(result['private_bytes'])
        self.assertEqual(result['uss_bytes'],23)

    def test_B03_identical_targets_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as root:
            session=fixture(root)
            output=Path(root)/'report.json'
            with redirect_stdout(StringIO()):
                status=main([str(session),'--json',str(output),'--html',str(output)])
            self.assertEqual(status,2)
            self.assertFalse(output.exists())

    def test_B03_second_publish_failure_rolls_back_first(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            first=root/'a.json';second=root/'b.html'
            import os
            original=os.link
            calls=[]
            def reject_second(*args,**kwargs):
                calls.append(1)
                if len(calls)==2: raise PermissionError('blocked')
                return original(*args,**kwargs)
            with patch('blackbox_investigation.__main__.os.link',side_effect=reject_second):
                with self.assertRaises(PermissionError):
                    _commit_export({'json':first,'html':second},{'json':b'{}','html':b'<h1/>'})
            self.assertEqual(list(root.iterdir()),[])

    def test_B03_preexisting_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'occupied.html';p.write_text('DO NOT EDIT',encoding='utf-8')
            with self.assertRaises(FileExistsError):
                _commit_export({'json':Path(folder)/'new.json','html':p},
                               {'json':b'{}','html':b'abc'})
            self.assertEqual(p.read_text(), 'DO NOT EDIT')
            self.assertFalse((Path(folder)/'new.json').exists())

    def test_B04_snapshot_nan_inf_bool_huge_and_negative_are_coded(self):
        for bad in (float('nan'),float('inf'),-float('inf'),True,-1,99999999999999):
            for field in ('seconds','rss_mb'):
                if field=='rss_mb' and bad == 99999999999999: pass
                with self.subTest(bad=repr(bad), field=field):
                    s={'schema_version':1,'product':'BLACK.BOX Universal','observed_process':{'pid':1},
                       'recent_samples':[{'seconds':0,'rss_mb':1,'process_count':1}]}
                    s['recent_samples'][0][field]=bad
                    with self.assertRaises(InvestigationError) as err:
                        analyze_snapshot(s)
                    self.assertTrue(err.exception.code.startswith('INVALID_'))

    def test_B04_bool_process_count_refused(self):
        data={'schema_version':1,'product':'BLACK.BOX Universal', 'observed_process':{'pid':1},
              'recent_samples':[{'seconds':0,'process_count':True}]}
        with self.assertRaises(InvestigationError):analyze_snapshot(data)

    def test_B05_missing_and_malformed_comparison_fields_refused(self):
        real=analyze([sample(0)])
        for bad in ({'type':'BLACKBOX_INVESTIGATION'},
                    {'type':'BLACKBOX_INVESTIGATION','schema_version':2},
                    dict(real,summary={}),
                    dict(real,summary={'cpu_percent':{'median':1,'count':1}}),
                    dict(real,evidence_sha256='x'),
                    dict(real,summary=dict(real['summary'],rss_bytes=dict(real['summary']['rss_bytes'],median=float('nan'))))):
            with self.subTest(bad=repr(bad)[:90]),self.assertRaises(InvestigationError) as err:
                compare_reports(real,bad)
            self.assertEqual(err.exception.code,'INVALID_COMPARISON')

    def test_B06_untyped_oversized_control_source_refused(self):
        sources=[['untrusted-list'],{},'A'*1000,'USER\n', 'EXTERNAL_OS_OBSERVATION', 'BLACKBOX_LIFECYCLE',True]
        for source in sources:
            with self.subTest(source=repr(source)[:20]),self.assertRaises(InvestigationError) as err:
                analyze([sample(0)],markers=[dict(elapsed_ms=0,kind='user_problem',source=source)])
            self.assertEqual(err.exception.code,'INVALID_MARKER_SOURCE')

    def test_B07_stable_memory_does_not_raise_growth_with_zero_threshold(self):
        report=analyze([sample(0),sample(1000),sample(2000)],policy=Policy(rss_growth_alert_bytes=0))
        self.assertFalse(any(f['code']=='MEMORY_GROWTH_CANDIDATE' for f in report['findings']))

    def test_B08_long_session_requires_explicit_interval_then_is_bounded_and_complete_about_omissions(self):
        with tempfile.TemporaryDirectory() as root:
            folder=fixture(root,100000)
            before=(folder/'session.sqlite3').stat().st_size
            with self.assertRaises(InvestigationError) as e:
                analyze_session(folder)
            self.assertEqual(e.exception.code,'SESSION_INTERVAL_REQUIRED')
            result=analyze_session(folder,interval_start_ms=100000,interval_end_ms=115000)
            self.assertEqual(result['observation_count'],16)
            self.assertEqual(result['coverage']['total_samples'],100000)
            self.assertEqual(result['coverage']['omitted_samples'],99984)
            self.assertFalse(result['coverage']['full_session_covered'])
            self.assertIn('PARTIAL_SESSION_INTERVAL',result['warnings'])
            self.assertEqual((folder/'session.sqlite3').stat().st_size,before)
            self.assertEqual(set(p.name for p in folder.iterdir()),{'session.sqlite3'})
            with self.assertRaises(InvestigationError) as e:
                analyze_session(folder,interval_start_ms=0,interval_end_ms=99999999)
            self.assertEqual(e.exception.code,'INTERVAL_TOO_LARGE')

    def test_B08_missing_or_reversed_interval_refused(self):
        with tempfile.TemporaryDirectory() as root:
            folder=fixture(root,5)
            for kw in ({'interval_start_ms':0}, {'interval_start_ms':100,'interval_end_ms':0},
                       {'interval_start_ms':True,'interval_end_ms':0}):
                with self.subTest(kw=kw), self.assertRaises(InvestigationError):
                    analyze_session(folder,**kw)

    def test_B09_ru_html_translates_known_limit_and_displays_coverage(self):
        result=analyze([sample(0),sample(1000),sample(2000)],policy=Policy(rss_growth_alert_bytes=0))
        result['coverage']={'omitted_samples':200}
        result['warnings']=['PARTIAL_SESSION_INTERVAL']
        html=to_html(result,lang='RU')
        self.assertIn('Пропущено измерений: 200',html)
        self.assertIn('Анализ частичного интервала',html)
        self.assertIn('Причина: НЕ УСТАНОВЛЕНА',html)
        self.assertNotIn('<script',html)

    def test_B11_hash_is_not_proven_attestation(self):
        result=analyze([sample(0)])
        self.assertEqual(result['provenance']['os_proof'],'NOT_ATTESTED')
        self.assertFalse(result['provenance']['digest_is_attestation'])
        self.assertEqual(result['schema_version'],2)


if __name__ == '__main__':unittest.main()
