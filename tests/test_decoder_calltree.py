"""Recorded sample count conservation, uncertainty and export safety."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
from threading import Event
import unittest
from blackbox_core.decoder_calltree import build_calltree, calltree_html, export_analysis
from test_decoder_modules import native_row, write_index


def stack_row(i,leaf='leaf',instance=2,frames=True):
    row=native_row(i,process_instance=instance)
    row['frames']=([dict(address='0x1000',name=leaf),dict(address='0x2000',name='parent')]
                   if frames else [])
    return row


class DecoderCalltreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_conservation_excludes_gc_and_never_calls_counts_cpu_percent(self):
        rows=[stack_row(1),stack_row(2),stack_row(3,'other'),stack_row(4,frames=False),
              stack_row(5,instance=9)]
        gc=stack_row(6);gc['provider']='Microsoft-Windows-DotNETRuntime';gc['name']='GC/AllocationTick';rows.append(gc)
        path,_=write_index(self.root,rows)
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        r=build_calltree(path)
        self.assertEqual(r['coverage']['samples_selected'],5)
        self.assertEqual(sum(n['self_samples'] for n in r['nodes']),5)
        self.assertEqual(r['coverage']['samples_without_stack'],1)
        self.assertEqual(r['nodes'][0]['inclusive_samples'],5)
        self.assertEqual(len([n for n in r['nodes'] if n['parent_id']==0]),2)
        self.assertIn('NOT_CPU_TIME_OR_CPU_PERCENT',r['measurement'])
        self.assertIsNone(r['capture_complete'])
        self.assertEqual(before,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_time_filter_is_half_open_and_process_instance_is_not_just_pid(self):
        path,_=write_index(self.root,[stack_row(1),stack_row(2),stack_row(3,instance=9)])
        r=build_calltree(path,start_ms=1,end_ms=3,process_instance=2)
        self.assertEqual(r['coverage']['samples_selected'],2)
        self.assertEqual(build_calltree(path,pid=999)['coverage']['samples_selected'],0)
        for kw in [dict(pid=True),dict(start_ms=2,end_ms=2),dict(start_ms=float('nan')),dict(max_nodes=1)]:
            with self.subTest(kw=kw),self.assertRaises(ValueError):build_calltree(path,**kw)

    def test_unknown_process_instances_do_not_merge_and_truncation_is_visible(self):
        rows=[stack_row(1,instance=None),stack_row(2,instance=None)]
        rows[0]['stack_status']='TRUNCATED_128_FRAMES'
        path,_=write_index(self.root,rows)
        r=build_calltree(path)
        self.assertEqual(r['coverage']['samples_without_process_identity'],2)
        self.assertEqual(r['coverage']['samples_with_truncated_stack'],1)
        self.assertEqual(len([n for n in r['nodes'] if n['parent_id']==0]),2)
        self.assertTrue(any('truncated' in n['label'] for n in r['nodes']))

    def test_node_budget_is_explicit_and_never_creates_fake_function_self_count(self):
        path,_=write_index(self.root,[stack_row(i,'function'+str(i)) for i in range(1,11)])
        r=build_calltree(path,max_nodes=5)
        c=r['coverage']
        self.assertGreater(c['samples_omitted_node_budget'],0)
        self.assertEqual(c['samples_represented']+c['samples_omitted_node_budget'],10)
        self.assertEqual(sum(n['self_samples'] for n in r['nodes']),c['samples_represented'])

    def test_html_escapes_imported_names_and_export_cannot_overwrite(self):
        path,_=write_index(self.root,[stack_row(1,'<script>alert(1)</script>')])
        r=build_calltree(path);h=calltree_html(r)
        self.assertNotIn('<script>',h);self.assertIn('&lt;script&gt;',h)
        self.assertIn('default-src',h)
        out=self.root/'tree.html';export_analysis(r,out,html=True)
        before=out.read_bytes()
        with self.assertRaises(ValueError):export_analysis(r,out,html=True)
        self.assertEqual(before,out.read_bytes())
        self.assertFalse(list(self.root.glob('.bb-analysis-*')))

    def test_cancelled_analysis_keeps_source_unchanged(self):
        path,_=write_index(self.root,[stack_row(1)])
        before=path.read_bytes();event=Event();event.set()
        with self.assertRaises(InterruptedError):build_calltree(path,cancel=event)
        self.assertEqual(before,path.read_bytes())

if __name__=='__main__':unittest.main()
