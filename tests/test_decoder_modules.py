"""Synthetic trace metadata tests; fixtures do not certify OS provenance."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

from blackbox_core.decoder_index import build_index, read_index, PROTOCOL
from blackbox_core.decoder_modules import binding_verdict

SHA = 'a'*64
GUID = '12345678-1234-4321-8765-123456789abc'


def native_row(i=1, **changes):
    module = dict(schema='blackbox.trace-module/1', source='TRACEEVENT_NATIVE_LOAD_WINDOW',
        process_instance=2, module_file_index=3, image_base='0x140000000', image_size=16384,
        image_timestamp=123, load_time_ms=0., unload_time_ms=100., pdb_guid=GUID, pdb_age=1,
        module_name='test.exe')
    row = dict(type='event', ordinal=i, time_ms=float(i), pid=42, tid=8, process_instance=2,
        provider='Microsoft-DotNETCore-SampleProfiler', name='Thread/Sample', payload={}, semantic=None,
        stack_status='RECORDED_ADDRESSES_OFFLINE_NAMES',
        frames=[dict(address='0x140001001', name='', module=module, rva=4097)])
    row.update(changes)
    return row


def write_index(root, rows, filename='index.sqlite3'):
    stream = root/(filename+'.jsonl')
    objects=[dict(type='header',protocol=PROTOCOL,input_sha256=SHA), *rows,
             dict(type='footer',protocol=PROTOCOL,status='DECODED',rows=len(rows))]
    stream.write_text(''.join(json.dumps(x)+'\n' for x in objects),encoding='utf-8')
    target=root/filename
    meta=build_index(stream,target,input_sha256=SHA,format_name='.etl')
    return target,meta


class DecoderModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_catalog_and_literal_filter_preserve_process_and_load_identity(self):
        a,b=native_row(),native_row(2)
        c=native_row(3,process_instance=9)
        c['frames'][0]['module']['process_instance']=9
        path,meta=write_index(self.root,[a,b,c])
        self.assertEqual(meta['schema'],'blackbox.decoder-index/4')
        self.assertEqual(meta['native_modules']['frames_with_native_module'],3)
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        first=read_index(path,mode='modules',limit=1)
        self.assertTrue(first['has_more']); self.assertEqual(first['rows'][0]['event']['frame_count'],2)
        second=read_index(path,mode='modules',after=first['next_cursor'],limit=1)
        self.assertEqual(second['rows'][0]['event']['process_instance'],9)
        self.assertEqual(read_index(path,mode='modules',pid=99)['rows'],[])
        self.assertEqual(read_index(path,mode='modules',search='%')['rows'],[])
        self.assertEqual(before,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_invalid_frame_binding_refuses_the_entire_index(self):
        faults=[('process_instance', True),('process_instance',3),('image_base','-1'),
            ('image_size',True),('pdb_age',False),('pdb_guid','not-guid'),
            ('load_time_ms',2),('unload_time_ms',1),('module_name','../private.dll')]
        for n,(key,value) in enumerate(faults):
            with self.subTest(key=key,value=value):
                row=native_row();row['frames'][0]['module'][key]=value
                with self.assertRaises(ValueError):write_index(self.root,[row],f'bad{n}.sqlite3')
                self.assertFalse((self.root/f'bad{n}.sqlite3').exists())
        self.assertFalse(list(self.root.glob('.decoder-building-*')))

    def test_frame_rva_and_high_address_are_checked_without_float_conversion(self):
        for rva in [True,-1,4098,2**64]:
            row=native_row(); row['frames'][0]['rva']=rva
            with self.assertRaises(ValueError):write_index(self.root,[row],str(rva)+'.sqlite3')
        row=native_row();row['frames'][0]['module']['image_base']='0xfffffffffffff000'
        row['frames'][0]['address']='0xfffffffffffff001';row['frames'][0]['rva']=1
        with self.assertRaises(ValueError):write_index(self.root,[row],'overflow.sqlite3')

    def test_missing_native_mapping_does_not_fabricate_one(self):
        row=native_row();row['frames']=[dict(address='0x1234',name='')]
        path,meta=write_index(self.root,[row])
        self.assertEqual(meta['native_modules']['frames_without_native_module'],1)
        self.assertEqual(read_index(path,mode='modules')['rows'],[])
        with closing(sqlite3.connect(path)) as db:db.execute('PRAGMA user_version=3')
        with self.assertRaisesRegex(ValueError,'REDECODE_REQUIRED'):read_index(path,mode='modules')
        self.assertEqual(len(read_index(path)['rows']),1)

    def test_binding_requires_all_three_identities_and_image_layout(self):
        row=native_row(); f=row['frames'][0]
        pe=dict(guid=GUID,age=1,image_size=16384,image_timestamp=123)
        pdb=dict(guid=GUID,age=1)
        self.assertEqual(binding_verdict(row,f,pe,pdb),'TRACE_PE_PDB_CONSISTENT_UNVERIFIED')
        for k in ['guid','age']:
            wrong={**pdb,k:2 if k=='age' else 'bad'}
            self.assertEqual(binding_verdict(row,f,pe,wrong),'TRACE_PE_PDB_IDENTITY_MISMATCH')
        self.assertEqual(binding_verdict(row,f,{**pe,'image_size':8192},pdb),'TRACE_PE_LAYOUT_MISMATCH')
        f['module']['pdb_guid']=None; f['module']['pdb_age']=None
        self.assertEqual(binding_verdict(row,f,pe,pdb),'TRACE_PDB_IDENTITY_NOT_RECORDED')

if __name__=='__main__':unittest.main()
