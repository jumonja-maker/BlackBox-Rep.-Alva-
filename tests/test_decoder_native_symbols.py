"""Actual clang/lld native PE/PDB plus adversarial trace-to-file bindings."""
from copy import deepcopy
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Event
import unittest
from unittest.mock import patch
from blackbox_core.decoder_native_symbols import load_native_symbols, resolve_event_stack
from test_decoder_modules import native_row

SOURCE='''__declspec(noinline) int blackbox_leaf(int value) { volatile int a=value*7; return a+3; }
__declspec(noinline) int blackbox_parent(int value) { return blackbox_leaf(value)+11; }
void entry(void) { volatile int value=blackbox_parent(5); (void)value; }
'''


def build_native(root):
    clang=shutil.which('clang');lld=shutil.which('lld-link')
    if not clang or not lld:raise unittest.SkipTest('Native QA requires local Clang and lld-link')
    source=root/'probe.c';source.write_text(SOURCE,encoding='utf-8')
    subprocess.run([clang,'--target=x86_64-pc-windows-msvc','-g','-gcodeview','-O0','-c',str(source),'-o',str(root/'probe.obj')],check=True,timeout=30,capture_output=True)
    subprocess.run([lld,'/debug','/nodefaultlib','/entry:entry','/subsystem:console',
        '/out:'+str(root/'probe.exe'),'/pdb:'+str(root/'probe.pdb'),'/map:'+str(root/'probe.map'),
        str(root/'probe.obj')],check=True,timeout=30,capture_output=True)
    return root/'probe.exe',root/'probe.pdb'


class NativeSymbolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.pe,cls.pdb=build_native(cls.root)
        cls.symbols=load_native_symbols(cls.pe,cls.pdb)

    def row(self):
        row=native_row();frame=row['frames'][0];m=frame['module'];p=self.symbols.pe
        m.update(pdb_guid=p['guid'],pdb_age=p['age'],image_size=p['image_size'],image_timestamp=p['image_timestamp'])
        start=next(a for a,b,n in self.symbols.functions if n=='blackbox_leaf')
        frame['rva']=start+1;frame['address']=hex(int(m['image_base'],16)+start+1)
        return row

    def test_real_function_range_agrees_with_linker_map_and_padding_stays_unknown(self):
        table=self.symbols
        text=(self.root/'probe.map').read_text()
        for start,end,name in table.functions:
            self.assertIn(name,text)
            self.assertIn(f'{0x140000000+start:016x}',text)
            self.assertEqual(table.lookup(start)['name'],name)
            self.assertEqual(table.lookup(end-1)['name'],name)
        first=table.functions[0];self.assertEqual(table.lookup(first[1])['status'],'NO_RECORDED_FUNCTION_RANGE')

    def test_trace_binding_and_resolution_preserve_original_row_and_files(self):
        row=self.row();copy=deepcopy(row);before=[p.read_bytes() for p in (self.pe,self.pdb)]
        report=resolve_event_stack(row,self.pe,self.pdb)
        self.assertEqual(report['resolved_frames'],1)
        self.assertEqual(report['frames'][0]['symbol']['name'],'blackbox_leaf')
        self.assertEqual(row,copy);self.assertEqual(before,[p.read_bytes() for p in (self.pe,self.pdb)])
        self.assertFalse(report['local_files']['symbol_server_contacted'])
        self.assertEqual(report['trace_to_session_alignment'],'NOT_ESTABLISHED')

    def test_wrong_trace_build_and_missing_identity_do_not_resolve(self):
        for key,value in [('pdb_age',99),('image_timestamp',123),('image_size',8192)]:
            row=self.row();row['frames'][0]['module'][key]=value
            with self.subTest(key=key):
                r=resolve_event_stack(row,self.pe,self.pdb)
                self.assertEqual(r['resolved_frames'],0)
                self.assertIsNone(r['frames'][0]['symbol']['name'])
        row=self.row();row['frames'][0].pop('module');row['frames'][0].pop('rva')
        self.assertEqual(resolve_event_stack(row,self.pe,self.pdb)['resolved_frames'],0)

    def test_wrong_pe_pdb_pair_is_not_loaded(self):
        other=self.root/'wrong.pdb';raw=bytearray(self.pdb.read_bytes())
        # Mutate identity through the stream map, not a guessed physical location.
        import struct
        from blackbox_core.decoder_native_symbols import MsfReader,Budget
        with self.pdb.open('rb') as stream:r=MsfReader(stream,len(raw),Budget())
        at=r.streams[1][1][0]*r.bs+12;raw[at]^=1;other.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'GUID_AGE_MISMATCH'):load_native_symbols(self.pe,other)

    def test_aliases_are_ambiguous_and_nearest_public_is_not_a_function_range(self):
        from blackbox_core.decoder_native_symbols import NativeSymbolTable
        p=self.symbols.pe
        t=NativeSymbolTable(p,self.symbols.pdb,[(4096,4112,'A'),(4096,4112,'B')],[(4128,'C')],['a','b'])
        self.assertIsNone(t.lookup(4097)['name'])
        self.assertEqual(t.lookup(4128)['status'],'LOCAL_PDB_EXACT_PUBLIC_ENTRY')
        self.assertIsNone(t.lookup(4129)['name'])

    def test_cancellation_and_read_budget_are_not_suppressed(self):
        event=Event();event.set()
        with self.assertRaises(InterruptedError):load_native_symbols(self.pe,self.pdb,cancel=event)
        with patch('blackbox_core.decoder_native_symbols.MAX_SYMBOL_BYTES',20):
            with self.assertRaisesRegex(ValueError,'READ_BUDGET'):load_native_symbols(self.pe,self.pdb)

if __name__=='__main__':unittest.main()
