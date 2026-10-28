"""Compiler-owned lines/inline evidence and adversarial format-level OMAP/C13."""
from pathlib import Path
import shutil
import struct
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from blackbox_core.decoder_codeview import Omap, c13_data, inline_ranges
from blackbox_core.decoder_native_symbols import Budget, MsfReader, NativeSymbolTable, load_native_symbols
from blackbox_core.decoder_pdb import MSF7_MAGIC
from tools.qa_decoder_symbols import build_probe, review_probe


def subsection(kind,data):
    return struct.pack('<II',kind,len(data))+data+b'\0'*((-len(data))%4)


def write_msf_fixture(path, streams):
    """Explicit format fixture; not an optimizer-produced OMAP binary."""
    size=512; pages=[]; next_page=4
    for data in streams:
        count=0 if data is None else (len(data)+size-1)//size
        pages.append(list(range(next_page,next_page+count)));next_page+=count
    directory=struct.pack('<I',len(streams))+b''.join(struct.pack('<I',0xffffffff if d is None else len(d)) for d in streams)
    directory+=b''.join(struct.pack('<I',i) for group in pages for i in group)
    count=(len(directory)+size-1)//size;dir_pages=list(range(next_page,next_page+count));next_page+=count
    assert next_page < 512 and count <=128
    out=bytearray(next_page*size);out[:32]=MSF7_MAGIC
    struct.pack_into('<6I',out,32,size,1,next_page,len(directory),0,3)
    for i,page in enumerate(dir_pages):
        struct.pack_into('<I',out,3*size+i*4,page)
        chunk=directory[i*size:(i+1)*size];out[page*size:page*size+len(chunk)]=chunk
    for data,group in zip(streams,pages):
        for i,page in enumerate(group):
            chunk=data[i*size:(i+1)*size];out[page*size:page*size+len(chunk)]=chunk
    path.write_bytes(out)


class CodeViewFormatTests(unittest.TestCase):
    def test_omap_lookup_translates_before_range_search_and_keeps_address_space(self):
        mapping=Omap(struct.pack('<8I',0x1000,0x2000,0x1010,0,0x1020,0x2020,0x1030,0),
                     0x3000,0x4000,Budget())
        table=NativeSymbolTable({'image_size':0x3000},{'guid':'x','age':1},
            [(0x2000,0x2010,'first'),(0x2020,0x2030,'second')],[],['a','b'],omap=mapping)
        result=table.lookup(0x1004)
        self.assertEqual(result['name'],'first');self.assertEqual(result['displacement'],4)
        self.assertEqual(result['rva'],0x1004);self.assertEqual(result['original_rva'],0x2004)
        self.assertEqual(result['symbol_address_space'],'OMAP_ORIGINAL_IMAGE')
        self.assertEqual(table.lookup(0x1010)['status'],'OMAP_ADDRESS_NOT_MAPPED')
        self.assertEqual(table.lookup(0xfff)['status'],'OMAP_ADDRESS_NOT_MAPPED')
        self.assertEqual(table.lookup(0x102f)['name'],'second')

    def test_omap_duplicate_unsorted_truncated_overflow_and_budget_rejected(self):
        for data in [b'x',struct.pack('<4I',10,20,10,30),struct.pack('<4I',20,20,10,30),
                     struct.pack('<2I',100,20),struct.pack('<2I',10,200)]:
            with self.subTest(data=data),self.assertRaises(ValueError):Omap(data,100,100,Budget())
        with patch('blackbox_core.decoder_codeview.MAX_OMAP',1),self.assertRaises(ValueError):
            Omap(struct.pack('<4I',1,1,2,2),100,100,Budget())
        event=Event();event.set()
        with self.assertRaises(InterruptedError):Omap(struct.pack('<2I',1,1),100,100,Budget(event))

    def test_c13_same_address_different_lines_stay_ambiguous(self):
        files=struct.pack('<IBB',1,0,0)+b'\0\0'
        lines=struct.pack('<IHHI',0,1,0,20)+struct.pack('<III',0,2,28)+struct.pack('<4I',0,5,0,6)
        data=subsection(0xf4,files)+subsection(0xf2,lines)
        rows,_,_=c13_data(data,b'\0C:\\private\\test.c\0',Budget(),lambda s,o,n:4096+o)
        table=NativeSymbolTable({'image_size':8192},{'guid':'x','age':1},[(4096,4116,'f')],[],['a','b'],source_lines=rows)
        result=table.lookup(4097)
        self.assertEqual(result['source_status'],'AMBIGUOUS_SOURCE_LINES')
        self.assertIsNone(result['source_location']);self.assertNotIn('private',str(rows))

    def test_c13_truncated_bad_count_and_unknown_file_are_rejected(self):
        files=struct.pack('<IBB',1,0,0)+b'\0\0'
        for block in [b'x',struct.pack('<IHHI',0,1,0,20)+struct.pack('<III',999,1,20)+struct.pack('<2I',0,4),
                      struct.pack('<IHHI',0,1,0,20)+struct.pack('<III',0,1000000,12)]:
            with self.subTest(block=block),self.assertRaises(ValueError):
                c13_data(subsection(0xf4,files)+subsection(0xf2,block),b'\0test.c\0',Budget(),lambda s,o,n:4096)

    def test_small_records_cannot_amplify_into_unbounded_source_maps(self):
        files=(struct.pack('<IBB',1,0,0)+b'\0\0')*2
        with patch('blackbox_core.decoder_codeview.MAX_SOURCE_FILES',1),self.assertRaisesRegex(ValueError,'SOURCE_FILE_BUDGET'):
            c13_data(subsection(0xf4,files),b'\0test.c\0',Budget(),lambda s,o,n:4096)
        with patch('blackbox_core.decoder_codeview.MAX_SUBSECTIONS',1),self.assertRaisesRegex(ValueError,'SUBSECTION_BUDGET'):
            c13_data(subsection(0x123,b'')*2,b'',Budget(),lambda s,o,n:4096)

    def test_inline_next_start_closes_prior_line_and_separated_chunks_not_guessed(self):
        location={'file':'probe.c','line':1}
        args=dict(procedure_start=4096,procedure_end=4128,location=location,files={},budget=Budget())
        rows=inline_ranges(bytes.fromhex('0b210b2d04040000'),**args)
        self.assertEqual([(a,b,r['line']) for a,b,r in rows],[(4097,4110,2),(4110,4114,3)])
        for annotations in [bytes([2,1]),bytes([11,0x80]),bytes([4,10]),bytes([1,1]),bytes([1,31,4,2])]:
            with self.subTest(annotations=annotations),self.assertRaises(ValueError):inline_ranges(annotations,**args)

    def test_separate_line_change_does_not_relabel_the_pending_range(self):
        args=dict(procedure_start=4096,procedure_end=4128,
                  location={'file':'probe.c','line':1},files={},budget=Budget())
        combined=inline_ranges(bytes.fromhex('0b210b2d04040000'),**args)
        separate=inline_ranges(bytes.fromhex('0b210602030d0404'),**args)
        self.assertEqual(separate,combined)
        first=inline_ranges(bytes.fromhex('010106020404'),**args)
        self.assertEqual([(a,b,r['line']) for a,b,r in first],[(4097,4101,2)])


@unittest.skipUnless(shutil.which('clang') and shutil.which('lld-link'),'Real native PDB compiler required')
class RealCodeViewTests(unittest.TestCase):
    def test_real_compiler_source_lines_nested_inline_and_independent_symbolizer(self):
        with tempfile.TemporaryDirectory() as temp:
            report=review_probe(Path(temp))
            self.assertEqual(report['status'],'PASS')
            self.assertGreaterEqual(report['symbol_table']['inline_ranges'],2)
            self.assertGreaterEqual(report['symbol_table']['source_line_ranges'],3)

    def test_line_and_inline_ranges_end_without_nearest_extension(self):
        with tempfile.TemporaryDirectory() as temp:
            _,pe,pdb=build_probe(Path(temp));table=load_native_symbols(pe,pdb)
            outer=next((a,b) for a,b,n in table.functions if n=='blackbox_outer')
            self.assertEqual(table.lookup(outer[1])['inline_frames'],[])
            self.assertIsNone(table.lookup(outer[1])['source_location'])
            end=max(b for a,b,_ in table.inline_sites)
            self.assertEqual(table.lookup(end)['inline_frames'],[])

    @unittest.skipUnless(shutil.which('llvm-symbolizer'),'Independent LLVM symbolizer required')
    def test_equivalent_separate_line_annotations_agree_with_llvm(self):
        """Encoding-level fixture derived from real compiler bytes, not a capture."""
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,pe,pdb=build_probe(root)
            original=load_native_symbols(pe,pdb)
            data=pdb.read_bytes();combined=bytes.fromhex('0b210b2d04040000')
            self.assertEqual(data.count(combined),1)
            pdb.write_bytes(data.replace(combined,bytes.fromhex('0b210602030d0404')))
            separate=load_native_symbols(pe,pdb)
            for start,_end,site in original.inline_sites:
                if site['name']!='inline_leaf':continue
                expected=original.lookup(start)['inline_frames']
                self.assertEqual(separate.lookup(start)['inline_frames'],expected)
                oracle=subprocess.run([shutil.which('llvm-symbolizer'),'--obj='+str(pe),
                    '--relative-address','--inlines',hex(start)],check=True,timeout=20,
                    capture_output=True,text=True).stdout.splitlines()
                self.assertEqual(oracle[0],'inline_leaf')
                self.assertTrue(oracle[1].endswith(f":{expected[-1]['source_location']['line']}:0"))

    def test_full_parser_accepts_explicit_omap_streams_and_rejects_missing_sections(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,pe,pdb=build_probe(root);plain=load_native_symbols(pe,pdb)
            with pdb.open('rb') as inp:
                msf=MsfReader(inp,pdb.stat().st_size,Budget())
                streams=[None if n==0xffffffff else msf.read(i) for i,(n,_) in enumerate(msf.streams)]
            dbi=bytearray(streams[3]);lengths=struct.unpack_from('<5i',dbi,24)
            debug_at=64+sum(lengths)+struct.unpack_from('<i',dbi,52)[0]
            debug=list(struct.unpack_from('<'+'H'*((len(dbi)-debug_at)//2),dbi,debug_at))
            debug += [0xffff]*(11-len(debug))
            start,end,_=plain.functions[0]
            original_index=len(streams)
            streams.extend([plain.pe['section_headers'],struct.pack('<4I',start,start+1,end,0),
                            struct.pack('<4I',start+1,start,end,0)])
            debug[3]=original_index+1;debug[4]=original_index+2;debug[10]=original_index
            dbi=dbi[:debug_at]+struct.pack('<'+'H'*len(debug),*debug);struct.pack_into('<i',dbi,48,len(debug)*2)
            streams[3]=bytes(dbi);modified=root/'explicit-omap.pdb';write_msf_fixture(modified,streams)
            mapped=load_native_symbols(pe,modified);result=mapped.lookup(start)
            self.assertEqual(result['name'],plain.lookup(start+1)['name'])
            self.assertEqual(result['original_rva'],start+1)
            self.assertEqual(result['source_location'],plain.lookup(start+1)['source_location'])
            self.assertEqual(mapped.summary()['omap'],'OPTIMIZED_TO_ORIGINAL')
            self.assertEqual(mapped.lookup(end)['status'],'OMAP_ADDRESS_NOT_MAPPED')
            struct.pack_into('<H',dbi,debug_at+20,0xffff);streams[3]=bytes(dbi)
            write_msf_fixture(modified,streams)
            with self.assertRaisesRegex(ValueError,'INCOMPLETE_OMAP'):load_native_symbols(pe,modified)


if __name__=='__main__':unittest.main()
