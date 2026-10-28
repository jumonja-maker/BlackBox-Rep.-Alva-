"""Real local PE/PDB, explicit synthetic ETW metadata; no fabricated capture."""
from copy import deepcopy
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from blackbox_core.decoder_calltree import build_calltree, export_analysis
from blackbox_core.decoder_native_symbols import load_native_symbols
from test_decoder_native_symbols import build_native
from test_decoder_modules import native_row, write_index
from test_decoder_cpu import etw_row


class SymbolTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.pe, cls.pdb = build_native(cls.root)
        cls.table = load_native_symbols(cls.pe, cls.pdb)

    def row(self, i):
        row = etw_row(i)
        frame = native_row(i)['frames'][0]
        pe = self.table.pe
        frame['module'].update(pdb_guid=pe['guid'], pdb_age=pe['age'],
            image_timestamp=pe['image_timestamp'], image_size=pe['image_size'])
        start = next(a for a, b, n in self.table.functions if n == 'blackbox_leaf')
        frame['rva'] = start+1; frame['address'] = hex(0x140000000+start+1)
        frame['name'] = ''
        row['frames'] = [frame]
        row['cpu_sample']['instruction_pointer'] = frame['address']
        return row

    def test_tree_symbols_load_once_preserve_originals_and_conserve_weights(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, c = self.row(1), self.row(2), self.row(3)
            c['frames'][0]['module']['pdb_age'] += 1
            rows = [a, b, c]; before_rows = deepcopy(rows)
            index, _ = write_index(Path(temp), rows)
            before_files = [p.read_bytes() for p in (index, self.pe, self.pdb)]
            with patch('blackbox_core.decoder_calltree.load_native_symbols', wraps=load_native_symbols) as load:
                result = build_calltree(index, source='etw', binary_path=self.pe, pdb_path=self.pdb)
            self.assertEqual(load.call_count, 1)
            self.assertEqual(result['coverage']['samples_selected'], 3)
            self.assertEqual(sum(n['self_samples'] for n in result['nodes']), 3)
            s = result['symbolization']
            self.assertEqual(s['frame_occurrences_reviewed'], 3)
            self.assertEqual(s['frame_occurrences_resolved'], 2)
            self.assertEqual(s['frame_occurrences_unresolved'], 1)
            self.assertEqual(s['reasons']['TRACE_PE_PDB_IDENTITY_MISMATCH'], 1)
            nodes = [n for n in result['nodes'] if n['derived_symbol'] and n['derived_symbol']['symbol']['name']]
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]['label'], 'blackbox_leaf+0x1')
            self.assertEqual(nodes[0]['frame']['name'], '')
            self.assertEqual(nodes[0]['inclusive_samples'], 2)
            self.assertEqual(rows, before_rows)
            self.assertEqual(before_files, [p.read_bytes() for p in (index, self.pe, self.pdb)])
            html = Path(temp)/'tree.html'; export_analysis(result, html, html=True)
            text = html.read_text()
            self.assertIn('blackbox_leaf', text)
            self.assertIn('pe_sha256', text)
            self.assertIn('cpu_source', text)
            self.assertIn('UNAUTHENTICATED_LOCAL_FILES', text)

    def test_missing_trace_binding_stays_unresolved_even_with_correct_local_pdb(self):
        with tempfile.TemporaryDirectory() as temp:
            row = self.row(1)
            del row['frames'][0]['module']; del row['frames'][0]['rva']
            index, _ = write_index(Path(temp), [row])
            r = build_calltree(index, source='etw', binary_path=self.pe, pdb_path=self.pdb)
            self.assertEqual(r['symbolization']['frame_occurrences_resolved'], 0)
            self.assertEqual(r['symbolization']['reasons']['TRACE_MODULE_NOT_RECORDED'], 1)

    def test_cancellation_and_missing_half_pair_never_yield_partial_analysis(self):
        with tempfile.TemporaryDirectory() as temp:
            index, _ = write_index(Path(temp), [self.row(1)])
            before = index.read_bytes()
            with self.assertRaisesRegex(ValueError, 'SYMBOL_PAIR_REQUIRED'):
                build_calltree(index, binary_path=self.pe)
            event = Event(); event.set()
            with self.assertRaises(InterruptedError):
                build_calltree(index, binary_path=self.pe, pdb_path=self.pdb, cancel=event)
            self.assertEqual(before, index.read_bytes())


if __name__ == '__main__':
    unittest.main()
