"""Typed native CPU samples are not GC stacks, PMC events or application time."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from blackbox_core.decoder_cpu import CPU_SCHEMA, ETW_PROVIDER_GUID, classify_cpu_sample
from blackbox_core.decoder_calltree import build_calltree, parse_calltree_filters
from test_decoder_calltree import stack_row
from test_decoder_modules import write_index


def etw_row(i=1, *, dpc=False, isr=False, **changes):
    row = stack_row(i)
    row.update(provider='Windows Kernel', provider_guid=ETW_PROVIDER_GUID,
               name='PerfInfo/Sample', event_id=65535, opcode=46, version=2)
    row['cpu_sample'] = dict(schema=CPU_SCHEMA, source='ETW_KERNEL_PROFILE',
        parser='TRACEEVENT_SAMPLED_PROFILE', instruction_pointer='0x1000',
        processor_index=0, executing_dpc=dpc, executing_isr=isr)
    row.update(changes)
    return row


class NativeCpuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_typed_etw_is_source_separated_and_count_payload_is_never_weight(self):
        a = etw_row(); a['payload']['Count'] = 90000
        b = etw_row(2); b['frames'] = []
        path, meta = write_index(self.root, [a, b, stack_row(3)])
        before = path.read_bytes()
        etw, dotnet = build_calltree(path, source='etw'), build_calltree(path)
        self.assertEqual(etw['coverage']['samples_selected'], 2)
        self.assertEqual(dotnet['coverage']['samples_selected'], 1)
        self.assertEqual(etw['coverage']['samples_without_stack'], 1)
        self.assertEqual(sum(n['self_samples'] for n in etw['nodes']), 2)
        self.assertEqual(meta['cpu_samples']['etw_classification']['PROCESS_SAMPLE'], 2)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(etw['filters']['cpu_source'], 'etw')
        self.assertIn('NOT_PAYLOAD_COUNT', etw['sample_weight_policy'])

    def test_kernel_interrupt_work_and_unknown_context_are_explicitly_excluded(self):
        rows = [etw_row(1), etw_row(2, dpc=True), etw_row(3, isr=True),
                etw_row(4, dpc=None, isr=None), etw_row(5, pid=0)]
        path, _ = write_index(self.root, rows)
        r = build_calltree(path, source='etw'); c = r['coverage']
        self.assertEqual(c['candidates_in_scope'], 5)
        self.assertEqual(c['samples_selected'], 1)
        self.assertEqual(c['samples_excluded_dpc_isr'], 2)
        self.assertEqual(c['samples_excluded_attribution_unknown'], 2)
        self.assertEqual(r['nodes'][0]['inclusive_samples'], 1)

    def test_legacy_etw_requires_redecode_not_fabricated_sample_identity(self):
        row = etw_row(); del row['cpu_sample']
        path, _ = write_index(self.root, [row])
        report = build_calltree(path, source='etw')
        self.assertEqual(report['status'], 'REDECODE_REQUIRED_FOR_ETW')
        self.assertEqual(report['coverage']['samples_selected'], 0)
        self.assertEqual(report['coverage']['samples_missing_typed_classification'], 1)

    def test_gc_pmc_stackwalk_and_counterfeit_names_cannot_be_typed_samples(self):
        for changes in [dict(provider='other'), dict(provider_guid='0'*36),
                        dict(opcode=47), dict(name='GC/AllocationTick'),
                        dict(name='StackWalk/Stack'), dict(event_id=True),
                        dict(version=True)]:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    write_index(self.root, [etw_row(**changes)], f'bad-{len(list(self.root.iterdir()))}.sqlite3')
        self.assertFalse(list(self.root.glob('.decoder-building-*')))

    def test_payload_conflicts_missing_flags_and_bad_numeric_contracts_fail_closed(self):
        candidates = []
        for key, value in [('processor_index', True), ('executing_dpc', 'false'),
                           ('instruction_pointer', '0x10000000000000000'),
                           ('executing_isr', None), ('schema', 'unknown')]:
            row = etw_row(); row['cpu_sample'][key] = value; candidates.append(row)
        row = etw_row(); row['payload']['InstructionPointer'] = 8192; candidates.append(row)
        row = etw_row(); row['payload']['ExecutingDPC'] = 0; candidates.append(row)
        row = etw_row(version=1); candidates.append(row)
        for row in candidates:
            with self.subTest(row=row), self.assertRaises(ValueError):
                classify_cpu_sample(row, 'etw')

    def test_filter_thread_instance_and_half_open_window_conserve_only_selected_source(self):
        rows = [etw_row(1), etw_row(2, tid=9), etw_row(3, process_instance=5), etw_row(4)]
        path, _ = write_index(self.root, rows)
        result = build_calltree(path, source='etw', pid=42, process_instance=2,
                                tid=8, start_ms=1, end_ms=4)
        self.assertEqual(result['coverage']['samples_selected'], 1)
        self.assertEqual(result['filters']['tid'], 8)
        self.assertEqual(build_calltree(path, source='etw', tid=99)['coverage']['samples_selected'], 0)

    def test_text_filters_blank_is_not_zero_and_nonfinite_or_unicode_ids_rejected(self):
        args = parse_calltree_filters(instance_text='0', tid_text='8', start_text='0', end_text='1.25', source='etw')
        self.assertEqual(args['process_instance'], 0)
        self.assertEqual(args['end_ms'], 1.25)
        self.assertIsNone(parse_calltree_filters()['process_instance'])
        for kw in [dict(instance_text='１２'), dict(tid_text='-1'), dict(tid_text='1.5'),
                   dict(start_text='nan'), dict(end_text='inf'), dict(start_text='2', end_text='2'),
                   dict(instance_text=str(2**63)), dict(source='all'), dict(pid=True)]:
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                parse_calltree_filters(**kw)


if __name__ == '__main__':
    unittest.main()
