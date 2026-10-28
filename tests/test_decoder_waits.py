"""Synthetic scheduler contracts test analysis; native acceptance is separate."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from blackbox_core.decoder_cpu import ETW_PROVIDER_GUID
from blackbox_core.decoder_index import build_index, PROTOCOL
from blackbox_core.decoder_waits import build_wait_report, validate_schedule_event, SCHEDULE_SCHEMA


def identity(pid=42, tid=8, instance=2, thread=3, start=0., end=1000.):
    return dict(pid=pid, tid=tid, process_instance=instance, thread_instance=thread,
                start_ms=start, end_ms=end, attribution='TRACELOG_THREAD_LIFETIME')


A = identity()
B = identity(43, 9, 4, 5)


def switch(i, now, old=A, new=B, state=5):
    return dict(type='event', ordinal=i, time_ms=now,
        pid=new['pid'], tid=new['tid'], process_instance=new['process_instance'],
        provider='Windows Kernel', provider_guid=ETW_PROVIDER_GUID,
        name='Thread/CSwitch', event_id=65535, opcode=36, version=2,
        payload={}, frames=[], semantic=None, errors=[],
        thread_schedule=dict(schema=SCHEDULE_SCHEMA, source='ETW_KERNEL_SCHEDULER',
            parser='TRACEEVENT_CSWITCH', kind='switch', processor_index=0,
            old_thread=deepcopy(old), new_thread=deepcopy(new), old_state_code=state,
            old_state='Wait' if state == 5 else 'Ready', wait_reason_code=4,
            wait_reason='DelayExecution', wait_mode=0))


def ready(i, now, target=A, waker=B):
    return dict(type='event', ordinal=i, time_ms=now,
        pid=waker['pid'], tid=waker['tid'], process_instance=waker['process_instance'],
        provider='Windows Kernel', provider_guid=ETW_PROVIDER_GUID,
        name='Dispatcher/ReadyThread', event_id=65535, opcode=50, version=2,
        payload={}, frames=[], semantic=None, errors=[],
        thread_schedule=dict(schema=SCHEDULE_SCHEMA, source='ETW_KERNEL_SCHEDULER',
            parser='TRACEEVENT_READY_THREAD', kind='ready', processor_index=1,
            ready_thread=deepcopy(target), waker_thread=deepcopy(waker)))


class WaitAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def index(self, rows, *, loss=0, status='DECODED'):
        stem = str(len(list(self.root.iterdir())))
        source = self.root/(stem+'.jsonl'); target = self.root/(stem+'.sqlite3')
        objects = [dict(type='header', protocol=PROTOCOL, input_sha256='a'*64), *rows,
                   dict(type='footer', protocol=PROTOCOL, status=status, rows=len(rows),
                        decoder_reported_lost_events=loss)]
        source.write_text(''.join(json.dumps(r)+'\n' for r in objects))
        build_index(source, target, input_sha256='a'*64, format_name='.etl')
        return target

    def normal(self):
        return [switch(1, 10.), ready(2, 20.), switch(3, 30., B, A, state=1)]

    def test_real_boundaries_split_blocked_and_ready_without_claiming_lock_owner(self):
        path = self.index(self.normal()); before = hashlib.sha256(path.read_bytes()).hexdigest()
        report = build_wait_report(path, pid=42)
        interval, = report['intervals']
        self.assertEqual(report['status'], 'OBSERVED_INTERVALS')
        self.assertEqual((interval['off_cpu_ms'], interval['blocked_ms'], interval['ready_delay_ms']), (20., 10., 10.))
        self.assertEqual(interval['source_event_ids'], [1, 2, 3])
        self.assertEqual(interval['wait_reason'], 'DelayExecution')
        self.assertEqual(interval['waker_is_lock_owner'], 'NOT_ESTABLISHED')
        self.assertEqual(report['root_cause'], 'UNKNOWN')
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_without_ready_boundary_offcpu_does_not_become_all_blocked(self):
        report = build_wait_report(self.index([switch(1, 10.), switch(2, 30., B, A)]), pid=42)
        row, = report['intervals']
        self.assertEqual(row['off_cpu_ms'], 20.)
        self.assertIsNone(row['blocked_ms']); self.assertIsNone(row['ready_delay_ms'])
        self.assertEqual(report['totals']['observed_blocked_ms'], 0.)

    def test_preempted_ready_thread_is_not_reported_waiting_for_a_lock(self):
        report = build_wait_report(self.index([switch(1, 10., state=1), switch(2, 30., B, A)]), pid=42)
        row, = report['intervals']
        self.assertEqual((row['blocked_ms'], row['ready_delay_ms']), (0., 20.))
        self.assertIsNone(row['wait_reason'])

    def test_loss_unknown_positive_and_truncation_do_not_assert_exact_offcpu(self):
        for loss, status in [(None, 'DECODED'), (2, 'DECODED'), (0, 'TRUNCATED')]:
            with self.subTest(loss=loss, status=status):
                report = build_wait_report(self.index(self.normal(), loss=loss, status=status), pid=42)
                row, = report['intervals']
                self.assertEqual(report['status'], 'PARTIAL_EVIDENCE')
                self.assertEqual(row['observed_span_ms'], 20.)
                self.assertIsNone(row['off_cpu_ms']); self.assertIsNone(row['blocked_ms'])
                self.assertEqual(report['totals']['observed_off_cpu_ms'], 0.)

    def test_pid_tid_reuse_does_not_pair_separate_thread_lifetimes(self):
        second = identity(thread=7, start=20.)
        rows = [switch(1, 10.), ready(2, 25., second), switch(3, 30., B, second)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['intervals'], [])
        self.assertEqual(report['coverage']['right_censored_switch_outs'], 1)
        self.assertEqual(report['coverage']['left_censored_switch_ins'], 1)

    def test_unknown_identity_never_uses_pid_tid_fallback(self):
        unknown = dict(A, process_instance=None, thread_instance=None, start_ms=None,
                       end_ms=None, attribution='UNRESOLVED_THREAD')
        rows = [switch(1, 10., unknown), switch(2, 30., B, unknown)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['intervals'], [])
        self.assertEqual(report['coverage']['unresolved_identities'], 2)

    def test_unresolved_middle_switch_cannot_bridge_hidden_execution(self):
        unknown = dict(A, process_instance=None, thread_instance=None, start_ms=None,
                       end_ms=None, attribution='UNRESOLVED_THREAD')
        rows = [switch(1, 10.), switch(2, 20., B, unknown),
                switch(3, 30., unknown, B), switch(4, 50., B, A)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['intervals'], [])
        self.assertEqual(report['totals']['observed_off_cpu_ms'], 0.)
        self.assertEqual(report['status'], 'PARTIAL_EVIDENCE')
        self.assertEqual(report['coverage']['pending_intervals_invalidated_by_identity'], 1)

    def test_unresolved_zero_pid_nonidle_tid_cannot_hide_execution(self):
        unknown = dict(A, pid=0, process_instance=None, thread_instance=None,
                       start_ms=None, end_ms=None, attribution='UNRESOLVED_THREAD')
        rows = [switch(1, 10.), switch(2, 20., B, unknown),
                switch(3, 30., unknown, B), switch(4, 50., B, A)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['intervals'], [])
        self.assertEqual(report['totals']['observed_off_cpu_ms'], 0.)
        self.assertEqual(report['status'], 'PARTIAL_EVIDENCE')
        self.assertEqual(report['coverage']['pending_intervals_invalidated_by_identity'], 1)

    def test_duplicate_switch_outs_never_invent_a_shorter_valid_interval(self):
        rows = [switch(1, 10.), switch(2, 12.), ready(3, 20.), switch(4, 30., B, A)]
        r = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(r['intervals'], [])
        self.assertEqual(r['coverage']['duplicate_switch_outs'], 1)
        self.assertEqual(r['coverage']['ambiguous_intervals'], 1)

    def test_duplicate_ready_loses_split_but_not_observed_switch_pair(self):
        rows = [switch(1, 10.), ready(2, 20.), ready(3, 21.), switch(4, 30., B, A)]
        r = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(r['intervals'][0]['off_cpu_ms'], 20.)
        self.assertIsNone(r['intervals'][0]['ready_delay_ms'])
        self.assertEqual(r['coverage']['duplicate_ready_events'], 1)

    def test_out_of_order_stream_invalidates_crossing_pairs(self):
        rows = [switch(1, 10.), ready(2, 5.), switch(3, 30., B, A)]
        r = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(r['intervals'], [])
        self.assertEqual(r['coverage']['out_of_order_events'], 1)

    def test_late_reordered_events_withhold_already_emitted_overlapping_durations(self):
        rows = [switch(1, 10.), switch(2, 50., B, A),
                switch(3, 20.), switch(4, 30., B, A)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['status'], 'PARTIAL_EVIDENCE')
        self.assertEqual(len(report['intervals']), 2)
        self.assertTrue(all(i['off_cpu_ms'] is None for i in report['intervals']))
        self.assertEqual(report['totals']['observed_off_cpu_ms'], 0.)
        self.assertTrue(report['coverage']['duration_totals_withheld_due_to_order'])

    def test_late_untyped_switch_withholds_already_emitted_duration(self):
        legacy = switch(3, 20., B, A)
        del legacy['thread_schedule']
        rows = [switch(1, 10.), switch(2, 50., B, A), legacy]
        report = build_wait_report(self.index(rows), pid=42)
        interval, = report['intervals']
        self.assertIsNone(interval['off_cpu_ms'])
        self.assertEqual(interval['quality'], 'OUT_OF_ORDER_BOUNDARIES_ONLY')
        self.assertEqual(report['coverage']['out_of_order_events'], 1)
        self.assertEqual(report['totals']['observed_off_cpu_ms'], 0.)

    def test_self_switch_in_pending_gap_cannot_hide_known_execution(self):
        rows = [switch(1, 10.), switch(2, 20., A, A), switch(3, 50., B, A)]
        report = build_wait_report(self.index(rows), pid=42)
        self.assertEqual(report['intervals'], [])
        self.assertEqual(report['status'], 'PARTIAL_EVIDENCE')
        self.assertEqual(report['coverage']['contradictory_self_switches'], 1)

    def test_partial_edges_are_reported_without_zero_filled_durations(self):
        r = build_wait_report(self.index([ready(1, 10.), switch(2, 20., B, A), switch(3, 30.)]), pid=42)
        self.assertEqual(r['intervals'], [])
        self.assertEqual(r['coverage']['unmatched_ready_events'], 1)
        self.assertEqual(r['coverage']['left_censored_switch_ins'], 1)
        self.assertEqual(r['coverage']['right_censored_switch_outs'], 1)

    def test_filters_clip_components_and_preserve_original_boundaries(self):
        path = self.index(self.normal())
        r = build_wait_report(path, pid=42, process_instance=2, tid=8, start_ms=15., end_ms=25.)
        row, = r['intervals']
        self.assertEqual((row['off_cpu_ms'], row['blocked_ms'], row['ready_delay_ms']), (10., 5., 5.))
        self.assertEqual((row['source_start_ms'], row['source_end_ms']), (10., 30.))
        self.assertTrue(row['window_clipped'])
        self.assertEqual(build_wait_report(path, pid=42, process_instance=99)['intervals'], [])
        self.assertEqual(build_wait_report(path, pid=42, start_ms=30.)['intervals'], [])

    def test_display_budget_is_disclosed_and_totals_conserve_all_observed_pairs(self):
        rows = [*self.normal(), switch(4, 40.), ready(5, 50.), switch(6, 60., B, A)]
        r = build_wait_report(self.index(rows), pid=42, max_intervals=1)
        self.assertEqual(len(r['intervals']), 1)
        self.assertEqual(r['coverage']['paired_intervals'], 2)
        self.assertEqual(r['coverage']['intervals_omitted_budget'], 1)
        self.assertEqual(r['totals']['observed_off_cpu_ms'], 40.)

    def test_legacy_scheduler_requires_redecode_and_eventpipe_has_no_scheduler_claim(self):
        old = switch(1, 10.); del old['thread_schedule']
        self.assertEqual(build_wait_report(self.index([old]))['status'], 'REDECODE_REQUIRED')
        other = dict(old, provider='Microsoft-DotNETCore-SampleProfiler', name='Thread/Sample')
        self.assertEqual(build_wait_report(self.index([other]))['status'], 'NO_SCHEDULER_EVENTS')

    def test_unclassified_middle_switch_invalidates_pending_interval(self):
        unknown = switch(2, 20.); del unknown['thread_schedule']
        r = build_wait_report(self.index([switch(1, 10.), unknown, switch(3, 30., B, A)]), pid=42)
        self.assertEqual(r['intervals'], [])

    def test_decode_error_withholds_exact_duration(self):
        rows = self.normal(); rows[1]['errors'] = ['PAYLOAD:ValueError']
        row, = build_wait_report(self.index(rows), pid=42)['intervals']
        self.assertIsNone(row['off_cpu_ms'])
        self.assertEqual(row['quality'], 'DECODE_ERROR_BOUNDARIES_ONLY')

    def test_fake_provider_opcode_bool_id_payload_or_invalid_lifetime_rejected(self):
        variants = []
        for k, v in [('provider', 'fake'), ('provider_guid', '0'*36), ('event_id', True),
                     ('opcode', 50), ('tid', 999), ('time_ms', float('nan'))]:
            row = switch(1, 10.); row[k] = v; variants.append(row)
        row = switch(1, 10.); row['payload']['OldThreadID'] = 999; variants.append(row)
        row = switch(1, 10.); row['thread_schedule']['old_thread']['end_ms'] = 5.; variants.append(row)
        row = switch(1, 10.); row['thread_schedule']['old_state_code'] = True; variants.append(row)
        for row in variants:
            with self.subTest(row=row), self.assertRaises(ValueError):validate_schedule_event(row)

    def test_lifetime_metadata_cannot_change_for_one_thread_index(self):
        rows = self.normal(); rows[-1]['thread_schedule']['new_thread']['end_ms'] = 900.
        with self.assertRaisesRegex(ValueError, 'LIFETIME_CHANGED'):
            build_wait_report(self.index(rows), pid=42)

    def test_mutated_sqlite_event_metadata_is_rejected(self):
        path = self.index(self.normal())
        with closing(sqlite3.connect(path)) as db:
            db.execute('UPDATE events SET pid=999 WHERE id=1'); db.commit()
        with self.assertRaisesRegex(ValueError, 'METADATA_MISMATCH'):build_wait_report(path)

    def test_cancel_deadline_and_thread_budget_do_not_modify_index(self):
        path = self.index(self.normal()); before = path.read_bytes(); cancel = Event(); cancel.set()
        with self.assertRaises(InterruptedError):build_wait_report(path, cancel=cancel)
        with patch('blackbox_core.decoder_waits.MAX_THREADS', 1), self.assertRaisesRegex(ValueError, 'THREAD_BUDGET'):
            build_wait_report(path)
        with patch('blackbox_core.decoder_waits.time.monotonic', side_effect=[0., 31.]), self.assertRaises(TimeoutError):
            build_wait_report(path)
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_filters_are_not_silently_coerced(self):
        path = self.index(self.normal())
        for kw in [dict(pid=True), dict(tid=-1), dict(start_ms=float('inf')),
                   dict(start_ms=2, end_ms=1), dict(max_intervals=True), dict(max_intervals=0)]:
            with self.subTest(kw=kw), self.assertRaises(ValueError):build_wait_report(path, **kw)


if __name__ == '__main__':unittest.main()
