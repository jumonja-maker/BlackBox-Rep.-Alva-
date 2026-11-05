"""Numerical contracts and storage integration, not fabricated native proof."""
from contextlib import closing, contextmanager
import copy
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

import psutil

from blackbox_core.decoder_alignment import (ALIGNED, ORDER_MODEL, SESSION_CLOCK_SCHEMA,
    assess_session_alignment, capture_session_binding, project_event_time,
    read_session_clock)
from blackbox_core.decoder_index import PROTOCOL, build_index
from blackbox_core.session_v2 import SessionV2Writer
from blackbox_core.trace_clock_evidence import bracket, CLOCK_IDENTITY_SCHEMA
from blackbox_core.trace_clock_evidence import (new_clock_order_samples,
                                               append_clock_order_sample,
                                               MAX_ORDER_SAMPLES)

SHA = "a" * 64
BOOT = "9acbf34a-750b-4dfb-a451-ef8a3056782d"
IDENTITY = {"schema": CLOCK_IDENTITY_SCHEMA, "boot_id": BOOT,
            "boot_id_source": "NT_SYSTEM_BOOT_ENVIRONMENT_INFORMATION",
            "monotonic_implementation": "QueryPerformanceCounter()",
            "monotonic_resolution_ns": 100,
            "evidence_class": "LOCAL_OS_OBSERVATION_NOT_AUTHENTICATED"}

_alignment_directories = []
_retained_alignment_directories = []
MAX_ALIGNMENT_DIRECTORIES = 8
MAX_ALIGNMENT_WRITERS = 4


def _fixture_code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,95}", value) else "UNSTRUCTURED"


def _writer_facts(record, phase):
    writer = record['writer']
    facts = {'phase': phase, 'finish_attempted': record['finish_attempted'],
             'finish_returned': record['finish_returned'], 'finish_confirmed': record['finish_confirmed']}
    for key, getter in (('thread_alive', lambda: writer.thread.is_alive()),
                        ('ready_set', lambda: writer._ready.is_set())):
        try:
            value = getter(); facts[key] = value if type(value) is bool else 'UNKNOWN'
        except Exception:
            facts[key] = 'UNKNOWN'
    try:
        failure = writer.failure
        facts['writer_failure'] = _fixture_code(failure) if failure is not None else None
    except Exception:
        facts['writer_failure'] = 'UNKNOWN'
    facts['file_bytes'] = {}
    for suffix in ('', '-wal', '-shm'):
        try:
            path = Path(str(writer.path) + suffix)
            facts['file_bytes'][suffix or 'database'] = path.stat().st_size if path.exists() else None
        except Exception:
            facts['file_bytes'][suffix or 'database'] = 'UNKNOWN'
    return facts


def _fixture_note(error, phase, facts):
    try:
        error.add_note('ALIGNMENT_FIXTURE ' + json.dumps({**facts, 'phase': phase}, sort_keys=True))
    except BaseException:
        pass  # Secondary diagnostics must preserve the original assertion.


class AlignmentTemporaryDirectory:
    """Own only these fixtures; never unlink a live or unconfirmed writer DB."""
    def __init__(self):
        if len(_alignment_directories) + len(_retained_alignment_directories) >= MAX_ALIGNMENT_DIRECTORIES:
            raise AssertionError('ALIGNMENT_FIXTURE_RETENTION_CAP_REACHED')
        self.name = tempfile.mkdtemp(prefix='blackbox-alignment-')
        self.path = Path(self.name); self.writers = []; self.retained = False
        _alignment_directories.append(self)

    def __enter__(self):
        return self.name

    def _retain(self, error, phase):
        if not self.retained:
            _retained_alignment_directories.append(self)
            self.retained = True
        _fixture_note(error, phase, {'owned_temp_basename': self.path.name,
            'retained': True, 'writers': [_writer_facts(record, phase) for record in self.writers]})

    def cleanup(self, primary=None):
        unknown = any(not record['finish_confirmed'] or _writer_facts(record, 'CLOSE_CHECK')['thread_alive'] is not False
                      for record in self.writers)
        if unknown:
            error = primary if primary is not None else AssertionError('ALIGNMENT_FIXTURE_WRITER_CLOSE_UNCONFIRMED')
            self._retain(error, 'TEMP_RETAINED_WRITER_UNCONFIRMED')
            if primary is None:
                raise error
            return
        try:
            shutil.rmtree(self.path)
        except BaseException as error:
            self._retain(primary if primary is not None else error, 'TEMP_CLEANUP_FAILED')
            if primary is None:
                raise
            _fixture_note(primary, 'SECONDARY_TEMP_CLEANUP_FAILED', {'error_type': type(error).__name__})
            return
        if self.retained:
            _retained_alignment_directories.remove(self)
            self.retained = False

    def __exit__(self, kind, primary, traceback):
        try:
            self.cleanup(primary)
        finally:
            _alignment_directories.remove(self)
        return False


def _new_alignment_writer(folder, **arguments):
    folder = Path(folder).resolve()
    owner = next((item for item in reversed(_alignment_directories) if folder.is_relative_to(item.path.resolve())), None)
    if owner is None:
        raise AssertionError('ALIGNMENT_FIXTURE_OWNED_TEMP_REQUIRED')
    if len(owner.writers) >= MAX_ALIGNMENT_WRITERS:
        raise AssertionError('ALIGNMENT_FIXTURE_WRITER_CAP_REACHED')
    writer = SessionV2Writer(folder, **arguments)
    owner.writers.append({'writer': writer, 'finish_attempted': False, 'finish_returned': False, 'finish_confirmed': False})
    return writer, owner.writers[-1]


@contextmanager
def _finished_alignment_writer(record):
    writer = record['writer']; primary = None
    try:
        yield writer
    except BaseException as error:
        primary = error
        _fixture_note(error, 'BODY_FAILED_BEFORE_FINISH', _writer_facts(record, 'BODY_FAILED_BEFORE_FINISH'))
        raise
    finally:
        record['finish_attempted'] = True
        try:
            writer.finish('COMPLETED', timeout=5)
            record['finish_returned'] = True
            if writer.thread.is_alive():
                raise AssertionError('ALIGNMENT_FIXTURE_WRITER_CLOSE_UNCONFIRMED')
            record['finish_confirmed'] = True
        except BaseException as error:
            facts = _writer_facts(record, 'FINISH_FAILED')
            facts['error_type'] = type(error).__name__
            if primary is None:
                _fixture_note(error, 'FINISH_FAILED', facts)
                raise
            _fixture_note(primary, 'SECONDARY_FINISH_FAILED', facts)


def anchor(qpc, *, offset_ns=4_000_000_000, frequency=10_000_000, boot=BOOT,
           pid=None):
    clock = {**IDENTITY, "boot_id": boot}
    mono = qpc * 1_000_000_000 // frequency + offset_ns
    return bracket(qpc, qpc+10, frequency, mono, mono+1000,
                   1_800_000_000_000_000_000 + qpc*100,
                   pid=os.getpid() if pid is None else pid, clock_identity=clock)


def session(folder):
    folder.mkdir()
    with patch("blackbox_core.decoder_alignment.capture_trace_clock_bracket",
               return_value=anchor(5_000_000)):
        writer, record = _new_alignment_writer(folder, pid=os.getpid(),
                                 created=psutil.Process().create_time(), name="clock fixture",
                                 origin_ns=4_400_000_000)
    with _finished_alignment_writer(record):
        assert writer._ready.wait(5), 'ALIGNMENT_FIXTURE_READY_TIMEOUT'
    # Synthetic capture timeline is deliberately independent of the test host.
    with closing(sqlite3.connect(writer.path)) as db:
        db.execute("UPDATE sessions SET ended_monotonic_ns=7000000000")
        db.commit()
    return writer.path


def fixture(folder, fmt=".etl"):
    source = folder/"decoder.jsonl"
    rows = [{"type": "header", "protocol": PROTOCOL, "input_sha256": SHA,
             "trace_counter_frequency_hz": 10_000_000,
             "trace_counter_kind": "TRACEEVENT_SOURCE_COUNTER"},
            {"type": "event", "ordinal": 1, "time_ms": 1., "pid": os.getpid(),
             "tid": 2, "process_instance": 1, "provider": "SYNTHETIC_TEST_ONLY",
             "name": "clock", "payload": {}, "frames": [], "semantic": None,
             "source_ticks": "15000000"},
            {"type": "footer", "protocol": PROTOCOL, "rows": 1, "status": "DECODED"}]
    source.write_text("".join(json.dumps(r)+"\n" for r in rows), encoding="utf-8")
    index=folder/"index.sqlite3"
    build_index(source,index,input_sha256=SHA,format_name=fmt)
    sp=session(folder/"session")
    if fmt==".etl":
        names=("before_tool_start","after_tool_start","before_tool_stop","after_tool_stop")
        counters=(10_000_000,12_000_000,18_000_000,20_000_000)
        provider="ETW_WPR"
    else:
        names=("before_tool_spawn","after_tool_spawn","after_tool_exit")
        counters=(10_000_000,12_000_000,20_000_000)
        provider="EVENTPIPE_DOTNET_TRACE"
    data={"source":provider,"state":"COMPLETED", "result":{"sha256":SHA},
          "owner_pid":os.getpid(),"owner_created":psutil.Process().create_time(),
          "session_clock_binding":capture_session_binding(sp),
          "clock_anchors":{n:anchor(q,pid=1234) for n,q in zip(names,counters)}}
    jp=folder/"capture.trace.json";jp.write_text(json.dumps(data),encoding="utf-8")
    return index,jp,sp,data


def use_gettickcount_clock(journal, session_path, data):
    """Explicit quantized numerical fixture, not simulated Windows acceptance."""
    resolution = 15_625_000

    def convert(point):
        point["clock_identity"].update(monotonic_implementation="GetTickCount64()",
                                       monotonic_resolution_ns=resolution)
        for key in ("monotonic_before_ns", "monotonic_after_ns"):
            point[key] = point[key] // resolution * resolution
        point["monotonic_bracket_width_ns"] = (point["monotonic_after_ns"] -
                                               point["monotonic_before_ns"])

    for point in data["clock_anchors"].values():
        convert(point)
    with closing(sqlite3.connect(session_path)) as db:
        record=json.loads(db.execute("SELECT evidence_json FROM clock_evidence").fetchone()[0])
        convert(record["clock_bracket"])
        db.execute("UPDATE clock_evidence SET evidence_json=?", (json.dumps(record),))
        db.commit()
    data["session_clock_binding"] = capture_session_binding(session_path)
    journal.write_text(json.dumps(data), encoding="utf-8")


class AlignmentFixtureLifecycleProtocolTests(unittest.TestCase):
    """Fake writer lifecycle faults only; the original storage tests remain real."""
    class Writer:
        def __init__(self, folder, *, ready=True, finish_error=None, alive_after_error=True, leave_alive=False):
            self.path = Path(folder) / 'session-v2.sqlite3'
            self.ready = ready; self.alive = True; self.finish_error = finish_error
            self.alive_after_error = alive_after_error; self.failure = None; self.leave_alive = leave_alive
            self.waits = []; self.finishes = []
            self._ready = SimpleNamespace(wait=self.wait, is_set=lambda: self.ready)
            self.thread = SimpleNamespace(is_alive=lambda: self.alive)

        def wait(self, seconds):
            self.waits.append(seconds)
            return self.ready

        def finish(self, code, *, timeout):
            self.finishes.append((code, timeout))
            if self.finish_error is not None:
                self.alive = self.alive_after_error
                raise self.finish_error
            self.ready = True; self.alive = self.leave_alive

    def release_fake_owner(self, owner):
        # Explicitly model confirmed recovery of these fake resources only.
        # Never clear a real writer's failure or force-unlink its database.
        for record in owner.writers:
            writer = record['writer']
            writer.finish_error = None; writer.leave_alive = False
            with _finished_alignment_writer(record):
                pass
        owner.cleanup()

    def test_ready_false_still_attempts_original_five_second_finish_and_preserves_gate_failure(self):
        owner = AlignmentTemporaryDirectory(); made = []
        def factory(folder, **kwargs):
            writer = self.Writer(folder, ready=False); made.append(writer); return writer
        with patch(__name__ + '.SessionV2Writer', side_effect=factory):
            with self.assertRaisesRegex(AssertionError, '^ALIGNMENT_FIXTURE_READY_TIMEOUT$'):
                with owner as td:
                    session(Path(td) / 'session')
        self.assertEqual(made[0].waits, [5])
        self.assertEqual(made[0].finishes, [('COMPLETED', 5)])
        self.assertTrue(owner.writers[0]['finish_confirmed'])
        self.assertFalse(owner.path.exists())
        self.assertFalse(owner.retained)

    def test_original_exception_survives_finish_failure_and_unknown_writer_temp_is_retained(self):
        owner = AlignmentTemporaryDirectory(); primary = AssertionError('ORIGINAL_READY_FAILURE')
        secondary = RuntimeError('SECONDARY_FINISH_FAILURE')
        writer = self.Writer(owner.path, finish_error=secondary)
        try:
            with patch(__name__ + '.SessionV2Writer', return_value=writer), \
                    patch(__name__ + '.shutil.rmtree', wraps=shutil.rmtree) as remove:
                with self.assertRaises(AssertionError) as caught:
                    with owner as td:
                        _, record = _new_alignment_writer(Path(td))
                        with _finished_alignment_writer(record):
                            raise primary
                self.assertIs(caught.exception, primary)
                remove.assert_not_called()
            self.assertEqual(writer.finishes, [('COMPLETED', 5)])
            self.assertTrue(owner.path.exists()); self.assertTrue(owner.retained)
            self.assertIs(_retained_alignment_directories[-1], owner)
            self.assertIs(owner.writers[0]['writer'], writer)
            self.assertFalse(owner.writers[0]['finish_confirmed'])
            self.assertIn('SECONDARY_FINISH_FAILED', '\n'.join(primary.__notes__))
            self.assertIn('TEMP_RETAINED_WRITER_UNCONFIRMED', '\n'.join(primary.__notes__))
        finally:
            self.release_fake_owner(owner)

    def test_finish_storage_error_is_primary_even_if_thread_has_already_exited(self):
        owner = AlignmentTemporaryDirectory(); failure = RuntimeError('ORIGINAL_STORAGE_FAILURE')
        writer = self.Writer(owner.path, finish_error=failure, alive_after_error=False)
        try:
            with patch(__name__ + '.SessionV2Writer', return_value=writer), \
                    patch(__name__ + '.shutil.rmtree', wraps=shutil.rmtree) as remove:
                with self.assertRaises(RuntimeError) as caught:
                    with owner as td:
                        _, record = _new_alignment_writer(Path(td))
                        with _finished_alignment_writer(record):
                            pass
                self.assertIs(caught.exception, failure)
                remove.assert_not_called()
            self.assertFalse(writer.thread.is_alive())
            self.assertFalse(record['finish_confirmed'])
            self.assertTrue(owner.retained)
        finally:
            self.release_fake_owner(owner)

    def test_finish_return_without_thread_exit_is_unconfirmed_and_retains_ownership(self):
        owner = AlignmentTemporaryDirectory(); writer = self.Writer(owner.path, leave_alive=True)
        try:
            with patch(__name__ + '.SessionV2Writer', return_value=writer), \
                    patch(__name__ + '.shutil.rmtree', wraps=shutil.rmtree) as remove:
                with self.assertRaisesRegex(AssertionError, 'WRITER_CLOSE_UNCONFIRMED'):
                    with owner as td:
                        _, record = _new_alignment_writer(Path(td))
                        with _finished_alignment_writer(record):
                            pass
                remove.assert_not_called()
            self.assertTrue(record['finish_returned'])
            self.assertFalse(record['finish_confirmed'])
            self.assertTrue(writer.thread.is_alive())
            self.assertTrue(owner.retained)
        finally:
            self.release_fake_owner(owner)

    def test_directory_cleanup_failure_cannot_mask_original_and_never_becomes_success(self):
        for primary in (RuntimeError('ORIGINAL_STORAGE_READ_FAILURE'), None):
            with self.subTest(primary=primary is not None):
                owner = AlignmentTemporaryDirectory(); writer = self.Writer(owner.path)
                cleanup = PermissionError('PRIVATE_CLEANUP_PATH')
                try:
                    with patch(__name__ + '.SessionV2Writer', return_value=writer), \
                            patch(__name__ + '.shutil.rmtree', side_effect=cleanup):
                        with self.assertRaises(RuntimeError if primary else PermissionError) as caught:
                            with owner as td:
                                _, record = _new_alignment_writer(Path(td))
                                with _finished_alignment_writer(record):
                                    if primary is not None:
                                        raise primary
                    self.assertIs(caught.exception, primary if primary is not None else cleanup)
                    self.assertTrue(record['finish_confirmed'])
                    self.assertTrue(owner.retained); self.assertTrue(owner.path.exists())
                    self.assertIn('TEMP_CLEANUP_FAILED', '\n'.join(caught.exception.__notes__))
                    if primary is not None:
                        self.assertNotIn('PRIVATE_CLEANUP_PATH', '\n'.join(primary.__notes__))
                finally:
                    owner.cleanup()

    def test_retention_and_writer_caps_deny_new_resources_before_creation(self):
        with patch(__name__ + '._retained_alignment_directories', [object()] * MAX_ALIGNMENT_DIRECTORIES), \
                patch(__name__ + '.tempfile.mkdtemp') as create:
            with self.assertRaisesRegex(AssertionError, 'RETENTION_CAP_REACHED'):
                AlignmentTemporaryDirectory()
            create.assert_not_called()
        owner = AlignmentTemporaryDirectory()
        with owner as td, patch(__name__ + '.SessionV2Writer', side_effect=lambda folder, **kwargs: self.Writer(folder)) as create:
            for _ in range(MAX_ALIGNMENT_WRITERS):
                _, record = _new_alignment_writer(Path(td))
                with _finished_alignment_writer(record):
                    pass
            with self.assertRaisesRegex(AssertionError, 'WRITER_CAP_REACHED'):
                _new_alignment_writer(Path(td))
            self.assertEqual(create.call_count, MAX_ALIGNMENT_WRITERS)
        self.assertFalse(owner.path.exists())


class DecoderAlignmentTests(unittest.TestCase):
    def test_dense_order_samples_tighten_bounds_and_bad_samples_fail_closed(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            use_gettickcount_clock(jp,sp,data)
            series=new_clock_order_samples(data["clock_anchors"]["before_tool_start"])
            for qpc in (13_000_000,14_000_000,16_000_000,17_000_000):
                point=anchor(qpc,pid=1234)
                point["clock_identity"]=copy.deepcopy(series["clock_identity"])
                for key in ("monotonic_before_ns","monotonic_after_ns"):
                    point[key]=point[key]//15_625_000*15_625_000
                point["monotonic_bracket_width_ns"]=point["monotonic_after_ns"]-point["monotonic_before_ns"]
                append_clock_order_sample(series,point)
            data["clock_order_samples"]=series
            jp.write_text(json.dumps(data),encoding="utf-8")
            model=assess_session_alignment(idx,jp,sp)
            self.assertEqual(model["status"],ALIGNED,model)
            self.assertEqual(model["additional_observations"],4)
            projected=project_event_time(model,{"source_ticks":"15000000"})
            self.assertLess(projected["uncertainty_width_ns"],250_000_000)
            self.assertLessEqual(projected["session_relative_lower_ns"],1_100_000_000)
            self.assertGreaterEqual(projected["session_relative_upper_ns"],1_100_000_000)
            invalid=[]
            changed=copy.deepcopy(series);changed["clock_identity"]["boot_id"]=str(uuid4());invalid.append(changed)
            changed=copy.deepcopy(series);changed["owner_pid"]=True;invalid.append(changed)
            changed=copy.deepcopy(series);changed["qpc_frequency_hz"]*=2;invalid.append(changed)
            changed=copy.deepcopy(series);changed["points"].reverse();invalid.append(changed)
            changed=copy.deepcopy(series);changed["points"][0][0]=True;invalid.append(changed)
            changed=copy.deepcopy(series);changed["points"][0]=changed["points"][0][:3];invalid.append(changed)
            changed=copy.deepcopy(series);changed["status"]="INVALID_OBSERVATION";invalid.append(changed)
            for changed in invalid:
                data["clock_order_samples"]=changed
                jp.write_text(json.dumps(data),encoding="utf-8")
                self.assertEqual(assess_session_alignment(idx,jp,sp)["status"],"NOT_ESTABLISHED")
            data["clock_order_samples"]={**series,"status":"SATURATED"}
            jp.write_text(json.dumps(data),encoding="utf-8")
            self.assertEqual(assess_session_alignment(idx,jp,sp)["status"],ALIGNED)

    def test_native_qa_negative_clock_controls_change_the_whole_dense_identity(self):
        from tools.qa_decoder import changed_clock_capture_evidence
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            use_gettickcount_clock(jp,sp,data)
            data["clock_order_samples"]=new_clock_order_samples(data["clock_anchors"]["before_tool_start"])
            # Deserialize exactly as the native QA does; JSON has no shared
            # object references between stage and compact clock identities.
            original=json.loads(json.dumps(data))
            before=copy.deepcopy(original)
            changed=changed_clock_capture_evidence(original,boot_id=str(uuid4()))
            jp.write_text(json.dumps(changed),encoding="utf-8")
            result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["status"],"NOT_ESTABLISHED")
            self.assertEqual(result["reason"],"BOOT_ID_MISMATCH")
            # Deliberately retain a separate mixed-identity negative: it must
            # fail before receiving the different-boot model verdict.
            mixed=copy.deepcopy(changed)
            mixed["clock_order_samples"]=copy.deepcopy(original["clock_order_samples"])
            jp.write_text(json.dumps(mixed),encoding="utf-8")
            self.assertEqual(assess_session_alignment(idx,jp,sp)["error"],
                             "INVALID_COMPACT_CLOCK_OBSERVATIONS")
            frequency=changed_clock_capture_evidence(original,frequency_multiplier=2)
            self.assertEqual(frequency["clock_order_samples"]["qpc_frequency_hz"],20_000_000)
            for point in frequency["clock_anchors"].values():
                self.assertEqual(point,bracket(point["qpc_before_ticks"],point["qpc_after_ticks"],
                    point["qpc_frequency_hz"],point["monotonic_before_ns"],point["monotonic_after_ns"],
                    point["sampled_utc_ns"],pid=point["owner_pid"],clock_identity=point["clock_identity"]))
            jp.write_text(json.dumps(frequency),encoding="utf-8")
            self.assertEqual(assess_session_alignment(idx,jp,sp)["status"],"NOT_ESTABLISHED")
            self.assertEqual(original,before)

    def test_compact_sample_cap_keeps_maximal_integer_journal_within_budget(self):
        from blackbox_core.trace_owner import _write,MAX_JOURNAL_BYTES
        with AlignmentTemporaryDirectory() as td:
            _,jp,_,data=fixture(Path(td))
            reference=bracket(2**63-2000,2**63-2000,10_000_000,
                              2**63-2000,2**63-2000,1_800_000_000_000_000_000,
                              pid=1234,clock_identity=IDENTITY)
            series=new_clock_order_samples(reference)
            for i in range(MAX_ORDER_SAMPLES+3):
                point=bracket(2**63-2000+i,2**63-2000+i,10_000_000,
                              2**63-2000+i,2**63-2000+i,1_800_000_000_000_000_000,
                              pid=1234,clock_identity=IDENTITY)
                append_clock_order_sample(series,point)
            self.assertEqual(len(series["points"]),512)
            self.assertEqual(series["status"],"SATURATED")
            data["clock_order_samples"]=series
            _write(jp,data)
            self.assertLess(jp.stat().st_size,MAX_JOURNAL_BYTES-8000)
            changed=new_clock_order_samples(reference)
            point=copy.deepcopy(reference);point["clock_identity"]["boot_id"]=str(uuid4())
            append_clock_order_sample(changed,point)
            self.assertEqual(changed["status"],"INVALID_OBSERVATION")
            self.assertEqual(changed["points"],[])

    def test_gettickcount_uses_honest_wide_order_bounds_without_offset_interpolation(self):
        for fmt in (".etl", ".nettrace"):
            with self.subTest(fmt=fmt), AlignmentTemporaryDirectory() as td:
                idx,jp,sp,data=fixture(Path(td),fmt)
                use_gettickcount_clock(jp,sp,data)
                result=assess_session_alignment(idx,jp,sp)
                self.assertEqual(result["status"],ALIGNED,result)
                self.assertEqual(result["clock_model"],ORDER_MODEL)
                self.assertEqual(result["monotonic_implementation"],"GetTickCount64()")
                self.assertNotIn("offset_lower_ns",result)
                self.assertGreater(result["uncertainty_width_ns"],500_000_000)
                projected=project_event_time(result,{"source_ticks":"15000000"})
                self.assertEqual(projected["status"],ALIGNED)
                self.assertLessEqual(projected["session_relative_lower_ns"],1_100_000_000)
                self.assertGreaterEqual(projected["session_relative_upper_ns"],1_100_000_000)
                self.assertGreater(projected["uncertainty_width_ns"],500_000_000)
                self.assertIn("NO_INTERPOLATION",projected["precision_quality"])
                self.assertEqual(projected["monotonic_resolution_ns"],15_625_000)
                for ticks in (9_999_999,20_000_011):
                    self.assertEqual(project_event_time(result,{"source_ticks":str(ticks)})["reason"],
                                     "EVENT_OUTSIDE_CAPTURE_WINDOW")

    def test_order_projection_encloses_non_linear_monotone_clock_at_every_counter(self):
        # This non-linear, quantized clock has no constant QPC offset/rate.
        # Only observed ordering is needed to enclose its reading.
        def reading(ticks):
            return (ticks*ticks//7)*1000
        points=[{"qpc_before_ticks":q,"qpc_after_ticks":q+2,
                 "monotonic_before_ns":reading(q-1),
                 "monotonic_after_ns":reading(q+3)} for q in (10,40,70,100)]
        model={"status":ALIGNED,"clock_model":ORDER_MODEL,
               "monotonic_implementation":"GetTickCount64()","frequency_hz":10_000_000,
               "session_origin_ns":0,"clock_order_brackets":points,
               "valid_qpc_min_ticks":12,"valid_qpc_max_ticks":100,
               "qpc_ordering_margin_ticks":1,
               "session_uuid":str(uuid4()),"source_trace_sha256":SHA}
        for ticks in range(12,101):
            projected=project_event_time(model,{"source_ticks":str(ticks)})
            self.assertEqual(projected["status"],ALIGNED)
            self.assertLessEqual(projected["session_relative_lower_ns"],reading(ticks))
            self.assertGreaterEqual(projected["session_relative_upper_ns"],reading(ticks))
        for changed in (list(reversed(points)),points[:1]):
            invalid={**model,"clock_order_brackets":changed}
            self.assertEqual(project_event_time(invalid,{"source_ticks":"50"})["reason"],
                             "INVALID_ALIGNMENT_MODEL")
        wrong_model={**model,"monotonic_implementation":"QueryPerformanceCounter()"}
        self.assertEqual(project_event_time(wrong_model,{"source_ticks":"50"})["status"],
                         "NOT_ESTABLISHED")

    def test_equal_qpc_readings_never_imply_order_in_a_different_clock(self):
        from blackbox_core.decoder_alignment import _order_max_width
        points=[{"qpc_before_ticks":q,"qpc_after_ticks":q,
                 "monotonic_before_ns":m,"monotonic_after_ns":m}
                for q,m in ((1,0),(10,100),(10,200),(10,300),(20,400))]
        model={"status":ALIGNED,"clock_model":ORDER_MODEL,
               "monotonic_implementation":"GetTickCount64()","frequency_hz":10_000_000,
               "session_origin_ns":0,"clock_order_brackets":points,
               "valid_qpc_min_ticks":3,"valid_qpc_max_ticks":18,
               "qpc_ordering_margin_ticks":1,
               "session_uuid":str(uuid4()),"source_trace_sha256":SHA}
        for ticks in (9,10,11):
            projected=project_event_time(model,{"source_ticks":str(ticks)})
            self.assertEqual(projected["session_relative_lower_ns"],0)
            self.assertEqual(projected["session_relative_upper_ns"],400)
            self.assertEqual(projected["uncertainty_width_ns"],400)
        self.assertEqual(_order_max_width(points,3,18),400)
        self.assertEqual(project_event_time(model,{"source_ticks":"1"})["status"],
                         "NOT_ESTABLISHED")

    def test_same_boot_bound_model_and_outward_rounded_event_interval(self):
        for fmt in (".etl", ".nettrace"):
            with self.subTest(fmt=fmt),AlignmentTemporaryDirectory() as td:
                idx,jp,sp,data=fixture(Path(td),fmt)
                before={p:p.read_bytes() for p in (idx,jp,sp)}
                result=assess_session_alignment(idx,jp,sp)
                self.assertEqual(result["status"],ALIGNED,result)
                self.assertFalse(result["utc_used_for_mapping"])
                self.assertLessEqual(result["uncertainty_width_ns"],2400)
                projected=project_event_time(result,{"source_ticks":"15000000"})
                self.assertLessEqual(projected["session_relative_lower_ns"],1_100_000_000)
                self.assertGreaterEqual(projected["session_relative_upper_ns"],1_100_000_000)
                self.assertEqual(result["capture_complete"],None)
                self.assertEqual(result["root_cause"],"UNKNOWN")
                self.assertIn("NOT_AUTHENTICATED",result["verification_class"])
                for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
                self.assertEqual(project_event_time(result,{"source_ticks":"21000000"})["status"],"NOT_ESTABLISHED")
                self.assertEqual(project_event_time(result,{"source_ticks":15_000_000})["status"],"NOT_ESTABLISHED")

    def test_wrong_session_even_same_boot_and_target_is_rejected(self):
        with AlignmentTemporaryDirectory() as td:
            folder=Path(td);idx,jp,sp,_=fixture(folder)
            other=session(folder/"other")
            result=assess_session_alignment(idx,jp,other)
            self.assertEqual(result["reason"],"CAPTURE_SESSION_BINDING_MISMATCH_OR_ABSENT")
            self.assertEqual(result["status"],"NOT_ESTABLISHED")

    def test_reboot_and_changed_clock_implementation_are_rejected(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            for boot,impl in ((str(uuid4()),"QueryPerformanceCounter()"),
                              (BOOT,"GetTickCount64()")):
                altered=copy.deepcopy(data)
                for item in altered["clock_anchors"].values():
                    item["clock_identity"].update(boot_id=boot,monotonic_implementation=impl)
                jp.write_text(json.dumps(altered),encoding="utf-8")
                result=assess_session_alignment(idx,jp,sp)
                self.assertEqual(result["status"],"NOT_ESTABLISHED")
                self.assertNotEqual(result["reason"],"CAPTURE_SESSION_BINDING_MISMATCH_OR_ABSENT")

    def test_sub_coarse_threshold_drift_rejected_by_offset_intersection(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            data["clock_anchors"]["after_tool_stop"]=anchor(20_000_000,offset_ns=4_020_000_000,pid=1234)
            jp.write_text(json.dumps(data),encoding="utf-8")
            result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["reason"],"QPC_MONOTONIC_OFFSET_DISCONTINUITY_OR_DRIFT")

    def test_missing_or_different_trace_frequency_and_missing_counter_fail_closed(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            with closing(sqlite3.connect(idx)) as db:
                base=json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
                for frequency in (None,20_000_000,True):
                    meta=copy.deepcopy(base);meta["engine"]["trace_counter_frequency_hz"]=frequency
                    db.execute("UPDATE metadata SET value=? WHERE key='summary'",(json.dumps(meta),));db.commit()
                    result=assess_session_alignment(idx,jp,sp)
                    self.assertEqual(result["reason"],"TRACE_COUNTER_FREQUENCY_UNAVAILABLE_OR_MISMATCH")
                meta=copy.deepcopy(base);meta["calendar_clock"].update(source_counter_events_observed=0,
                    source_counter_events_missing=1,source_counter_min_ticks=None,source_counter_max_ticks=None)
                db.execute("UPDATE metadata SET value=? WHERE key='summary'",(json.dumps(meta),));db.commit()
                self.assertEqual(assess_session_alignment(idx,jp,sp)["reason"],"TRACE_COUNTER_COVERAGE_INCOMPLETE")

    def test_changed_session_metadata_is_not_silently_rebound(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,_=fixture(Path(td))
            with closing(sqlite3.connect(sp)) as db:
                db.execute("UPDATE sessions SET monotonic_origin_ns=monotonic_origin_ns+1");db.commit()
            result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["status"],"NOT_ESTABLISHED")
            self.assertIn("SESSION_CLOCK_METADATA_MISMATCH",result["error"])

    def test_old_session_without_clock_table_stays_readable_but_unaligned(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,_=fixture(Path(td))
            with closing(sqlite3.connect(sp)) as db:db.execute("DROP TABLE clock_evidence");db.commit()
            result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["status"],"NOT_ESTABLISHED")
            self.assertIn("SESSION_CLOCK_NOT_RECORDED",result["error"])
            self.assertEqual(capture_session_binding(sp)["status"],"SESSION_CLOCK_NOT_BOUND")

    def test_cancelled_alignment_and_session_metadata_query_stop_promptly(self):
        cancel=Event();cancel.set()
        with self.assertRaises(InterruptedError):assess_session_alignment("missing","missing","missing",cancel=cancel)
        with self.assertRaises(InterruptedError):read_session_clock("missing",cancel=cancel)

    def test_owner_reuse_utc_step_and_legacy_capture_never_receive_a_model(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            variants=[]
            changed=copy.deepcopy(data);changed["owner_created"]+=1;variants.append(changed)
            changed=copy.deepcopy(data);changed.pop("session_clock_binding");variants.append(changed)
            changed=copy.deepcopy(data)
            for item in changed["clock_anchors"].values():item.pop("clock_identity")
            variants.append(changed)
            changed=copy.deepcopy(data)
            changed["clock_anchors"]["after_tool_stop"]["sampled_utc_ns"]+=5_000_000_000
            variants.append(changed)
            for altered in variants:
                jp.write_text(json.dumps(altered),encoding="utf-8")
                with self.subTest(altered=altered):
                    self.assertEqual(assess_session_alignment(idx,jp,sp)["status"],"NOT_ESTABLISHED")

    def test_single_metadata_snapshot_cannot_inherit_approval_after_reread(self):
        from blackbox_core.decoder_index import read_index
        from blackbox_core.trace_owner import _read
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            broken=copy.deepcopy(data)
            broken.update(state="FAILED",result={"sha256":"b"*64})
            # The former implementation approved first read, then consumed
            # the replacement on a second read without repeating validation.
            with patch("blackbox_core.trace_owner._read",side_effect=[data,broken]) as journal_read, \
                 patch("blackbox_core.decoder_index.read_index",wraps=read_index) as index_read:
                result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["status"],ALIGNED)
            self.assertEqual(journal_read.call_count,1)
            self.assertEqual(index_read.call_count,1)
            self.assertIn("journal_snapshot_sha256",result)
            with patch("blackbox_core.trace_owner._read",return_value=broken):
                self.assertEqual(assess_session_alignment(idx,jp,sp)["reason"],"CAPTURE_NOT_COMPLETED")
            self.assertEqual(_read(jp)["state"],"COMPLETED")

    def test_interval_math_preserves_exact_rational_counter_bounds(self):
        # Non-decimal frequency verifies floor/ceil outward rounding and a
        # billion-second counter without floating-point precision loss.
        ticks=3_000_000_001
        model={"status":ALIGNED,"frequency_hz":3,"offset_lower_ns":-7,
               "offset_upper_ns":11,"session_origin_ns":1,
               "valid_qpc_min_ticks":ticks-1,"valid_qpc_max_ticks":ticks+1,
               "session_uuid":str(uuid4()),"source_trace_sha256":SHA}
        value=project_event_time(model,{"source_ticks":str(ticks)})
        self.assertEqual(value["session_relative_lower_ns"],ticks*1_000_000_000//3-8)
        self.assertEqual(value["session_relative_upper_ns"],(ticks*1_000_000_000+2)//3+10)
        for frequency in (True,0,-1,10**13):
            self.assertEqual(project_event_time({**model,"frequency_hz":frequency},
                                               {"source_ticks":str(ticks)})["status"],"NOT_ESTABLISHED")

    def test_extreme_signed_counter_cannot_approve_an_unusable_offset_model(self):
        with AlignmentTemporaryDirectory() as td:
            idx,jp,sp,data=fixture(Path(td))
            shift=-9_000_000_000_000_000_000
            for item in data["clock_anchors"].values():
                item["qpc_before_ticks"]+=shift;item["qpc_after_ticks"]+=shift
            with closing(sqlite3.connect(sp)) as db:
                record=json.loads(db.execute("SELECT evidence_json FROM clock_evidence").fetchone()[0])
                record["clock_bracket"]["qpc_before_ticks"]+=shift
                record["clock_bracket"]["qpc_after_ticks"]+=shift
                db.execute("UPDATE clock_evidence SET evidence_json=?",(json.dumps(record),));db.commit()
            data["session_clock_binding"]=capture_session_binding(sp)
            jp.write_text(json.dumps(data),encoding="utf-8")
            with closing(sqlite3.connect(idx)) as db:
                meta=json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
                for name in ("source_counter_min_ticks","source_counter_max_ticks"):
                    meta["calendar_clock"][name]+=shift
                db.execute("UPDATE metadata SET value=? WHERE key='summary'",(json.dumps(meta),));db.commit()
            result=assess_session_alignment(idx,jp,sp)
            self.assertEqual(result["status"],"NOT_ESTABLISHED")
            self.assertEqual(result["reason"],"CLOCK_MODEL_RANGE_UNSUPPORTED")

    def test_live_writer_metadata_is_visible_without_ending_session(self):
        with AlignmentTemporaryDirectory() as td:
            writer,record=_new_alignment_writer(Path(td),pid=os.getpid(),created=psutil.Process().create_time(),
                                                name="live",origin_ns=0)
            with _finished_alignment_writer(record):
                self.assertTrue(writer._ready.wait(5))
                stored=read_session_clock(writer.path)
                self.assertEqual(stored["session"]["session_uuid"],writer.session_uuid)
                self.assertIsNone(stored["session"]["ended_monotonic_ns"])
                self.assertEqual(stored["record"]["schema"],SESSION_CLOCK_SCHEMA)
                self.assertEqual(capture_session_binding(writer.path)["status"],"SESSION_CLOCK_BOUND")


if __name__=="__main__":unittest.main()
