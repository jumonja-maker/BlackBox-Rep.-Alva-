"""Real Windows ETW scheduler acceptance with three owned Win32 wait oracles."""
from __future__ import annotations
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'src')]
from blackbox_core.decoder_index import file_hash
from blackbox_core.decoder_service import decode_file
from blackbox_core.decoder_waits import build_wait_report
from tools.qa_schedule_capture import OwnedScheduleCapture


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'RUNNING', 'source_sha': os.environ.get('GITHUB_SHA'),
              'scope': 'REAL_WINDOWS_OWNED_SLEEP_EVENT_MUTEX_ETW', 'root_cause': 'UNKNOWN'}
    capture = None; child = None
    try:
        capture = OwnedScheduleCapture(output)
        report['capture_start'] = capture.start()
        oracle_path = output/'fixture.json'
        child = subprocess.Popen([sys.executable, str(ROOT/'tools/fixtures/ThreadWaitProbe/probe.py'), str(oracle_path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, stderr = child.communicate(timeout=15)
        require(child.returncode == 0, 'OWNED_WAIT_FIXTURE_FAILED:'+stderr.decode(errors='replace')[-1500:])
        oracle = json.loads(oracle_path.read_text(encoding='utf-8'))
        require(oracle['pid'] == child.pid and oracle['status'] == 'PASS', 'OWNED_WAIT_FIXTURE_IDENTITY')
        captured = capture.stop(); report['capture_result'] = captured
        source = output/captured['path']; digest = file_hash(source)
        require(0 < source.stat().st_size <= 256*1024**2, 'WAIT_TRACE_SIZE_BUDGET')
        index = output/'waits.sqlite3'
        with patch('blackbox_core.decoder_service.helper_path', return_value=args.helper.resolve(strict=True)):
            meta = decode_file(source, index)
        require(meta['status'] == 'DECODED' and meta['decoder_reported_lost_events'] == 0,
                'WAIT_TRACE_MUST_BE_DECODED_WITHOUT_REPORTED_LOSS')
        require(meta['engine'].get('trace_counter_frequency_hz') == oracle['qpc_frequency_hz'],
                'WAIT_FIXTURE_TRACE_COUNTER_FREQUENCY_MISMATCH')
        before_index = file_hash(index)
        waits = build_wait_report(index, pid=child.pid)
        (output/'wait-report.json').write_text(json.dumps(waits, indent=2), encoding='utf-8')
        require(waits['coverage']['typed_events'] > 0 and waits['intervals'], 'REAL_TYPED_SCHEDULER_INTERVALS_REQUIRED')
        matches = {}
        with closing(sqlite3.connect(index.resolve().as_uri()+'?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            for phase in oracle['observations']:
                found = []
                for interval in waits['intervals']:
                    if interval['tid'] != phase['tid'] or interval['off_cpu_ms'] is None or interval['off_cpu_ms'] < 20:
                        continue
                    start_id, end_id = interval['source_event_ids'][0], interval['source_event_ids'][-1]
                    begin = json.loads(db.execute('SELECT data FROM events WHERE id=?', (start_id,)).fetchone()[0])
                    end = json.loads(db.execute('SELECT data FROM events WHERE id=?', (end_id,)).fetchone()[0])
                    if (phase['begin_qpc'] <= int(begin['source_ticks']) <= int(end['source_ticks']) <= phase['end_qpc'] and
                            interval['blocked_ms'] is not None and interval['blocked_ms'] > 10 and
                            interval['thread_state_code'] == 5):
                        found.append(interval)
                require(found, 'REAL_BLOCKED_INTERVAL_NOT_CONFIRMED_'+phase['role'])
                matches[phase['role']] = found
        require(any('Delay' in (r['wait_reason'] or '') for r in matches['Sleep']),
                'REAL_SLEEP_DELAY_REASON_NOT_RECORDED')
        require(file_hash(index) == before_index and file_hash(source) == digest, 'WAIT_ANALYSIS_MODIFIED_EVIDENCE')
        report.update(status='PASS', source_trace_sha256=digest, owned_pid=child.pid,
                      wait_coverage=waits['coverage'], totals=waits['totals'], oracle_matches=matches,
                      fixture=oracle, trace_counter_frequency_hz=meta['engine']['trace_counter_frequency_hz'],
                      interpretation='FIXTURE_API_CONTROL_CONFIRMED; GENERAL_WAIT_REASON_IS_NOT_LOCK_OWNER_OR_ROOT_CAUSE')
    except BaseException as exc:
        report.update(status='FAILED', error=type(exc).__name__, reason=str(exc)[:1500])
        raise
    finally:
        cleanup_error = None
        try:
            if child is not None and child.poll() is None:
                child.kill(); child.wait(timeout=5)
            if capture is not None and capture.active:
                capture.cancel()
        except BaseException as exc:
            cleanup_error = exc
            report.update(status='FAILED', cleanup_error=type(exc).__name__+': '+str(exc)[:1000])
        finally:
            (output/'wait-qa.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        if cleanup_error is not None:
            raise RuntimeError('OWNED_WAIT_QA_CLEANUP_NOT_CONFIRMED') from cleanup_error
    print('DECODER_REAL_WINDOWS_WAIT_QA_PASS')


if __name__ == '__main__':main()
