"""Hosted full Linux unittest diagnostics; never turn a crashed child into PASS."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
DIAGNOSTIC_FAILURE = 125
UNIT_CODE = '''import faulthandler, os, unittest
if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
    raise SystemExit('FULL_LINUX_UNIT_SUITE_REQUIRES_GITHUB_HOSTED_RUNNER')
faulthandler.enable(all_threads=True)
faulthandler.dump_traceback_later(120, repeat=True)
try:
    unittest.main(module=None, argv=['unittest', 'discover', '-s', 'tests', '-v'])
finally:
    faulthandler.cancel_dump_traceback_later()
'''


def child_result(proof, debugger_code, expected_sha):
    """Require an observed inferior exit, independently of gdb's process status."""
    if not isinstance(proof, dict) or proof.get('source_sha') != expected_sha:
        return DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_RESULT_MISSING_OR_SOURCE_MISMATCH'
    if (proof.get('inferior_started') is not True or type(proof.get('inferior_pid')) is not int or
            proof['inferior_pid'] <= 0):
        return DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_NO_INFERIOR_STARTED'
    if proof.get('debugger_error') or proof.get('inferior_exited') is not True:
        return DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_EXIT_UNCONFIRMED'
    code, signal = proof.get('child_exit_code'), proof.get('child_exit_signal')
    if type(signal) is int and 1 <= signal <= 64 and code is None:
        return 128 + signal, 'LINUX_UNIT_CHILD_SIGNAL_' + str(signal)
    if type(code) is not int or not 0 <= code <= 255 or signal is not None:
        return DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_EXIT_UNKNOWN_OR_AMBIGUOUS'
    if code:
        return code, 'LINUX_UNIT_CHILD_EXIT_' + str(code)
    if debugger_code != 0:
        return DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_FAILED_AFTER_CHILD_SUCCESS'
    return 0, 'LINUX_UNIT_CHILD_SUCCESS'


def debugger_script(result_path, expected_sha):
    # This script runs inside gdb's own Python, without importing the application.
    return '''set pagination off
set confirm off
set debuginfod enabled off
set print thread-events off
set startup-with-shell off
set disable-randomization off
set follow-fork-mode parent
set detach-on-fork on
handle SIGPIPE nostop noprint pass
python
import gdb, json, re
proof = {'source_sha': SOURCE_SHA, 'inferior_started': False, 'inferior_pid': None,
         'inferior_exited': False, 'child_exit_code': None, 'child_exit_signal': None,
         'signal_stops': [], 'debugger_error': None}
last_stop = None
def continued(event):
    pid = gdb.selected_inferior().pid
    if pid > 0:
        proof['inferior_started'] = True
        proof['inferior_pid'] = pid
def stopped(event):
    global last_stop
    last_stop = event
def exited(event):
    proof['inferior_exited'] = True
    proof['child_exit_code'] = getattr(event, 'exit_code', None)
def convenience_integer(name):
    value = gdb.parse_and_eval(name)
    return None if value.type.code == gdb.TYPE_CODE_VOID else int(value)
gdb.events.cont.connect(continued)
gdb.events.stop.connect(stopped)
gdb.events.exited.connect(exited)
try:
    gdb.execute('run')
    while not proof['inferior_exited']:
        if not isinstance(last_stop, gdb.SignalEvent):
            raise RuntimeError('INFERIOR_STOPPED_WITHOUT_SIGNAL_OR_EXIT')
        signal_name = last_stop.stop_signal
        if not re.fullmatch(r'SIG[A-Z0-9]+', signal_name) or len(proof['signal_stops']) >= 8:
            raise RuntimeError('INFERIOR_SIGNAL_DIAGNOSTIC_LIMIT')
        record = {'signal': signal_name, 'native_backtrace_errors': []}
        proof['signal_stops'].append(record)
        print('LINUX_UNIT_NATIVE_SIGNAL ' + json.dumps({'source_sha': SOURCE_SHA, 'signal': signal_name}), flush=True)
        for command in ('thread apply all bt 30', 'info registers pc', 'x/8i $pc'):
            try:
                gdb.execute(command)
            except gdb.error as error:
                record['native_backtrace_errors'].append(str(error))
        # Deliver the same observed signal. Never restart the suite or suppress
        # the child's fatal signal merely to get a successful debugger exit.
        gdb.execute('handle ' + signal_name + ' nostop noprint pass')
        last_stop = None
        gdb.execute('continue')
    proof['child_exit_signal'] = convenience_integer('$_exitsignal')
    if proof['child_exit_code'] is None and proof['child_exit_signal'] is None:
        proof['child_exit_code'] = convenience_integer('$_exitcode')
except Exception as error:
    proof['debugger_error'] = type(error).__name__ + ': ' + str(error)
finally:
    with open(RESULT_PATH, 'w', encoding='utf-8') as stream:
        json.dump(proof, stream, sort_keys=True)
    print('LINUX_UNIT_INFERIOR_RESULT ' + json.dumps(proof, sort_keys=True), flush=True)
end
'''.replace('SOURCE_SHA', repr(expected_sha)).replace('RESULT_PATH', repr(str(result_path)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args(argv)
    if (not sys.platform.startswith('linux') or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('FULL_LINUX_UNIT_SUITE_REQUIRES_GITHUB_HOSTED_LINUX_RUNNER')
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_sha):
        raise SystemExit('FULL_LINUX_UNIT_SUITE_REQUIRES_EXACT_SOURCE_SHA')
    from blackbox_universal.provenance import source_identity
    identity = source_identity(args.source_sha)
    if identity.get('source_identity_status') != 'VERIFIED_EXPECTED_HEAD':
        raise SystemExit('FULL_LINUX_UNIT_SUITE_CHECKOUT_MISMATCH')
    print('LINUX_UNIT_GDB_BEGIN ' + json.dumps({'source_identity': identity,
          'suite': "unittest discover -s tests -v", 'periodic_dump_seconds': 120,
          'native_backtrace_frames_per_thread': 30}), flush=True)
    with tempfile.TemporaryDirectory(prefix='blackbox-linux-gdb-', dir=os.environ.get('RUNNER_TEMP')) as owned:
        result_path = Path(owned) / 'inferior-result.json'
        script = Path(owned) / 'unit-suite.gdb'
        script.write_text(debugger_script(result_path, args.source_sha), encoding='utf-8')
        try:
            # -c preserves the repository cwd as sys.path[0] == '', as in the
            # previous stdin driver. The complete suite and its order are intact.
            completed = subprocess.run(['gdb', '--nx', '--nh', '--batch', '--return-child-result',
                                        '-x', str(script), '--args', sys.executable, '-c', UNIT_CODE], cwd=ROOT)
            proof = json.loads(result_path.read_text(encoding='utf-8')) if result_path.is_file() else None
            code, reason = child_result(proof, completed.returncode, args.source_sha)
        except (OSError, ValueError) as error:
            proof = {'debugger_error': type(error).__name__ + ': ' + str(error)}
            code, reason = DIAGNOSTIC_FAILURE, 'LINUX_UNIT_GDB_STARTUP_OR_RESULT_FAILURE'
        print('LINUX_UNIT_GDB_VERDICT ' + json.dumps({'status': 'PASS' if code == 0 else 'FAIL',
              'source_sha': args.source_sha, 'exit_code': code, 'reason': reason,
              'inferior': proof}, sort_keys=True), flush=True)
        return code


if __name__ == '__main__':
    raise SystemExit(main())
