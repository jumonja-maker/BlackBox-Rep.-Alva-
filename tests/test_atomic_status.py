"""Windows sharing failures cannot become false workload/guardian failures."""
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from blackbox_core.library_files import atomic_json


def native_error(code):
    error=PermissionError('TEST_ONLY_NATIVE_SHARE_FAILURE')
    error.winerror=code
    return error


class AtomicStatusTests(unittest.TestCase):
    def test_transient_native_sharing_keeps_atomic_content_and_no_qa_fsync(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.json';atomic_json(path,{'seq':1})
            replace=os.replace;attempts=[]
            def intermittently(source,dest):
                attempts.append(1)
                self.assertEqual(json.loads(path.read_text()),{'seq':1})
                if len(attempts)<3:raise native_error(32 if len(attempts)==1 else 5)
                return replace(source,dest)
            with patch('blackbox_core.library_files.os.replace',side_effect=intermittently), \
                 patch('blackbox_core.library_files.time.sleep') as delay, \
                 patch('blackbox_core.library_files.os.fsync',side_effect=AssertionError('QA MUST NOT ADD FSYNC')):
                atomic_json(path,{'seq':2},durable=False)
            self.assertEqual(len(attempts),3);self.assertEqual(delay.call_count,2)
            self.assertEqual(json.loads(path.read_text()),{'seq':2})
            self.assertEqual(list(Path(temp).glob('*.tmp')),[])

    def test_permanent_denial_is_bounded_and_preserves_old_status(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.json';atomic_json(path,{'seq':1})
            with patch('blackbox_core.library_files.os.replace',side_effect=native_error(5)) as replace, \
                 patch('blackbox_core.library_files.time.sleep') as delay:
                with self.assertRaises(PermissionError) as raised:atomic_json(path,{'seq':2})
            self.assertEqual(raised.exception.winerror,5)
            self.assertEqual(replace.call_count,8);self.assertEqual(delay.call_count,7)
            self.assertAlmostEqual(sum(a.args[0] for a in delay.call_args_list),.28)
            self.assertEqual(json.loads(path.read_text()),{'seq':1})
            self.assertEqual(list(Path(temp).glob('*.tmp')),[])

    def test_other_errors_and_exclusive_collision_are_never_retried_or_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.json';atomic_json(path,{'seq':1})
            with patch('blackbox_core.library_files.os.replace',side_effect=native_error(3)) as replace, \
                 patch('blackbox_core.library_files.time.sleep') as delay:
                with self.assertRaises(PermissionError):atomic_json(path,{'seq':2})
            self.assertEqual(replace.call_count,1);delay.assert_not_called()
            with patch('blackbox_core.library_files.os.replace',side_effect=AssertionError('NO REPLACE FOR EXCLUSIVE')):
                with self.assertRaises(FileExistsError):atomic_json(path,{'seq':3},exclusive=True)
            self.assertEqual(json.loads(path.read_text()),{'seq':1})

    @unittest.skipUnless(os.name=='nt','actual Windows delete-sharing semantics')
    def test_actual_windows_reader_can_overlap_atomic_status_update(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.json';atomic_json(path,{'seq':1})
            errors=[]
            def update():
                try:atomic_json(path,{'seq':2})
                except BaseException as exc:errors.append(repr(exc))
            with path.open('r') as reader:
                self.assertEqual(json.load(reader),{'seq':1})
                worker=threading.Thread(target=update);worker.start();time.sleep(.06)
            worker.join(2)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
            self.assertEqual(json.loads(path.read_text()),{'seq':2})
            self.assertEqual(list(Path(temp).glob('*.tmp')),[])


if __name__=='__main__':unittest.main()
