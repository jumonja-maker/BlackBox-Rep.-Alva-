"""Changing private scratch files; these local-file contracts run only in CI."""
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbox_core import decoder_service as service
from blackbox_core.decoder_limits import DecodeBudget


class ScratchBudgetContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.keep = self.root / 'decoded.jsonl'
        self.keep.write_bytes(b'keep')

    def test_deleted_directory_between_enumeration_and_scandir_is_tolerated(self):
        scratch = self.root / '.etlx-owned-helper'
        scratch.mkdir()
        (scratch / 'trace.etlx').write_bytes(b'gone scratch bytes')
        real_scandir = os.scandir
        removed = []
        def disappear_before_open(path):
            if Path(path) == scratch:
                (scratch / 'trace.etlx').unlink()
                scratch.rmdir()
                removed.append(path)
            return real_scandir(path)
        with patch.object(service.os, 'scandir', side_effect=disappear_before_open):
            self.assertEqual(service._check_work_bytes(self.root, DecodeBudget()), 4)
        self.assertEqual(len(removed), 1)
        self.assertEqual(self.keep.read_bytes(), b'keep')

    def test_vanished_file_stat_is_tolerated_without_skipping_remaining_files(self):
        vanished = self.root / 'removed-before-stat'
        vanished.write_bytes(b'gone')
        real_scandir = os.scandir
        class Entry:
            def __init__(self, value): self.value = value; self.path = value.path
            def is_dir(self, **options): return self.value.is_dir(**options)
            def is_file(self): return self.value.is_file()
            def stat(self):
                if Path(self.path) == vanished: vanished.unlink()
                return Path(self.path).stat()
        class Scan:
            def __init__(self, path): self.scan = real_scandir(path)
            def __enter__(self): return (Entry(row) for row in self.scan.__enter__())
            def __exit__(self, *args): return self.scan.__exit__(*args)
        with patch.object(service.os, 'scandir', side_effect=Scan):
            self.assertEqual(service._check_work_bytes(self.root, DecodeBudget()), 4)
        self.assertFalse(vanished.exists())
        self.assertEqual(self.keep.read_bytes(), b'keep')

    def test_descendant_disappearing_during_iterator_advance_keeps_seen_and_sibling_bytes(self):
        scratch = self.root / '.etlx-owned-helper'
        scratch.mkdir()
        transient = scratch / 'trace.etlx'
        transient.write_bytes(b'observed')
        sibling = self.root / 'other-owned-work'
        sibling.mkdir()
        (sibling / 'keep.bin').write_bytes(b'sibling')
        real_scandir = os.scandir
        # Close the real enumeration first so this fault fixture is portable
        # even on systems where an open directory handle prevents removal.
        with real_scandir(scratch) as scan:
            observed_entry = next(scan)
        advances = []
        class VanishingScan:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def __iter__(self): return self
            def __next__(self):
                advances.append(1)
                if len(advances) == 1:
                    return observed_entry
                transient.unlink()
                scratch.rmdir()
                raise FileNotFoundError('DESCENDANT_REMOVED_DURING_ITERATION')
        def scan(path):
            return VanishingScan() if Path(path) == scratch else real_scandir(path)
        with patch.object(service.os, 'scandir', side_effect=scan):
            # Live-tree sampling is conservative: bytes already observed
            # remain counted even if their scratch directory vanishes later.
            self.assertEqual(service._check_work_bytes(self.root, DecodeBudget()), 19)
        self.assertEqual(len(advances), 2)
        self.assertFalse(scratch.exists())
        self.assertEqual((sibling / 'keep.bin').read_bytes(), b'sibling')
        self.assertEqual(self.keep.read_bytes(), b'keep')

    def test_root_iterator_failure_and_iterator_permission_errors_are_not_swallowed(self):
        class Entry:
            path = str(self.keep)
            def is_dir(self, **options): return False
            def is_file(self): return True
            def stat(self): return self_keep.stat()
        self_keep = self.keep
        for failure in (FileNotFoundError('ROOT_ITERATOR_LOST'), PermissionError('ROOT_ITERATOR_DENIED'),
                        OSError('ROOT_ITERATOR_IO_ERROR')):
            with self.subTest(error=type(failure).__name__):
                class FailingScan:
                    def __enter__(self): return self.entries()
                    def __exit__(self, *args): return False
                    def entries(self):
                        yield Entry()
                        raise failure
                with patch.object(service.os, 'scandir', return_value=FailingScan()):
                    with self.assertRaises(type(failure)) as caught:
                        service._check_work_bytes(self.root, DecodeBudget())
                self.assertIs(caught.exception, failure)

    def test_directory_permission_or_other_io_failure_is_not_swallowed(self):
        scratch = self.root / '.etlx-owned-helper'
        scratch.mkdir()
        real_scandir = os.scandir
        for failure in (PermissionError('DENIED_SCRATCH'), OSError('SCRATCH_IO_ERROR')):
            with self.subTest(error=type(failure).__name__):
                def fail(path):
                    if Path(path) == scratch: raise failure
                    return real_scandir(path)
                with patch.object(service.os, 'scandir', side_effect=fail):
                    with self.assertRaises(type(failure)) as caught:
                        service._check_work_bytes(self.root, DecodeBudget())
                self.assertIs(caught.exception, failure)

    def test_stat_permission_failure_is_not_swallowed(self):
        class Entry:
            path = str(self.keep)
            def is_dir(self, **options): return False
            def is_file(self): return True
            def stat(self): raise PermissionError('DENIED_FILE_STAT')
        class Scan:
            def __enter__(self): return iter([Entry()])
            def __exit__(self, *args): return False
        with patch.object(service.os, 'scandir', return_value=Scan()):
            with self.assertRaisesRegex(PermissionError, 'DENIED_FILE_STAT'):
                service._check_work_bytes(self.root, DecodeBudget())

    def test_loss_of_staging_root_is_not_reported_as_empty_workspace(self):
        missing = self.root / 'missing-root'
        with self.assertRaises(FileNotFoundError):
            service._check_work_bytes(missing, DecodeBudget())

    def test_existing_disk_limit_and_cancel_deadline_checks_remain_enforced(self):
        with patch.object(service, 'MAX_WORK_BYTES', 3):
            with self.assertRaisesRegex(ValueError, 'DECODER_DISK_BUDGET'):
                service._check_work_bytes(self.root, DecodeBudget())
        stop = threading.Event()
        budget = DecodeBudget(stop)
        real_scandir = os.scandir
        def cancel_during_scan(path):
            stop.set()
            return real_scandir(path)
        with patch.object(service.os, 'scandir', side_effect=cancel_during_scan):
            with self.assertRaisesRegex(InterruptedError, 'DECODER_CANCELLED'):
                service._check_work_bytes(self.root, budget)
        self.assertIs(budget.cancel, stop)
        original = DecodeBudget()
        original.deadline = 0
        with self.assertRaisesRegex(TimeoutError, 'DECODER_TIMEOUT'):
            service._check_work_bytes(self.root, original)


if __name__ == '__main__':
    unittest.main()
