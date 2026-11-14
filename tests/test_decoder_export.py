"""A failed save must not expose a final partial SQLite file."""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.decoder_export import export_index_copy


class _WriteHook:
    """Inject a write failure/change while retaining the real file owner."""
    def __init__(self,stream,write):
        self.stream,self.write=stream,write

    def __getattr__(self,name):
        return getattr(self.stream,name)


class DecoderIndexExportTests(unittest.TestCase):
    def test_disk_failure_keeps_source_and_allows_fresh_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output = root/'source.sqlite3', root/'export.sqlite3'
            original = b'SQLite format 3\x00' + b'controlled index fixture' * 200
            source.write_bytes(original)
            native_fdopen=os.fdopen;partial_writes=[]
            @contextmanager
            def full_disk(fd,mode):
                with native_fdopen(fd,mode) as stream:
                    def write(data):
                        stream.write(data[:16]);stream.flush()
                        partial_writes.append(data[:16])
                        raise OSError('injected full disk after partial write')
                    yield _WriteHook(stream,write)
            with patch('blackbox_core.decoder_export.os.fdopen', side_effect=full_disk):
                with self.assertRaisesRegex(OSError,'injected full disk after partial write'):
                    export_index_copy(source, output)
            self.assertEqual(partial_writes,[original[:16]])
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob('.blackbox-index-export-*')), [])
            self.assertEqual(source.read_bytes(), original)
            export_index_copy(source, output)
            self.assertEqual(output.read_bytes(), original)

    def test_destination_race_never_overwrites_unrelated_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root/'source'; output = root/'result'
            source.write_bytes(b'index')
            real_link = os.link
            def competing_file(src, dst):
                Path(dst).write_bytes(b'other evidence')
                return real_link(src, dst)
            with patch('blackbox_core.decoder_export.os.link', side_effect=competing_file):
                with self.assertRaises(FileExistsError):
                    export_index_copy(source, output)
            self.assertEqual(output.read_bytes(), b'other evidence')
            self.assertEqual(list(root.glob('.blackbox-index-export-*')), [])

    def test_source_change_during_copy_refuses_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root/'source'; output = root/'result'
            source.write_bytes(b'index')
            native_fdopen=os.fdopen;writes=[]
            @contextmanager
            def changed(fd,mode):
                with native_fdopen(fd,mode) as stream:
                    def write(data):
                        count=stream.write(data)
                        writes.append(data)
                        source.write_bytes(b'changed index')
                        return count
                    yield _WriteHook(stream,write)
            with patch('blackbox_core.decoder_export.os.fdopen', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'INDEX_CHANGED'):
                    export_index_copy(source, output)
            self.assertEqual(writes,[b'index'])
            self.assertEqual(source.read_bytes(),b'changed index')
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob('.blackbox-index-export-*')),[])

    def test_destination_created_before_final_recheck_keeps_file_exists_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'source';output=root/'result'
            source.write_bytes(b'index')
            native_fsync=os.fsync
            def competing_file(fd):
                native_fsync(fd)
                output.write_bytes(b'other evidence')
            with patch('blackbox_core.decoder_export.os.fsync',side_effect=competing_file):
                with self.assertRaises(FileExistsError):
                    export_index_copy(source,output)
            self.assertEqual(source.read_bytes(),b'index')
            self.assertEqual(output.read_bytes(),b'other evidence')
            self.assertEqual(list(root.glob('.blackbox-index-export-*')),[])
