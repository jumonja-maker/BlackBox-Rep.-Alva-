"""A failed save must not expose a final partial SQLite file."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.decoder_export import export_index_copy


class DecoderIndexExportTests(unittest.TestCase):
    def test_disk_failure_keeps_source_and_allows_fresh_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output = root/'source.sqlite3', root/'export.sqlite3'
            original = b'SQLite format 3\x00' + b'controlled index fixture' * 200
            source.write_bytes(original)
            def full_disk(src, dst, length):
                dst.write(src.read(16))
                raise OSError('injected full disk after partial write')
            with patch('blackbox_core.decoder_export.shutil.copyfileobj', side_effect=full_disk):
                with self.assertRaises(OSError):
                    export_index_copy(source, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob('.blackbox-index-export-*')), [])
            self.assertEqual(source.read_bytes(), original)
            export_index_copy(source, output)
            self.assertEqual(output.read_bytes(), original)

    def test_destination_race_never_overwrites_unrelated_file(self):
        import os
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
            def changed(src, dst, length):
                dst.write(src.read())
                source.write_bytes(b'changed index')
            with patch('blackbox_core.decoder_export.shutil.copyfileobj', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'INDEX_CHANGED'):
                    export_index_copy(source, output)
            self.assertFalse(output.exists())
