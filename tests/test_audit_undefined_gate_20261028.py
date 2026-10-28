"""Actual Pyflakes analysis contracts for the QA-only binding gate."""
import builtins
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.check_undefined_names import check_paths


class UndefinedBindingGateTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'fixture.py'
            path.write_text(source, encoding='utf-8')
            return check_paths([path])

    def test_missing_exception_import_is_caught_in_function_body(self):
        data, code = self.analyze('def health():\n try: return 1\n except (OSError, sqlite3.Error): return 0\n')
        self.assertEqual(code, 1)
        self.assertEqual(data['status'], 'FAIL')
        self.assertEqual(data['findings'][0]['code'], 'UndefinedName')
        self.assertIn('sqlite3', data['findings'][0]['message'])

    def test_unbound_local_is_caught(self):
        data, code = self.analyze('value=1\ndef f():\n print(value)\n value=2\n')
        self.assertEqual(code, 1)
        self.assertEqual(data['findings'][0]['code'], 'UndefinedLocal')

    def test_unused_import_does_not_fail_this_narrow_gate(self):
        data, code = self.analyze('import sqlite3\nunused = 1\ndef f(): return 3\n')
        self.assertEqual(code, 0)
        self.assertEqual(data['status'], 'PASS')
        self.assertEqual(data['findings'], [])

    def test_syntax_error_cannot_be_ignored_as_nonbinding_warning(self):
        data, code = self.analyze('def broken(:\n pass\n')
        self.assertEqual(code, 1)
        self.assertEqual(data['findings'][0]['code'], 'SyntaxError')

    def test_undefined_public_export_is_caught(self):
        data, code = self.analyze('__all__=["missing"]\n')
        self.assertEqual(code, 1)
        self.assertEqual(data['findings'][0]['code'], 'UndefinedExport')

    def test_missing_dependency_is_incomplete_not_pass(self):
        real_import = builtins.__import__
        def import_without_pyflakes(name, *args, **kwargs):
            if name == 'pyflakes':raise ImportError('controlled QA dependency unavailable')
            return real_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=import_without_pyflakes):
            data, code = check_paths([Path(__file__)])
        self.assertEqual(code, 2)
        self.assertEqual(data['status'], 'INCOMPLETE')

    def test_missing_source_and_empty_directory_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in (root, root/'missing.py'):
                with self.subTest(path=path):
                    data, code = check_paths([path])
                    self.assertEqual(code, 2)
                    self.assertEqual(data['status'], 'INCOMPLETE')
