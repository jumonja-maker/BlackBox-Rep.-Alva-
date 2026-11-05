"""Exercise the tracked QA scope command without importing application code."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools' / 'qa_wave02_scope.py'
CONTAINERS = ('r20', 'r30', 'r40', 'full')
EXISTING_OUTPUT = 'existing=kept\n'


class Wave02ScopeCliTests(unittest.TestCase):
    def setUp(self):
        self.scope = json.loads(SCRIPT.with_suffix('.json').read_text(encoding='utf-8'))

    def run_cli(self, *args):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'github-output.txt'
            output.write_text(EXISTING_OUTPUT, encoding='utf-8')
            environment = os.environ.copy()
            environment.pop('GITHUB_OUTPUT', None)
            environment['GITHUB_OUTPUT'] = str(output)
            result = subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT,
                env=environment, capture_output=True, text=True, encoding='utf-8', timeout=20)
            return result, output.read_text(encoding='utf-8')

    def test_default_and_matching_container_keep_tracked_json_and_append_outputs(self):
        expected_output = (EXISTING_OUTPUT + 'container=' + self.scope['container'] + '\n'
            + 'endurance_required=' + str(self.scope['endurance_required']).lower() + '\n')
        for args in ((), ('--container', self.scope['container'])):
            with self.subTest(arguments=args):
                result, output = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), self.scope)
                self.assertEqual(result.stderr, '')
                self.assertEqual(output, expected_output)

    def test_different_known_container_fails_without_emitting_github_outputs(self):
        different = next(value for value in CONTAINERS if value != self.scope['container'])
        result, output = self.run_cli('--container', different)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('WAVE02_REQUIRED_SCOPE_MISMATCH', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(output, EXISTING_OUTPUT)

    def test_unknown_option_is_rejected_without_emitting_github_outputs(self):
        result, output = self.run_cli('--unknown-scope-option')
        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(output, EXISTING_OUTPUT)

    def test_unknown_container_is_rejected_without_emitting_github_outputs(self):
        result, output = self.run_cli('--container', 'unknown')
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid choice', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(output, EXISTING_OUTPUT)


if __name__ == '__main__':
    unittest.main()
