"""The actual frozen archive gate retains old modules and the new expert path."""
from __future__ import annotations

import unittest
from importlib.metadata import version
import json
from pathlib import Path
import tempfile
import tomllib
from unittest.mock import patch

from blackbox_core import __version__ as core_version
from blackbox_universal import __version__ as gui_version
from tools.release_gate import VERSION
from tools.qa_sdk_clients import run_preparation
from tools.verify_frozen_research import REQUIRED_MODULES, verify_embedded_modules
from tools.write_build_provenance import write_provenance


class ExpertFrozenModuleGateTests(unittest.TestCase):
    def test_complete_archive_table_is_read_only_and_accepted(self):
        table = {name: ('synthetic archive position', 0, 1) for name in REQUIRED_MODULES}
        original = dict(table)
        verify_embedded_modules(table)
        self.assertEqual(table, original)

    def test_missing_expert_import_or_original_native_module_is_refused(self):
        for missing in ('blackbox_universal.evidence_presentation',
                        'blackbox_universal.expert_context', 'tools.qa_expert_workflow', 'tools.qa_sdk_clients',
                        'blackbox_core.archive_policy', 'blackbox_core.trace_cleanup',
                        'blackbox_core.deep_native', 'blackbox_core.operation_worker'):
            with self.subTest(missing=missing):
                table = {name: None for name in REQUIRED_MODULES}
                del table[missing]
                with self.assertRaisesRegex(RuntimeError, 'FROZEN_MODULES_MISSING: ' + missing):
                    verify_embedded_modules(table)


class ProductVersionProvenanceTests(unittest.TestCase):
    def test_core_gui_project_installed_package_and_archive_agree(self):
        project = tomllib.loads((Path(__file__).resolve().parents[1] / 'pyproject.toml').read_text(encoding='utf-8'))
        self.assertEqual(core_version, '0.6.1')
        self.assertEqual(gui_version, core_version)
        self.assertEqual(VERSION, core_version)
        self.assertEqual(project['project']['version'], core_version)
        self.assertEqual(version('blackbox-core'), core_version)

    def test_actual_manifest_writer_uses_the_same_version_and_verified_source(self):
        identity = {'source_identity_status': 'VERIFIED_EXPECTED_HEAD',
                    'actual_source_sha': 'a' * 40, 'source_tree_sha': 'b' * 40}
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'build' / 'blackbox-build.json'
            with patch('tools.write_build_provenance.source_identity', return_value=identity):
                write_provenance('a' * 40, target)
            manifest = json.loads(target.read_text(encoding='utf-8'))
            self.assertEqual(manifest['version'], core_version)
            self.assertEqual(manifest['source_sha'], 'a' * 40)
            self.assertEqual(manifest['source_tree_sha'], 'b' * 40)
            self.assertIs(manifest['tracked_worktree_clean'], True)

    def test_unverified_source_cannot_write_a_versioned_build_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'blackbox-build.json'
            with patch('tools.write_build_provenance.source_identity',
                       return_value={'source_identity_status': 'MISMATCH_OR_DIRTY'}):
                with self.assertRaisesRegex(RuntimeError, 'BUILD_CHECKOUT_NOT_VERIFIED'):
                    write_provenance('a' * 40, target)
            self.assertFalse(target.exists())


class SdkPreparationWorkingDirectoryTests(unittest.TestCase):
    def test_actual_owned_workdir_is_outside_checkout_and_only_workdir_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            evidence = output / 'generated'
            evidence.mkdir()
            sentinel = evidence / 'preparation-source.json'
            sentinel.write_text('TEST_ONLY_GENERATED_EVIDENCE', encoding='utf-8')
            observed = []

            def child(command, folder, name, **options):
                observed.append(folder)
                self.assertFalse(folder.is_relative_to(output))
                self.assertTrue(sentinel.is_file())
                (folder / name).write_text('TEST_ONLY_PREPARATION_LOG', encoding='utf-8')
                return 123

            with patch('tools.qa_sdk_clients.ROOT', output), patch('tools.qa_sdk_clients.run_client', side_effect=child):
                proof = run_preparation(['TEST_ONLY_NO_PROCESS'], output)
            self.assertEqual(proof['status'], 'PASS')
            self.assertIs(proof['cwd_outside_checkout'], True)
            self.assertIs(proof['owned_cwd_removed'], True)
            self.assertFalse(observed[0].exists())
            self.assertEqual(sentinel.read_text(encoding='utf-8'), 'TEST_ONLY_GENERATED_EVIDENCE')
            self.assertEqual((output / 'preparation-logs/preparation.log').read_text(encoding='utf-8'),
                             'TEST_ONLY_PREPARATION_LOG')

    def test_early_app_failure_retains_error_and_log_before_owned_workdir_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            observed = []

            def child(command, folder, name, **options):
                observed.append(folder)
                (folder / name).write_text('TEST_ONLY_FAILURE_LOG', encoding='utf-8')
                (folder / 'blackbox-sdk-qa-error.txt').write_text('TEST_ONLY_EARLY_APP_FAILURE', encoding='utf-8')
                raise AssertionError('CONTROLLED_PREPARATION_FAILURE')

            with patch('tools.qa_sdk_clients.run_client', side_effect=child):
                with self.assertRaisesRegex(AssertionError, 'CONTROLLED_PREPARATION_FAILURE'):
                    run_preparation(['TEST_ONLY_NO_PROCESS'], output)
            proof = json.loads((output / 'preparation-working-directory.json').read_text(encoding='utf-8'))
            self.assertEqual(proof['status'], 'FAIL')
            self.assertEqual(proof['error_type'], 'AssertionError')
            self.assertIs(proof['owned_cwd_removed'], True)
            self.assertFalse(observed[0].exists())
            self.assertEqual((output / 'preparation-logs/blackbox-sdk-qa-error.txt').read_text(encoding='utf-8'),
                             'TEST_ONLY_EARLY_APP_FAILURE')

    def test_temp_configuration_inside_checkout_is_refused_before_app_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            inside = output / 'misconfigured-temp'
            inside.mkdir()
            from types import SimpleNamespace
            configured = SimpleNamespace(name=str(inside), cleanup=inside.rmdir)
            with patch('tools.qa_sdk_clients.ROOT', output), \
                    patch('tools.qa_sdk_clients.tempfile.TemporaryDirectory', return_value=configured), \
                    patch('tools.qa_sdk_clients.run_client') as launch:
                with self.assertRaisesRegex(AssertionError, 'SDK_PREPARATION_CWD_MUST_BE_OUTSIDE_CHECKOUT'):
                    run_preparation(['TEST_ONLY_NO_PROCESS'], output)
            launch.assert_not_called()
            self.assertFalse(inside.exists())
            proof = json.loads((output / 'preparation-working-directory.json').read_text(encoding='utf-8'))
            self.assertEqual(proof['status'], 'FAIL')
            self.assertIs(proof['cwd_outside_checkout'], False)


if __name__ == '__main__':
    unittest.main()
