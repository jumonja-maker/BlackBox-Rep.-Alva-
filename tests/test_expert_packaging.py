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
        self.assertEqual(core_version, '0.6.0')
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


if __name__ == '__main__':
    unittest.main()
