"""The actual frozen archive gate retains old modules and the new expert path."""
from __future__ import annotations

import unittest

from tools.verify_frozen_research import REQUIRED_MODULES, verify_embedded_modules


class ExpertFrozenModuleGateTests(unittest.TestCase):
    def test_complete_archive_table_is_read_only_and_accepted(self):
        table = {name: ('synthetic archive position', 0, 1) for name in REQUIRED_MODULES}
        original = dict(table)
        verify_embedded_modules(table)
        self.assertEqual(table, original)

    def test_missing_expert_import_or_original_native_module_is_refused(self):
        for missing in ('blackbox_universal.evidence_presentation',
                        'blackbox_universal.expert_context', 'tools.qa_expert_workflow',
                        'blackbox_core.deep_native', 'blackbox_core.operation_worker'):
            with self.subTest(missing=missing):
                table = {name: None for name in REQUIRED_MODULES}
                del table[missing]
                with self.assertRaisesRegex(RuntimeError, 'FROZEN_MODULES_MISSING: ' + missing):
                    verify_embedded_modules(table)


if __name__ == '__main__':
    unittest.main()
