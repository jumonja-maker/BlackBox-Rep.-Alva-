"""Existing research UI must not elevate the entire desktop application."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from blackbox_universal.research_panel import ResearchPanel


class DiagnosticPermissionNavigationTests(unittest.TestCase):
    def test_old_permissions_entry_opens_scoped_actions_without_relaunch(self):
        panel, toggle, details = Mock(), Mock(), Mock()
        context = SimpleNamespace(
            window=SimpleNamespace(deep_inspector_panel=panel, deep_inspector_toggle=toggle),
            bridge=SimpleNamespace(active=True, pending=True),
            details=details, tr=lambda en, ru: en)
        with patch("subprocess.Popen", side_effect=AssertionError("GUI_RELAUNCH_FORBIDDEN")):
            ResearchPanel.elevate(context)
        toggle.setChecked.assert_called_once_with(True)
        panel.setFocus.assert_called_once_with()
        panel.bridge.elevate.assert_not_called()
        self.assertIn("specific action", details.setPlainText.call_args.args[0])

    def test_embedded_context_missing_panel_explains_next_action(self):
        details = Mock()
        context = SimpleNamespace(window=SimpleNamespace(), details=details,
                                  tr=lambda en, ru: ru)
        ResearchPanel.elevate(context)
        self.assertIn("выберите действие", details.setPlainText.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
