"""Hosted real Qt workspace reflow across repeated application style changes.

The isolated regression adds a native-exit oracle. Existing full-suite Qt
tests still execute in their original shared application and order.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
import unittest
from unittest.mock import patch


def exercise_workspace_styles():
    if not (os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        raise AssertionError("WORKSPACE_STYLE_TEST_REQUIRES_GITHUB_HOSTED_RUNNER")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    root_path = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root_path), str(root_path / "src")]
    from PySide6.QtCore import QEvent, QCoreApplication
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget
    from shiboken6 import isValid
    from blackbox_universal.action_grid import ActionGrid
    from blackbox_universal.theme import set_retro_theme
    from blackbox_universal.window import _AnalysisWorkspace, _button, _label
    from qt_test_support import dispose_closed_fixture

    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    errors = []
    previous_hook = sys.excepthook
    sys.excepthook = lambda kind, value, tb: errors.append(
        "".join(traceback.format_exception(kind, value, tb)))
    hosts, views = [], []
    names = (("Timeline", "Шкала"), ("Findings", "Находки"), ("Library", "Библиотека"),
             ("Actions / SDK", "Действия / SDK"), ("Snapshot / compare", "Снимок / сравнение"),
             ("Copy analysis context", "Копировать контекст анализа"))

    def require(condition, reason):
        if not condition:
            raise AssertionError(reason)

    def geometry(view):
        host, workspace, caption, buttons, following = view
        require(not errors, "WORKSPACE_QT_CALLBACK_ERROR: " + repr(errors))
        required = caption.heightForWidth(caption.width())
        valid = (caption.hasHeightForWidth() and caption.sizePolicy().hasHeightForWidth() and
                 caption.height() >= required > 0 and
                 workspace.minimumHeight() >= workspace.layout().totalHeightForWidth(workspace.width()) and
                 workspace.rect().contains(caption.geometry()) and
                 workspace.geometry().bottom() < following.geometry().top() and
                 all(workspace.rect().contains(button.geometry()) and
                     button.height() >= button.minimumSizeHint().height() and
                     button.visibleRegion().boundingRect() == button.rect() and
                     all(not button.geometry().intersects(other.geometry()) for other in buttons if other is not button)
                     for button in buttons))
        snapshot = (workspace.geometry().getRect(), caption.geometry().getRect(),
                    following.geometry().getRect(), tuple(button.geometry().getRect() for button in buttons))
        return valid, snapshot

    def settle(view):
        previous = None
        for _ in range(160):
            app.processEvents()
            valid, current = geometry(view)
            if valid and current == previous and not view[1]._height_update.isActive():
                return current
            previous = current if valid else None
            QTest.qWait(5)
        raise AssertionError("WORKSPACE_REFLOW_DID_NOT_SETTLE: " + repr(geometry(view)))

    try:
        set_retro_theme(app)
        for _ in range(3):
            host = QWidget(); hosts.append(host)
            root = QVBoxLayout(host)
            scroll = QScrollArea(); scroll.setWidgetResizable(True); root.addWidget(scroll)
            page = QWidget(); outer = QVBoxLayout(page); outer.setSpacing(17); scroll.setWidget(page)
            workspace = _AnalysisWorkspace(); workspace.setObjectName("expertAnalysisWorkspace")
            inner = QVBoxLayout(workspace); inner.setContentsMargins(0, 0, 0, 0)
            caption = _label("Ready\nRoot PID: 123\nSelected interval: 0–2 s\nRoot cause: UNKNOWN", "caption")
            policy = caption.sizePolicy(); policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
            caption.setSizePolicy(policy); inner.addWidget(caption)
            grid = ActionGrid(max_columns=3); inner.addLayout(grid)
            buttons = [_button(pair[0]) for pair in names]
            for button in buttons: grid.addWidget(button)
            outer.addWidget(workspace)
            following = QLabel("Following report panel"); following.setMinimumHeight(500); outer.addWidget(following)
            views.append((host, workspace, caption, buttons, following))
            host.resize(1440, 1000); host.show()
        settle(views[0])

        # A Qt metric callback may request a second update before the first
        # query returns. The guard must cover the query, not only its setter.
        workspace = views[0][1]; layout = workspace.layout()
        original = layout.totalHeightForWidth
        query_calls = []
        def reenter(width):
            query_calls.append(width)
            workspace._sync_minimum_height()
            QCoreApplication.sendEvent(workspace, QEvent(QEvent.Type.FontChange))
            return original(width)
        with patch.object(layout, "totalHeightForWidth", side_effect=reenter):
            workspace._sync_minimum_height()
        require(len(query_calls) == 1, "WORKSPACE_METRIC_QUERY_REENTERED")
        settle(views[0])

        hosts[1].hide()  # Retain hidden native widgets during application-wide replacements.
        cycles = []
        for cycle in range(12):
            print("WORKSPACE_STYLE_PHASE " + json.dumps({"cycle": cycle, "phase": "BEFORE_THEME"}), flush=True)
            set_retro_theme(app)
            language = cycle % 2
            for view in views[:2]:
                _, _, caption, buttons, _ = view
                source = " / ".join(["recorded source component"] * (10 if cycle % 3 else 1))
                caption.setText("Analysis source: " + source +
                                "\nRoot PID: 123 · selected recorded instance: 1\nSelected interval: 0–2 s\nRoot cause: UNKNOWN")
                caption.setStyleSheet("font-size: 20px;" if cycle % 3 == 1 else "")
                for button, pair in zip(buttons, names): button.setText(pair[language])
            hosts[0].resize(*((1440, 1000), (1020, 850), (740, 650))[cycle % 3])
            settled = settle(views[0])
            if cycle == 3:
                views[2][2].setText("Pending layout when its owner is destroyed\nUNKNOWN")
                hosts[2].close(); dispose_closed_fixture(hosts[2], app)
                require(not isValid(hosts[2]), "WORKSPACE_PENDING_TIMER_OWNER_NOT_DESTROYED")
            cycles.append({"cycle": cycle, "workspace": settled[0], "following": settled[2]})
        require(not errors, "WORKSPACE_QT_CALLBACK_ERROR: " + repr(errors))
        print("WORKSPACE_STYLE_LIFECYCLE " + json.dumps({"status": "PASS", "metric_query_guarded": True,
              "cycles": cycles, "pending_timer_owner_destroyed": True,
              "scope": "ACTUAL_QT_LAYOUT_AND_STYLE_NO_CAPTURE_OR_HELPER"}), flush=True)
    finally:
        for host in reversed(hosts):
            if isValid(host):
                host.close(); dispose_closed_fixture(host, app)
        sys.excepthook = previous_hook


class WorkspaceStyleLifecycleTests(unittest.TestCase):
    def test_metric_reentry_and_repeated_global_styles_keep_caption_rows_and_siblings(self):
        if not (os.environ.get("GITHUB_ACTIONS") == "true" and
                os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
            raise AssertionError("WORKSPACE_STYLE_TEST_REQUIRES_GITHUB_HOSTED_RUNNER")
        completed = subprocess.run([sys.executable, "-X", "faulthandler", str(Path(__file__).resolve()),
                                    "--exercise-workspace-styles"],
                                   env=dict(os.environ, QT_QPA_PLATFORM="offscreen"),
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
        self.assertEqual(completed.returncode, 0, (completed.stdout + completed.stderr)[-16000:])
        markers = [line.partition("WORKSPACE_STYLE_LIFECYCLE ")[2] for line in completed.stdout.splitlines()
                   if line.startswith("WORKSPACE_STYLE_LIFECYCLE ")]
        self.assertEqual(len(markers), 1)
        proof = json.loads(markers[0]); self.assertEqual(proof["status"], "PASS")
        self.assertTrue(proof["metric_query_guarded"])
        self.assertEqual(len(proof["cycles"]), 12)
        self.assertTrue(proof["pending_timer_owner_destroyed"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--exercise-workspace-styles"]:
        exercise_workspace_styles()
    else:
        unittest.main()
