"""Hosted Qt fixture disposal, isolated from ownership/lifetime aborts.

Retained-owner rows below are explicit GUI fixtures, never native cleanup proof.
No performance deadline is used as an oracle: native Qt trees must be destroyed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def exercise_fixture_lifecycle():
    from collections import Counter
    from copy import deepcopy
    import gc
    import tempfile
    import time
    from unittest.mock import patch
    import weakref
    from PySide6.QtWidgets import QApplication, QWidget
    from shiboken6 import isValid
    from blackbox_universal.decoder_window import DecoderWindow
    from blackbox_universal.theme import set_retro_theme
    from qt_test_support import close_and_drain, dispose_closed_fixture

    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    errors = []
    previous_hook = sys.excepthook
    def hook(kind, value, tb):
        errors.append(kind.__name__)
        previous_hook(kind, value, tb)
    sys.excepthook = hook

    def check(condition, reason):
        if not condition:
            raise AssertionError(reason)

    def widget_census(stage):
        """Bounded native widget observations, without deleting any orphan."""
        classes, groups = Counter(), Counter()
        for widget in app.allWidgets():
            cls = widget.metaObject().className()
            classes[cls] += 1
            parents = []
            parent = widget.parentWidget()
            for _ in range(3):
                if parent is None:
                    break
                parents.append({"class": parent.metaObject().className(), "name": parent.objectName()[:48]})
                parent = parent.parentWidget()
            text = getattr(widget, "text", None)
            text = text()[:48] if callable(text) else ""
            row = {"class": cls, "name": widget.objectName()[:64], "text_prefix": text,
                   "parents": parents, "visible": widget.isVisible(), "is_window": widget.isWindow()}
            groups[json.dumps(row, ensure_ascii=True, sort_keys=True)] += 1
        rows = [{**json.loads(row), "count": count} for row, count in groups.most_common(100)]
        print("R60_QT_WIDGET_CENSUS " + json.dumps({"stage": stage, "classes": dict(classes),
            "native_widget_count": sum(classes.values()), "distinct_groups": len(groups), "rows": rows},
            ensure_ascii=True, sort_keys=True), flush=True)

    def idle(window):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            app.processEvents()
            if not window.chain_builder_panel.bridge.busy:
                return
            time.sleep(.005)
        raise AssertionError("LIFECYCLE_CATALOG_NOT_DRAINED")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        window = None
        try:
            # Observe Qt's close semantics directly; this is not an assumption
            # that hiding a fixture releases its object tree.
            plain = QWidget()
            plain.show()
            app.processEvents()
            check(plain.close() and isValid(plain), "QT_CLOSE_CONTROL_DID_NOT_RETAIN_NATIVE_WIDGET")
            dispose_closed_fixture(plain, app)
            check(not isValid(plain), "QT_CLOSE_CONTROL_NOT_DISPOSED")
            del plain
            set_retro_theme(app)
            window = DecoderWindow(output_root=root / "warmup", allow_update_check=False)
            window._timer.stop()
            window.show()
            idle(window)
            close_and_drain(window, app, timeout=15)
            del window
            window = None
            gc.collect()
            baseline = len(app.allWidgets())
            widget_census("AFTER_WARMUP_DISPOSE")
            cycles = []
            for cycle in range(4):
                set_retro_theme(app)
                window = DecoderWindow(output_root=root / str(cycle), allow_update_check=False)
                window._timer.stop()
                window.show()
                idle(window)
                panel = window.chain_builder_panel
                panel.add_tool("process_select")
                template = deepcopy(panel.document["nodes"][0])
                panel.document["nodes"] = [dict(deepcopy(template), node_id="fixture_" + str(index),
                    position=[index % 16 * 320, index // 16 * 160]) for index in range(256)]
                panel._render()
                scene = panel.canvas.scene()
                check(len(panel.canvas.items_by_id) == 256, "LIFECYCLE_LARGE_SCENE_NOT_CREATED")
                roots = (weakref.ref(window), weakref.ref(panel), weakref.ref(scene))
                destroyed = []
                window.destroyed.connect(lambda *_: destroyed.append("window"))
                scene.destroyed.connect(lambda *_: destroyed.append("scene"))
                live_count = len(app.allWidgets())
                close_and_drain(window, app, timeout=15)
                check(all(ref() is None or not isValid(ref()) for ref in roots),
                      "LIFECYCLE_NATIVE_WINDOW_PANEL_OR_SCENE_STILL_VALID")
                check("window" in destroyed and "scene" in destroyed, "LIFECYCLE_OWNED_SCENE_NOT_DESTROYED")
                del scene, panel, window
                window = None
                gc.collect()
                app.processEvents()
                gc.collect()
                after = len(app.allWidgets())
                if after != baseline:
                    widget_census("AFTER_LARGE_SCENE_DISPOSE_" + str(cycle))
                check(after == baseline, "LIFECYCLE_NATIVE_WIDGET_COUNT_ACCUMULATED:" + str((baseline, after)))
                check(all(ref() is None or not isValid(ref()) for ref in roots), "LIFECYCLE_WEAKREF_RETAINED_NATIVE_TREE")
                cycles.append({"cycle": cycle, "baseline_widgets": baseline, "live_widgets": live_count,
                    "after_widgets": after, "native_roots_and_scene_destroyed": True,
                    "python_wrappers_released": [ref() is None for ref in roots]})
            window = DecoderWindow(output_root=root / "retained", allow_update_check=False)
            window._timer.stop()
            window.show()
            idle(window)
            deep = window.deep_inspector_panel.bridge
            deep._service = object()
            deep._closing = True
            deep.cleanup_required = True
            scene = window.chain_builder_panel.canvas.scene()
            try:
                with patch.object(deep, "retry_cleanup", return_value=False):
                    refused = False
                    try:
                        close_and_drain(window, app, timeout=.05)
                    except AssertionError as error:
                        check("WINDOW_WORKERS_NOT_CLOSED_BEFORE_FIXTURE_CLEANUP" in str(error),
                              "LIFECYCLE_UNEXPECTED_REFUSAL_REASON")
                        refused = True
                    check(refused and isValid(window) and isValid(scene) and window.isVisible(),
                          "LIFECYCLE_RETAINED_OWNER_TREE_WAS_DESTROYED")
            finally:
                # Only the synthetic fixture is removed. No successful native
                # cleanup, closed signal, or shutdown flag is fabricated.
                deep._service = None
                deep._closing = False
                deep.cleanup_required = False
                close_and_drain(window, app, timeout=15)
                window = None
            check(not errors, "LIFECYCLE_QT_CALLBACK_EXCEPTION:" + ",".join(errors))
            print("R60_QT_FIXTURE_LIFECYCLE " + json.dumps({"status": "PASS", "cycles": cycles,
                "close_without_delete_keeps_native_widget": True, "large_scene_nodes_per_cycle": 256,
                "retained_owner_refused_destruction": True,
                "scope": "ACTUAL_QT_OBJECT_DESTRUCTION_NOT_NATIVE_OR_PERFORMANCE_ACCEPTANCE"}), flush=True)
        finally:
            if window is not None and isValid(window):
                close_and_drain(window, app, timeout=15)
            sys.excepthook = previous_hook


class FixtureLifecycleChildTests(unittest.TestCase):
    def test_both_evidence_modes_own_all_controls_and_hide_only_unused_fields(self):
        from types import SimpleNamespace
        from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget
        from blackbox_universal.evidence_panels import EvidencePanel
        from qt_test_support import dispose_closed_fixture
        app = QApplication.instance() or QApplication([])
        host = QWidget()
        host.language = "EN"
        calls = []
        host.probe = SimpleNamespace(session_folder=None, send=lambda *args, **kwargs: calls.append((args, kwargs)))
        layout = QVBoxLayout(host)
        panels = [EvidencePanel(host, events=events) for events in (False, True)]
        for panel in panels:
            layout.addWidget(panel)
        host.show()
        app.processEvents()
        try:
            fields = ("question", "sort", "source", "severity", "target", "start", "end", "search")
            for panel in panels:
                with self.subTest(events=panel.events):
                    unused = {"question", "sort"} if panel.events else {
                        "source", "severity", "target", "start", "end", "search"}
                    for name in fields:
                        control = getattr(panel, name)
                        self.assertIs(control.parentWidget(), panel, name)
                        self.assertFalse(control.isWindow(), name)
                        if name in unused:
                            self.assertTrue(control.isHidden(), name)
                            self.assertFalse(control.isVisible(), name)
                        else:
                            self.assertTrue(control.isVisible(), name)
            self.assertEqual(calls, [], "Ownership and visibility must not execute evidence queries")
        finally:
            host.close()
            dispose_closed_fixture(host, app)

    def test_closed_large_qt_trees_are_destroyed_but_unconfirmed_owners_are_retained(self):
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
        completed = subprocess.run([sys.executable, "-X", "faulthandler", str(Path(__file__).resolve()),
                                    "--exercise-lifecycle"], env=env, capture_output=True, text=True, timeout=60)
        for line in completed.stdout.splitlines():
            if line.startswith("R60_QT_WIDGET_CENSUS "):
                print(line, flush=True)
        self.assertEqual(completed.returncode, 0, (completed.stdout + completed.stderr)[-12000:])
        markers = [line.partition("R60_QT_FIXTURE_LIFECYCLE ")[2] for line in completed.stdout.splitlines()
                   if line.startswith("R60_QT_FIXTURE_LIFECYCLE ")]
        self.assertEqual(len(markers), 1)
        proof = json.loads(markers[0])
        self.assertEqual(proof["status"], "PASS")
        self.assertEqual(len(proof["cycles"]), 4)
        self.assertTrue(proof["retained_owner_refused_destruction"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--exercise-lifecycle"]:
        exercise_fixture_lifecycle()
    else:
        unittest.main()
