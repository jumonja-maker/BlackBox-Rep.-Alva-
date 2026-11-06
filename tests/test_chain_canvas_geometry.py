"""Hosted real Qt drag regression, isolated from native stack-overflow failures.

The graph is an explicit GUI fixture. No diagnostic/native results are inferred.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


def exercise_canvas():
    from PySide6.QtCore import QPoint, QPointF, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from blackbox_universal.chain_builder import WorkflowCanvas
    from blackbox_universal.theme import set_retro_theme

    app = QApplication.instance() or QApplication([])
    set_retro_theme(app)
    canvas = WorkflowCanvas()
    canvas.resize(1100, 650)
    canvas.show()
    port = {"types": ["REPORT"], "required": True, "many": False}
    catalog = {"fixture": {"inputs": {"in1": dict(port), "in2": dict(port)},
                           "outputs": {"out1": dict(port), "out2": dict(port)}}}
    document = {"nodes": [{"node_id": "n" + str(index), "kind": "TOOL", "tool_id": "fixture",
        "parameters": {}, "position": [40 + index % 3 * 330, 40 + index // 3 * 180]}
        for index in range(6)], "edges": [
            {"edge_id": "a", "source_node": "n0", "source_port": "out2", "target_node": "n1", "target_port": "in2"},
            {"edge_id": "b", "source_node": "n1", "source_port": "out1", "target_node": "n2", "target_port": "in1"},
            {"edge_id": "c", "source_node": "n4", "source_port": "out2", "target_node": "n5", "target_port": "in2"}]}
    canvas.set_graph(document, catalog, {})
    updates = []
    canvas.positions_changed.connect(updates.append)

    def check(condition, reason):
        if not condition:
            raise AssertionError(reason)

    def settled():
        # An ordinary burst of moves must coalesce and then become idle. This
        # is bounded event pumping, not an increase to an acceptance timeout.
        for _ in range(20):
            app.processEvents()
            if not canvas._edge_update_timer.isActive() and not canvas._edges_dirty:
                return
        raise AssertionError("CANVAS_GEOMETRY_DID_NOT_SETTLE")

    def assert_geometry():
        for edge in document["edges"]:
            edge_item = canvas.edge_items[edge["edge_id"]]
            path = edge_item.path()
            expected = (canvas.items_by_id[edge["source_node"]].port_position("outputs", edge["source_port"]),
                        canvas.items_by_id[edge["target_node"]].port_position("inputs", edge["target_port"]))
            for actual, target in zip((path.pointAtPercent(0), path.pointAtPercent(1)), expected):
                check(abs(actual.x() - target.x()) < .001 and abs(actual.y() - target.y()) < .001,
                      "STALE_EDGE_PORT:" + edge["edge_id"])
            # A horizontal curve has an empty mathematical QRectF (height 0).
            # Qt contains(emptyRect) is false even when its painted stroke is
            # wholly visible. Check the actual item bounds, including its pen.
            painted = edge_item.sceneBoundingRect()
            check(not painted.isEmpty() and canvas.sceneRect().contains(painted),
                  "EDGE_PAINTED_BOUNDS_OUTSIDE_SCENE_RECT:" + json.dumps({"edge_id": edge["edge_id"],
                      "path_rect": list(path.boundingRect().getRect()), "painted_rect": list(painted.getRect()),
                      "scene_rect": list(canvas.sceneRect().getRect())}, sort_keys=True))
        for item in canvas.items_by_id.values():
            check(canvas.sceneRect().contains(item.mapRectToScene(item.boundingRect())), "NODE_OUTSIDE_SCENE_RECT")

    try:
        settled()
        flat = canvas.edge_items["b"]
        check(flat.path().boundingRect().height() == 0 and flat.path().boundingRect().isEmpty(),
              "HORIZONTAL_PATH_FIXTURE_NOT_FLAT")
        check(not flat.sceneBoundingRect().isEmpty() and canvas.sceneRect().contains(flat.sceneBoundingRect()),
              "HORIZONTAL_PAINTED_STROKE_NOT_CONTAINED")
        assert_geometry()
        first = canvas.items_by_id["n0"]
        canvas.resetTransform()
        canvas.centerOn(first)
        app.processEvents()
        point = canvas.mapFromScene(first.scenePos() + QPointF(90, 18))
        before = first.pos()
        QTest.mousePress(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
        QTest.mouseMove(canvas.viewport(), point + QPoint(35, 20), delay=30)
        QTest.mouseRelease(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point + QPoint(35, 20))
        settled()
        check(first.pos() != before and updates, "REAL_DRAG_DID_NOT_PUBLISH_MOVED_POSITION")
        check(updates[-1]["n0"] == [first.x(), first.y()], "DRAG_POSITION_SIGNAL_STALE")
        assert_geometry()
        second = canvas.items_by_id["n1"]
        first.setSelected(True)
        second.setSelected(True)
        canvas.setFocus()
        old_first, old_second = first.x(), second.x()
        QTest.keyClick(canvas, Qt.Key.Key_Right)
        settled()
        check(first.x() == old_first + 10 and second.x() == old_second + 10, "MULTI_MOVE_NOT_APPLIED")
        assert_geometry()

        # The bounds signal is an explicit re-entry fixture: one further real
        # item move while publishing scene geometry requires a dirty followup.
        moved_inside_bounds = []
        def move_during_bounds(_):
            if not moved_inside_bounds:
                moved_inside_bounds.append(True)
                item = canvas.items_by_id["n5"]
                item.setPos(item.pos() + QPointF(80, 60))
        canvas.scene().sceneRectChanged.connect(move_during_bounds)
        first.setPos(first.pos() - QPointF(400, 300))
        settled()
        check(moved_inside_bounds, "BOUNDS_REENTRY_FIXTURE_DID_NOT_RUN")
        assert_geometry()
        canvas.scene().sceneRectChanged.disconnect(move_during_bounds)
        for step in range(64):
            second.setPos(370 + step * 2, 40 + step)
        check(canvas._edge_update_timer.isActive(), "MOVE_BURST_NOT_QUEUED")
        settled()
        assert_geometry()
        canvas.fitInView(canvas.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        settled()
        assert_geometry()
        print("R60_CANVAS_GEOMETRY_TEST " + json.dumps({"status": "PASS", "nodes": 6, "edges": 3,
            "actual_pointer_drag": True, "multi_node_keyboard": True, "bounds_reentry_followup": True,
            "flat_path_painted_bounds": True, "edge_endpoints_current": True,
            "scene_contains_nodes_and_paths": True}), flush=True)
    finally:
        canvas.close()
        canvas.deleteLater()
        app.processEvents()


class CanvasGeometryChildTests(unittest.TestCase):
    def test_real_multi_node_drag_geometry_settles_without_native_stack_recursion(self):
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
        completed = subprocess.run([sys.executable, "-X", "faulthandler", str(Path(__file__).resolve()),
                                    "--exercise-canvas"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, (completed.stdout + completed.stderr)[-12000:])
        lines = [line.partition("R60_CANVAS_GEOMETRY_TEST ")[2] for line in completed.stdout.splitlines()
                 if line.startswith("R60_CANVAS_GEOMETRY_TEST ")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["status"], "PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--exercise-canvas"]:
        exercise_canvas()
    else:
        unittest.main()
