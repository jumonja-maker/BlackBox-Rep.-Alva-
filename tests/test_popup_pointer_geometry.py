"""Pointer target regression, independent of Qt rendering and OS availability."""
import unittest

from tools.qa_popup_geometry import visible_row_point


class PopupPointerGeometryTests(unittest.TestCase):
    def test_regular_row_uses_reachable_interior(self):
        self.assertEqual(visible_row_point((100, 80, 300, 32), [(0, 0, 1024, 768)]),
                         (249, 95))

    def test_scaled_desktop_clips_centre_but_keeps_visible_row(self):
        # A 1020-DIP application can be wider than a hosted screen at 150%.
        row = (500, 220, 680, 32)
        x, y = visible_row_point(row, [(0, 0, 683, 512)])
        self.assertGreaterEqual(x, 503)
        self.assertLess(x, 680)
        self.assertGreaterEqual(y, 223)
        self.assertLess(y, 249)
        self.assertGreater(row[0] + row[2] // 2, 683)

    def test_taskbar_and_negative_monitor_origin_are_respected(self):
        x, y = visible_row_point((-150, 455, 220, 60), [(-800, 0, 800, 480)])
        self.assertTrue(-147 <= x < -3)
        self.assertTrue(458 <= y < 477)

    def test_no_cursor_target_in_gap_between_monitors(self):
        with self.assertRaisesRegex(AssertionError, 'POPUP_ROW_OUTSIDE_AVAILABLE_SCREENS'):
            visible_row_point((810, 100, 70, 32), [(0, 0, 800, 600), (900, 0, 800, 600)])

    def test_wholly_offscreen_row_fails_instead_of_synthetic_hover(self):
        with self.assertRaisesRegex(AssertionError, 'POPUP_ROW_OUTSIDE_AVAILABLE_SCREENS'):
            visible_row_point((50, 800, 600, 32), [(0, 0, 1024, 768)])

    def test_invalid_margin_and_tiny_row_fail(self):
        for margin in (0, -1, True, 1.5):
            with self.subTest(margin=margin), self.assertRaises(ValueError):
                visible_row_point((0, 0, 50, 32), [(0, 0, 800, 600)], margin=margin)
        with self.assertRaisesRegex(AssertionError, 'POPUP_ROW_TOO_SMALL_FOR_POINTER'):
            visible_row_point((0, 0, 3, 32), [(0, 0, 800, 600)])


if __name__ == '__main__':
    unittest.main()
