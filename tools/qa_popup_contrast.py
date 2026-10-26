"""Render real Qt popup states; never infer readability from a closed screenshot.

The CLI uses the production isolated window without attaching a target or
starting capture. Only QA-owned settings and helper output are written.
Optional baseline checkout is read-only and must fail the same pixel gate.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch


def _source_root() -> Path:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-root', type=Path)
    args, _ = parser.parse_known_args()
    return (args.source_root or Path(__file__).resolve().parents[1]).resolve()

sys.path.insert(0, str(_source_root()))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QPoint, QSettings, Qt
from PySide6.QtGui import QColor, QCursor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow

SELECTION = '#ffddaa'
FOREGROUND = '#302c43'
PROFILES = ('STANDARD', 'DETAILED', 'INCIDENT_BURST')


def require(value: bool, code: str) -> None:
    if not value:
        raise AssertionError(code)


def wait_until(app, condition, *, timeout=15.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    require(bool(condition()), 'POPUP_QA_DEADLINE')


def _near(color, expected, tolerance=22) -> bool:
    return max(abs(color.red() - expected.red()),
               abs(color.green() - expected.green()),
               abs(color.blue() - expected.blue())) <= tolerance


def row_pixels(view, index) -> dict:
    """Measure painted pixels, not the intended palette or stylesheet string."""
    rect = view.visualRect(index).intersected(view.viewport().rect())
    require(rect.width() > 30 and rect.height() > 10, 'POPUP_ROW_CLIPPED')
    image = view.viewport().grab(rect).toImage()
    dpr = image.devicePixelRatio()
    margin = max(3, round(3 * dpr))
    bg, fg = QColor(SELECTION), QColor(FOREGROUND)
    total = backgrounds = text_pixels = 0
    text_right = min(image.width() - margin, round(250 * dpr))
    for y in range(margin, image.height() - margin):
        for x in range(margin, image.width() - margin):
            color = image.pixelColor(x, y)
            total += 1
            backgrounds += int(_near(color, bg, 8))
            if x < text_right and _near(color, fg):
                text_pixels += 1
    require(total > 0, 'POPUP_EMPTY_RENDER')
    return {'background_fraction': backgrounds / total,
            'dark_text_pixels': text_pixels,
            'logical_row': [rect.x(), rect.y(), rect.width(), rect.height()],
            'pixel_size': [image.width(), image.height()], 'dpr': dpr}


def assert_readable(stats: dict) -> None:
    require(stats['background_fraction'] > .55, 'POPUP_SELECTION_BACKGROUND_LOST')
    require(stats['dark_text_pixels'] >= max(4, round(4 * stats['dpr'] ** 2)),
            'POPUP_SELECTED_TEXT_UNREADABLE')


def capture_combo(app, combo, output: Path, prefix: str, *, after_choice=None) -> list:
    require(combo.isEnabled(), 'POPUP_CONTROL_UNEXPECTEDLY_DISABLED')
    values = [combo.itemData(i) for i in range(combo.count())]
    records = []

    def save_measurement(view, index, mode, row):
        stats = row_pixels(view, index)
        record = {'mode': mode, 'row': row, 'current_view_row': view.currentIndex().row(),
                  'text': combo.itemText(row), 'value': values[row], **stats}
        require(view.grab().save(str(output / f'{prefix}-{mode}-{row}.png')),
                'POPUP_SCREENSHOT_WRITE_FAILED')
        (output / f'{prefix}-{mode}-{row}.json').write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        records.append(record)
        assert_readable(stats)

    for row in range(combo.count()):
        before_hover = combo.currentData()
        combo.setFocus()
        combo.showPopup()
        app.processEvents()
        QTest.qWait(120)  # Allow native popup show/animation before mouse input.
        view = combo.view()
        require(view.isVisible(), 'POPUP_NOT_VISIBLE')
        index = combo.model().index(row, combo.modelColumn(), combo.rootModelIndex())
        view.scrollTo(index)
        app.processEvents()
        QTest.mouseMove(view.viewport(), QPoint(1, 1))
        QTest.qWait(25)
        QTest.mouseMove(view.viewport(), view.visualRect(index).center())
        wait_until(app, lambda: view.indexAt(view.viewport().mapFromGlobal(
            QCursor.pos())).row() == row, timeout=2.0)
        QTest.qWait(80)
        app.processEvents()
        # Qt supports both current-item and active-only hover tracking. Assert
        # the actual row under the pointer and its pixels, not a chosen policy.
        save_measurement(view, index, 'hover', row)
        require(combo.currentData() == before_hover, 'POPUP_HOVER_COMMITTED_VALUE')
        QTest.keyClick(view, Qt.Key.Key_Escape)
        combo.hidePopup()
        app.processEvents()
        require(combo.currentData() == before_hover, 'POPUP_ESCAPE_COMMITTED_VALUE')
        combo.showPopup()
        app.processEvents()
        QTest.qWait(120)
        view = combo.view()
        QTest.keyClick(view, Qt.Key.Key_Home)
        for _ in range(row):
            QTest.keyClick(view, Qt.Key.Key_Down)
        app.processEvents()
        require(view.currentIndex().row() == row, 'POPUP_KEYBOARD_SELECTION_WRONG')
        save_measurement(view, index, 'keyboard', row)
        QTest.keyClick(view, Qt.Key.Key_Return)
        app.processEvents()
        if after_choice is not None:
            after_choice(values[row])
        require(combo.currentData() == values[row], 'POPUP_ENTER_CHANGED_WRONG_VALUE')
    require([combo.itemData(i) for i in range(combo.count())] == values,
            'POPUP_INTERNAL_VALUES_CHANGED')
    return records


def run(output: Path, *, expect_baseline_failure=False) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    set_retro_theme(app)
    result = {'result': 'RUNNING', 'platform': app.platformName(),
              'scale': os.environ.get('QT_SCALE_FACTOR', '1'),
              'source_root': str(_source_root()),
              'physical_windows_acceptance': False, 'records': []}
    window = None
    with tempfile.TemporaryDirectory(prefix='bb-popup-qa-') as scratch:
        scratch = Path(scratch)
        prefs = QSettings(str(scratch / 'settings.ini'), QSettings.Format.IniFormat)
        try:
            with patch('blackbox_universal.window.QSettings', return_value=prefs):
                window = UniversalWindow(isolated=True, output_root=scratch / 'sessions',
                                         allow_update_check=False)
            window._timer.stop()
            window.resize(1330, 850)
            window.show()
            window.activateWindow()
            wait_until(app, lambda: not window.probe.pending)
            require(window.stack.count() == 5, 'POPUP_FIVE_PAGES_CHANGED')
            for lang in ('EN', 'RU'):
                window._set_language(lang)
                window._navigate('dashboard')
                app.processEvents()
                window.stack.currentWidget().ensureWidgetVisible(window.dashboard_profile)
                app.processEvents()
                def verify_profile(value):
                    wait_until(app, lambda: not window.probe.pending and
                               window.probe.data.get('capture_policy', {}).get('profile') == value)
                    require(not window.probe.active, 'PROFILE_STARTED_RECORDING')
                result['records'].extend(capture_combo(
                    app, window.dashboard_profile, output, f'{lang}-overview',
                    after_choice=verify_profile))
                require(tuple(window.dashboard_profile.itemData(i) for i in range(3)) == PROFILES,
                        'PROFILE_KEYS_CHANGED')
                window._navigate('settings')
                app.processEvents()
                window.stack.currentWidget().ensureWidgetVisible(window.capture_settings.profile)
                app.processEvents()
                result['records'].extend(capture_combo(
                    app, window.capture_settings.profile, output, f'{lang}-settings'))
                window.stack.currentWidget().ensureWidgetVisible(window.interval_combo)
                app.processEvents()
                result['records'].extend(capture_combo(
                    app, window.interval_combo, output, f'{lang}-interval',
                    after_choice=lambda value: wait_until(app, lambda: not window.probe.pending)))
            window._navigate('dashboard')
            window.stack.currentWidget().ensureWidgetVisible(window.dashboard_profile)
            app.processEvents()
            require(window.grab().save(str(output / 'overview-patched.png')),
                    'POPUP_SCREENSHOT_WRITE_FAILED')
            require(not window.probe.active, 'QA_UNEXPECTED_RECORDING')
            require(not expect_baseline_failure, 'BASELINE_DID_NOT_REPRODUCE')
            result['result'] = 'PASS'
        except AssertionError as error:
            if expect_baseline_failure and str(error) in (
                    'POPUP_SELECTION_BACKGROUND_LOST', 'POPUP_SELECTED_TEXT_UNREADABLE'):
                result.update(result='EXPECTED_BASELINE_FAILURE', error=str(error))
            else:
                result.update(result='FAIL', error=str(error))
                raise
        except Exception as error:
            result.update(result='FAIL', error=type(error).__name__ + ': ' + str(error))
            raise
        finally:
            try:
                if window is not None:
                    window.dashboard_profile.hidePopup()
                    window.capture_settings.profile.hidePopup()
                    window.interval_combo.hidePopup()
                    window.close()
                    wait_until(app, lambda: not window.probe.alive)
                    window.close()
                    window.deleteLater()
                    app.processEvents()
            finally:
                (output / 'popup-result.json').write_text(
                    json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--expect-baseline-failure', action='store_true')
    args = parser.parse_args()
    result = run(args.output, expect_baseline_failure=args.expect_baseline_failure)
    print('BLACKBOX_POPUP_QA ' + json.dumps({k: v for k, v in result.items() if k != 'records'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
