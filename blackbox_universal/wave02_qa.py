"""Explicit hosted-only Qt routes over actual saved BB-WAVE-02 native evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QFileDialog, QScrollArea, QTableView, QWidget

from .provenance import source_identity
from .theme import font_coverage


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def widget_text(widget):
    for name in ('toPlainText', 'text'):
        method = getattr(widget, name, None)
        if callable(method):
            return str(method())
    return ''


def run_wave02_e2e(app, window, output, evidence_root, container, expected_sha):
    require(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'WAVE02_GUI_REQUIRES_FREE_GITHUB_HOSTED_WINDOWS')
    scopes = {'r20': ['R20'], 'r30': ['R20', 'R30'], 'r40': ['R20', 'R40'],
              'full': ['R20', 'R30', 'R40', 'R50']}
    require(container in scopes, 'WAVE02_GUI_UNKNOWN_SCOPE')
    output, evidence_root = Path(output).resolve(), Path(evidence_root).resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    proof = {'schema': 'blackbox.wave02.gui-qa/1', 'status': 'RUNNING',
        'source_identity': source_identity(expected_sha), 'container': container,
        'required_containers': scopes[container], 'frozen': bool(getattr(sys, 'frozen', False)),
        'physical_windows_10_11': 'NOT_TESTED', 'physical_secure_desktop': 'NOT_TESTED',
        'dpi_scope': 'QT_SCALE_FACTOR_SIMULATION', 'scale': os.environ.get('QT_SCALE_FACTOR', '1'),
        'sections': [], 'case_ids': [], 'exports': [], 'reader_errors': [], 'geometry': []}
    panel = window.investigation_graph_panel
    closed = []
    panel.closed.connect(lambda: closed.append(True))
    panel.bridge.result_ready.connect(lambda operation, _value, error, _generation:
        proof['reader_errors'].append({'operation': operation, 'error': str(error)[:700]}) if error else None)
    inputs = {}

    def pump(predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.005)
            require(not proof['reader_errors'], 'WAVE02_GUI_READER_FAILED:' + str(proof['reader_errors'][-1:]))
        # The observed terminal condition must not be invalidated by an extra
        # event turn starting a legitimate unrelated heartbeat.
        require(predicate(), 'WAVE02_GUI_DEADLINE:' + str(proof.get('phase')))

    def reveal(widget):
        scroll = window.stack.currentWidget()
        require(isinstance(scroll, QScrollArea), 'WAVE02_EXISTING_SCROLLABLE_OVERVIEW_REQUIRED')
        scroll.ensureWidgetVisible(widget)
        app.processEvents()
        require(widget.isVisible(), 'WAVE02_GUI_WIDGET_NOT_VISIBLE:' + widget.objectName())

    def click(widget):
        reveal(widget)
        require(widget.isEnabled(), 'WAVE02_GUI_WIDGET_DISABLED:' + widget.objectName())
        observed = []
        def delivered(*_): observed.append(True)
        widget.clicked.connect(delivered)
        try:
            QTest.mouseClick(widget, Qt.MouseButton.LeftButton)
        finally:
            widget.clicked.disconnect(delivered)
        require(observed, 'WAVE02_GUI_POINTER_EVENT_NOT_DELIVERED')

    def section(key):
        index = panel.section.findData(key)
        require(index >= 0, 'WAVE02_REQUIRED_GUI_SECTION_MISSING:' + key)
        reveal(panel.section)
        panel.section.setFocus()
        QTest.keyClick(panel.section, Qt.Key.Key_Home)
        for _ in range(index): QTest.keyClick(panel.section, Qt.Key.Key_Down)
        app.processEvents()
        require(panel.section.currentData() == key and panel.pages.currentIndex() == index,
                'WAVE02_ACTUAL_SECTION_NAVIGATION_FAILED:' + key)

    def inspect_section(key, summary_name, table_name, detail_name):
        section(key)
        summary = panel.findChild(QWidget, summary_name)
        table = panel.findChild(QTableView, table_name)
        detail = panel.findChild(QWidget, detail_name)
        require(summary is not None and table is not None and detail is not None,
                'WAVE02_TYPED_GUI_CONTROLS_MISSING:' + key)
        reveal(summary)
        require(bool(widget_text(summary).strip()), 'WAVE02_GUI_SUMMARY_EMPTY:' + key)
        require(table.model() is not None and table.model().rowCount() > 0,
                'WAVE02_GUI_ACTUAL_EVIDENCE_ROWS_MISSING:' + key)
        require(bool(widget_text(detail).strip()), 'WAVE02_GUI_DETAILS_EMPTY:' + key)
        if key == 'integrity':
            run_id = panel.case.get('run_receipt', {}).get('run_id')
            require(bool(run_id) and run_id in widget_text(detail),
                    'WAVE02_GUI_RECEIPT_NOT_BOUND_TO_CURRENT_REAL_RUN')
            require(table.model().rowCount() == len(panel.case['sources']),
                    'WAVE02_GUI_SOURCE_ROWS_DO_NOT_MATCH_CURRENT_CASE')
        height_for_width = summary.heightForWidth(summary.width())
        require(summary.width() >= 100 and summary.height() >= summary.fontMetrics().height()
                and (height_for_width < 0 or summary.height() + 2 >= height_for_width),
                'WAVE02_GUI_LOCALIZED_SUMMARY_CLIPPED:' + key)
        rows = table.model().rowCount()
        index = table.model().index(0, 0)
        reveal(table); table.scrollTo(index); app.processEvents()
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=table.visualRect(index).center())
        require(table.selectionModel().hasSelection(), 'WAVE02_GUI_EVIDENCE_POINTER_SELECTION_FAILED:' + key)
        proof['sections'].append({'section': key, 'language': window.language,
            'case_id': panel.case['case_id'], 'rows': rows,
            'summary_nonempty': True, 'detail_nonempty': True, 'actual_qt_row_click': True})

    try:
        require(proof['source_identity']['source_identity_status'] == 'VERIFIED_EXPECTED_HEAD',
                'WAVE02_GUI_SOURCE_SHA_NOT_VERIFIED')
        native = json.loads((evidence_root / 'wave02-native.json').read_text(encoding='utf-8'))
        manifest = json.loads((evidence_root / 'sources.json').read_text(encoding='utf-8'))
        require(native.get('status') == 'PASS' and native['source_identity']['actual_source_sha'] == expected_sha
                and manifest.get('source_sha') == expected_sha and
                manifest.get('scope', {}).get('required_containers') == scopes[container],
                'WAVE02_GUI_REQUIRES_EXACT_HEAD_REAL_NATIVE_EVIDENCE')
        for source in manifest['sources']:
            path = Path(source['path']).resolve(strict=True); inputs[str(path)] = digest(path)
        for key, _ in window.PAGES:
            QTest.mouseClick(window._nav_buttons[key], Qt.MouseButton.LeftButton)
            app.processEvents()
            require(window.stack.currentIndex() == window._page_ids[key],
                    'WAVE02_EXISTING_SIX_PAGE_NAVIGATION_CHANGED:' + key)
        QTest.mouseClick(window._nav_buttons['dashboard'], Qt.MouseButton.LeftButton)
        reveal(window.deep_inspector_toggle)
        if not window.deep_inspector_panel.isVisible():
            QTest.mouseClick(window.deep_inspector_toggle, Qt.MouseButton.LeftButton)
        if not panel.isVisible(): click(window.deep_inspector_panel._action_buttons['investigate_problem'])
        require(panel.isVisible() and not window.deep_inspector_panel.bridge.has_session,
                'WAVE02_OFFLINE_GUI_MUST_NOT_START_UAC_OR_NATIVE_HELPER')
        cases = [('R20', Path(manifest['case_index']))]
        if 'R40' in scopes[container]:
            cases.append(('R40', Path(native['container_results']['R40']['case_index'])))
        for case_kind, case_path in cases:
            proof['phase'] = 'OPEN_REAL_' + case_kind + '_CASE'
            inputs[str(case_path)] = digest(case_path)
            previous = panel.case
            with patch.object(QFileDialog, 'getOpenFileName', return_value=(str(case_path), 'Investigation index (*.sqlite3)')):
                click(panel.open_button)
            pump(lambda: panel.bridge.worker is None and panel.case is not None and panel.case is not previous)
            proof['case_ids'].append(panel.case['case_id'])
            require(panel.case.get('run_receipt', {}).get('operation') == 'investigation.create',
                    'WAVE02_GUI_LOST_REAL_RUN_RECEIPT')
            for language in ('EN', 'RU'):
                window._set_language(language); app.processEvents()
                require(font_coverage(app)['ok'], 'WAVE02_RU_EN_GLYPHS_MISSING')
                proof['phase'] = 'REAL_SOURCE_INTEGRITY_' + language
                inspect_section('integrity', 'invIntegritySummary', 'invIntegritySources', 'invIntegrityReceipt')
                if case_kind == 'R20' and 'R30' in scopes[container]:
                    inspect_section('delays', 'invDelaySummary', 'invDelayEvidenceTable', 'invDelayReport')
                if case_kind == 'R40':
                    inspect_section('crash', 'invCrashSummary', 'invCrashEvidenceTable', 'invCrashReport')
                shot = output / (case_kind + '-' + language + '.png')
                require(window.grab().save(str(shot), 'PNG'), 'WAVE02_GUI_SCREENSHOT_WRITE_FAILED')
                proof['geometry'].append({'language': language, 'case': case_kind,
                    'viewport_width': window.width(), 'viewport_height': window.height(),
                    'screenshot_sha256': digest(shot)})
            for kind in ('json', 'html'):
                proof['phase'] = 'ACTUAL_GUI_EXPORT_' + case_kind + '_' + kind
                path = output / (case_kind + '-gui-export.' + kind)
                with patch.object(QFileDialog, 'getSaveFileName', return_value=(str(path), kind.upper())):
                    click(panel.export_button)
                pump(lambda: panel.bridge.worker is None and path.is_file())
                raw = path.read_text(encoding='utf-8')
                require('BLACKBOX_WAVE02_PRIVATE_SECRET_MUST_NOT_EXPORT' not in raw and
                        'BLACKBOX_WAVE02_DUMP_PRIVATE_CONTENT' not in raw,
                        'WAVE02_GUI_EXPORT_LEAKED_PRIVATE_FIXTURE_PAYLOAD')
                if kind == 'json':
                    parsed = json.loads(raw)
                    require(parsed['case_id'] == panel.case['case_id'] and
                            len(parsed['nodes']) == len(panel.case['nodes']),
                            'WAVE02_GUI_INDEPENDENT_JSON_READBACK_FAILED')
                proof['exports'].append({'case_id': panel.case['case_id'], 'format': kind,
                    'sha256': digest(path), 'bytes': path.stat().st_size, 'independent_readback': True})
        require(all(digest(path) == value for path, value in inputs.items()),
                'WAVE02_GUI_MODIFIED_ORIGINAL_EVIDENCE')
        proof['phase'] = 'GUI_CLOSE_AND_RESOURCE_EXIT'
        window.close()
        pump(lambda: not window.isVisible() and not window.probe.alive and
             panel.bridge.worker is None and not window.deep_inspector_panel.bridge.has_session, timeout=60)
        require(closed, 'WAVE02_GUI_GRAPH_CLOSE_ACK_NOT_OBSERVED')
        proof['cleanup'] = {'status': 'COMPLETED', 'ordinary_observer_exit_verified': not window.probe.alive,
            'graph_worker_finished': panel.bridge.worker is None,
            'graph_closed_acknowledged': True,
            'diagnostic_helper_started': False, 'source_hashes_unchanged': True}
        proof['status'] = 'PASS'
    except BaseException as error:
        proof.update(status='FAIL', reason=str(error)[:2000], error=type(error).__name__,
                     traceback=traceback.format_exc(limit=12))
    finally:
        if window.isVisible() or window.probe.alive:
            try:
                window.close()
                pump(lambda: not window.isVisible() and not window.probe.alive and panel.bridge.worker is None,
                     timeout=45)
            except BaseException as error:
                proof.update(status='FAIL', cleanup_error=str(error)[:1000])
        (output / 'wave02-gui.json').write_text(json.dumps(proof, indent=2, ensure_ascii=False), encoding='utf-8')
    return 0 if proof['status'] == 'PASS' else 1
