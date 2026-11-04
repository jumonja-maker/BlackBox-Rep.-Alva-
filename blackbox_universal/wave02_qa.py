"""Explicit hosted-only Qt routes over actual saved BB-WAVE-02 native evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from unittest.mock import patch

from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (QApplication, QComboBox, QDialogButtonBox,
    QFileDialog, QInputDialog, QPushButton, QScrollArea, QTableView, QWidget)

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


class _WaveGuiFixture:
    """Packaged QA talks only to the separately compiled owned Win32 oracle."""
    def __init__(self, executable, output):
        from blackbox_core.optional_jobs import OwnedProcess
        output.mkdir(parents=True, exist_ok=False)
        self.log = (output / 'stderr.log').open('wb')
        self.lines = queue.Queue(maxsize=64); self.records = []
        self.owner = self.reader = None
        try:
            self.owner = OwnedProcess([str(executable),str(output),str(output/'unused-private.dmp')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,detach_console=True)
            self.process = self.owner.process
            self.reader = threading.Thread(target=self._read,daemon=True,name='wave02-gui-oracle')
            self.reader.start()
        except BaseException:
            self.close(False)
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(16385)
                if not line: raise EOFError('WAVE02_GUI_ORACLE_CLOSED')
                require(len(line)<=16384 and line.endswith(b'\n'),'WAVE02_GUI_ORACLE_LINE_BUDGET')
                value = json.loads(line)
                require(type(value) is dict and type(value.get('event')) is str,'WAVE02_GUI_ORACLE_SHAPE')
                self.lines.put_nowait(value)
        except BaseException as error:
            try: self.lines.put_nowait(error)
            except queue.Full: pass

    def poll(self, event):
        while not self.lines.empty():
            item = self.lines.get_nowait()
            if isinstance(item,BaseException): raise item
            self.records.append(item)
            require(len(self.records)<=64,'WAVE02_GUI_ORACLE_RECORD_BUDGET')
        return next((q for q in self.records if q['event']==event),None)

    def send(self, command):
        require(command in {'burst','stop'} and self.process.poll() is None,'WAVE02_GUI_ORACLE_COMMAND')
        self.process.stdin.write((command+'\n').encode('ascii'));self.process.stdin.flush()

    def close(self, graceful):
        result = {'status':'NOT_STARTED'}
        try:
            if self.owner is not None and graceful:
                self.send('stop');self.process.wait(timeout=15)
                # Reader may still be draining the final small proof line.
                if self.reader is not None:self.reader.join(timeout=2)
                # An expected EOF follows a real normal_exit and is not reused
                # as a successful oracle; inspect the queued record explicitly.
                while not self.lines.empty():
                    item=self.lines.get_nowait()
                    if isinstance(item,dict):self.records.append(item)
                stopped=next((q for q in self.records if q['event']=='normal_exit'),None)
                require(self.process.returncode==0 and stopped and stopped['cleanup_complete'] is True,
                        'WAVE02_GUI_FIXTURE_GRACEFUL_EXIT_NOT_CONFIRMED')
                result={'status':'COMPLETED','exit_code':0,'oracle':stopped}
        finally:
            if self.owner is not None:
                self.owner.close(kill=True)
                for stream in (self.process.stdin,self.process.stdout):
                    if stream is not None:stream.close()
                if self.reader is not None:
                    self.reader.join(timeout=2)
                    require(not self.reader.is_alive(),'WAVE02_GUI_ORACLE_READER_NOT_CLOSED')
                self.owner=None
            self.log.close()
        return result


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
    observer_results = []
    window.probe.result_ready.connect(lambda operation,value,error:
        observer_results.append({'operation':operation,'value':value,'error':error}))
    inputs = {}; live_fixture = None

    def pump(predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.005)
            require(not proof['reader_errors'], 'WAVE02_GUI_READER_FAILED:' + str(proof['reader_errors'][-1:]))
        # The observed terminal condition must not be invalidated by an extra
        # event turn starting a legitimate unrelated heartbeat.
        require(predicate(), 'WAVE02_GUI_DEADLINE:' + str(proof.get('phase')))

    def wait_observer(operation, after):
        pump(lambda: any(q['operation']==operation for q in observer_results[after:]) and
             not window.probe.pending)
        result = next(q for q in observer_results[after:] if q['operation']==operation)
        require(not result['error'],'WAVE02_GUI_OBSERVER_OPERATION_FAILED:'+str(result['error'])[:700])
        return result['value']

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

    def answer_input_dialog(*, text=None, select_last=False):
        """Operate the real modal Qt dialog; only source file pickers are fixed."""
        state = {'answered':False,'error':None}; attempts = [0]
        def failed(error):
            state['error']=type(error).__name__+': '+str(error)[:300]
            dialog=QApplication.activeModalWidget()
            if isinstance(dialog,QInputDialog):dialog.reject()
        def answer():
            try:
                dialog=QApplication.activeModalWidget();attempts[0]+=1
                if not isinstance(dialog,QInputDialog):
                    if attempts[0]<500:QTimer.singleShot(10,answer)
                    else:failed(TimeoutError('WAVE02_REAL_INPUT_DIALOG_NOT_SHOWN'))
                    return
                if select_last:
                    box=dialog.findChild(QComboBox)
                    require(box is not None,'WAVE02_REAL_MODE_DIALOG_COMBO_MISSING')
                    box.setFocus();QTest.keyClick(box,Qt.Key.Key_End)
                if text is not None:
                    editor=dialog.findChild(QWidget,'qt_inputdlg_lineedit')
                    if editor is None:
                        from PySide6.QtWidgets import QLineEdit
                        editor=dialog.findChild(QLineEdit)
                    require(editor is not None,'WAVE02_REAL_MARK_DIALOG_EDITOR_MISSING')
                    editor.setFocus();QTest.keyClicks(editor,text)
                buttons=dialog.findChild(QDialogButtonBox)
                require(buttons is not None,'WAVE02_REAL_INPUT_DIALOG_BUTTONS_MISSING')
                button=buttons.button(QDialogButtonBox.StandardButton.Ok)
                require(button is not None,'WAVE02_REAL_INPUT_DIALOG_OK_MISSING')
                QTest.mouseClick(button,Qt.MouseButton.LeftButton)
                state['answered']=True
            except BaseException as error:failed(error)
        QTimer.singleShot(0,answer)
        return state

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
        if 'R50' in scopes[container]:
            cases.append(('R50', Path(native['container_results']['R50']['case_index'])))
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
                    section('crash')
                    reveal(panel.crash_kind);panel.crash_kind.setFocus()
                    QTest.keyClick(panel.crash_kind,Qt.Key.Key_End);app.processEvents()
                    require(panel.crash_kind.currentData()=='frames','WAVE02_GUI_SAVED_FRAMES_KIND_NOT_SELECTED')
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
        if 'R40' in scopes[container]:
            proof['phase']='R40_ACTUAL_SAVED_DUMP_BUTTON_AND_MATCHED_LOCAL_SYMBOLS'
            crash=native['container_results']['R40']
            paths=[Path(crash[key]).resolve(strict=True) for key in
                   ('private_dump_path','local_image_path','local_pdb_path')]
            for path in paths:inputs[str(path)]=digest(path)
            section('crash');previous=panel.case
            answered=answer_input_dialog(select_last=True)
            with patch.object(QFileDialog,'getOpenFileName',side_effect=[
                    (str(paths[0]),'Minidump (*.dmp)'),(str(paths[1]),'PE image (*.exe)'),
                    (str(paths[2]),'PDB (*.pdb)')]):
                click(panel.saved_dump_button)
            require(answered['answered'] and answered['error'] is None,
                    'WAVE02_GUI_ACTUAL_DUMP_MODE_DIALOG_NOT_OPERATED:'+str(answered['error']))
            pump(lambda:panel.bridge.worker is None and panel.case is not None and panel.case is not previous)
            projected=panel.case['crash_investigation']
            require(projected['summary']['recorded_exceptions']==1 and
                    projected['summary']['unwound_callers']>=2 and
                    projected['root_cause']=='UNKNOWN' and
                    not window.deep_inspector_panel.bridge.has_session,
                    'WAVE02_GUI_SAVED_DUMP_WORKER_LOST_REAL_EXCEPTION_OR_CALLERS')
            proof['r40_raw_dump_route']={'status':'PASS','case_id':panel.case['case_id'],
                'source_sha256':crash['dump_sha256'],'unwound_callers':projected['summary']['unwound_callers'],
                'actual_mode_dialog':True,'native_helper_started':False}
            for language in ('EN','RU'):
                window._set_language(language);section('crash')
                reveal(panel.crash_kind);panel.crash_kind.setFocus()
                QTest.keyClick(panel.crash_kind,Qt.Key.Key_End)
                inspect_section('crash','invCrashSummary','invCrashEvidenceTable','invCrashReport')
        if 'R50' in scopes[container]:
            proof['phase'] = 'R50_ACTUAL_GUI_CAPTURE_POLICY_AND_OWNED_BURST'
            executable = Path(manifest['fixture_executable']).resolve(strict=True)
            require(digest(executable)==manifest['fixture_executable_sha256'],
                    'WAVE02_GUI_NATIVE_FIXTURE_IMAGE_CHANGED')
            live_fixture = _WaveGuiFixture(executable,output/'gui-owned-native-target')
            pump(lambda: live_fixture.poll('ready') is not None,timeout=25)
            ready = live_fixture.poll('ready')
            require(ready['pid']==live_fixture.process.pid and ready['created_100ns']>0,
                    'WAVE02_GUI_OWNED_NATIVE_READY_IDENTITY_REQUIRED')
            window._attach_pid(ready['pid'])
            pump(lambda: window.probe.pid==ready['pid'] and not window.probe.pending)
            QTest.mouseClick(window._nav_buttons['settings'],Qt.MouseButton.LeftButton)
            settings = window.capture_settings
            toggle = next(q for q in settings.findChildren(QPushButton) if q.isCheckable())
            if not settings.form_widget.isVisible():click(toggle)
            reveal(settings.profile);settings.profile.setFocus()
            QTest.keyClick(settings.profile,Qt.Key.Key_End)
            require(settings.profile.currentData()=='INCIDENT_BURST','WAVE02_GUI_INCIDENT_PROFILE_SELECTION_FAILED')
            limits={'burst_seconds':3,'incident.threshold':20,'incident.min_duration_ms':0,
                'incident.pre_ms':2000,'incident.post_ms':1000,'incident.cooldown_ms':1000,
                'incident.growth_window_ms':1000,'incident.memory_growth_bytes':8*1024**2,
                'incident.io_rate_bytes_s':1024,'incident.max_buffer_samples':512,
                'incident.max_buffer_bytes':1024**2}
            for key,value in limits.items():
                box=settings.boxes[key];reveal(box);box.setFocus()
                QTest.keyClick(box,Qt.Key.Key_A,Qt.KeyboardModifier.ControlModifier)
                QTest.keyClicks(box,str(value));QTest.keyClick(box,Qt.Key.Key_Tab)
                require(box.value()==value,'WAVE02_GUI_POLICY_SPIN_EDIT_FAILED:'+key)
            if not settings.incidents.isChecked():
                reveal(settings.incidents);QTest.mouseClick(settings.incidents,Qt.MouseButton.LeftButton)
            if settings.adaptive.isChecked():
                reveal(settings.adaptive);QTest.mouseClick(settings.adaptive,Qt.MouseButton.LeftButton)
            after=len(observer_results);click(settings.apply);wait_observer('capture_policy',after)
            pump(lambda: window.probe.data.get('capture_policy',{}).get('profile')=='INCIDENT_BURST')
            QTest.mouseClick(window._nav_buttons['dashboard'],Qt.MouseButton.LeftButton)
            pump(lambda:window.start_btn.isEnabled())
            after=len(observer_results);click(window.start_btn);wait_observer('start',after)
            pump(lambda:window.probe.active and window.probe.total_samples>=3)
            pump(lambda:window.mark_problem_btn.isEnabled())
            after=len(observer_results)
            answered=answer_input_dialog(text='owned GUI manual marker, cause unknown')
            click(window.mark_problem_btn)
            require(answered['answered'] and answered['error'] is None,
                    'WAVE02_GUI_ACTUAL_MANUAL_MARK_DIALOG_NOT_OPERATED:'+str(answered['error']))
            wait_observer('mark',after)
            marked_samples=window.probe.total_samples
            pump(lambda:window.probe.total_samples>=marked_samples+2)
            live_fixture.send('burst')
            pump(lambda:live_fixture.poll('burst_begin') is not None,timeout=20)
            pump(lambda:live_fixture.poll('burst_done') is not None,timeout=20)
            done=live_fixture.poll('burst_done')
            require(done['pid']==ready['pid'] and done['created_100ns']==ready['created_100ns'] and
                    done['io_bytes']>0 and done['worker_threads']==4 and done['worker_exit_verified'] is True,
                    'WAVE02_GUI_NATIVE_BURST_ORACLE_NOT_CONFIRMED')
            final_samples=window.probe.total_samples
            pump(lambda:window.probe.total_samples>=final_samples+2)
            folder=Path(window.probe.session_folder)
            after=len(observer_results);click(window.stop_btn);stop=wait_observer('stop',after)
            pump(lambda:not window.probe.active and window.probe.report_result is not None)
            require(stop['cleanup_required'] is False and not stop['errors'],
                    'WAVE02_GUI_NEW_RECORDING_CLEANUP_UNCONFIRMED')
            recording_path=folder/'session-v2.sqlite3';recording_hash=digest(recording_path)
            db=sqlite3.connect(recording_path.resolve().as_uri()+'?mode=ro',uri=True)
            try:
                db.execute('PRAGMA query_only=ON')
                require(db.execute('PRAGMA integrity_check').fetchone()==('ok',),
                        'WAVE02_GUI_NEW_RECORDING_CORRUPTED')
                rows=db.execute('SELECT trigger_code,root_cause,context_json FROM incidents').fetchall()
            finally:db.close()
            require(any(q[0]=='MANUAL_PROBLEM' for q in rows) and
                    any(q[0] in ('CPU_SUSTAINED','RSS_GROWTH','IO_BURST') or
                        set(json.loads(q[2]).get('secondary_signals',{})) &
                        {'CPU_SUSTAINED','RSS_GROWTH','IO_BURST'} for q in rows) and
                    all(q[1]=='UNKNOWN' for q in rows),
                    'WAVE02_GUI_NEW_NATIVE_AND_MANUAL_INCIDENTS_NOT_PERSISTED')
            require(digest(recording_path)==recording_hash,'WAVE02_GUI_RECORDING_READBACK_CHANGED_SOURCE')
            proof['r50_new_gui_capture']={'status':'PASS','target':ready,'burst':done,
                'recording_sha256':recording_hash,'incident_count':len(rows),'stop':stop,
                'fixture_cleanup':live_fixture.close(True)}
            live_fixture=None
            QTest.mouseClick(window._nav_buttons['settings'],Qt.MouseButton.LeftButton)
            for language in ('EN','RU'):
                window._set_language(language);app.processEvents()
                require(widget_text(settings.coverage_status).strip(),
                        'WAVE02_GUI_ACTUAL_RETAINED_PREHISTORY_STATUS_EMPTY')
                proof.setdefault('r50_coverage_languages',[]).append(language)
            research=window.research_panel
            before=native['container_results']['R50']['before']['folder']
            after_folder=native['container_results']['R50']['after']['folder']
            for folder_name in (before,after_folder):
                for filename in ('session.sqlite3','session-v2.sqlite3','research.sqlite3'):
                    path=Path(folder_name)/filename;inputs[str(path)]=digest(path)
            for language in ('EN','RU'):
                proof['phase']='R50_ACTUAL_COMPARE_AND_EXPORT_'+language
                window._set_language(language)
                QTest.mouseClick(window._nav_buttons['reports'],Qt.MouseButton.LeftButton)
                if not research.isVisible():click(window.research_toggle)
                after=len(observer_results)
                with patch.object(QFileDialog,'getExistingDirectory',side_effect=[before,after_folder]):
                    click(research.by_action['Compare investigations…'])
                compared=wait_observer('compare',after)
                pump(lambda:research._comparison_result is not None and
                     research._comparison_result.get('comparison_status')=='COMPARABLE')
                require(compared['comparison_status']=='COMPARABLE' and
                        widget_text(research.details).strip() and
                        compared['causal_link_proven'] is False,
                        'WAVE02_GUI_ACTUAL_COMPARISON_OR_LOCALIZED_DETAILS_MISSING')
                for kind in ('json','html'):
                    path=output/('r50-gui-comparison-'+language+'.'+kind)
                    after=len(observer_results)
                    with patch.object(QFileDialog,'getSaveFileName',return_value=(str(path),kind.upper())):
                        click(research.by_action['Save comparison JSON / HTML…'])
                    exported=wait_observer('compare_export',after)
                    require(path.is_file() and exported['readback_verified'] is True and
                            exported['sha256']==digest(path),'WAVE02_GUI_COMPARE_EXPORT_READBACK_FAILED')
                    after=len(observer_results)
                    with patch.object(QFileDialog,'getOpenFileName',return_value=(str(path),kind.upper())):
                        click(research.by_action['Open saved comparison…'])
                    loaded=wait_observer('load_comparison',after)
                    require(loaded['source_trust']=='UNVERIFIED_IMPORT' and
                            loaded['comparison']['comparison_status']=='COMPARABLE' and
                            loaded['causal_link_proven'] is False and research._comparison_sources is None and
                            not research.by_action['Save comparison JSON / HTML…'].isEnabled(),
                            'WAVE02_GUI_COMPARISON_IMPORT_FABRICATED_TRUST_OR_LIVE_PAIR')
                    proof['exports'].append({'case':'R50-comparison','format':kind,'language':language,
                        'sha256':digest(path),'bytes':path.stat().st_size,'independent_readback':True})
                    # Opening an offline report intentionally clears source
                    # selection. Select the real pair again before another save.
                    if kind=='json':
                        after=len(observer_results)
                        with patch.object(QFileDialog,'getExistingDirectory',side_effect=[before,after_folder]):
                            click(research.by_action['Compare investigations…'])
                        wait_observer('compare',after)
        require(all(digest(path) == value for path, value in inputs.items()),
                'WAVE02_GUI_MODIFIED_ORIGINAL_EVIDENCE')
        proof['phase'] = 'GUI_CLOSE_AND_RESOURCE_EXIT'
        graph_busy_at_close = panel.bridge.busy
        graph_worker_at_close = panel.bridge.worker is not None
        close_ack_before = len(closed)
        require(graph_busy_at_close == graph_worker_at_close,
                'WAVE02_GUI_GRAPH_OWNER_STATE_INCONSISTENT')
        window.close()
        pump(lambda: not window.isVisible() and not window.probe.alive and
             panel.bridge.worker is None and not panel.bridge.busy and
             not window.deep_inspector_panel.bridge.has_session and
             (not graph_busy_at_close or len(closed) > close_ack_before), timeout=60)
        require(not graph_busy_at_close or len(closed) > close_ack_before,
                'WAVE02_GUI_GRAPH_CLOSE_ACK_NOT_OBSERVED')
        proof['cleanup'] = {'status': 'COMPLETED', 'ordinary_observer_exit_verified': not window.probe.alive,
            'graph_worker_finished': panel.bridge.worker is None,
            'graph_busy_at_close': graph_busy_at_close,
            'graph_close_scope': 'BUSY_READER_CLOSE_ACK' if graph_busy_at_close else 'IDLE_NO_GRAPH_READER_AT_CLOSE',
            'graph_closed_acknowledged': len(closed) > close_ack_before,
            'diagnostic_helper_started': False, 'source_hashes_unchanged': True}
        proof['status'] = 'PASS'
    except BaseException as error:
        proof.update(status='FAIL', reason=str(error)[:2000], error=type(error).__name__,
                     traceback=traceback.format_exc(limit=12))
    finally:
        if live_fixture is not None:
            try:live_fixture.close(False)
            except BaseException as error:proof.update(status='FAIL',fixture_cleanup_error=str(error)[:700])
        if window.isVisible() or window.probe.alive:
            try:
                window.close()
                pump(lambda: not window.isVisible() and not window.probe.alive and panel.bridge.worker is None,
                     timeout=45)
            except BaseException as error:
                proof.update(status='FAIL', cleanup_error=str(error)[:1000])
        (output / 'wave02-gui.json').write_text(json.dumps(proof, indent=2, ensure_ascii=False), encoding='utf-8')
    return 0 if proof['status'] == 'PASS' else 1
