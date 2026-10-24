"""Explicit, bounded library browsing on the existing Reports page.

All index/source IO is delegated to disposable operations. Neither painting,
sample notifications nor row selection scan recording directories.
"""
from __future__ import annotations
from datetime import datetime
import json
from pathlib import Path
from PySide6.QtCore import Qt,QTimer,Signal
from PySide6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QGridLayout,QLabel,QLineEdit,
    QComboBox,QPushButton,QTableWidget,QTableWidgetItem,QHeaderView,QAbstractItemView,
    QPlainTextEdit,QFileDialog,QMessageBox,QSpinBox,QDialog,QDialogButtonBox,QInputDialog)


class LibraryPanel(QWidget):
    open_requested=Signal(dict)
    comparison_ready=Signal(dict)

    def __init__(self,window):
        super().__init__(window);self.window=window;self.bridge=window.probe
        self._available=hasattr(self.bridge,'send') and hasattr(self.bridge,'result_ready')
        self._labels=[];self.rows=[];self.candidates=[];self.last_result=None
        self._generation=0;self._page_pending=False;self._query_dirty=False
        self._cursor=None;self._history=[];self._next_cursor=None;self._has_more=False
        self._busy=set();self._scan_cursor='';self._scan_more=False;self._policy_loaded=False
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0)
        self.note=QLabel();self.note.setWordWrap(True)
        self.label(self.note,'Local index only. Search does not scan recording folders. Size is a cached estimate.',
            'Локальный индекс. Поиск не обходит папки записей. Размер указан по сохранённой оценке.')
        layout.addWidget(self.note)
        search=QHBoxLayout();self.search=QLineEdit();self.search.setMaxLength(256)
        self.search.setObjectName('librarySearch');self.filter=QComboBox()
        for state in ('ALL','COMPLETED','INCOMPLETE','ACTIVE','TRASH'):self.filter.addItem(state,state)
        search.addWidget(self.search,1);search.addWidget(self.filter)
        self.refresh_button=self.button('Refresh index','Обновить список',self.refresh)
        search.addWidget(self.refresh_button);layout.addLayout(search)
        self._search_timer=QTimer(self);self._search_timer.setSingleShot(True);self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self.refresh)
        self.search.textChanged.connect(lambda:self._search_timer.start())
        self.filter.currentIndexChanged.connect(self.refresh)
        self.table=self.make_table(7,'researchLibrary');layout.addWidget(self.table)
        self.table.itemSelectionChanged.connect(self.selection_changed)
        self.table.cellDoubleClicked.connect(lambda *_:self.open_selected())
        paging=QHBoxLayout()
        self.previous=self.button('Previous page','Предыдущая страница',self.previous_page)
        self.next=self.button('Next page','Следующая страница',self.next_page)
        paging.addWidget(self.previous);paging.addWidget(self.next)
        self.page_label=QLabel();paging.addWidget(self.page_label,1);layout.addLayout(paging)
        actions=QGridLayout()
        self.open_button=self.button('Open selected','Открыть выбранную',self.open_selected)
        self.compare_button=self.button('Compare two…','Сравнить две…',self.compare_selected)
        self.register_button=self.button('Add saved folder…','Добавить сохранённую папку…',self.register_folder)
        self.scan_button=self.button('Find older recordings','Найти прежние записи',self.scan_next)
        self.trash_button=self.button('Move selected to Trash…','Выбранные в корзину…',self.plan_selected)
        self.restore_button=self.button('Restore selected','Восстановить выбранную',self.restore_selected)
        self.trace_button=self.button('Inspect interrupted traces…','Проверить прерванные трассы…',self.trace_scan)
        for i,b in enumerate((self.open_button,self.compare_button,self.register_button,self.scan_button,self.trash_button,self.restore_button,self.trace_button)):
            actions.addWidget(b,i//2,i%2)
        layout.addLayout(actions)
        self.storage_toggle=self.button('Storage policy / reversible Trash','Хранение / обратимая корзина',lambda:None)
        self.storage_toggle.setCheckable(True);layout.addWidget(self.storage_toggle)
        self.storage=QWidget();storage=QVBoxLayout(self.storage);storage.setContentsMargins(0,0,0,0)
        storage_note=QLabel();storage_note.setWordWrap(True)
        self.label(storage_note,'No automatic deletion. These thresholds only prepare a review list. Trash preserves every file and does not free disk space. Permanent deletion is not provided.',
            'Автоматического удаления нет. Пороги только составляют список для просмотра. Корзина сохраняет все файлы и не освобождает место. Окончательного удаления здесь нет.')
        storage.addWidget(storage_note)
        policy=QGridLayout();self.days=QSpinBox();self.days.setRange(0,36500)
        self.size_mb=QSpinBox();self.size_mb.setRange(0,1024*1024*1024)
        for i,(box,en,ru) in enumerate(((self.days,'Older than days (0: off)','Старше, дней (0: выключено)'),
                (self.size_mb,'Size threshold, MiB (0: off)','Порог объёма, MiB (0: выключено)'))):
            label=QLabel();self.label(label,en,ru);policy.addWidget(label,i,0);policy.addWidget(box,i,1)
        storage.addLayout(policy)
        row=QHBoxLayout();self.policy_button=self.button('Save thresholds','Сохранить пороги',self.save_policy)
        self.preview_button=self.button('Preview candidates','Показать кандидатов',lambda:self.send('library_retention'))
        self.reconcile_button=self.button('Reconcile interrupted moves','Проверить прерванные перемещения',lambda:self.send('library_reconcile'))
        for b in (self.policy_button,self.preview_button,self.reconcile_button):row.addWidget(b)
        storage.addLayout(row)
        self.purge_button=self.button('Permanently delete selected Trash entries…','Окончательно удалить выбранные из корзины…',self.plan_purge)
        self.purge_button.setStyleSheet('color: #a43649;');storage.addWidget(self.purge_button)
        self.candidate_table=self.make_table(3,'libraryRetentionCandidates');self.candidate_table.setMinimumHeight(100);self.candidate_table.setMaximumHeight(165)
        self.candidate_table.itemSelectionChanged.connect(self.selection_changed);storage.addWidget(self.candidate_table)
        self.candidate_trash=self.button('Review selected candidates…','Рассмотреть выбранных кандидатов…',self.plan_candidates)
        storage.addWidget(self.candidate_trash)
        self.storage.setVisible(False);layout.addWidget(self.storage)
        self.storage_toggle.toggled.connect(self._toggle_storage)
        self.status=QLabel();self.status.setWordWrap(True);layout.addWidget(self.status)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(140);layout.addWidget(self.details)
        if self._available:self.bridge.result_ready.connect(self.receive)
        else:self.setEnabled(False)
        self.retranslate();self.selection_changed()

    def tr(self,en,ru):return ru if self.window.language=='RU' else en
    def label(self,widget,en,ru):self._labels.append((widget,en,ru));widget.setText(self.tr(en,ru))
    def button(self,en,ru,callback):
        b=QPushButton();self.label(b,en,ru);b.clicked.connect(callback);return b
    def make_table(self,columns,name):
        table=QTableWidget(0,columns);table.setObjectName(name)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setMinimumHeight(180);table.setWordWrap(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False);return table
    def retranslate(self):
        for widget,en,ru in self._labels:widget.setText(self.tr(en,ru))
        self.search.setPlaceholderText(self.tr('Program, scenario, version, workload…','Программа, сценарий, версия, нагрузка…'))
        self.search.setAccessibleName(self.tr('Search the local recording index','Поиск по локальному индексу записей'))
        for i,(en,ru) in enumerate((('All','Все'),('Completed','Завершённые'),('Incomplete','Неполные'),('Active / unconfirmed','Активные / неподтверждённые'),('Trash / pending moves','Корзина / перемещения'))):
            self.filter.setItemText(i,self.tr(en,ru))
        self.table.setHorizontalHeaderLabels(tuple(self.tr(en,ru) for en,ru in
            (('DATE','ДАТА'),('PROGRAM','ПРОГРАММА'),('SCENARIO','СЦЕНАРИЙ'),('SCENARIO VER.','ВЕРС. СЦЕНАРИЯ'),('APP VER.','ВЕРС. ПРИЛ.'),('RUNS','ПОВТОРЫ'),('STATE','СОСТОЯНИЕ'))))
        self.candidate_table.setHorizontalHeaderLabels(tuple(self.tr(en,ru) for en,ru in
            (('RECORDING','ЗАПИСЬ'),('SIZE ESTIMATE','ОЦЕНКА РАЗМЕРА'),('REASON','ПРИЧИНА'))))
        if self.rows:self.render_rows(self.rows)
        self._update_paging();self._scan_label()

    def send(self,op,**args):
        if not self._available:return False
        if op in self._busy:return False
        try:
            self.bridge.send(op,**args);self._busy.add(op)
            self.status.setText(self.tr('Reading local evidence…','Читаем локальные данные…'));self.selection_changed();return True
        except (RuntimeError,ValueError) as exc:
            self.status.setText(str(exc));return False
    def activated(self,visible):
        self.setVisible(visible)
        if visible:self.refresh()
    def refresh(self):
        self._search_timer.stop();self._generation+=1;self._cursor=None;self._history=[]
        self._request_page()
    def _request_page(self):
        if self._page_pending:self._query_dirty=True;return
        key=self._generation
        if self.send('library_query',search=self.search.text(),state=self.filter.currentData(),after=self._cursor,limit=50,request_key=key):
            self._page_pending=True;self._query_dirty=False
        self._update_paging()
    def next_page(self):
        if self._page_pending or not self._has_more:return
        self._history.append(self._cursor);self._cursor=self._next_cursor;self._generation+=1;self._request_page()
    def previous_page(self):
        if self._page_pending or not self._history:return
        self._cursor=self._history.pop();self._generation+=1;self._request_page()
    def _update_paging(self):
        self.previous.setEnabled(bool(self._history) and not self._page_pending)
        self.next.setEnabled(self._has_more and not self._page_pending)
        self.page_label.setText(self.tr('Page ','Страница ')+str(len(self._history)+1)+' · '+str(len(self.rows))+
            self.tr(' rows (up to 50)',' записей (до 50)'))
    def selected(self,table=None,rows=None):
        table=table or self.table;rows=self.rows if rows is None else rows
        return [rows[i.row()] for i in table.selectionModel().selectedRows() if i.row()<len(rows)]
    def selection_changed(self):
        selected=self.selected();available=not self._busy
        normal=all(r['state'] not in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED') for r in selected)
        self.open_button.setEnabled(available and len(selected)==1 and normal)
        self.compare_button.setEnabled(available and len(selected)==2 and normal and
            all(r['state'] not in ('RECORDING','FINALIZATION_UNCONFIRMED') for r in selected))
        self.trash_button.setEnabled(available and bool(selected) and all(r['trash_eligible'] for r in selected))
        self.restore_button.setEnabled(available and len(selected)==1 and selected[0]['state']=='TRASH')
        self.trace_button.setEnabled(available and len(selected)==1 and normal and selected[0]['origin']=='LOCAL_APP_MARKED')
        readers=any(getattr(self.window,key,None) is not None for key in ('_interval_worker','_interval_export_worker','_thread_detail_worker','_investigation_worker'))
        self.purge_button.setEnabled(available and not readers and bool(selected) and all(r['origin']=='LOCAL_APP_MARKED' and r['state'] in ('TRASH','PURGING','PURGE_PARTIAL') for r in selected))
        self.candidate_trash.setEnabled(available and bool(self.selected(self.candidate_table,self.candidates)))
        for b in (self.refresh_button,self.register_button,self.scan_button,self.policy_button,self.preview_button,self.reconcile_button):b.setEnabled(available)
        if len(selected)==1:
            r=selected[0]
            self.details.setPlainText(self.tr('Scenario / version: ','Сценарий / версия: ')+r['scenario']+' / '+r['scenario_version']+'\n'+
                self.tr('Workload: ','Нагрузка: ')+r['workload']+'\n'+
                self.tr('Profile / interval: ','Профиль / интервал: ')+r['profile']+' / '+str(r['interval_ms'])+' ms\n'+
                self.tr('Configuration changed: ','Настройки менялись: ')+
                (self.tr('yes','да') if r['configuration_changed'] else self.tr('no','нет'))+'\n'+
                self.tr('Samples / completed runs: ','Отсчёты / завершённые повторы: ')+str(r['samples'])+' / '+str(r['completed_runs'])+'\n'+
                self.tr('Cached size: ','Сохранённая оценка размера: ')+self.size(r['size_bytes'])+' · '+str(r['size_status'])+'\n'+
                r['file_trust']+'\n'+r['folder'])
    def size(self,value):return self.tr('unknown','неизвестно') if value is None else f'{value/1048576:.2f} MiB'
    def state_text(self,value):
        ru={'COMPLETED':'Завершено','RECORDING':'Запись','INCOMPLETE':'Неполная запись','INTERRUPTED':'Прервано',
            'PROCESS_EXITED':'Процесс завершился','PID_REUSED':'PID переиспользован','STORAGE_ERROR':'Ошибка хранения',
            'SAMPLE_UNAVAILABLE':'Измерения недоступны','ACCESS_DENIED':'Нет доступа','RECOVERED_INCOMPLETE':'Восстановлена неполной',
            'FINALIZATION_UNCONFIRMED':'Завершение не подтверждено','TRASH':'Корзина','MOVING_TO_TRASH':'Перенос в корзину','RESTORING':'Восстановление'}
        return ru.get(value,value) if self.window.language=='RU' else value
    def render_rows(self,rows):
        self.table.blockSignals(True);self.table.setRowCount(len(rows))
        for i,r in enumerate(rows):
            try:stamp=datetime.fromtimestamp(r['started_ns']/1e9).astimezone().strftime('%Y-%m-%d %H:%M:%S %z')
            except (ValueError,OverflowError,OSError):stamp='UNKNOWN'
            values=(stamp,r['target_name'],r['scenario'],r['scenario_version'],r['target_version'],
                '—' if r['completed_runs'] is None else r['completed_runs'],self.state_text(r['state']))
            for j,value in enumerate(values):
                item=QTableWidgetItem(str(value or '—'));item.setToolTip(str(value or '—')+(' · '+r['state'] if j==6 else ''));self.table.setItem(i,j,item)
        self.table.clearSelection();self.table.blockSignals(False);self.selection_changed()
    def open_selected(self):
        rows=self.selected()
        if len(rows)==1 and self.open_button.isEnabled():self.send('library_open',entry_id=rows[0]['entry_id'])
    def compare_selected(self):
        rows=self.selected()
        if len(rows)!=2 or not self.compare_button.isEnabled():return
        rows=sorted(rows,key=lambda r:r['started_ns'])
        dialog=QDialog(self);dialog.setWindowTitle(self.tr('Choose comparison order','Порядок сравнения'))
        layout=QVBoxLayout(dialog);before=QComboBox();after=QComboBox()
        for row in rows:
            text=row['scenario']+' · '+row['target_version']+' · '+row['entry_id'][:8]
            before.addItem(text,row['entry_id']);after.addItem(text,row['entry_id'])
        after.setCurrentIndex(1)
        layout.addWidget(QLabel(self.tr('Before → After; differing conditions are reported.','До → После; различия условий будут указаны.')))
        layout.addWidget(before);layout.addWidget(after)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
        if dialog.exec()==QDialog.DialogCode.Accepted:
            self.send('library_compare',before_id=before.currentData(),after_id=after.currentData())
    def register_folder(self):
        folder=QFileDialog.getExistingDirectory(self,self.tr('Saved BLACK.BOX recording','Сохранённая запись BLACK.BOX'))
        if folder:self.send('library_register',folder=folder)
    def scan_next(self):self.send('library_scan',after=self._scan_cursor if self._scan_more else '',limit=50)
    def _scan_label(self):self.scan_button.setText(self.tr('Find next older recordings','Найти следующие прежние записи') if self._scan_more else self.tr('Find older recordings','Найти прежние записи'))
    def _toggle_storage(self,visible):
        self.storage.setVisible(visible)
        if visible and not self._policy_loaded:self.send('library_policy')
    def save_policy(self):
        self.send('library_policy',values={'days':self.days.value(),'max_bytes':self.size_mb.value()*1048576,'automatic_deletion':False})
    def plan_selected(self):
        rows=self.selected()
        if rows:self.send('library_plan_trash',entry_ids=[r['entry_id'] for r in rows])
    def plan_candidates(self):
        rows=self.selected(self.candidate_table,self.candidates)
        if rows:self.send('library_plan_trash',entry_ids=[r['entry_id'] for r in rows])
    def confirm_plan(self,result):
        box=QMessageBox(self);box.setWindowTitle(self.tr('Review reversible move','Проверка обратимого перемещения'))
        box.setIcon(QMessageBox.Icon.Question);box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(self.tr('Move these recordings to the local reversible Trash?','Переместить эти записи в локальную обратимую корзину?')+'\n'+
            str(len(result['items']))+self.tr(' recordings. No files are deleted; no disk space is freed.',' записей. Файлы не удаляются; место на диске не освобождается.'))
        box.setInformativeText('\n'.join(item['folder_name']+' · '+self.size(item['bytes']) for item in result['items'][:5]))
        box.setDetailedText('\n'.join(item['folder']+' · '+self.size(item['bytes']) for item in result['items']))
        box.setStandardButtons(QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No);box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec()==QMessageBox.StandardButton.Yes:self.send('library_apply_trash',confirmation_token=result['confirmation_token'])
        else:self.status.setText(self.tr('Cancelled. Recordings were not moved.','Отменено. Записи не перемещены.'))
    def restore_selected(self):
        rows=self.selected()
        if len(rows)==1:self.send('library_restore',entry_id=rows[0]['entry_id'])
    def trace_scan(self):
        rows=self.selected()
        if len(rows)==1:self.send('library_trace_scan',entry_id=rows[0]['entry_id'])
    def trace_review(self,result):
        self.details.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
        rows=[r for r in result['rows'] if r.get('eligible')]
        if not rows:return
        name,ok=QInputDialog.getItem(self,self.tr('Review owned trace recovery','Восстановление собственной трассы'),
            self.tr('Select an abandoned trace. No files are deleted.','Выберите оставшуюся трассу. Файлы не удаляются.'),[r['journal'] for r in rows],0,False)
        if not ok:return
        row=next(r for r in rows if r['journal']==name)
        box=QMessageBox(self);box.setWindowTitle('BLACK.BOX');box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(self.tr('Stop only this named BLACK.BOX trace / verified owned collector? The observed application is not terminated.',
            'Остановить только эту именованную трассу BLACK.BOX / проверенный собственный сборщик? Наблюдаемая программа не завершается.')+'\n'+name)
        box.setStandardButtons(QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No);box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec()==QMessageBox.StandardButton.Yes:self.send('library_trace_recover',entry_id=row['recording_id'],journal=name,confirmed=True)

    def plan_purge(self):
        rows=self.selected()
        if self.purge_button.isEnabled() and rows:self.send('library_plan_purge',entry_ids=[r['entry_id'] for r in rows])
    def confirm_purge(self,plan):
        text=self.tr('Permanently delete the selected app-owned recordings from Trash? This cannot be undone. Original files outside these folders are not selected.',
            'Безвозвратно удалить выбранные собственные записи из корзины? Отменить удаление нельзя. Файлы вне этих папок не выбраны.')
        text+='\n\n'+'\n'.join(str(r['remaining_entries'])+' · '+r['folder'] for r in plan['items'])
        box=QMessageBox(self);box.setIcon(QMessageBox.Icon.Warning);box.setWindowTitle(self.tr('Confirm permanent deletion','Подтвердить окончательное удаление'))
        box.setTextFormat(Qt.TextFormat.PlainText);box.setText(text);box.setStandardButtons(QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No);box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec()==QMessageBox.StandardButton.Yes:self.send('library_apply_purge',confirmation_token=plan['confirmation_token'])

    def receive(self,op,result,error):
        if not op.startswith('library_') or op not in self._busy:return
        self._busy.discard(op)
        if op=='library_query':self._page_pending=False
        if error:
            from .research_messages import explain
            self.status.setText(explain(error,self.window.language))
        else:
            self.last_result={'op':op,'result':result}
            self.status.setText(self.tr('Local operation completed. Original observations were not edited.','Локальная операция завершена. Исходные наблюдения не редактировались.'))
            if op=='library_query':
                if result.get('request_key')==self._generation:
                    self.rows=result['rows'];self._has_more=result['has_more'];self._next_cursor=result['next_cursor'];self.render_rows(self.rows)
                if result.get('request_key')!=self._generation:self._query_dirty=True
            elif op=='library_open':self.open_requested.emit(result)
            elif op=='library_compare':
                self.comparison_ready.emit(result['comparison'])
                if 'resource_comparison' in result['comparison']:
                    from .experiment_view import comparison_text
                    self.details.setPlainText(comparison_text(result['comparison'],self.window.language))
                else:self.details.setPlainText(json.dumps(result['comparison'],ensure_ascii=False,indent=2))
            elif op=='library_scan':
                self._scan_cursor=result['cursor'];self._scan_more=result['has_more'];self._scan_label()
                self.status.setText(self.tr('Indexed: ','Добавлено в индекс: ')+str(result['added'])+
                    self.tr(' · Read failures: ',' · Ошибки чтения: ')+str(len(result['errors']))+
                    (self.tr(' · Continue with the next scan.',' · Продолжите следующей порцией.') if self._scan_more else ''))
                self.details.setPlainText(json.dumps(result,ensure_ascii=False,indent=2));self.refresh()
            elif op=='library_policy':
                self._policy_loaded=True;self.days.setValue(result['days']);self.size_mb.setValue(result['max_bytes']//1048576)
            elif op=='library_retention':
                self.candidates=result['candidates'];self.candidate_table.setRowCount(len(self.candidates))
                for i,row in enumerate(self.candidates):
                    for j,value in enumerate((row['scenario']+' · '+row['target_version'],self.size(row['size_bytes']),', '.join(row['reasons']))):
                        self.candidate_table.setItem(i,j,QTableWidgetItem(value))
                self.status.setText(self.tr('Preview only. Candidates: ','Только просмотр. Кандидатов: ')+str(len(self.candidates))+
                    self.tr(' · Entries with unknown size: ',' · Записей неизвестного размера: ')+str(result.get('unknown_size_entries',0))+
                    (self.tr(' · First 50 eligible entries only.',' · Проверены первые 50 подходящих записей.') if result.get('preview_limited') else ''))
            elif op=='library_plan_trash':self.confirm_plan(result)
            elif op=='library_plan_purge':self.confirm_purge(result)
            elif op=='library_trace_scan':self.trace_review(result)
            elif op=='library_trace_recover':self.details.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
            elif op in ('library_apply_trash','library_restore','library_register','library_reconcile','library_apply_purge'):
                self.candidates=[];self.candidate_table.setRowCount(0)
                self.details.setPlainText(json.dumps(result,ensure_ascii=False,indent=2));self.refresh()
        self.selection_changed();self._update_paging()
        if self._query_dirty and not self._page_pending:QTimer.singleShot(0,self._request_page)
