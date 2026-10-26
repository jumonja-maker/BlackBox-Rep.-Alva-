"""Stable machine codes plus concise bilingual next actions."""
MESSAGES={
 "LIBRARY_ACTIVE_OR_EXTERNAL_RECORDING":("Only finalized, app-marked local recordings can be moved. Stop recording first; external folders stay read-only.","Перемещать можно только завершённые локальные записи, помеченные приложением. Сначала остановите запись; внешние папки доступны только для чтения."),
 "LIBRARY_FINALIZATION_UNCONFIRMED":("Some recording resources have not confirmed shutdown. Keep the folder and finish or recover the investigation first.","Завершение части источников не подтверждено. Сохраните папку; сначала завершите или восстановите исследование."),
 "LIBRARY_TRACE_STILL_ACTIVE":("A trace journal still indicates an active or interrupted capture. Finish or recover it before moving this recording.","Журнал трассы указывает на активную или прерванную запись. Завершите или восстановите её перед перемещением."),
 "LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN":("The recording changed after review. Refresh it and prepare a new confirmation; no stale plan is accepted.","Запись изменилась после просмотра. Обновите список и получите новое подтверждение: прежний план не принимается."),
 "LIBRARY_CONFIRMATION_EXPIRED_OR_USED":("The confirmation expired or was already used. Review the selected recordings again.","Подтверждение истекло или уже использовано. Повторно просмотрите выбранные записи."),
 "LIBRARY_DESTINATION_EXISTS":("The original folder name is occupied. Both folders are preserved. Resolve the conflict before restoring.","Исходное имя папки занято. Обе папки сохранены. Устраните конфликт перед восстановлением."),
 "LIBRARY_RESTORE_BEFORE_OPEN":("Restore the recording from Trash before opening or comparing it.","Восстановите запись из корзины перед открытием или сравнением."),
 "LIBRARY_STOP_BEFORE_COMPARE":("Stop or recover this recording before comparing completed experiments.","Остановите или восстановите запись перед сравнением завершённых экспериментов."),
 "LIBRARY_SELECT_TWO_RECORDINGS":("Select two different completed recordings and choose the Before/After order.","Выберите две разные завершённые записи и укажите порядок «до/после»."),
 "OPTIONAL_OPERATION_TIMEOUT":("This diagnostic exceeded its deadline. Its owned worker was stopped; the base recording continues.","Диагностика превысила время ожидания. Её вспомогательный процесс остановлен; базовая запись продолжается."),
 "OPTIONAL_QUEUE_FULL":("The diagnostic queue is full. Wait for an operation to finish.","Очередь диагностики заполнена. Дождитесь завершения операции."),
 "OPTIONAL_OPERATION_CANCELLED_RESULT_UNCONFIRMED":("The diagnostic was cancelled. Completion of its output is unconfirmed.","Диагностика отменена. Завершённость её результата не подтверждена."),
 "STOP_TRACE_BEFORE_SENSITIVE_EXPORT":("Wait for the trace guardian to finish before including raw artifacts.","Дождитесь завершения записи трассы перед экспортом исходных материалов."),
 "START_RECORDING_FIRST":("Start a recording, then repeat this operation.","Начните запись и повторите действие."),
 "STOP_RECORDING_BEFORE_EXPORT":("Stop recording before packaging the investigation.","Остановите запись перед сохранением пакета исследования."),
 "STOP_BEFORE_RECONFIGURING":("Stop recording to change the experiment context.","Остановите запись, чтобы изменить условия эксперимента."),
 "WPR_TOOL_UNAVAILABLE":("WPR is unavailable. Use a supported Windows installation with Windows Performance Recorder.","WPR недоступен. Для этой функции нужен Windows Performance Recorder."),
 "DOTNET_TRACE_TOOL_UNAVAILABLE":("Install dotnet-trace separately to enable this optional source; other observation remains available.","Для этого дополнительного источника нужен локальный dotnet-trace. Остальные наблюдения доступны."),
 "RECORDING_OWNER_STILL_ACTIVE":("The recording owner is still active. Stop it before recovery.","Процесс записи ещё работает. Остановите его перед восстановлением."),
 "EXPORT_DESTINATION_EXISTS":("Choose a new filename; existing evidence is protected.","Выберите новое имя файла. Существующий результат защищён от перезаписи."),
 "TARGET_INSTANCE_CHANGED":("The selected process instance changed. Select and verify it again.","Выбранный экземпляр процесса изменился. Выберите и проверьте его заново."),
 "RESEARCH_HELPER_UNAVAILABLE":("Restart BLACK.BOX; interrupted session files are retained for recovery.","Перезапустите BLACK.BOX. Файлы прерванного сеанса сохранены для восстановления."),
 "UNSUPPORTED_PLATFORM":("This sensor requires Windows. Use available sources or open the recording on Windows.","Этот датчик требует Windows. Используйте доступные источники или откройте запись в Windows."),
 "INVALID_RESEARCH_PATH":("Choose a folder containing a BLACK.BOX research.sqlite3 recording.","Выберите папку исследования BLACK.BOX с файлом research.sqlite3."),
 "ACCESS_DENIED":("This source was denied access. Check the selected target and required privileges.","Источник получил отказ доступа. Проверьте выбранную программу и необходимые права."),
 "APPLICATION_EVENT_COVERAGE_INCOMPLETE":("Some application events could not be confirmed. Inspect capture_health for unread bytes, partial lines and source failures; the base recording is retained.","Часть событий приложения не подтверждена. Откройте capture_health: там указаны недочитанные байты, незавершённые строки и отказы источника. Базовая запись сохранена."),
}


MESSAGES.update({
 'PURGE_REQUIRES_OWNED_TRASH':('Only finalized app-owned recordings in Trash can be permanently deleted. Move the selected recording to Trash first.','Окончательно удалить можно только завершённые собственные записи в корзине. Сначала переместите выбранную запись в корзину.'),
 'PURGE_OWNER_STILL_ACTIVE':('Another cleanup is running. Wait for it to finish, then refresh the list.','Другая очистка ещё выполняется. Дождитесь её завершения и обновите список.'),
 'PURGE_NEW_OR_REPLACED_FILE':('The folder now contains a new or replaced file. No stale deletion plan is accepted; review the folder.','В папке появился новый или заменённый файл. Прежний план удаления не принимается; проверьте содержимое папки.'),
 'EXPORT_RECOVERY_OWNER_ACTIVE':('The exporter is still running. Wait for it to exit before recovery.','Процесс экспорта ещё работает. Дождитесь его завершения перед восстановлением.'),
 'EXPORT_RECOVERY_BUILD_INCOMPLETE':('This export was not fully built, or new files are present. Preserve the journal and retry export from the original recording; only inventoried temporary files can be discarded.','Экспорт не был полностью построен либо появились новые файлы. Сохраните журнал и повторите экспорт исходной записи; удалить можно только проверенные временные файлы.'),
 'EXPORT_RECOVERY_FILE_CHANGED':('An export file changed. Keep the journal and inspect the files; automatic replacement is refused.','Файл экспорта изменился. Сохраните журнал и проверьте файлы; автоматическая замена запрещена.'),
 'EXPORT_DESTINATION_EXISTS':('The destination is occupied. Choose a different name or folder; existing files are preserved.','Путь уже занят. Выберите другое имя или папку; существующие файлы сохранены.'),
 'LIBRARY_CONFIRMATION_QUEUE_FULL':('Too many unfinished review plans. Wait up to five minutes for them to expire, then review again.','Слишком много незавершённых планов просмотра. Подождите до пяти минут, пока они истекут, затем повторите просмотр.'),
 'INVALID_CAPTURE_POLICY':('Check profile limits and keep at least one incident trigger selected. Stop recording before applying changes.','Проверьте лимиты профиля и оставьте хотя бы один триггер инцидентов. Перед изменением остановите запись.'),
 'USER_STAGE_LIMIT_OR_NAME':('Enter a stage name and finish an existing stage if the 32-stage limit is reached.','Укажите название этапа; при достижении лимита 32 этапов завершите один из открытых.'),
 'INVALID_INCIDENT_TRIGGERS':('Select at least one supported incident trigger.','Выберите хотя бы один поддерживаемый триггер инцидента.'),
 'STOP_BEFORE_RECONFIGURING':('Stop recording before changing this policy.','Остановите запись перед изменением политики.'),
})

def explain(error,language):
    import re
    raw=str(error)
    code=next((key for key in sorted(MESSAGES,key=len,reverse=True) if re.search(r'(?<![A-Z0-9_])'+re.escape(key)+r'(?![A-Z0-9_])',raw)),None)
    text=MESSAGES.get(code)
    if text:return text[1 if language=="RU" else 0]+"\n\n"+str(error)
    return (("Не удалось подтвердить завершение операции. Проверьте код, состояние записи и контекст ошибки ниже."
             if language=="RU" else "Operation completion was not confirmed. Check recording state and the source error below.")+"\n\n"+str(error))
