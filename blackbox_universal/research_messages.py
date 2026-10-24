"""Stable machine codes plus concise bilingual next actions."""
MESSAGES={
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


def explain(error,language):
    code=str(error).split(": ")[-1]
    text=MESSAGES.get(code)
    if text:return text[1 if language=="RU" else 0]+"\n\n"+str(error)
    return (("Не удалось подтвердить завершение операции. Проверьте код, состояние записи и контекст ошибки ниже."
             if language=="RU" else "Operation completion was not confirmed. Check recording state and the source error below.")+"\n\n"+str(error))
