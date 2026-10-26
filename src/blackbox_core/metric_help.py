"""Versioned unit/formula/source limitations. Source IDs are not translated."""
ROWS={
'cpu_percent':('percentage_of_one_logical_cpu','PSUTIL_CPU_TIMES','100 × delta(user+system CPU seconds) / actual monotonic seconds. Can exceed 100%; first pair is unavailable.','100 × приращение CPU user+system / фактическое монотонное время. Может превышать 100%; первая пара недоступна.'),
'rss_bytes':('bytes','PSUTIL_MEMORY_INFO','Resident/Working Set pages; shared pages may appear in several processes. Growth does not prove a leak.','Резидентная память / Working Set; общие страницы могут учитываться в нескольких процессах. Рост не доказывает утечку.'),
'private_bytes':('bytes','WINDOWS_PRIVATE_USAGE_VIA_PSUTIL','Windows PrivateUsage where supplied. Unsupported/denied is NULL; never substitute RSS.','Windows PrivateUsage, если доступно. Отказ/отсутствие даёт NULL; RSS не подставляется.'),
'uss_bytes':('bytes','PSUTIL_MEMORY_FULL_INFO','Memory unique to the process. More expensive query; access may be denied.','Память, уникальная для процесса. Запрос дороже; доступ может быть запрещён.'),
'handle_count':('handles','PSUTIL_NUM_HANDLES','Open Windows process handles. Not an application object count or proof of a leak.','Открытые дескрипторы Windows. Это не количество объектов приложения и не доказательство утечки.'),
'thread_count':('threads','PSUTIL_NUM_THREADS','Snapshot count. Short-lived threads between observations can be missed.','Количество на момент опроса. Короткоживущие потоки между опросами могут быть пропущены.'),
'cpu_user_s':('seconds','PSUTIL_CPU_TIMES','Cumulative user-mode CPU time, not wall duration.','Накопленное CPU-время пользовательского режима, не длительность по часам.'),
'cpu_system_s':('seconds','PSUTIL_CPU_TIMES','Cumulative kernel/system CPU time, not wall duration.','Накопленное CPU-время системного режима, не длительность по часам.'),
'read_bytes':('bytes','PSUTIL_IO_COUNTERS','Cumulative read bytes under OS accounting. Hardware service time is not measured.','Накопленное чтение по определению ОС. Задержка физического устройства не измеряется.'),
'write_bytes':('bytes','PSUTIL_IO_COUNTERS','Cumulative written bytes. Physical-media flush is not established.','Накопленная запись. Завершение записи на физический носитель не устанавливается.'),
'read_ops':('ops','PSUTIL_IO_COUNTERS','Cumulative operations. Not individual operation latencies.','Накопленные операции. Это не задержки отдельных операций.'),
'write_ops':('ops','PSUTIL_IO_COUNTERS','Cumulative operations. Not individual operation latencies.','Накопленные операции. Это не задержки отдельных операций.'),
'children_total':('processes','PSUTIL_CHILDREN_RECURSIVE','Observed descendants. Enumeration limits and access failures retain missing coverage.','Наблюдавшиеся потомки. Ограничения обхода и отказы доступа сохраняются как неполное покрытие.'),
'io_rate':('bytes_per_second','DERIVED_COMPARABLE_COUNTER_PAIR','Delta bytes / actual delta time; only consecutive non-reset pairs. A gap is not zero.','Приращение байтов / фактическое время; только соседние пары без сброса. Пропуск не равен нулю.'),
'thread_cpu':('percentage_of_one_logical_cpu','DERIVED_THREAD_CPU_TIMES','Delta thread CPU / actual time; TID reuse between captures cannot be excluded.','Приращение CPU потока / фактическое время; повторное использование TID между опросами исключить нельзя.'),
'ui_timeout':('events','WIN32_SEND_MESSAGE_TIMEOUT_W','Bounded WM_NULL timeout. Long UI handler, scheduling delay and waits are alternatives.','Тайм-аут ограниченной пробы WM_NULL. Возможны длинный обработчик, задержка планирования или ожидания.'),
'wct':('native_nodes','WIN32_WCT','Asynchronous wait-chain snapshot with access/timeout/cleanup status. Dynamic, not complete root-cause proof.','Асинхронный снимок цепочки ожидания со статусом доступа/срока/очистки. Динамический, не полное доказательство причины.'),
'action_duration':('milliseconds','USER_COMMAND_MONOTONIC','End command time minus begin command time. Transport latency is separate; target-internal time needs voluntary instrumentation.','Время команды «Конец» минус «Начало». Задержка доставки отдельно; внутреннее время требует добровольной инструментализации.'),
'p95':('same_as_metric','DERIVED_LINEAR_QUANTILE','Sorted rank (N-1)×0.95 with interpolation; unstable with small N, no significance claim.','Ранг (N-1)×0,95 с интерполяцией; при малом N нестабилен, значимость не заявляется.'),
'application_io_latency':('nanoseconds','APPLICATION_EVENT_UNAUTHENTICATED','Voluntarily supplied operation wall latency; not independent storage latency. Source clocks are retained separately.','Добровольно сообщённая задержка операции; не независимая задержка диска. Часы источника сохраняются отдельно.')}
def definitions():
 return {'schema_version':1,'metrics':[{'metric':k,'unit':v[0],'source':v[1],'explanation_en':v[2],'explanation_ru':v[3]} for k,v in ROWS.items()],
 'limitations':['NULL_IS_NOT_ZERO','COUNTERS_DO_NOT_PROVE_ROOT_CAUSE','OBSERVER_MAY_AFFECT_TARGET','IMPORTED_SOURCE_IDS_NOT_AUTHENTICATED']}

