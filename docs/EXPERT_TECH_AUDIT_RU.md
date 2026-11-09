# BLACK.BOX: техническая инспекция патча рабочего процесса

**Статус: исправления подготовлены в исходниках; финальный интегрированный CI ожидается.** Это описание конкретных дефектов, изменений и проверяемых границ, а не акт успешной приёмки.

База патча: `86fe4dcf3f49bd623da045d554d6ef36abf7bea4`. Ветка: `patch/expert-workflow-20261109`. Работа выполняется в [PR #49](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/49). Окончательные SHA, полные результаты CI, отказы/повторы/пропуски, ZIP и скриншоты относятся к отдельному внешнему итоговому протоколу после проверки. Документ не ссылается на собственный будущий коммит как на доказательство.

Исходники имеют версию v0.6.0; опубликованный комплект, проверенный для патча, — v0.5.4. v0.6.0 остаётся неопубликованным кандидатом. Ни этот список, ни зелёный отдельный job не означают новый Release или завершённую приёмку всего PR.

## Задача и сохранённая область

Патч ускоряет существующий путь специалиста: выбрать экземпляр → записать нагрузку → остановить → явно открыть сохранённый результат → выбрать интервал/потомка → проверить факты → сравнить/экспортировать. Сохраняются шесть производственных страниц, пятистраничный embedding API, Deep Inspection, Investigation Engine, Trace Decoder, Chain Builder, локальные форматы и полные технические сведения.

После первоначальных UX-изменений задача в том же PR расширена до технической инспекции перед полным интегрированным прогоном. Поэтому область включает исправления чтения импорта, отчётов, recovery, GUI/bridge lifecycle и packaging. Базовый sampler и сохраняемый R60 scheduler не изменяются. **ResearchBridge quit/retry и владение staging legacy tracerpt изменены**; их нельзя скрывать формулировкой «только интерфейс» или «все helper-пути без изменений». Новые коллекторы, расширение native-полномочий и обход подтверждений не добавлены.

## Матрица подтверждённых дефектов и исправлений

«Исправлено» ниже означает изменение исходников и наличие соответствующего regression-контракта. Фактический PASS каждого контракта на окончательном SHA ещё требуется.

| Область / дефект | Конкретная правка | Проверка / файлы |
| --- | --- | --- |
| Смешение live/saved/compare | Источник Reports берётся из соответствующего выбранным папке/instance пакета. Корневой PID и выбранный исторический instance различаются. Live JSON/HTML последней записи и две папки сравнения подписаны отдельно. | `test_expert_context.py`, `test_expert_navigation.py`; `window.py`, `expert_context.py` |
| Поздние данные прежнего контекста | При смене источника/instance очищаются шкала/TID/события/находки; неподходящий или вытесненный interval reply не применяется. Находки учитывают выбранного потомка; события сохраняют свой явный фильтр. | `test_expert_navigation.py`, `test_expert_evidence_panel.py` |
| Поздняя карточка/экспорт | Карточка связана с поколением/папкой/строкой. Receipt экспорта не помечает другую выборку как экспортированную. | `test_expert_evidence_panel.py`, `test_expert_navigation.py` |
| Непринятый quit навсегда запрещал retry | При отказе очереди ResearchBridge откатывает только latch `closing`, сохраняя helper, pending work и неизвестное владение. GUI остаётся открытым, сообщает неподтверждённую очистку и допускает повторную попытку. Только настоящий ACK завершает старый lifecycle. | `test_queue_full_quit_submission_preserves_unknown_owner_and_can_retry`, `test_rejected_window_shutdown_stays_visible_and_retries_after_dispatch_recovers` в `test_expert_navigation.py`; `research_bridge.py` |
| Зависший pending close | Finished-сигналы TID/investigation/update освобождают завершённый QObject и продолжают отложенное закрытие; живой QThread не уничтожается. | `test_each_window_owned_reader_completion_resumes_deferred_close` |
| Новая работа после начала закрытия | Отложенные update/investigation retries и новые recorded/TID reads не запускаются при closing; существующие владельцы сохраняются до завершения. | `test_closing_suppresses_queued_update_investigation_and_recorded_reads` |
| Live attach/start стирал исторические TID | При выбранном сохранённом анализе live-смена цели не очищает его TID DTO/table/status. | `test_live_attach_and_start_preserve_selected_historic_thread_evidence` |
| Dispatch-ошибки или ложный UI-выбор | Отказ helper/queue не объявляет успешными Start/Stop, не меняет подтверждённые interval/HWND; ошибочный визуальный выбор откатывается, cached process rows помечаются. | `test_bridge_dispatch_failures_do_not_claim_start_stop_or_change_interval`, `test_rejected_window_selection_restores_the_cached_hwnd` |
| Согласие на экспорт применялось к другой записи | До модального диалога фиксируются папка/instance/range/series; после обоих диалогов повторно проверяются та же выборка и готовность. | `test_export_modal_cannot_switch_the_consented_source_or_use_a_loading_packet` |
| Реальное переполнение Reports в RU | Hosted Windows обнаружил panel 902 px при viewport 788 px в окне 1020×850. Пять фиксированных столбцов заменены существующим responsive ActionGrid с сохранением всех команд/имён. Старый failing contract не ослаблен. | `test_reports_and_expert_buttons_fit_minimum_width_in_both_languages`; существующий `test_research_gui...test_reports_fit_minimum_window_width_in_russian`; source/frozen minimum-width driver |
| Импорт relabel другого экземпляра | Schema 2 требует, чтобы единственная declared target соответствовала canonical root 1, как у writer. Несогласованная identity не смешивает counters instance 1 с PID другого экземпляра. | `test_storage_import_boundaries.py`; `session_view.py` |
| Неверные импортированные часы назывались anchored | Строго проверяются anchor/origin/uncertainty/resolution/end; malformed clock отклоняется с `INVALID_IMPORTED_SESSION_CLOCK`. Известные нули сохраняются, часы не исправляются текущим временем. | `test_storage_import_boundaries.py` |
| Schema 1 молча игнорировала child/series | Legacy interval/thread APIs явно поддерживают только root 1 / STANDARD; иной scope получает стабильный отказ вместо root counters под чужой подписью. | `test_storage_import_boundaries.py` |
| Неизвестный recovery-owner считался вышедшим | Живой PID с отсутствующей/невалидной birth либо недоступной идентичностью считается active/unknown. Только NoSuchProcess или валидная другая birth доказывают отсутствие прежнего владельца. | `test_storage_import_boundaries.py`; `export_recovery.py`, `retention_delete.py` |
| Recovery называл неизвестного владельца подтверждённо активным | UI/error различает «active or unverified» от доказанно отсутствующего владельца: conservative `True` не доказывает активность; выбранные сведения переводятся заново и очищаются при пустом списке journal. Решение блокировки/команды не ослабляется. | `test_expert_recovery_context.py`: unknown blocked, verified exit, EN/RU, stale detail clear, no commands issued; `recovery_panel.py`, `research_messages.py` |
| Unbounded imported research context | Ограничены строки/суммарные байты/значение/ключ и время запроса; duplicate keys и nonfinite JSON отклоняются до возврата частичных conditions. | `test_storage_import_boundaries.py`; `casebook.py` |
| Deadline library scan начинался после enumeration | Перечисление разделяет deadline и hard entry cap; отказ происходит до регистрации папок и продвижения sorted cursor. | `test_storage_import_boundaries.py`; `library_catalog.py` |
| Unbounded schema-1 report read/scan | Report-only SQLite имеет value/progress budget; события ограничены producer JSON contract, count, distinct errors и временем. Нет успешного частичного summary после отказа. Writer/sampler connections не изменены. | `test_expert_report_limits.py`; `storage.py::_open_ro`, `report.py` |
| Rollback отчёта удалял чужой заменивший HTML | Перед удалением опубликованного пути сравнивается filesystem identity с сохранённым staging source. Удаляется только собственный hard link; exclusive publication и JSON-last marker сохранены. | `test_expert_report_limits.py`: collision cleanup и foreign HTML replacement preservation |
| NaN birth проходила optional validation | Nonfinite/unrepresentable birth отклоняется до `psutil.Process`; ошибка `INVALID_TARGET_IDENTITY` сохраняется. Это malformed/internal packet defect, не доказанный внешний обход авторизации. | `test_optional_jobs.py::...test_nonfinite_birth_never_passes_identity_validation_or_reaches_native_capture`; `operation_worker.py` |
| tracerpt staging удалялся при неизвестном cleanup | Используется существующий `_private_decode_stage`, сохраняющий настоящий staging с удерживаемым owner до подтверждённой явной очистки. | `test_crash_and_trace_decode.py::...test_unconfirmed_tracerpt_close_retains_staging_until_explicit_owner_cleanup`; `trace_decode.py` |
| XML deadline зависел от Event-узлов | Chunked XML stream ограничивает фактически прочитанные байты, все узлы, глубину и время независимо от распознанных Event; declarations отклоняются до parser; ненужные payload очищаются постепенно. | `test_crash_and_trace_decode.py`: node/depth/deadline и mixed payload/System-header regressions |
| В portable попадали старые release notes | Копируются текущие unpublished v0.6.0 notes; verifier требует `RELEASE-NOTES.md` с точным version heading. | `test_release_gate.py`; `shell-qa.yml`, `release_gate.py` |
| Final PR ZIP обходил существующий offline gate | После maintenance QA тот же archive verifier проверяет SHA/tree/inventory/version и сохраняет `release_published: false`. Нового маршрута публикации нет. | `test_release_gate.py`; `shell-qa.yml` |
| Новые expert-модули отсутствовали в frozen allowlist | PYZ gate требует `expert_context`, `evidence_presentation` и QA entry, проверяет отсутствие обязательных expert/native/operation modules. | `test_expert_packaging.py`; `verify_frozen_research.py` |
| Scalar/null event detail ломал selection | Incident ID читается только из object с положительным int; list/scalar/null сохраняются буквально и полностью в Raw JSON. | `test_imported_scalar_and_list_details_remain_navigable_without_incident_identity` |
| Чужой ответ одноимённой bridge-команды | Production `command_result` связывает ответ/ошибку с точным returned command ID; generation/folder/row guards сохранены. Совместимый старый result-only API остаётся. | `test_exact_command_ids_ignore_foreign_page_and_card_results_and_errors` |
| Неверные единицы и overflow импортированных facts | Metric context не переносится в неизвестные vendor containers; huge integer scaling использует integer arithmetic; nonfinite явно invalid, unknown/zero/false различаются. | `test_facts_keep_null_zero_false_unknown_fields_and_metric_dependent_units`, `test_huge_integer_measurements_and_nonfinite_values_do_not_overflow_or_become_zero` |
| Глубокие/широкие данные блокировали default render | Default facts/text имеют явные preview limits; iterative compact raw serializer сохраняет полную запись без рекурсивной/indent amplification. | `test_deep_and_wide_imports_have_bounded_default_views_and_complete_compact_raw_json`, `test_long_unknown_codes_have_explicit_previews_and_raw_record_remains_complete` |
| Malformed snapshot/time ломал интервал | Неизвестные snapshot containers показываются буквально; навигация требует ordered nonnegative int64, missing end сохраняет известную точку, invalid/reversed time не становится диапазоном. | `test_malformed_snapshot_containers_remain_literal_and_invalid_clocks_stay_explicit` |
| Failed pagination теряла согласованный cursor | Сохраняется последний принятый query/page/history. Отказ той же страницы откатывает cursor с видимой ошибкой; failed new-filter query очищает старые сведения. | `test_page_failure_retains_the_accepted_cursor_and_changed_filter_failure_clears_old_evidence`, `test_send_failure_rolls_back_pagination_without_losing_the_accepted_page` |
| Malformed envelope повторял запросы/ломал Qt | Bounded shape/row checks отвергают неподдержанный schema, scalar row и oversized page один раз; отсутствующие summaries остаются unknown. Error/status отображается plain text. | `test_malformed_page_envelopes_fail_once_without_retries_or_qt_callback_errors`, `test_missing_summary_and_invalid_time_are_explicit_while_raw_fields_remain_complete` |
| Невалидный instance/schema мог выглядеть ready | Контекст требует positive int64 instance, matching packet и поддержанный явный report/source schema; legacy caller без schema совместим. Huge clock вне int64 неизвестен; metadata имеет явный preview. | `test_invalid_selected_instance_cannot_make_a_matching_malformed_packet_ready`, `test_unknown_report_or_source_schema_suppresses_interpretation_and_preserves_selection`, `test_huge_clock_is_unknown_and_unbounded_imported_status_has_an_explicit_preview` |
| Устаревшая maintenance-документация | Текущий source v0.6.0 явно unpublished; actual native baseline v0.5.4; old-v0.3.6→v0.4.0 явно исторический сценарий. | `UPDATES_FEEDBACK_UNINSTALL.md`; runtime maintenance не менялся ради этой находки |

Читаемые RU/EN-сведения не заменяют Raw JSON и не повышают trust. Исходные коды, неизвестные значения, пределы и ссылки на источники сохраняются. Полная Raw JSON-запись отделена от ограниченного представления; её открытие/копирование остаётся явным действием.

## Введённые бюджеты и явные отказы

| Путь | Ограничение | Результат превышения |
| --- | --- | --- |
| Report-only SQLite | 1 МиБ на SQLite value; 15с cooperative SQL progress deadline; read-only/query-only/trusted-schema guards | Явный invalid/report failure, источник не меняется; это не ограничение writer/sampler |
| Event JSON отчёта | Producer contract 8192 байт; strict finite JSON и обработка recursion/overflow | Отказ вместо скрытого усечения или ложного полного отчёта |
| Python report scan | До 250000 событий, 128 distinct error codes, 15с cooperative deadline | Нет успешного частичного summary |
| Imported case context | До 128 строк, 2 МиБ aggregate encoded bytes, 64 КиБ value, bounded keys и SQL deadline | Отказ до частичного словаря; неизвестные поля в допустимом бюджете остаются |
| Library enumeration | 5с общий deadline, 10000 entries, малый retained-name heap | Нет регистрации/продвижения cursor после budget failure |
| Default evidence view | 24 уровня / 1024 traversed entries на секцию, final detail до 65536 символов плюс notice; длинные recorded metadata context — preview 512 символов | Явное сокращение только представления; полная выбранная запись сохраняется в Raw JSON |
| Legacy tracerpt XML | До 1000000 XML-узлов, глубина 64, существующая 10с time policy и byte bound | Явный decode refusal, сохранённые unknown/omitted counts не выдаются за полное покрытие |

Deadlines cooperative: проверяются на SQL VM progress, Python event/chunk boundaries. Они не прерывают произвольный зависший filesystem/native call и не доказывают любой предел wall-clock/RSS на физической машине. Совместимые ранее записи внутри контракта остаются доступны; malformed/патологические импорты могут теперь явно отклоняться.

## Maintenance, настройки и recovery

Read-only инспекция `maintenance.py`, `releases.py`, `shortcuts.py` не установила нового подтверждённого runtime-дефекта. В коде сохраняются exact marked portable folder, проверка reparse ancestry, sibling staging, size+digest до установки, ожидание выхода процесса, ограниченный rollback, удаление только matching shortcut, собственного HKCU subtree и marker-scoped temp helper.

Settings применяет policy через backend, Apply отключён при active/pending. Recovery требует явного выбора экспортной папки, отрицательного owner-active результата, подходящего состояния и отдельного подтверждения с No по умолчанию. UI gating не заменяет проверку journal/ownership в backend; исправление unknown owner описано выше.

Ограничения сохраняются: Windows portable, доступ на запись в parent/temp/Documents, доступность WSH/COM; rename между томами может отказать до удаления. Partial filesystem/антивирусный failure и backup cleanup не имеют универсальной транзакционности/rollback. Текущий native maintenance harness использует immutable v0.5.4 baseline; его наличие не доказывает final PASS и публичный discovery ещё неопубликованного кандидата.

## Требуемая интегрированная проверка

Все application/test/build/native/GUI запуски выполняются только на GitHub-hosted runners. Локально выполнялись source review, правки, Git и создание документов. Ни один локальный test/app/compiler run здесь не заявляется.

Для окончательного расширенного патча требуются hosted syntax/name checks, focused/affected regressions, полный Windows/Linux source suite, native integration, существующие portable build/smoke/maintenance gates, реальный frozen expert workflow, финальный offline ZIP gate и сохранённый **один час Standard/Incident Burst runtime/owner evidence**. Из-за изменения bridge quit/retry обязательны targeted queue-full/helper-death/deferred-close случаи. Новый 5ч30 результат не заявляется; достаточность длительного покрытия оценивается по фактическим изменениям владельцев и квитанциям.

Source/frozen GUI проверяет RU/EN при Qt scale 1/1.25/1.5/2, обычное окно и 1020×850 с раскрытыми секциями. Реальная часть записывает собственный GUI/PID и проверяет SQLite/отчёты. Детерминированные карточки/находки/события используют отдельно маркированный `TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE`, а не выдают fixture за наблюдения стороннего приложения. PNG/receipt связывают изображение с source/frozen, языком, scale, SHA и областью; фактические файлы и hash входят в отдельный итоговый протокол.

Ранний focused success относится только к своему прежнему source SHA. Следующий Windows run выявил настоящий RU minimum-width failure; первоначальный полный run PR отменён при расширении задачи. Успех одного Linux/Windows job и presence новых tests не означают завершения всего расширенного патча.

## Оставшиеся границы и непроверенное

- Полный Raw JSON принятой записи всё ещё формирует полный текст на Qt; iterative compact encoder предотвращает recursion/indent amplification, но не гарантирует UI latency или RAM для любого допустимого источника.
- Legacy `session_bounds()` и часть file/EXE inspection остаются синхронными в Qt. Byte/SQLite lock budgets не гарантируют latency при очень большом файле или медленном OS/filesystem call; все чтения интерфейса не объявляются асинхронными.
- Deferred close ждёт существующих bounded I/O/owner завершений; retry quit не подтверждает произвольное native recovery. Неизвестные execution/cleanup остаются неизвестными.
- Сохранение staging в legacy tracerpt исправляет конкретную ownership-границу. Его исходный ETL защищён before/after hashing, а не private input snapshot основного decoder; change-and-restore race на реальной Windows не установлен и не объявлен устранённым.
- Identity-checked rollback снижает риск удаления конкурирующего файла, но не создаёт общей filesystem transaction против замены путей между каждой OS-операцией.
- Физические Windows 10/11, interactive Secure Desktop, реальные AV/OneDrive/locks, physical DPI и screen-reader acceptance не подтверждены source review/Qt offscreen. Доступ/PPL определяет Windows.
- EXE остаются unsigned. SHA подтверждает byte identity, не безопасность, доверенное авторство или Authenticode reputation. Лицензионные notices не заменяют полного legal-аудита native dependencies.
- Memory/dumps, ETL, пути и свободный текст могут раскрыть секреты. Share export создаёт редактированную копию по известным полям, не гарантирует распознавание любого секрета. Буфер обмена и экспорт проверяются пользователем.
- Импорт остаётся unverified, неизвестные clocks/loss/symbols/coverage явны. CPU/RSS/I/O, temporal coincidence, `BLOCKED` и успешное диагностическое действие сами по себе не доказывают root cause/lock owner/leak/speedup; GC elapsed не равен stop-the-world pause.

[Рабочий процесс патча](EXPERT_WORKFLOW_PATCH_RU.md) · [Руководство RU](USER_GUIDE_RU.md) · [Guide EN](USER_GUIDE_EN.md) · [Обновление и обслуживание](UPDATES_FEEDBACK_UNINSTALL.md)
