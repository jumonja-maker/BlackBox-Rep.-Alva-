# BLACK.BOX — технический патч по аудиту 28 октября 2026 года

Отдельный пакет исправлений для основной записи, приватности экспорта, находок, Qt-интерфейса, декодера и владения дочерними процессами. Этот документ описывает внесённый код и доказательства его проверки; он не объявляет выпуск продукта или выполнение всего исторического BB-DI-001.

## 1. Версия, происхождение и статус

| Поле | Значение |
|---|---|
| Репозиторий | `jumonja-maker/BlackBox-Rep.-Alva-` |
| Исходное задание | Предоставленный владельцем `BlackBox_Technical_Audit_RU.pdf`, 8 страниц; технический аудит 27–28 октября |
| База отдельного патча | `765156068a2d2f0171be4d048e74c7676feba143` |
| Ветка патча | `patch/technical-audit-20261028` |
| PR | [PR #25](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/25) |
| Окончательный функциональный source SHA / tree | `da63ea85749e9b484eb4af088de61385eb6c4caf` / `6e219a0a8ff40c5a8ac4bfd779cab79b49a432b3` |
| Окончательная интеграционная проверка | [Run 40711406662 — SUCCESS](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40711406662): Windows source, Linux source и portable SUCCESS; publication SKIPPED. [UI contrast run 40711406642 — SUCCESS](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40711406642) |
| Итоговая готовность к независимой интеграции | BB-01–10 и перечисленные дополнительные дефекты исправлены и проверены. Отдельный Draft PR готов к независимому review/integration; это не выпуск релиза и не закрытие всех исторических BB-DI-001 требований. |

Исходный PDF отдельно различает проверенный прежний `5277ffffcc308d4dee0f6d71398f9d1c04b0b1fd` и последующий `7651560`. Успешные 583 теста и прежние Windows-артефакты относятся к старому SHA. Они не считаются результатом проверки этого патча, обновлённого decoder или новой сборки.

Владелец прямо запросил **новый отдельный патч**. Поэтому выбрана новая ветка вместо прежнего предписания `AGENTS.md` работать в `patch/trace-decoder-phase5`. Это не разрешение сливать изменения в `main`, переносить старые ветки, публиковать Release, менять существующие теги или выполнять историческую авторизацию выпуска v0.5.0 повторно. Слияние и выпуск не выполнены. Билингвальное личное вступление README и адрес обратной связи Outlook сохранены.

Четыре важных разных результата:

1. Дефект воспроизведён и исправлен в коде.
2. Целевая переносимая регрессия прошла в изолированной среде.
3. Настоящий сценарий ОС/процесса/Qt прошёл на точном SHA.
4. Финальный portable EXE и пользовательский выпуск прошли приёмку.

Успех одного уровня не заменяет последующие. Окончательные результаты приведены выше; ограничения указаны в разделе 9. Количество тестов не подменяет приёмку требований.

## 2. Матрица исходных BB-01–10

| ID / приоритет исходного аудита | Подтверждённая причина | Что изменено | Существенная проверка |
|---|---|---|---|
| BB-01 / P1 | `sqlite3.Error` использовался без импорта и заменял ошибку индекса на `NameError` | Импорт стандартного `sqlite3`; существующая деградация и завершение достигаются без подмены исключения | `INDEX_UNAVAILABLE` не останавливает sampler; ошибка закрытия стадии сохраняет `INCOMPLETE`; нативные own-PID случаи отдельно |
| BB-02 / P1 | Default share policy очищала JSON, но пропускала scalar TEXT и часть БД | Общий проход по текстовым значениям экспортных копий, ключам JSON и omitted manifest; nonce-bound непрозрачные токены | Sentinel отсутствует в SQLite/JSON/CSV/HTML; исходные базы неизменны; references и foreign keys сохранены |
| BB-03 / P2 | Любой pending helper request считался остановкой | Отдельный `ResearchBridge.stopping`; Stop доступна при Verify/Export | Настоящий Qt/helper, реальный клик Stop; двойная остановка не ставится |
| BB-04 / P2 | `worker.finished` мог выполниться внутри модального вопроса раньше записи retry | Один exactly-once путь запуска pending retry после освобождения worker | Реальный вложенный event loop: Yes до/после finished и No |
| BB-05 / P2 | Экспорт брал три потока находок, UI — четыре | Общий поток `finding_streams`, включая action findings | Равенство finding IDs UI/JSON/CSV/HTML, больше одной страницы, явный интервал |
| BB-06 / P2 | Первый redaction безусловно удалял заметку до обработки согласия | Один центральный проход с явным consent только для user findings | COMMENT и legacy user_problem включаются при согласии; default и произвольные attributes остаются закрыты |
| BB-07 / P2 | Evidence CSV проверял только первый символ | Общий `csv_safety.csv_safe` для evidence и findings | Прочитанные CSV cells с пробелами/TAB/CR/LF перед `=`, `+`, `-`, `@` |
| BB-08 / P2 | LIKE применялся к сериализованному JSON | Поиск только декодированных `name` и `address` через SQLite JSON API | Unicode, отсутствие совпадений по JSON keys, literal wildcard/backslash, pagination, immutable index |
| BB-09 / P3 | Тест зависел от глобального QSettings и порядка suite | Собственный временный INI и явный RU/EN | Исходный standalone тест падает на чистых настройках; исправленный проходит отдельно |
| BB-10 / P3 | Закрытый лидер POSIX-группы делал последующий cleanup невозможным | Закрывается принадлежащая группа, даже если лидер уже завершился | Реальный собственный потомок с heartbeat; отдельная контрольная группа остаётся живой |

Таблица описывает выполненные исправления и тестовые контракты. Она не присваивает всем пунктам одинаковую степень нативного подтверждения: ограничения текущего host и окончательного CI приведены в разделах 7–9.

## 3. Основная запись и необязательные подсистемы

### BB-01: ошибка библиотечного индекса больше не превращается в остановку основной записи

В `research_worker.py` два обработчика ссылались на `sqlite3.Error`, хотя модуль не импортировался. Во время SQLite-ошибки Python вычислял tuple исключений и создавал новый `NameError`. Внешний recorder-loop принимал его за отказ основной записи и завершал сеанс `STORAGE_ERROR`.

Внесён минимальный импорт. Уже существующие механизмы — короткий timeout чтения индекса, кеш бюджета и явный `INDEX_UNAVAILABLE` — сохранены. Не добавлено сканирования библиотеки на каждый sample, фоновой перестройки индекса или подавления ошибок основного evidence storage. Ошибка необязательного каталога не должна мешать продолжающимся измерениям; ошибка самой записи по-прежнему требует честного отказа.

Тот же импорт исправляет обработчик закрытия пользовательской стадии. Если завершающая запись стадии отказала, закрытие владельцев и основных хранилищ продолжается; research получает `USER_STAGES_FINALIZATION_UNCONFIRMED`/`INCOMPLETE`. Это не выдаётся за успешное завершение всех событий и не означает, что уже сохранённые измерения потеряны.

Новые проверки охватывают испорченный индекс, настоящую эксклюзивную SQLite-блокировку, кеширование ошибки и закрытие активной стадии. Переносимые контракты `_health` и `stop` используют явно управляемую probe-границу. Реальные PID/helper проверки не подменены фиктивной наблюдаемостью; на несовместимом локальном procfs они имеют явный SKIP и должны выполняться на нормальном Linux/Windows.

## 4. Приватность, полный экспорт и согласие

### BB-02: default share policy применяется ко всем текстовым значениям копий

Воспроизведение исходной базы использует допустимые SDK/evidence строки: Windows-путь в `kind`, POSIX-путь в `source`, URL в `quality`. Прежний проход обрабатывал JSON payload, но сохранял эти scalars, а затем производные CSV/HTML/JSON повторно распространяли их. Manifest при этом заявлял `known_paths_urls=REDACTED`.

`redact_copies` теперь обрабатывает **экспортные копии** четырёх собственных SQLite: research, legacy session, session-v2 и detail-v2. Реально текстовые значения очищаются независимо от declared affinity колонки: SQLite может хранить TEXT и в INTEGER-affinity поле. JSON проходит рекурсивно; распознаваемые пути в dictionary keys тоже не остаются. Числа и NULL не заменяются произвольными строками.

Простой одинаковый placeholder не подходит для primary/reference keys: разные пути могли бы схлопнуться в одну запись. В этом патче используется непрозрачный token со случайным nonce конкретного экспорта. Один исходный путь получает согласованный token внутри копии, разные пути сохраняют различимость. Nonce не сохраняется; внешней таблицы обратного соответствия нет. Это средство согласованности очищенной копии, не обещание анонимности от всех возможных корреляций.

Обход выполняется ограниченными страницами с проверкой существующей отмены. `secure_delete` и VACUUM очищают прежние текстовые payload из свободных SQLite-страниц. `manifest.omitted` очищается отдельно: даже имя не включённого raw artifact могло содержать приватный путь.

До обновления отвергаются схемы, которые нельзя безопасно обработать этим контрактом: triggers, views, virtual tables, WITHOUT ROWID/неоднозначный rowid или распознаваемый путь в самой схеме. Произвольный импорт в таком случае не получает ложный статус успешно очищенного пакета; экспорт останавливается, исходник сохраняется. Штатные схемы приложения продолжают поддерживаться.

Байтовые SHA исходных SQLite проверены до/после и для default export, и для явно sensitive варианта. Policy обозначена `SHARE_COPY_DEFAULT_V2`. Очищение известных путей/URL и перечисленных полей не является универсальным детектором секретов в произвольном свободном тексте.

### BB-05: UI и экспорт используют один инвентарь находок

`investigate()` раньше объединял persisted, counters, research и action findings. `write_findings()` повторял похожий код, но пропускал actions. Пользователь видел `ACTION_RESOURCE_COINCIDENCE` на экране, а «все находки» не содержали его в JSON/CSV/HTML.

Новый `finding_streams` является общим источником. UI сохраняет bounded heap/pagination и собственные фильтры; экспорт сохраняет внешнюю SQLite-сортировку. В Python не накапливается весь архив результатов. Finding IDs и предупреждения об отсутствии доказанной причинности остаются прежними.

Проверено равенство набора IDs на одном и нескольких UI pages, включая 65 action intervals, а также совпадение при явно обрезанном интервале. Частичный action interval остаётся помеченным `partial_action_interval`; временное совпадение ресурсов и действия не объявляется причиной.

### BB-06: согласие на заметки исполняется без расширения доступа к attributes

Прежний первый `redact(row)` удалял `note/comment`; последующий `privacy(..., include_notes=True)` не мог восстановить уже исчезнувший текст. Теперь центральный проход получает opt-in до удаления разрешённого поля. Finding exporter разрешает его только для `USER_REPORTED`. Необязательная checkbox не раскрывает заметки других application/observer evidence.

Произвольные `attributes` и context остаются закрыты. Знакомые пути/URL и прочие sensitive fields продолжают очищаться даже внутри разрешённого пользовательского note. Default `include_notes=False` проверен по всем текстовым членам interval export; согласие true — по JSON/HTML и legacy notes в events JSONL. Согласие не меняет исходную запись.

### BB-07: одна CSV-политика

`csv_safety.csv_safe` используется в обоих экспортёрах. Защитный апостроф добавляется с учётом начальных пробелов и управляющих whitespace перед формульными префиксами. Старый импорт `findings_export.csv_safe` сохраняет совместимость через re-export.

Регрессии читают выходные bytes стандартным CSV reader и проверяют именно значения клеток. Реальное выполнение формулы в Excel, RCE и универсальная безопасность каждого стороннего CSV-import режима не утверждаются.

### Дополнительные подтверждённые исправления рядом с BB-05/06

1. **Legacy user_problem отсутствовал в research findings.** Добавлен узкий путь известного producer kind для источников USER/BLACKBOX_LEGACY. Это пользовательское сообщение, а не OS-наблюдение.
2. **Explicit series терялся.** Interval export STANDARD мог содержать метрики восьми standard samples, а finding coverage — двух автоматически выбранных detailed samples. Выбор серии теперь передаётся writer.
3. **Комментарий после последнего resource sample исчезал.** UI по умолчанию учитывал research tail, экспорт заканчивался раньше. Default end теперь совпадает; явная пользовательская граница не расширяется.
4. **Scalar paths в interval events JSONL обходили политику.** После выбора разрешённого detail очищается вся финальная event row, включая event type/correlation key.

Положительные контроли сохраняют no-clobber: повторный экспорт в существующие имена не меняет прежние файлы; отменённый экспорт убирает только собственный staging и оставляет посторонний файл. Source hashes неизменны.

### Независимое review новой очистки

Review воспроизвело два дополнительных обхода расширенного TEXT-прохода. `PRAGMA table_info` не включает generated columns, а SELECT * включает их: позиционное сопоставление могло пропустить следующее приватное поле. Кроме того, приватный путь в имени/SQL индекса сохранялся в sqlite_schema. Исправления используют table_xinfo с явным отказом hidden/generated columns и проверяют имена/SQL всех schema objects. STORED, VIRTUAL и индекс с приватным sentinel теперь отказываются с UNSUPPORTED_SHARE_COPY_SCHEMA. Обычная индексированная rowid-таблица по-прежнему очищается; независимые 4 контроля прошли.

Для приватных scalar-колонок note/comment/attributes применяется та же политика, что для JSON. Экспортные копии могут быть отброшены при неизвестной схеме; исходник не изменяется, ZIP не получает ложный статус очистки.

## 5. Qt-интерфейс и завершение фоновой работы

### BB-03: Stop доступна во время Verify/Export

Generic pending request больше не приравнивается к stopping. `ResearchBridge.stopping` означает реальный pending Stop/Quit или closing. Остальные controls сохраняют прежний консервативный режим занятости; Stop активной записи использует точное состояние. Повторно доставленный Stop handler не ставит вторую команду, когда первая уже pending.

Регрессии используют настоящее окно, helper и файлы, а не подменённый backend. Во время Verify/Export проверяется enabled кнопка и настоящий клик, затем закрытое состояние записи. Это доказательство правильного маршрута команды, не гарантия определённой миллисекундной задержки на любом диске, trace tool или workload.

### BB-04: ровно один повтор после модального согласия

Реальная база из 4097 measurements заставляет `InvestigationWorker` предложить последние 4096. Вложенный Qt event loop модального QMessageBox может доставить `worker.finished` раньше ответа Yes. Раньше callback очистки уже прошёл, а сохранённый позже retry никто не запускал.

Единый scheduler вызывается и после согласия, и после завершения worker. Он потребляет pending retry только когда worker очищен и busy false. Контроли охватывают оба порядка Yes, а также No после finished. Согласившийся пользователь получает ровно один HTML и JSON результата последних 4096 samples; отказ не создаёт отчёт.

### BB-09: язык теста не зависит от машины оператора

Тест получает собственный временный INI QSettings. RU выбирается до утверждений о русском тексте, затем отдельно проверяется EN. Настоящие настройки пользователя не читаются и не переписываются. Исходный standalone тест с пустым XDG_CONFIG_HOME действительно падал; исправленный проходит отдельно. Production default языка не меняется.

### Дополнительно: завершённые InvestigationWorker удерживались окном

Отработавшие QObject workers оставались parent-owned до уничтожения окна. После finished теперь используется `deleteLater`, аналогично существующему пути ReportWorker. Контроль выполняет Qt DeferredDelete и три законченных расследования: дочерних InvestigationWorker больше нет. Это устранённое удержание конкретных объектов, не сертификат отсутствия всех RSS/Qt/GPU утечек.

## 6. Декодер, trace guardian и принадлежащие процессы

### BB-08: поиск по реальным именам/адресам кадров

SQL LIKE по `frames_json` находил JSON keys `name`/`address`, но не видимый кириллический frame, записанный как `\\u...`. Теперь SQLite `json_each` рассматривает только декодированные значения `$.name` и `$.address`.

Сохранены literal escaping `%`, `_` и backslash, keyset pagination, выбор PID и поддержка прежней layout индекса. Миграция и пересоздание чужого SQLite не требуются. Reader по-прежнему ограничивает query временем, размером строки и страницы; профиль builder остаётся bounded. Полное Unicode casefold не добавлено: case-поведение соответствует прежнему SQLite LIKE, то есть ASCII insensitive, не все алфавиты.

Проверены Cyrillic stack, отрицательные JSON-key/serialization matches, literal patterns, stable paging и byte-identical source index. Реальная полнота native symbols или произвольных ETL payload из этого SQL-контроля не выводится.

### Дополнительно: умерший guardian не должен оставаться RECORDING

В исходном аудите это было отдельно отмеченным отрицательным сценарием без нативного подтверждения. В текущем патче воспроизведён контракт journal/owner: завершившийся guardian мог вернуть старое RESERVED/STARTING/RECORDING/STOPPING, повторный Stop терял уже полученные terminal details. JSON root `[]` приводил к AttributeError; foreign-instance journal мог ошибочно приниматься за принадлежащий capture.

Теперь смерть без достоверного matching terminal journal возвращает `CLEANUP_REQUIRED`. Last journal state и exit code остаются явными; `lost_events=None`. Несогласованное COMPLETED при ненулевом exit не объявляется успехом. Наблюдение кешируется, поэтому следующий Stop не откатывает результат к старому journal. Process exit фиксируется до чтения journal, чтобы не пропустить последнюю запись на границе завершения; оставшаяся stdin pipe закрывается после выхода.

Journal не переписывается. Глобальный WPR stop/cancel не добавлен. Только явная named-instance recovery может подтвердить cleanup. Проверки используют настоящих собственных Python children с normal/forced exit и управляемое interleaving; birth-time boundary изолирована отдельно от реальных exit codes. **Настоящая WPR capture, аварийное завершение её guardian и восстановление capture этим локальным тестом не выполнены.** Успех этих контролей нельзя объявить полным закрытием native WPR-negative приёмки.

### BB-10: POSIX-группа очищается после выхода лидера

`OwnedProcess.close(kill=False)` раньше видел завершённого непосредственного child, пропускал killpg и устанавливал `_closed=True`. Последующий forced close становился no-op, хотя собственный потомок продолжал работать.

OwnedProcess по-прежнему запускается в новой сессии. Close завершает принадлежащую POSIX-группу независимо от состояния лидера, затем освобождает ownership capability. Чужие процессы по имени или общему PID-списку не завершаются; Windows Job Object не заменяется POSIX-механизмом.

Реальный Linux fixture использует subreaper, нормальный выход лидера и heartbeat собственного потомка. До исправления heartbeat продолжался после обоих close; после исправления прекращается, а отдельная контрольная группа остаётся живой. Fixture завершает и reap-ит своих детей. Поскольку mounted procfs здесь несовместим с PID namespace, жизнь доказывалась изменениями heartbeat, а не совпадением числового PID в `/proc`.

Специально отвязавшийся в другую session процесс этой границей не охватывается. Теоретическое повторное использование числового POSIX PGID при сильно отложенном close после полного исчезновения старой группы не воспроизведено и не объявляется устранённым; Windows использует отдельный Job Object. Для shipped GUI-операции, естественно создающей такой daemon, исходный аудит не доказывал утечку; уровень P3 не повышен искусственно.

### Дополнительно: отказ ready marker после успешного Popen

После создания owner `OptionalJobs._launch` пишет ready marker. Если запись отказывала, прежний except удалял temp, но терял owner работающего процесса. Новый error path сначала пытается bounded cleanup владельца, затем temp и сохраняет первоначальное исключение. Вторичный cleanup failure добавляется как exception note, не подменяя исходный диагноз.

Негативный контроль использует настоящий OwnedProcess и отказ `Path.touch`. Отдельный контроль одновременно отказывает marker и temp cleanup. Он проверяет остановку принадлежащего процесса и сохранение первоначальной ошибки; не обещает принудительно удалить файл вопреки запрету ОС.

## 7. QA и сопровождение сборки

### Undefined-name gate

`tools/check_undefined_names.py` использует закреплённый Pyflakes как QA-only инструмент. Приложение и EXE его не импортируют. Gate ищет undefined names/locals/exports, ошибки forward annotation, syntax и чтения. Старые unused imports/locals не превращаются в блокирующую ошибку этого узкого контракта.

PASS имеет exit 0; обнаруженный дефект — FAIL/exit 1. Отсутствующий инструмент, путь или пустая проверка не получают ложный PASS: INCOMPLETE/exit 2. Есть отрицательные контроли на недостающий exception import, undefined `__all__`, unbound local и syntax error. Число проверенных файлов окончательного источника берётся из финального evidence, а не из промежуточных 226.

### Закреплённые зависимости и Actions

Добавлены отдельные `requirements/ci-linux-py311.lock` и `ci-windows-py311.lock` для Python 3.11 x64. В CI-пути сборки/полного теста установка использует `--require-hashes`; установка локального core — `--no-build-isolation --no-deps`, чтобы повторный resolver не менял уже выбранный набор незаметно.

В частности, закреплены PySide6/Addons/Essentials/Shiboken 6.11.3, psutil 7.2.2, Pyflakes 3.4.0, pip **26.2.2**, setuptools **84.2.1**. Windows build tooling содержит Pillow **13.0.0**, PyInstaller 6.22.3 и его точные сопутствующие wheels. Pillow используется для собственной иконки, а не как новый runtime decoder приложения. Старая верхняя граница, исключавшая исправленную ветку Pillow, не сохраняется в этом сборочном пути.

Actions обновлены до выбранных Node-24 поколений и закреплены полными commit SHA, включая checkout/setup-python/upload-artifact/setup-dotnet. Это фиксирует код Action; не означает одинаковую машину hosted runner через месяц. Windows CI закреплён на доступной 3.11.9, Linux — на 3.11.14. Различие Windows/Linux runtime, образ ОС, системные packages, SDK/.NET и вложенные native DLL всё ещё требуют записи фактических версий и не превращаются автоматически в герметичную воспроизводимую сборку.

SHA wheels подтверждают конкретные скачиваемые bytes, но не являются полным SCA. Наличие обновления перечисленных tooling packages не означает, что проверены все advisories CPython, Qt, .NET и каждой native DLL. Исходный аудит не доказывал эксплуатацию Pillow/setuptools/pip через BLACK.BOX; патч не заявляет устранение несуществующего RCE.

### Исправления самого CI и выведенный из эксплуатации импортёр

Первый прогон `40707583368` остановил Windows до тестов: setup-python не нашёл 3.11.14 для Windows 2025. Уточнена платформенная конфигурация: доступная Windows 3.11.9 и Linux 3.11.14, те же wheel hashes для ABI-compatible зависимостей. Этот отказ не объявляется продуктовой ошибкой или успешной проверкой.

При механическом обновлении Actions был затронут исторический import-investigation.yml. Его push hook ещё пытался импортировать уже отсутствующий vendor ZIP и содержал push HEAD:main. Запуск `40707497184` отказал при чтении отсутствующего архива до записи в main. Такой legacy hook сам по себе не должен оставаться доступным из произвольной patch-ветки: он заменён ручным status-only workflow с contents:read, без checkout, архива, commit и push. Старый source importer не является необходимой частью текущего приложения. Основная ветка осталась на исходном SHA.

### Конкретные notices и инвентарь portable-пакета

`tools/build_distribution_inventory.py` добавляет в создаваемый portable payload:

- `DISTRIBUTION-INVENTORY.json` с SHA-256 и размером каждого regular file, кроме самого manifest;
- metadata точных установленных distributions сборочной среды, явно отделённую от доказательства их включения в EXE;
- реальные доступные license texts из installed distribution records;
- привязанные к версии reference texts Qt/PySide 6.11.3 и CPython 3.11.14 fallback, с provenance.

Для другого runtime fallback не используется без соответствующего installed LICENSE. Несовпадающая версия PySide отвергается до копирования notices. Существующие decoder files/notices не переписываются. Повторный destination — no-clobber; links/reparse paths отвергаются. Hash/copy validation проверяет изменение файла во время операции; rollback удаляет только созданные этой операцией элементы.

Это улучшение состава поставки, а не правовое заключение. Manifest явно содержит `licenseCoverageReviewRequired=true`, `allNativeDllLicensesCertified=false` и `allEnvironmentPackagesDeclaredBundled=false`. Metadata-only package не выдаётся за найденный текст лицензии. Отдельная проверка всех обязательств распространения точных бинарников, исходников/offer и third-party Qt notices остаётся необходимой перед публичной поставкой.

**Authenticode-подпись не создана.** Для настоящей подписи нужен принадлежащий владельцу сертификат/служба подписи и отдельное разрешение использования. Патч не создаёт фиктивного свидетельства доверия, не меняет SmartScreen reputation и не объявляет исследованные старые unsigned EXE вредоносными. Отсутствие сертификата не мешает сохранить честный статус unsigned, но не позволяет считать замечание о подписи закрытым.

## 8. Локальные проверки и честные ограничения среды

Рабочая среда: Python 3.12, PySide6 6.11.3, psutil 7.2.2, Pyflakes 3.4.0; Qt offscreen. Lock-файлы CI ориентированы отдельно на Python 3.11 x64.

В этом host `os.getpid()`/Popen.pid и видимая procfs относятся к разным namespaces. psutil может получить `NoSuchProcess` для собственного живого процесса либо прочитать посторонний PID. Попытка получить согласованную изолированную procfs недоступна в среде. Это ограничение обнаружено, а не исправлено ослаблением product owner/identity guards.

Последствия для доказательств:

- Старый полный baseline suite здесь не зелёный: нативные real-process/owner tests блокируются несовместимой procfs. Ошибки не списываются в PASS.
- Четыре новых own-PID capture-теста имеют узкий guard `CONTROLLED_PROCESS_NAMESPACE_UNAVAILABLE`. На обычном Linux и Windows они должны исполняться.
- В pure synthetic export fixtures изолирован только creation-time вызов владельца transaction; SQLite, parsing, source hashes, запись/публикация остаются production. Это не owner-liveness proof.
- В guardian journal fixtures birth time — управляемая граница, но child exit/forced termination реальны. Это не WPR capture proof.
- В POSIX child cleanup жизнь проверяется собственным heartbeat и subreaper, не ненадёжным `/proc` PID совпадением.
- Отдельные Qt helper tests проходят реальный протокол/окно/закрытие, но не удостоверяют точность OS CPU/RSS измерения по несовместимому namespace.

### Промежуточные целевые результаты

| Направление | Выполнено | Существенная граница |
|---|---|---|
| Общая новая группа до финального CI | **59 обнаружено: 55 PASS, 4 SKIP, 0 FAIL/ERROR** | 4 own-PID capture fixture guard; не полный штатный suite |
| Capture | 3 переносимых PASS / 4 own-PID SKIP | Нативные случаи нужны на правильной ОС |
| Privacy/CSV | Исходные 9 + дополнительные schema/scalar контроли PASS; adjacent 54 PASS / 2 Windows-only SKIP из 56 | Это не full SCA/секрет-детектор |
| Findings/export | 10 новых + 7 existing = 17 PASS | Pure export owner metadata boundary явна |
| UI/language | 12 целевых PASS; отдельный language test PASS | Offscreen Qt, не physical DPI/accessibility |
| Decoder/guardian | 10 новых PASS; 61 executed decoder tests, 2 native symbol class skip records | Здесь нет Clang/lld-link и настоящего WPR-negative capture |
| OptionalJobs/undefined gate | 10 новых PASS | Реальная Linux process group, не Windows Job Object proof |
| Distribution inventory | 5 PASS, 0 SKIP | Fixture metadata/files, не подпись или legal certification |

Строки пересекаются по existing tests, поэтому их нельзя складывать. Финальный exact-SHA результат в разделе 1 имеет приоритет. Исходные red logs сохранены: для BB-05/06 и соседних gaps точный baseline даёт 7 FAIL/3 positive PASS; для UI — четыре отрицательных случая и два положительных; для OptionalJobs — три воспроизведённых отказа; для decoder — failing subcases плюс один literal-pagination control. Падение fixture или host не выдаётся за новую ошибку продукта.

Были и экспериментальные более широкие прогоны с ошибками: существующий exit-clock тест, export recovery child fixtures и library export получали NoSuchProcess; UI run перестал продвигаться после decoder output. Эти журналы не подтверждают общий PASS и не исключаются из истории ради красивого результата. Приёмку обновлённого кода должен дать новый Windows/Linux/portable CI на зафиксированном источнике.

### Промежуточный полный Linux и исправление тестового времени

На корректной Linux-среде run `40708091319` выполнил 704 теста: 19 записей SKIP и один FAIL (в числе skip есть class-level fixtures; количество PASS простым вычитанием здесь не присваивается) нового lock/recovery fixture. Продолжение sampling под настоящей SQLite-блокировкой прошло; отказал контроль refresh после unlock. Fixture использовал `_library_budget_at=0` как будто 60-секундный кеш обязательно истёк. На свежем runner `monotonic()` меньше 60, так что такой reset неправилен. Исправление теста использует относительные `monotonic()-61`/`monotonic()-6`, не ослабляя проверку восстановления индекса. Дополнительный переносимый тест с monotonic=10 подтверждает и сохранение кеша до срока, и повтор чтения после истечения. Продуктовый код после исходника `3d0b58e…` не изменён; окончательный тестовый кандидат — `da63ea8…`.

Промежуточный FAIL сохранён отдельно в `linux-initial-clock-fixture-failure.json`. Успешный portable предшествующего SHA не подменяет окончательную проверку нового кандидата; его независимый readback указан ниже со своим source.

### Окончательная интеграционная приёмка

| Проверка exact SHA da63ea8 | Результат |
|---|---|
| Windows source unit suite | **714 тестов: 706 PASS, 8 SKIP, 0 FAIL/ERROR**, 955,649 с |
| Linux source unit suite | **705 testsRun: 688 PASS, 17 skipped test cases, дополнительно 2 class-level skip fixtures; 0 FAIL/ERROR**, 735,966 с |
| Capture-регрессии | Все 7 выполнялись и прошли на Windows и Linux; локальные 4 host-PID SKIP больше не являются единственным доказательством |
| Qt/source smoke, research E2E и deep-smoke | PASS на Windows/Linux |
| Windows native/API | Source job SUCCESS, включая штатные нативные проверки; Win32/WCT, EventLog, ETL, minidump, CPP/.NET clients не заменялись Linux SKIP |
| Portable/decoder | SUCCESS: TraceEvent/EventPipe/ETW, PE/PDB/sample-tree, сборка GUI+Maintenance, icons, frozen smoke/E2E/deep, STANDARD token, notices/inventory |
| Обновление/удаление | Реальное controlled native update/uninstall PASS, пользовательские данные сохранены |
| UI contrast | Оба hosted Windows popup-профиля SUCCESS на том же SHA |
| Release job | SKIPPED; публикация не выполнялась |

Class-level skip отличается от пропущенного отдельного testcase: unittest не включает тело класса в testsRun после setUpClass skip. Поэтому Linux PASS не вычислялся наивным 705−19; 688 успешных статусных строк независимо совпали с 705−17. Все причины записаны в final-linux-ci.json/final-windows-ci.json. Windows source не имел optional dotnet-trace; настоящий EventPipe проверен отдельно portable job. Linux не исполнял Windows API, а два symbol-класса без Clang/lld-link не объявляются пройденными. Windows native/portable проверки восполняют нужную платформенную часть, но это не делает Linux symbol-испытания выполненными.

Окончательный отчёт/evidence добавляется документационным commit с `[skip ci]`: после проверенного SHA не меняются продуктовые файлы, тесты, зависимости или workflows. Это предотвращает повторный многоэтапный build только из-за сохранения его собственных результатов. Для независимого review авторитетны точный source SHA и успешные run выше; SHA итогового HEAD указан в PR.

### Независимая проверка собранного portable

Windows portable job прогона `40708091319` завершился SUCCESS. Скачаны отдельные artifact ZIP для portable, frozen diagnostics и native maintenance; их SHA-256 совпали с GitHub artifact digest. Внутренний portable ZIP имеет SHA-256 `295e81dcd4e0c1c3e0f247cfa8797a7a17ec75cb13a9b2a7132ff6b919748fa0`.

Затем независимо от сборочного инструмента пересчитаны **525 файлов** payload: все размеры и SHA совпали с DISTRIBUTION-INVENTORY.json; неожиданных/пропавших файлов нет. Единственный исключённый из собственного inventory файл — сам manifest. Включены **73 notice files**, включая установленную лицензию CPython 3.11.9 и привязанные PySide 6.11.3 reference texts; **217 decoder files** также совпали с отдельным decoder manifest. Внутренний build provenance указывает точный функциональный SHA/tree и clean checkout.

Артефакты показывают frozen E2E отдельно ADMINISTRATOR и STANDARD; GUI/helper PID различаются, helper exit0. Native maintenance действительно обновил проверенный официальный v0.4.2 до локального кандидата, перезапустил GUI и удалил приложение/ярлык, сохранив evidence, пользовательский документ и посторонние файлы. Реального discovery нового публичного релиза не было: кандидат подавался по контролируемому offline release contract. Релиз не опубликован.

У новых GUI/Maintenance EXE PE Certificate Table остаётся пустой. Внешние catalog signatures и SmartScreen не проверялись. Эта фактическая проверка не заменяет подпись владельца и не меняет заявленные пределы license/SCA-приёмки. Машинные доказательства — portable-independent-verification.json и signature-observation.json.

Окончательный portable повторно собран для `da63ea85749e9b484eb4af088de61385eb6c4caf` в run `40711406662`: artifact `12826542643` SHA-256 `4d765a2eb3c50e0009c585aa47e33b26167f5d5762e2079326a0d0b8ebf2da6e`, внутренний ZIP SHA-256 `559d9b4519cb102b90dec25c004f5841b037a6bf83767f436d5faf824cdcd3b1`. Независимо повторены все 525 file hashes, точный provenance и 217 decoder hashes; несоответствий и лишних/пропавших файлов нет. См. final-portable-independent-verification.json. Предыдущее измерение выше остаётся отдельным промежуточным доказательством и не выдаётся за другой SHA.

## 9. Что остаётся вне доказанного закрытия

| Область | Чего этот патч не доказывает | Следующая доказательная проверка |
|---|---|---|
| Реальный WPR guardian crash | Полное завершение/восстановление реального trace после аварии | Native negative capture/recovery на Windows, с named ownership и readback журнала/ETL |
| Длительные сценарии 1h/8h | Отсутствие всех медленных утечек и бюджетных ошибок | Неизменный workload, согласованная ОС, время/RSS/handles/диск и сохранённый exact SHA |
| Physical GUI | Все DPI, accessibility, AV/OneDrive особенности и пользовательские диалоги | Отдельная видимая приёмка Windows 10/11; offscreen не заменяет её |
| Любой imported trace | Полная декодировка всех ETL/WPP payload, clocks, symbols и отсутствие dropped events | Корпус проверяемых native traces; unknown loss не превращать в zero |
| Privacy | Поиск всех возможных секретов/стеганографии в свободном тексте | Чёткая policy и явное согласие; не обещать универсальную анонимизацию |
| Состав дистрибутива | Полная SCA и выполнение всех условий каждого native binary | Проверка фактического inventory/notices точной сборки |
| Подпись | Authenticode и SmartScreen trust | Владелец предоставляет законный signing path; отдельное разрешение публикации |
| Окончательный продукт | Полная историческая приёмка BB-DI-001 | Отдельная матрица обязательных требований, native/frozen/endurance evidence |

Эти ограничения не отменяют исправления десяти конкретных ошибок. Они отделяют работающий исправленный код от неподтверждённых заявлений о всей программе.

## 10. Передача и воспроизведение

Рассматривать весь PR как один технический патч к точной базе. Не переносить Windows PASS прежнего `5277fff` и не сравнивать старые artifact hashes с новой сборкой. Сохранять вместе source SHA, tree, logs, действительные причины skip и manifest зависимостей.

Минимальный порядок проверки:

1. Убедиться, что source соответствует SHA в разделе 1, а не движущемуся main.
2. Установить соответствующий hash-locked набор CI и выполнить undefined-name gate.
3. Выполнить все новые regressions BB-01–10 и весь прежний suite без подмены native observations.
4. Проверить Windows/native decoder, portable/frozen startup, собственные процессы и export/readback.
5. Просмотреть новый distribution inventory: неизвестная license coverage остаётся неизвестной.
6. Принимать merge отдельно от решения о Release; никаких фоновых публикаций патч не разрешает.

Команды и entrypoints: `tools/check_undefined_names.py`, `python -m unittest discover -s tests -v`, существующие smoke/research/deep/native QA из workflow и `tools/build_distribution_inventory.py`. Результаты exact-SHA CI сохранены в evidence, вместе с hash-манифестом опубликованных доказательств.
