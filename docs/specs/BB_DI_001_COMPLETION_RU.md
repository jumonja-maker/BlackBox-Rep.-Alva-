# BLACK.BOX UNIVERSAL — ТЕХНИЧЕСКОЕ ЗАДАНИЕ НА ЗАВЕРШЕНИЕ РАЗРАБОТКИ

**Код поручения:** `BB-DI-001-COMPLETION`  
**Связанный нормативный заказ:** `BB-DI-001 — Deep Investigation & Reproducible Measurement`, документ от 23.10.2026  
**Срез состояния:** 24.10.2026, проверено в GitHub  
**Язык работы и отчётности:** русский  
**Тип задачи:** реальная разработка, интеграция, тестирование и инженерная приёмка — **не** только рекомендации или исследование.

> **Поручение следующему чату / исполнителю.** Продолжи работу над существующим BLACK.BOX Universal непосредственно в текущем Draft PR #17. Тебе передаются исходное полное ТЗ, существующий код, прогресс и нерешённые контрольные пункты. Восстанови контекст по репозиторию и нормативному ТЗ, реализуй оставшиеся требования, интегрируй их с реальным PySide6 UI и SQLite, добавь воспроизводимые проверки. Сохраняй `main` и релизы без изменений до явного решения владельца. Не считай отдельные unit tests доказательством готовности всего продукта. Если объём задачи превосходит один сеанс работы, вноси максимально содержательные проверяемые изменения в тот же PR, отмечай незавершённое и не утверждай, что заказ принят.

---

## 1. Источники истины и рабочие адреса

1. **Репозиторий:** https://github.com/jumonja-maker/BlackBox-Rep.-Alva-
2. **Единый накопительный Draft PR:** https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/17
3. **Рабочая ветка PR:** `review/bb-di-001-action-integration-20261023`. Не создавать параллельные PR без отдельного поручения.
4. **HEAD на момент передачи:** `7ab0bad65cb4315c16e58d5894196c229fea208f` (сначала перепроверь живой HEAD: он может измениться).
5. **Базовый `main` v0.3.6:** `7be5e3899c115b1703d67aee5a575647aec17615`. Сохранять `main` неизменным до одобрения владельцем.
6. **Последний подтверждённый CI точного HEAD:** https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40030385818 — `SUCCESS`: Windows 222/222 PASS, Linux 220 PASS + 2 SKIP; Windows portable PyInstaller EXE, обычный frozen `--smoke`, ZIP — SUCCESS; публикация релиза — SKIPPED. Это **не** полная глубокая Windows E2E-приёмка.
7. **Актуальная матрица 128 контрольных пунктов:** `docs/BB_DI_001_IMPLEMENTATION_STATUS.md` в ветке PR: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/blob/review/bb-di-001-action-integration-20261023/docs/BB_DI_001_IMPLEMENTATION_STATUS.md
8. **Главный нормативный документ (идёт отдельным файлом в пакете передачи):** `BLACKBOX_BigPatch_Technical_Spec_BB-DI-001_RU.md`. Его формулировки по `M-001..M-075`, `A-001..A-005`, `AC-01..AC-36`, `FIX-01..FIX-12` имеют приоритет над кратким пересказом ниже. При расхождении: изучи фактический код/исходное ТЗ, объясни расхождение в ADR, не меняй смысл требования без явного согласования.
9. Дополнительные архитектурные заметки уже в PR: `docs/BB_DI_001_BASE_WORKER_ARCHITECTURE.md`, `BB_DI_001_EVENT_JOURNAL_ARCHITECTURE.md`, `BB_DI_001_SAMPLING_BACKPRESSURE.md`, `BB_DI_001_MONOTONIC_CADENCE.md`, `BB_DI_001_ASYNC_REPORT_OWNERSHIP.md`, `BB_DI_001_DETAIL_V2_CONTRACT.md`.

**Статус по матрице на момент передачи:** 128 записей: `PARTIAL = 50`, `NOT-IMPLEMENTED = 29`, `NOT-RUN = 49`, полностью принятого `PASS = 0`. Из `NOT-IMPLEMENTED` 24 пункта `M` и 5 пунктов `A` с **разными** уровнями обязательности; `NOT-RUN` включает `M-045`, все 36 `AC` и все 12 `FIX`. Это статусы приёмки, **не проценты завершённости исходников**.

## 2. Назначение конечного результата

Поставить **автономное локальное Windows-приложение**, в котором обычный пользователь сможет:

1. Выбрать конкретный `PID`/EXE и закрепить экземпляр по `PID + creation time`, при необходимости дерево потомков.
2. Включить Standard/Detailed, записать точные пользовательские действия и пометки, повторить сценарий несколько раз.
3. Получить проверяемые метрики CPU, памяти, I/O, handles, TID и дерево дочерних процессов **за весь выбранный интервал**, включая неполный охват и недоступные датчики.
4. При настоящем зависании окна увидеть отдельные факты Windows HWND responsiveness и, когда Windows разрешает, данные WCT; при отказе — точную причину. Не подменять Windows-факты пользовательскими пометками или синтетикой.
5. Автоматически сохранить ограниченный контекст инцидента «до/во время/после», открыть общий интерактивный timeline и понятную доказательную карточку расследования.
6. Сравнить эквивалентные повторные измерения и создать локальные HTML/JSON/CSV/выбранный ZIP bundle с обозначением источника, качества и ограничений.
7. Повторно открыть старые и новые сеансы, сохранив старые файлы **побайтно неизменными**.
8. Запустить то же самое **в реально собранном Windows EXE без Python/SDK**, а не только в Python-тестах.

BLACK.BOX использует Alva только как внутреннюю инженерную основу. **Ни отдельной вкладки Alva, ни облачной зависимости. Ровно пять вкладок:** «Обзор», «Процессы», «События», «Отчёты», «Настройки». Сохранить существующий старт через `app.py`, PySide6, ядро и расследование.

## 3. Что уже существует: НЕ ПЕРЕПИСЫВАТЬ ВСЛЕПУЮ

В PR #17 уже присутствуют и частично интегрированы:

- Основной процессный psutil sampling с PID/birth check; schema1 `session.sqlite3`, JSON/HTML, базовый PySide6 GUI и RU/EN.
- Точные монотонные метки начала/конца пользовательских действий; частичный `ActionCycle`, повторения, базовая статистика длительностей.
- Пользовательская отметка проблемы; ограниченные CPU/sampling-gap автотриггеры, pre/post буфер и cooldown.
- Опциональный детальный sidecar `detail-v2.sqlite3`: psutil thread/child/CPU/private/USS/handles/I/O, частичная provenance/clock mapping/quality; это **не** полноценная нормализованная schema2.
- Анализ соседних снимков CPU выбранного TID, включая ограничения при исчезновении/повторном использовании TID; недавняя ограниченная история, Qt-таблица и части отчёта.
- Фоновый `BaseSampleWorker` для периодического вызова psutil и schema1 sample INSERT; ограничение одного in-flight worker.
- Фоновый 64-слотовый SQLite event journal, подтверждение сохранения пользовательских маркеров; учёт доставленных, но отброшенных Qt callbacks, фактической дистанции между снимками и Python-темпов worker.
- `ReportWorker(QThread)` для построения JSON/HTML **после** закрытия основного SQLite owner; отложенное закрытие окна, защита от повторного Stop/Start и сохранённый синхронный CLI API.
- Часть read-only Investigation / выбранного интервала, частичный compare, существующая защита обновления и пользовательских файлов.

**Не путать:** green CI подтверждает перечисленные частичные сценарии. `ReadOnlyProbe.stop()` для GUI по-прежнему выполняет SQLite finish/journal drain на Qt owner, user actions ждут disk acknowledgement, в Python sensor calls нет жёстких OS deadlines. Полный Windows HWND/WCT отсутствует. Длинная история и полноценная schema2 отсутствуют. E2E реального frozen EXE по всей цепочке не пройден.

## 4. Обязательный объём завершения, в порядке зависимости

### Этап I — Контракты, schema2 и безопасная модель владения (P0)

**Требования:** M-001..M-004, M-027..M-035, M-055, M-065..M-071, в сочетании с исходным полным ТЗ.

1. Создать формальную `schema_version=2`: `sessions`, `targets`, `process_instances`, `samples`, `thread_samples`, `child_process_samples`, `windows`, `events`, `action_intervals`, `incidents`, `measurements_quality`, `experiments`, `experiment_runs`, `artifacts`, `sensor_errors` (или эквивалент с явно сохранённой семантикой). Стабильные ключи, индексы, lifecycle, версия контрактов, миграции/sidecar и атомарность — с ADR и тестами.
2. Сформировать `session_uuid`, UTC↔monotonic mapping, точность и качество временных источников; корреляционные ключи. Сохранять действительные `monotonic_ns`, не округлять время до секунд.
3. У каждого источника/поля фиксировать `source_kind`, `verification_class`, `measurement_status`, права, accuracy, единицы и reason. `0` не равен `UNKNOWN`; импортированный JSON не может повышать доверие до `OS_OBSERVED` только по строке.
4. Оставить schema1 v0.3.4–0.3.6 **read-only**. Реализовать `SchemaV1Reader`, `SchemaV2Reader` и общий read-only `SessionView`. Любые sidecar/migrations — в новый файл/копию с checksum/rollback, без изменения исходных записей.
5. Перестроить владение очередями/писателем: bounded pipeline `Sensor → DTO → SQLite owner → Qt`, гарантированный порядок/action acknowledgements, нет псевдоуспеха до commit, явное backpressure, dropped/unknown quality. **Перенести оставшиеся блокирующие `SessionStore.finish()`, journal barriers и опасные операции из Qt** с соблюдением SQLite thread affinity. Не передавать созданный Qt `sqlite3.Connection` в другой поток.
6. Завершить graceful stop/cancel/heartbeat/worker health; прописать пределы и семантику остановки при зависшем OS syscall. Реальная гарантированная отмена требует изолированного ресурса/потока или helper — простой `QThread.wait()` в UI не допускается. Исчерпание диска, lock, crash-recovery, WAL/checkpoint, atomic no-clobber экспорты и ретенция без самовольного удаления.
7. Реализовать capability registry и `Sensor` API `capabilities()/start(context)/sample(deadline)/stop()/health()` с явными permissions, `supported_os`, `requires_optin`, status; fake sensors для unit tests. Ядро не зависит от доступности WCT/ETW.

**Критерии:** нормальная запись в v2 с полной целевой идентичностью; v1 SHA-256 неизменен после открытия/анализа; Qt сохраняет отзывчивость при намеренно заблокированном сенсоре, journal, SQLite и построении отчёта; отсутствие подвешенных/чужих ресурсов, бессрочного ожидания в UI и ложного COMMITTED; правдоподобная отчётность о gaps/unknown. AC-02, 05, 19–23, 25, 27–28, 35–36.

### Этап II — Полные процессные, потоковые и ресурсные измерения (P0)

**Требования:** M-005..M-012, M-023..M-026, M-033, M-049, M-052, M-063.

1. CPU процесса с реальным интервалом `dt`, `user/system_seconds`, возможностью **>100%**, без ошибочного обрезания многопоточной нагрузки.
2. RSS/Working Set, Windows Private Bytes, USS отдельно, commit/pagefile только при корректной семантике; handle count и thread count. Отсутствующее поле = NULL+status, не ноль и не подставленная другая метрика.
3. I/O накопленные bytes/ops; безопасные производные rates только при допустимом интервале без reset/PID-reuse.
4. Реальные `thread_samples` с TID+PID+временем и CPU за интервал; Top-N **за выбранный диапазон**, cumulative CPU, peak CPU, observed presence%, статус truncation/доля неотображённых потоков, отсутствие ложной continuity при TID reuse.
5. Дерево с PID+birth каждого потомка, временем появления/исчезновения, полными per-process samples, историей после выхода, честными агрегатами корня/дерева и оговоркой о double-count RSS.
6. `observer_coverage`: expected/observed/missed/error/unknown intervals для каждой серии; реальные пропуски не заполнять нулями. Нельзя выдавать величину, которую датчик объективно не мог измерить при данной частоте.
7. Полный bounded long-session selected interval на SQLite без `last 4096 only`: stream/paging/chunks для статистики и min/max/first/last downsampling для UI с сохранением пиков.
8. Все триггеры из исходного ТЗ: sustained CPU, private/RSS/handles growth, IO burst, UI_TIMEOUT, EXIT, sampling gap; ограниченные pre/post ring (ориентир 60/20 c), incident burst, debounce, hysteresis, cooldown, квоты, честные event-source и timestamps.

**Критерии:** FIX-01, 04–08, 11; AC-03–09, 18, 20–21, 27. Проверить 300+ потоков и 100+ дочерних процессов, завершение и повтор PID/TID.

### Этап III — Реальные Windows HWND, responsiveness и WCT (P0)

**Требования:** M-013..M-017, M-023, M-026, M-041, M-057–M-058, M-072.

1. Реальное Win32 перечисление связанных top-level HWND, проверка владельца PID/TID, lifecycle окон; не сохранять window title по умолчанию.
2. Безопасный малочастотный timeout-based responsiveness probe строго вне Qt с bounded latency. Фиксировать метод, Win32 status, threshold, число последовательных независимых проверок; создавать `UI_UNRESPONSIVE_OBSERVED` и `UI_RESPONSIVE_AGAIN`, а исчезновение — `WINDOW_GONE`.
3. Реальный Wait Chain Traversal для целевых потоков: узлы/владельцы/cycle и коды Windows; `UNKNOWN`, `ACCESS_DENIED`, `UNSUPPORTED` честно отображаются и не обрывают базовый сбор. Внешние Windows-запросы должны иметь штатное освобождение ресурсов.
4. Для non-GUI показывать `NOT_APPLICABLE`, а не «приложение не зависает»; для нескольких окон — выбор HWND без смены корневой цели.
5. Оформить Windows x64 API/ctypes/wintypes struct/callback lifetime, ctypes bounds, security и win32 error mapping, CI fake adapters и настоящие Windows VM fixtures.

**Критерии:** FIX-02, FIX-03, FIX-10; AC-10–13. Нельзя называть timeout или отдельный WCT snapshot доказанной корневой причиной.

### Этап IV — Действия, эксперименты, корреляция и Investigation 2.x (P0)

**Требования:** M-018..M-026, M-037..M-042, M-044, M-047..M-056.

1. Довести action state machine, ввод этапов/комментариев, optional безопасный локальный инструментированный канал собственных приложений. Время пользовательского нажатия = USER_COMMAND_UNVERIFIED, не доказательство фактического выполнения чужой операции.
2. Эксперименты с **2–20** повторами, их история, версии сценариев, сопоставимость профиля/цели/окружения. Median/p95/min/max/вариативность, CPU time, memory/handles/I/O delta, UI timeout frequency, явно недостаточная выборка и warning для некорректного сравнения.
3. Findings contract: `code`, `severity`, `start_ns`, `end_ns`, `facts`, `hypotheses`, `alternative_explanations`, `limitations`, `sources`, `coverage`, `confidence_class`; различать `OBSERVED`, `DERIVED`, `CANDIDATE`, `USER_REPORTED`, `UNAVAILABLE`.
4. Генерировать incident Investigation card: до/внутри/после, TID, память, handles, I/O, дерево, Windows UI/WCT при наличии; отделить фактические совпадения от причинных гипотез. Пагинация всех находок, выбранный временной интервал, не терять длинный сеанс.
5. Отчёты JSON schema2, локальный HTML без CDN, безопасный CSV и явно выбранный ZIP bundle с checksum, units, privacy preview/redaction, source/coverage/limitations, no-clobber и XSS escaping. Полная read-only история и экспорт любого выбранного диапазона.

**Критерии:** AC-14–18, AC-23–26, AC-35–36 и реальный повторённый сценарий по фиксированным Windows-приложениям. Отчёт не заявляет «обнаружена утечка» только по растущей памяти.

### Этап V — Реальный пользовательский UI из пяти вкладок (P0)

**Требования:** M-036..M-046, M-070..M-074.

- **Обзор:** цель/идентичность, Start/Stop, профиль, подготовка/замер, проблема, последние эпизоды и быстрый переход к интервалу.
- **Процессы:** дерево потомков и история, Top TID выбранного PID и интервала, честные метрики/покрытие.
- **События:** unified timeline USER/CPU/memory/IO/Win32/WCT/ETW/ошибки, фильтры и навигация к участку графика.
- **Отчёты:** человеческий Investigation Summary **перед** сырым JSON, отсортированные evidence findings, history, compare, export и открытие старого сеанса.
- **Настройки:** профили/частота/триггеры/capabilities/лимиты/согласия/приватность/RU-EN/error log.
- **Общий график:** синхронизированный по monotonic clock многодорожечный timeline, zoom/pan/A-B cursors/selected range, min/max bucket и точная статистика исходных данных. Пробелы не интерполировать нулями.
- Физические DPI 100/125/150/200%, 1366×768 и 1920×1080, keyboard/focus/screen reader roles, читаемые длинные русские строки. Никакой шестой вкладки.

**Критерии:** через реальные UI-обработчики генерируются соответствующие SQLite rows; пользователь может выполнить полный сценарий без CLI. AC-01, 19–21, 29, 32.

### Этап VI — Дополнительные Windows-capabilities (условно обязательно / SHOULD / FUTURE)

ОСОБО ВАЖНО: **не сводить все A-пункты к одному уровню MUST**. Следовать точным уровням в нормативном ТЗ.

- **A-001 MUST-IF-CAPABLE:** реальный короткий opt-in ETW CPU/I/O/thread trace на поддерживаемой Windows и правах; Stop/TTL/size limit, owned session cleanup, ETL provenance, возможность экспорта/открытия WPA; при unavailable — точная причина, не заглушка с `None`.
- **A-002 SHOULD:** реальные файловые I/O latency **только** из поддерживаемых ETW событий или добровольной инструментализации, не выводить latency из bytes/sec.
- **A-003 SHOULD:** opt-in .NET EventPipe GC/alloc/runtime при локальной доступности официального инструмента; без принудительного SDK/download. Другие runtime -> `RUNTIME_NOT_SUPPORTED`.
- **A-004 SHOULD:** opt-in crash signals/manual minidump import, защита секретов; не менять HKLM WER и не собирать дампы автоматически.
- **A-005 FUTURE:** задокументировать расширяемые контракты per-process network, GPU, FPS/frame-time; не объявлять эти метрики готовыми без проверенного PID-attributed источника. **Не блокирует приёмку основного ядра**.

### Этап VII — безопасность, производительность и окончательная приёмка (release blockers)

**Требования:** M-057–M-065, M-071..M-075, AC-01..AC-36, FIX-01..FIX-12.

- Базовый режим **без администратора**, локально и read-only; нет `TerminateProcess`, `SuspendThread`, `WriteProcessMemory`, DLL injection, драйверов, служб, скрытой облачной телеметрии и несанкционированного ETW/WER.
- По умолчанию не собирать command line, environment, full paths, оконные заголовки, URLs, содержимое памяти/дампы. Опциональный sensitive capture требует согласия. Перед экспортом preview/redaction.
- Path hardening: UNC/ADS/device/reparse/junction, архивы/ZIP traversal, symlink, HTML/script injection, отказ прав, безопасный rollback без удаления чужих файлов. Сохранить защиту v0.3.6.
- **Performance-цели нормативного документа (целевые, не уже достигнутые):** Standard при 2s polling ориентировочно ≤1 процентного пункта CPU всей машины; Detailed ≤3 процентных пунктов без ETW/dump. Измерить реальные observer on/off median/p95 и влияние на target на описанном железе, а не заявлять без замера.
- **Long-run:** реальная запись 8 часов Standard, 1 час Detailed; ≥300 threads, ≥100 descendants, >100k rows, ≥10k events, >500 injected incidents. Жёсткий бюджет памяти/диска, динамическое снижение частоты, подробный QA. Если стенд недоступен — оставить `NOT-RUN`, **не** заменять реальный endurance синтетикой.
- **Windows fixtures FIX-01..12:** CPU Burner; UI Block; WaitChain; Memory Steps; Handles; IO Burst; Multiprocess; Crash/Exit; .NET Runtime Optional; Broken Sensors; LongRun; Import Attack. Требуются исходники, инструкции сборки, условия запуска, реальные positive/negative results.
- **AC-01..AC-36:** по каждому автоматизированный тест + evidence и blocking/nonblocking статус ровно как в оригинале. В частности AC-22 — неизменность SHA legacy SQLite, AC-32 — **глубокий frozen EXE** с реальным `action → thread → incident → report`, AC-33 — all CI на **финальном** HEAD, AC-34 — честная ETW-capability, AC-35 — no-clobber, AC-36 — provenance/coverage/UNKNOWN.

## 5. Инженерные deliverables (обязательные выходные материалы)

1. Рабочий код, GUI, корректные зависимости, один PR #17 с понятными коммитами; никаких скрытых служб или обязательной внешней платформы.
2. `ADR-01` (сенсоры/workers/clocks), `ADR-02` (schema2/v1 compatibility), `ADR-03` (формулы CPU/memory/I/O/coverage), `ADR-04` (Windows HWND/WCT/ETW и права).
3. Versioned JSON/SQLite contracts + fixtures: `OK`, `MISSING`, `DENIED`, `UNSUPPORTED`, `PARTIAL`, подробные status/units.
4. Automated unit/integration/Qt/Windows-native tests, 12 fixture apps/source, полностью заполненная матрица `M-001..M-075`, `A-001..A-005`, `AC-01..36`, `FIX-01..12` со статусом, командой, ссылкой на evidence.
5. Доказательный QA Windows 10/11 x64, Linux compatibility, DPI/keyboard, heavy sessions и frozen EXE full E2E.
6. Perf и security/privacy отчёты, README RU/EN, справка метрик, CHANGELOG, dependency/SPDX/license inventory, rollback/upgrade proof.
7. Итоговый инженерный handoff: точный PR/branch/HEAD, изменения по файлам, результаты **только этого HEAD**, известные limitations, pending manual Windows QA, инструкции сборки и отката.

## 6. Правила исполнения в следующем чате

**Сразу после получения документа:**

1. Прочитай **полный** приложенный оригинальный документ `BLACKBOX_BigPatch_Technical_Spec_BB-DI-001_RU.md`; он первичен. Затем текущую матрицу реализации и ADR в ветке. Посмотри код и тесты, не доверяй устаревшим summary.
2. Проверь, что PR #17 остаётся `OPEN / DRAFT`, получи **живой HEAD** и подтверждение, что `main` не изменён относительно согласованного baseline; не откатывай накопленные функции ради чистого переписывания.
3. Кратко обозначь архитектуру следующего слоя (особенно безопасный SQLite owner и schema2) и точные требования, которые он покрывает, **затем переходи к реальному кодированию в том же PR**. Разделение на коммиты допускается, но конечная задача едина.
4. Не завершай работу советом «что сделать»: нужен реальный патч, реальные тесты, корректный CI и отчёт. Исправляй обнаруженные CI failures и проверяй финальный commit. Если инфраструктура/тестовая Windows недоступны, не фабрикуй PASS.
5. Не создавай PR #18+ для частей заказа, не делай merge, не меняй default branch, не публикуй GitHub Release/v0.4.0, не запускай ETW/дамп на пользовательской машине без отдельного opt-in.
6. Сохраняй только доказанные claims. Корреляция не равна причинности; User Command Marker не удостоверяет, что пользовательская операция реально завершилась; psutil CPU/TID не доказывает WCT/deadlock; Windows denied ≠ zero.
7. Обновляй `docs/BB_DI_001_IMPLEMENTATION_STATUS.md` после каждой существенной вертикальной части и прилагай точный CI. Статус `PASS` ставить лишь при соответствии **полной** исходной норме, реальной UI-интеграции и требуемой приёмке; `NOT-RUN` оставлять честным, если тест не был проведён.
8. Владелец проекта **не обязан вручную тестировать вместо исполнителя**. Подготовь Windows fixture evidence самостоятельно через доступный runner/VM, а физическое испытание, если объективно не проведено, пометь `MANUAL-NOT-RUN`.

## 7. Что считать полным завершением заказа

**Заказ BB-DI-001 закрыт только если одновременно:**

- Все обязательные `MUST` и работающие `MUST-IF-CAPABLE` реализованы в product UI и имеют тесты; исключения для недоступных capabilities подтверждены статусом и тестом, а `SHOULD/FUTURE` честно классифицированы.
- Весь сквозной сценарий **EXE → PID+birth → Standard/Detailed → action/marker → thread/tree/resources → Windows UI/WCT (если доступно) → bounded incident → timeline/investigation → repeat/compare → HTML/JSON/CSV → reopen session** проходит на Windows **в реально собранном EXE**.
- Пройдены и задокументированы AC-01..AC-36 и FIX-01..FIX-12 (для недоступного физического стенда — явный НЕПРОЙДЕННЫЙ статус, а не выдуманный PASS); есть 8h Standard, 1h Detailed, benchmarks, privacy/security/regression.
- Финальный exact-HEAD CI зелёный. Повторное открытие/анализ не меняет legacy v1 SQLite и уже опубликованные пользовательские файлы. Нет новой вкладки Alva, скрытой передачи данных, опасного изменения исследуемого процесса.
- Переданы ADR, contracts, сборка, тесты, документация, риск-реестр и ссылки на артефакты. Лишь владелец принимает решение о merge/release.

**Действующий статус на момент передачи:** BB-DI-001 **НЕ ЗАВЕРШЁН**. Текущий Draft PR #17 — накопительная рабочая ветка, не релиз. Проверяй любую заявленную готовность против исходного текста, а не против количества прошедших unit tests.
