# BB-02 / BB-07 — экспорт приватности и CSV

База: `765156068a2d2f0171be4d048e74c7676feba143`.

## Подтверждения

BB-02 воспроизведён реальным ResearchSession и export_case: Windows-путь в evidence.kind, POSIX-путь в source и URL в quality попадают в evidence.csv и производные JSON/HTML/SQLite. Scalar-поля session-v2 событий также обходили прежнюю JSON-only обработку. Исходные базы не изменяются, но share-copy содержала приватный sentinel при known_paths_urls=REDACTED.

BB-07: parsed CSV клетки ` =1+1`, LF+=1+1 и два пробела++2 не имели защитного апострофа. Это доказательство недостаточного экранирования, не доказательство исполнения формулы/RCE.

Дополнительно воспроизведено: detail-v2.sqlite3 вообще не проходил redaction; JSON dictionary key и не-JSON текстовые значения SQLite могли сохранять узнаваемый путь. Название пропущенного raw artifact попадало в manifest.omitted без redaction (на POSIX допустимо имя, похожее на Windows-путь).

Первые четыре теста: 3 FAIL + ожидаемая ошибка отсутствовавшего additive include_notes API. Red log сохранён в privacy-red.log.

## Исправление

redact_copies обрабатывает только созданные export_case копии всех четырёх собственных БД. Внутри обычных rowid tables применяется единый рекурсивный JSON-aware проход по всем реально текстовым значениям (также TEXT, помещённый SQLite в INTEGER-affinity колонку). Политика note/comment/attributes действует одинаково для JSON и scalar columns. JSON keys тоже очищаются. secure_delete и VACUUM удаляют прежнее содержимое свободных страниц.

Разные пути не превращаются в одинаковый primary key: используются непрозрачные path tokens со случайным, не сохраняемым nonce одного экспорта. Совпадающие ID/reference внутри копии получают совпадающие токены; разные ID и JSON keys остаются различимыми. Прогон foreign_key_check после такой обработки чист. Числовые значения и NULL не подменяются.

Таблицы/колонки читаются из метаданных, SQL identifiers экранируются как identifiers. В копии до обновлений отвергаются triggers/views/virtual tables/WITHOUT ROWID/неоднозначный rowid или схема с узнаваемыми путями. Такие imports не объявляются проверенно очищенными: экспорт прекращается, исходник сохраняется. При обычной штатной схеме это не новый запрет формата. Каждые 100 строк проверяется существующая отмена экспорта.

manifest.omitted тоже проходит ту же политику. Поиск произвольных секретов в свободном тексте не обещается; policy version теперь SHARE_COPY_DEFAULT_V2. Whole absolute path fields с пробелами скрываются целиком.

Новый csv_safety.csv_safe общий для evidence.csv и findings exporter (коллега findings сохраняет re-export API). Способ обработки CSV сохранён совместимым с прежним более надёжным findings helper.

redact(..., include_notes=False) получил additive opt-in. include_notes=True разрешает только note/comment; raw application attributes остаются закрытыми, узнаваемые пути/URL всё равно скрываются. Findings agent ограничивает opt-in пользовательскими finding classes.

## Проверки и пределы

9 новых сценариев PASS. Соседняя группа: **56 total, 54 PASS, 2 SKIP, 0 FAIL/ERROR** — прежние package_privacy/research_product/interval tests плюс новые. Два пропуска — реальные Windows minidump/WCT, не применимые в Linux. Дополнительно pyflakes новых файлов чист.

В отдельном пробном adjacent запуске с test_export_recovery пять прежних subprocess-fixture остановились до операций экспорта: psutil.NoSuchProcess на собственном child PID в текущем /proc namespace. Лог privacy-adjacent-final.log сохранён; это не скрыто за PASS и не использовано как основание ослабить проверку владельца. Сам экспорт/recovery API не менялся.

Новый regression имени artifact с Windows-looking filename допустим только POSIX и имеет явный platform SKIP на Windows. Остальные новые проверки работают на обеих платформах. Windows/integrated QA выполняются root на общем точном SHA. Байтовое сохранение исходников проверено и default, и explicit-sensitive контролем.
