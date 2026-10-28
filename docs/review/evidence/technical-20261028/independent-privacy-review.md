# Независимый review default-share privacy (capture agent)

Область: `package_privacy.py`, `casebook.py`, взаимодействия findings/interval export. Изменений product этот reviewer не делал.

## Подтверждённые blockers финального generic sweep

### 1. Generated-column mapping

SQLite `PRAGMA table_info` не возвращает generated columns, а `SELECT _rowid_,*` их возвращает. `dict(zip(columns,row[1:]))` поэтому читает не те значения и обрезает конец ряда.

Временный copied `detail-v2.sqlite3`:

```sql
CREATE TABLE sensor_errors(
 id INTEGER PRIMARY KEY,
 generated TEXT GENERATED ALWAYS AS ('constant') STORED,
 code TEXT
);
INSERT INTO sensor_errors(id,code) VALUES(1,'/home/private/GENERATED_LEAK_SENTINEL');
```

`redact_copies()` успешно вернул known_paths_urls=REDACTED, text_cells_rewritten=0. Ряд остался `(1,'constant','/home/private/GENERATED_LEAK_SENTINEL')`, sentinel присутствовал в байтах DB. Это воспроизведение read/write copy path; не заявление, что текущий native writer создаёт generated schema.

Минимальный безопасный fix: `table_xinfo` и отказ при hidden!=0 (STORED/virtual/default-generated), поскольку generated SQL/value может сохранять узнаваемые пути, даже если выбирать ordinary columns явно.

### 2. Индексы с приватным текстом schema

```sql
CREATE TABLE sensor_errors(code TEXT);
CREATE INDEX "C:\private\BB_INDEX_SCHEMA_LEAK" ON sensor_errors(code);
INSERT INTO sensor_errors VALUES('OBSERVED');
```

Тот же copy export успешно вернул REDACTED, но raw DB сохранил `BB_INDEX_SCHEMA_LEAK` в sqlite_schema. Причина: `_PATH.search(sql)` проверялся только для kind='table'. Нужно fail-closed проверять schema names/SQL всех разрешённых объектов, включая indexes. Натуральные product indexes не должны пострадать.

Оба случая переданы root и privacy agent. Исправления/регрессии выполняются владельцем области; этот файл фиксирует исходное независимое воспроизведение, а не финальный green.

## Остальная проверка

- Export копирует SQLite через backup, редактирует staging, производные данные читает оттуда; источник не меняется.
- Общий salt на четыре DB сохраняет одинаковые scalar/JSON references без коллапса разных path IDs; токен не публикует соль.
- `io_latency_statistics(folder)` отдельно читает оригинал, но выводит только enum IO kinds, численные агрегаты и ссылки на integer evidence IDs. Бypass private text в этом пути не подтверждён.
- Notes consent в findings ограничен user confidence; произвольные application attributes всё ещё удаляются.
- CSV policy использует общий helper.
- Других подтверждённых blockers в проверенной области не обнаружено. Это не полный сертификат распознавания любых секретов.
