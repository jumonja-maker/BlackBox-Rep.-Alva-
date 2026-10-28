# BLACK.BOX Universal v0.5.1 — recording, privacy and audit fixes

## Русский

Выпуск объединяет исправления BB-01–10 из PR #25 и независимые замечания review.
Основная запись не останавливается из-за отказа необязательного библиотечного
индекса. Stop доступна во время Verify/Export; согласие на анализ длинной записи
запускает повтор ровно один раз. UI и экспорт используют общий набор находок,
а согласие на пользовательские заметки не открывает произвольные attributes.
CSV-политика едина; CPU-профили ищутся по декодированным именам/адресам, включая
Unicode, а не по JSON-ключам. Исправлены изоляция настроек тестов, очистка дочерних
процессов и сообщение о завершившемся WPR guardian.

Default share-экспорт очищает только копии баз и производные файлы. При обнаружении
распознаваемого пути/URL скрывается **всё текстовое значение**: имя с пробелами
внутри сообщения больше не оставляет приватный остаток. Одинаковые значения
получают согласованные токены внутри копии; исходные базы неизменны. Исправлено
ошибочное исключение пользовательских таблиц вида `sqliteXextra` из очистки.
Это не универсальная анонимизация и не поиск всех секретов. Перед передачей
пакета проверяйте его содержимое; raw sensitive export остаётся отдельным согласием.

Сборка использует закреплённые Python wheels/хеши и Actions, undefined-name gate,
инвентаризацию файлов и тексты лицензий. Workflow скриншотов запускается только
вручную и сохраняет артефакт для review, никогда не пишет в main. Публикация
проверяет точный SHA/tree/version, контрольные суммы и numeric draft ID. Релиз
v0.5.0 и его файлы не заменяются. Обновление проверяется с настоящего v0.5.0 ZIP.

Декодер v0.5.0 сохранён: ETL/EventPipe/JSONL, локальные PE/PDB, CPU-деревья и фильтры.
Количество выборок не означает CPU%, GC elapsed не означает паузу, синхронизация
трассы с сеансом остаётся NOT_ESTABLISHED. Неизвестные данные не выдумываются.
Нет автоматической загрузки символов или отправки наблюдений. EXE не подписан.
CI не заменяет физическую Windows 10/11, AV/OneDrive/accessibility приёмку, полный
native/license SCA, аварийный WPR/recovery и длительные endurance-испытания.

Скачайте BLACK.BOX-Universal-Windows.zip, распакуйте полностью и запустите
BLACK.BOX-Universal.exe. Сохраните _internal, decoder и helper рядом. Отдельная
установка Python/.NET не нужна. Контакт: DonJeoJesky@outlook.com.

## English

This patch integrates PR #25 audit fixes BB-01–10 and independent review
corrections. Optional catalog failure no longer stops primary recording;
Stop remains available during optional work; modal analysis consent retries
exactly once. Findings/export inventories agree, explicit user-note consent
is scoped, CSV safety is shared, and CPU stack search uses decoded frame values.
Process cleanup, guardian terminal reporting and test settings isolation improve.

Share copies redact whole textual values containing recognizable paths/URLs,
including embedded filenames with spaces. SQLite-lookalike user tables are not
mistaken for reserved internal metadata. Original evidence remains unchanged;
this is not universal secret detection. Explicit sensitive export remains opt-in.

Versioned, hash-pinned build dependencies, file inventory and notices are retained.
Screenshot collection is manual/artifact-only. Publication checks the exact main
SHA/tree/version and uploaded asset digests, and finalizes the verified draft by
numeric ID. Existing v0.5.0 assets/tags are not replaced. Real v0.5.0-to-candidate
portable update and uninstall are part of Windows acceptance.

All v0.5.0 decoder features and evidence limitations remain. Samples are not CPU
percent, GC elapsed is not application pause, and trace/session alignment is not
established. The EXE remains unsigned. Hosted CI is not physical Windows, complete
native/license SCA, emergency WPR/recovery or long-duration endurance acceptance.
