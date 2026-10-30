# BLACK.BOX Universal v0.5.3 — deep process inspection and controlled diagnostics

> **Unpublished release candidate.** Promotion to `main` and public release
> remain subject to the owner's explicit approval and fresh exact-SHA GitHub
> Actions acceptance. This document is not a claim of publication.

## Русский

BB-DEEP-001 добавляет в существующий **Overview**, без новой основной
вкладки, раскрываемый инспектор выбранного процесса с девятью разделами:
процессы, модули, потоки, дескрипторы, память, сеть, диск, отладчик и история.

- **INSPECT**: реальные Windows-снимки процессов, модулей, дескрипторов,
  регионов памяти, текущие стеки AMD64, WCT, TCP/UDP и исторические
  ETW-файловые/сетевые/дисковые события; локальные символы и просмотр
  сохранённого minidump через существующий декодер.
- **INTERVENE**: пользователь может явно подтвердить подключение
  отладчика, breakpoint, pause/continue/single-step, собственную
  приостановку потока, точечную запись и проверяемую попытку
  восстановления памяти. Откат изменений в поведении процесса не обещается.
- **Права**: основной GUI остаётся asInvoker. Отдельный Diagnostic Helper
  через системный UAC запрашивает нужные права для ограниченного списка
  команд и одного экземпляра процесса; отказ не отключает OBSERVE.
- **Доказательства**: REQUESTED/RESULT, снимки ДО/ПОСЛЕ, локальный журнал,
  проверяемые экспортные хеши и контроль потерь/неполноты. Чувствительное
  содержимое памяти/дампов не включается в обычный пакет.

### Исправления предрелизного аудита

- Кнопка normal/full дампа в Overview использует тот же лимит **512 МиБ**,
  что и native Minidump writer; реальный сценарий через GUI → helper →
  дамп с проверкой формата и известной памяти включён в Windows QA.
- При отсутствии подтверждённой остановки для debug cleanup сохраняются
  собственные ресурсы/guardian и статус RECOVERY_UNCONFIRMED. Попытки
  восстановления байтов и контекста на потенциально работающем процессе
  не продолжаются; повторная очистка ограничена исходным временем сеанса.
- Release gate проверяет весь конечный ZIP по
  DISTRIBUTION-INVENTORY.json, включая Diagnostic Helper и его внутренние
  DLL/данные, сравнивает source manifests GUI/helper и запрещает
  отсутствующие, изменённые и неперечисленные файлы.
- Новый выпуск имеет уникальную версию **v0.5.3** и проверяет переход
  с официального неизменённого **v0.5.2** ZIP.

### Ограничения

Проверка GitHub-hosted Windows не заменяет реальное окно Secure Desktop UAC
или физическую Windows 10/11. Принудительный shutdown helper и необратимые
эффекты отладки/изменения памяти могут оставить RECOVERY_UNCONFIRMED.
Автоматический rollback не гарантируется при произвольной аварии.
Живые стеки/контекст поддерживаются для AMD64, а не для WOW64/ARM64.
Системные DiskIO события не доказывают задержку конкретного файла без
проверенной атрибуции. Неизвестные символы и связь часов остаются
явно неполными. Расширенные дампы ограничены **512 МиБ**; большему
процессу требуется другой инструмент или отдельный режим.

Все автоматизированные испытания выполняются **только на GitHub Actions**.
Ранее проверенная непрерывная запись 5 ч 30 мин не считается 8 часами.
Результаты итогового кандидата должны относиться к его собственному
точному SHA. EXE остаётся неподписанным.

Полный переносимый ZIP распаковывать без извлечения отдельных EXE:
сохранять `_internal`, `decoder`, `diagnostic` и
`BLACK.BOX-Maintenance.exe`. Пользователю не требуется устанавливать
Python или .NET вручную.

Обратная связь: DonJeoJesky@outlook.com.

## English

BB-DEEP-001 adds a nine-section process inspector **inside Overview**,
retaining six primary pages. It includes on-demand Windows module/handle/
memory/thread inspection, AMD64 current stacks, network and file/disk ETW,
local minidump review, and explicitly confirmed debugging, breakpoints,
thread suspension, and checked memory writes. The GUI remains asInvoker;
a separate scoped helper asks Windows for administrator consent through UAC
when required. Durable intent/results and before/after snapshots preserve
the source and uncertainty of each observation.

This release candidate resolves a previously mismatched GUI dump budget
(1 GiB versus the native 512 MiB maximum), prevents debug cleanup from
rewriting code/context without a confirmed stopped event, and verifies
the **entire final ZIP file inventory**, including all diagnostic helper
files and matching source manifests. A unique v0.5.3 release is required:
official v0.5.2 assets and tag remain unchanged.

Actual UAC Secure Desktop, physical Windows 10/11, arbitrary crash-state
recovery, universal native/managed stacks and attributed per-file physical
disk latency are **not certified** by hosted CI. In particular, no rollback
can reverse already executed instructions or application side effects.
Long-run acceptance must explicitly state actual continuous duration.

The next release requires all exact-SHA Windows/Linux/portable/native
checks, final archive SHA256 verification, and the owner's authorization.
Use the complete portable folder; no external Python or .NET install.
Feedback: DonJeoJesky@outlook.com.
