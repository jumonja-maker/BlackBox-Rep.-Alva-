# BLACK.BOX Universal v0.5.2 — completed offline trace decoder

## Русский

Выпуск добавляет завершающий крупный пакет Trace Decoder поверх официальной
v0.5.1. Исправления основного приложения и приватности из v0.5.1 сохранены.

- **Временная привязка к сеансу:** отдельная проверка исходной трассы,
  журнала захвата и session-v2.sqlite3 по SHA-256, экземпляру процесса,
  идентификатору загрузки Windows, QPC и метаданным часов. Поддержаны
  QPC-backed и GetTickCount64; интервал неопределённости показывается
  явно. Неаутентифицированные или несовместимые сведения дают
  `NOT_ESTABLISHED`, без притворной синхронизации.
- **ETW off-CPU:** типизированные CSwitch/ReadyThread, отдельные
  интервалы неисполнения, blocked/ready-delay, фильтры PID/TID/экземпляра
  процесса и времени. Положительные или неизвестные потери событий,
  противоречия идентификаторов и разрывы не превращаются в точные
  длительности. Причина планировщика — не владелец блокировки и не
  доказательство внутреннего сбоя приложения.
- **Локальная PDB-символизация:** строки исходников и контрольные суммы C13,
  CodeView inline, OMAP, дополнительная проверка соответствия PE/PDB и
  жизненного цикла модуля. Исходные адреса сохраняются. Portable PDB,
  произвольный managed JIT native-IP→IL и неизвестные форматы не
  угадываются; загрузки символов из сети нет.
- **Устойчивый импорт:** общий deadline, предел исходника 256 МиБ,
  не более 250 000 событий, пределы индекса/временных файлов,
  контролируемая память helper, ограниченное чтение страниц,
  отмена, отказ от повреждённых/неполных индексов и атомарный
  экспорт без перезаписи. Повтор начинается с оригинальной трассы.

Проверка кандидата проводилась в отдельной ветке на точном source
`7469dbe74154539ea58816306aba748976b863b1`:
[Windows/Linux/native/portable CI #40752408448](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40752408448)
— все четыре задания SUCCESS. Проверены настоящие ETL/EventPipe,
контролируемые Sleep/Event/Mutex, 7-Zip 26.04, PowerShell 7.6.7,
Notepad++ 8.9.8.1 и импорт 250 000 синтетических JSONL-событий.
**Итоговый выпуск допускается только после повторной проверки точного
объединённого коммита в `main`**, включая Windows/Linux, native QA,
portable EXE и реальное обновление с официальной v0.5.1.
Контрольные суммы опубликованных файлов сверяются GitHub Actions
до окончательной публикации.

Границы: hosted Windows Server не является физическим Windows 10/11.
Проверки 5 ч 30 мин и долговременная пользовательская приёмка остаются
отдельными тестами GitHub Actions и не выдаются за выполненные.
Сложные PDB/JIT случаи и некоторые WPP/TMF, dump/heap форматы
не поддерживаются. Некоторые временные интервалы могут иметь
погрешность до нескольких секунд. Файлы исследуемых приложений
не выполняются во время офлайн-декодирования. EXE не подписан.

Скачайте `BLACK.BOX-Universal-Windows.zip` и распакуйте целиком.
Запускайте `BLACK.BOX-Universal.exe`; сохраняйте папку `_internal`,
`decoder` и `BLACK.BOX-Maintenance.exe` рядом. Python и .NET
отдельно устанавливать не нужно.

Обратная связь: DonJeoJesky@outlook.com.

## English

This release integrates the trace decoder completion patch on top of
v0.5.1. Offline trace/session clock evidence review now supports
implementation-aware bounded windows for Windows QPC and GetTickCount64,
with explicit per-event uncertainty and no invented synchronization.
Typed native ETW CSwitch/ReadyThread observations support conservative
off-CPU and ready-delay reports. Local MSF7 PDB decoding adds source
line/checksum, inline and OMAP support while preserving raw addresses.
Import adds total wall-clock deadlines, explicit memory/disk/event
limits, reliable cancellation, source rehash and no-clobber publication.

The exact development source `7469dbe74154539ea58816306aba748976b863b1`
passed all four jobs in [CI #40752408448](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40752408448),
including real trace and third-party 7-Zip, PowerShell 7 and Notepad++
acceptance. Official publication requires a **new full CI run on the
integrated main SHA**, verifying both portable binaries and genuine
v0.5.1→v0.5.2 update/uninstall. The old v0.5.1 tag and assets are retained.

Limits: missing evidence stays unknown; sample counts are not CPU
percentages, GC elapsed is not a pause, and scheduling does not prove
a lock owner or root cause. Portable PDB and arbitrary managed JIT
native-IP-to-IL recovery remain unsupported. This is GitHub-hosted
Windows acceptance, not physical Win10/11 or a completed 5h30/8h
endurance test. The EXE remains unsigned; no automatic symbol downloads,
telemetry upload or capture are added.

Extract the full Windows ZIP, launch `BLACK.BOX-Universal.exe`,
and keep `_internal`, `decoder`, and Maintenance alongside it.
No separate Python or .NET installation is required.
Feedback: DonJeoJesky@outlook.com.
