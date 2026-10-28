# BLACK.BOX Universal v0.5.0 — offline trace decoder

## English

This release integrates the complete saved decoder work from both Phase 5
packets, together with the earlier ETL/EventPipe/JSONL decoder stages.
The portable Windows ZIP contains the GUI, maintenance helper and a
self-contained Microsoft TraceEvent decoder; users do not need Python or .NET.

- Sixth RU/EN Trace Decoder page: events, recorded stacks, conservative GC
  intervals/statistics, UTC estimates and manual capture-clock evidence review.
- Trace-scoped native module observations and local PE/PDB GUID/Age checks.
  Supported Windows PDB procedure ranges can produce derived function names
  for individual recorded stacks or a complete selected sample tree.
- Separate .NET SampleProfiler and typed native ETW SampledProfile trees.
  Explicit PID, process-instance, thread and half-open time filters, cancellable
  analysis, and JSON or script-free HTML/SVG flame-view exports.
- DPC/ISR observations, missing or truncated stacks, ambiguous module bindings,
  unsupported PDB layouts and omitted samples remain visible or unresolved;
  they are not substituted with fabricated application CPU evidence.
- Immutable input traces/indexes, exclusive-created exports, bounded resources,
  safer capture cleanup and bilingual UI feedback. Contact: DonJeoJesky@outlook.com.

**Limits:** sample counts are not CPU percentages or execution duration. GC
elapsed time is not an application pause. Trace/session clock alignment remains
NOT_ESTABLISHED. A consistent local PDB match does not independently authenticate
the trace or files. Portable PDB, source lines, inline frames and unsupported
optimized/OMAP layouts are not claimed as supported. No automatic recording,
symbol-server download, telemetry upload or automated root-cause verdict.

The release workflow requires the exact approved main commit to pass full
Windows and Linux tests, actual frozen EXE checks, real EventPipe/WPR captures,
native ETW-to-PDB tree acceptance, and an official v0.4.2-to-v0.5.0 portable
update/uninstall test. It verifies frozen source provenance and every packaged
decoder file before publishing the ZIP and its SHA-256 sidecar. GitHub-hosted
checks do not replace physical Windows 10/11, antivirus/OneDrive, accessibility
or independent acceptance testing. The executable remains unsigned.

Download BLACK.BOX-Universal-Windows.zip, extract the entire folder and run
BLACK.BOX-Universal.exe. Keep _internal, decoder and the maintenance helper.
The previous v0.4.2 release and its assets are not replaced.

## Русский

Выпуск объединяет оба сохранённых пакета декодера и предыдущие этапы разбора
ETL/EventPipe/JSONL. В Windows ZIP входят программа, помощник обновления и
автономный Microsoft TraceEvent: устанавливать Python или .NET не требуется.

Шестая вкладка позволяет просматривать события и стеки, интервалы и сводки GC,
оценки UTC и свидетельства часов записи; проверять локальные PE/PDB; получать
производные имена функций; строить отдельные деревья CPU-выборок .NET и ETW.
Доступны фильтры по PID, экземпляру процесса, потоку и времени [от, до), отмена
анализа и экспорт JSON либо HTML/SVG flame graph без скриптов. Исходные файлы
и индекс не переписываются. Почта обратной связи: DonJeoJesky@outlook.com.

**Ограничения:** количество выборок — не процент CPU и не длительность работы.
GC elapsed — не пауза приложения. Синхронизация трассы с сеансом не доказана.
Неизвестные/обрезанные стеки, DPC/ISR, неоднозначные привязки и неподдерживаемые
PDB не превращаются в выдуманные результаты. Нет автоматического поиска причин
сбоя, записи трасс или скачивания символов. Portable PDB, строки исходников,
inline-кадры и неподдерживаемые оптимизированные/OMAP-разметки не заявлены.

Публикация выполняется только после полного CI точного согласованного коммита,
проверки настоящего EXE, трасс и обновления v0.4.2 → v0.5.0. Контрольные суммы
и происхождение файлов проверяются до публикации. Это не заменяет испытания
на обычных Windows 10/11 и проверку антивирусной совместимости/доступности.
Цифровой подписи EXE пока нет. Предыдущий релиз v0.4.2 остаётся доступным.
