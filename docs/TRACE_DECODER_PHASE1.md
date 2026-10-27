# BLACK.BOX Trace Decoder — phase 1, MAIN development build

**Historical phase-1 contract.** Current MAIN development uses decoder-index/2
for derived CPU-sample stack groups and GC generation statistics. See
[Phase 2](TRACE_DECODER_PHASE2.md). This is not an official Release.

This is a development patch, NOT an official new release. The owner explicitly
requested direct MAIN delivery and no release/tag without a separate command.
The existing manual release gate remains unchanged and is not dispatched.

## Реализованный первый этап

Шестая страница **06 ДЕКОДЕР ТРАСС / TRACE DECODER** открывает `.etl`, `.nettrace`
и JSONL событий BLACK.BOX. Открытие файла не запускает запись или наблюдение.
Тяжёлый бинарный разбор выполняется в отдельном self-contained .NET процессе;
пользователь portable-сборки не должен устанавливать .NET отдельно.
Python-адаптер создаёт отдельный SQLite-индекс, не изменяя базы наблюдения.
Список событий постраничный (200 строк), а не обрезанный 500-строчный результат.
Есть фильтр PID, буквальный поиск по провайдеру/событию и видам интервалов,
просмотр записанных кадров стека, полей события и GC-интервалов, отмена
операции, открытие файла из папки текущего сеанса и сохранение индекса.
Открытие нового файла очищает старую таблицу: ошибка декодирования не выдаёт
результаты прошлой трассы за новые.

The primary backend is the unmodified Microsoft.Diagnostics.Tracing.TraceEvent
NuGet package, pinned to **4.0.0**. The helper converts a private input snapshot
into a scratch ETLX with KeepAllEvents=true / ContinueOnError=false, then exports
versioned JSONL. Native ETL decoding requires Windows. No PDB, source or symbol
server download is initiated. Available method names come from recorded metadata
and local engine behavior; an empty or partial frame name is not fabricated.
The original trace remains unchanged, with SHA-256 checked before and after.

## What the BLACK.BOX adapter adds

- A strict `blackbox.trace-event/1` protocol with header, consecutive event IDs,
  input hash and mandatory completion footer; failed/partial child output cannot
  be certified as a completed index.
- A separate `blackbox.decoder-index/1` SQLite schema, indexed pagination and
  explicit quality/loss/clock fields. Imported sources remain UNVERIFIED_IMPORT.
- Pairing of typed GC events by trace process instance, PID, CLR instance and GC
  number. Duplicate starts, missing ends and ambiguous identity remain incomplete.
- `GC_ELAPSED_NOT_PAUSE`: collection start/stop elapsed time, **not** application
  stop-the-world time. `RUNTIME_SUSPENSION_ENVELOPE` includes suspend/resume work;
  `RUNTIME_FULLY_SUSPENDED` requires all four ordered suspension/restart phases.
  Runtime suspensions are not automatically attributed to GC or a user incident.
- An independent adapter for BLACK.BOX schema-1 application JSONL. Tokens are
  removed. Distinct observed writer tokens are mapped to anonymous in-memory
  producer IDs, so two writers reusing the same PID/clock do not share a false
  time origin. The token is never written into the index and is NOT proof of
  writer authenticity. When absent, producer identity remains explicitly
  ambiguous. No per-producer clock is assumed aligned with another clock.
- Literal, bounded provider/name/interval-kind search over SQLite keyset pages.
  Search never interprets user-written % or _ as SQL wildcards.

## Budgets and limits — do not overstate this patch

Input <=256 MiB; output <=approximately 384 MiB; <=250000 events; up to 32 decoded
payload fields and 128 recorded stack frames per event. Limits are visible as
TRUNCATED/BOUNDED/errors, not loss=0. Native helper time is bounded, managed heap
has a 1 GiB limit; total RSS (1.5 GiB) and scratch disk (1 GiB) are polled soft
limits. Windows Job ownership / POSIX process groups clean up only owned helpers.
Process isolation is NOT an OS security sandbox. Parsing untrusted binary traces
still depends on upstream decoder correctness. Cancel/close must drain workers.

`DECODED` means the accepted TraceLog projection was indexed, **not** that every
provider has a schema or that capture had zero loss. The decoder's own reported
loss counter is kept separately; total capture completeness remains unknown.
Trace-relative time is not calibrated to BLACK.BOX session monotonic time.
Generic unknown-provider fields, WPP/TMF, custom manifest installation, symbol
servers, arbitrary formats, native dump analysis/ClrMD, full GC heap analysis,
CPU flame graphs and automatic causal investigation are not implemented here.
The existing tracerpt header-only decoder remains as a compatibility operation.
The legacy five-page UniversalWindow embedding API is unchanged; app.py and DPI
QA use the new six-page DecoderWindow. No new collectors or sampling changes.

## Build / use

From the source checkout (Python requirements installed and .NET 10 SDK available):

    python tools/build_decoder.py --rid win-x64
    python app.py

On Linux use `--rid linux-x64` (EventPipe/JSONL only, not Windows ETL).
Source-only users can import JSONL without the helper. Missing helper is explicit,
never reported as decoded. Portable CI includes the entire decoder/ folder; keep
it next to BLACK.BOX-Universal.exe. Download the Windows artifact of the MAIN CI,
not the older official Release. A branch ZIP is source code, not a Windows EXE.

## Verification

Unit tests use synthetic fixtures only to test protocol/GC/cancellation contracts.
`tools/qa_decoder.py` builds and RUNS an actual .NET EventSource workload with
runtime EventPipe recording, 12 distinct custom payload values, forced GCs and
sampling. It requires real payloads, GC pairs and recorded stacks after decoding.
On disposable Windows CI it additionally records a uniquely-owned ETW fixture
and requires all 12 provider events through TraceEvent, not tracerpt. It rejects
invalid nettrace bytes and verifies the original file hash is unchanged.
The frozen smoke requires a functioning packaged helper and all six pages.
Source tests, native .NET/ETL tests and frozen packaging evidence are distinct;
none substitutes for physical Win10/11, accessibility or full diagnostic acceptance.

## Upstream references and licensing

- https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/4.0.0
- https://github.com/microsoft/perfview
- https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventProgrammersGuide.md
- https://learn.microsoft.com/dotnet/core/diagnostics/eventpipe
- https://learn.microsoft.com/dotnet/fundamentals/diagnostics/runtime-garbage-collection-events

TraceEvent uses MIT. The build inventories resolved package versions/SHA-512 and
retains package license declarations/files, application license and per-file
SHA-256 in decoder/notices and decoder-manifest.json. Redistribution includes the
self-contained .NET runtime as well; all its applicable notices must accompany it.
