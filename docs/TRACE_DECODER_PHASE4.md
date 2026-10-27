# BLACK.BOX Trace Decoder — Phase 4: capture-side QPC evidence

**Status:** development only, direct `main`. No GitHub Release, new recording
service, automatic investigation, or change to the ordinary sampling cadence.

## What is implemented

- When the owner **explicitly** enables ETW/WPR or EventPipe capture, its
  existing, bounded guardian also reads a few clock snapshots around tool
  activation and completion. No new background timer or target injection.
- On Windows each snapshot records `QueryPerformanceCounter` before/after
  `time.time_ns()`, the outer `time.monotonic_ns` bracket, the native
  `QueryPerformanceFrequency`, measured bracket widths, and owner PID.
  For other platforms the record is explicitly `WINDOWS_QPC_UNAVAILABLE`.
  A wide or failed bracket is **not** silently assigned zero uncertainty.
- ETW journaling retains labelled points `before_tool_start`,
  `after_tool_start`, `before_tool_stop`, `after_tool_stop`. EventPipe
  journaling retains `before_tool_spawn`, `after_tool_spawn` and
  `after_tool_exit`. Capture failure and owner exit do not certify the
  presence of complete anchors.
- Completed opt-in EventPipe traces now also have a locally calculated
  `result.sha256`, which can be compared to the decoder's source hash.
  The existing ETW guardian already wrote `result.sha256`.
- The Trace Decoder has a **manual** button **CHECK CAPTURE CLOCK… /
  ПРОВЕРИТЬ ЧАСЫ ЗАПИСИ…**. After decoding a matching captured
  `.etl`/`.nettrace`, the user may select the corresponding
  `*.trace.json` journal. BLACK.BOX checks that the decoder and
  journal agree on source format and SHA-256, that capture completed,
  and that **all required capture stages** have valid QPC/monotonic
  brackets, consistent owner and frequency, ordered observations and no
  gross QPC/monotonic or UTC elapsed-time disagreement. Missing middle
  stages fail closed; the checks do **not** certify calibrated clocks.
- New imports also summarize the validated extrema and coverage of original
  TraceEvent `source_ticks` counters without retaining a second complete
  event scan. The manual journal review can now reject numeric trace QPC
  counters outside the guardian's outer capture brackets. Numeric agreement
  is a **necessary sanity check only**, never independent same-boot evidence,
  time-scale calibration, or causal attribution. Older indexes and missing
  source counters clearly report `NOT_ASSESSED` / `NO_TRACE_QPC_COUNTERS_RECOVERED`.
  Re-import the source to obtain the new extrema.
- A successful review is named
  `HASH_MATCHED_QPC_BRACKETS_UNVERIFIED`, **not `CLOCK_SYNCED`**.
  Every review (even the positive case) reports
  `trace_to_blackbox_session_clock_alignment: NOT_ESTABLISHED`.
  These JSON journals are editable and do not attest the source machine,
  boot ID, PID identity, accuracy of system UTC, provenance of trace
  events, or the session's timestamps.
- Phase 3's trace UTC `decoder-index/3` remains unchanged; old saved
  session schemas, indexes v1/v2 and existing decoder modes are not
  migrated or rewritten.

## Почему это пока не автоматическая синхронизация

Снимки сделаны **около** запуска/завершения WPR и dotnet-trace, но не в
точности на первом/последнем ETW/EventPipe-событии. По одним этим
данным нельзя удостоверить общее время загрузки ОС, точный
процессный экземпляр и преобразование шкал с гарантированной погрешностью.
Даже одинаковый SHA-256 в локальном журнале и индексе не является цифровой
подписью: оба файла могут быть заменены.

Кроме того, сохранённый сеанс schema-v2 имеет отдельную базовую
монотонную/UTC опору. Этот этап НЕ вычисляет смещение EventPipe/ETW
относительно неё и НЕ объединяет потоки данных в единую доказанную
временную шкалу. Измеренное QPC в журнале — только необходимые
дополнительные данные для будущего, более строгого анализа.

**Поэтому недопустимо утверждать, что совпавший QPC/UTC доказывает
причину GC, зависания окна или активности другого процесса.**

## Validation / Регрессионные тесты

- `tests/test_trace_clock_evidence.py`: adversarial fixtures for
  missing/modified intermediate stages, malformed JSON root, coarse QPC versus
  monotonic/UTC disagreement, source mismatch, non-monotonic anchors, unsupported
  OS, and a complete EventPipe chain. Negative evidence rejects alignment;
  agreement is never attestation.
- `tests/test_trace_guardian.py`: ownership guardian really records
  labelled clock brackets during a synthetic capture without causing
  target/recorder side effects.
- `tests/test_managed_runtime_fixture.py`: when local
  `dotnet-trace` and SDK are present, a real opt-in EventPipe capture
  checks `result.sha256` and guardian bracket markers.
- On the disposable Windows portable runner, CI installs Microsoft's
  `dotnet-trace` **10.0.750501** into a CI-local directory. The actual
  guardian captures a controlled .NET test process, the built TraceEvent
  helper decodes the produced `.nettrace`, and QA checks source SHA-256
  before/after decode and the full 3-stage QPC journal. The result still
  reports `NOT_ESTABLISHED` alignment and `UNKNOWN` capture completeness.
- When WPR and administrative privileges exist on that runner, a separately
  named, time-bounded real WPR ETL capture is also decoded; QA compares its
  original hash to the guardian journal and checks all four QPC stages.
  Unsupported WPR is marked `NOT_AVAILABLE_NO_WPR_OR_ADMIN`, not success.
  The independent Windows shell raw-capture TTL test remains unchanged.
- `tests/test_decoder_gui.py`: RU/EN manual journal review and
  disabled review when a replacement trace fails.
- `tests/test_decoder_index.py`: reject malformed signed QPC strings
  even when the UTC projection is absent; no partial index is published.
- `tests/test_trace_clock_evidence.py`: positive and negative trace-source
  QPC-range review and explicit missing-counter coverage.
- `tools/qa_decoder.py`: real Windows EventPipe/WPR captures now require
  nonempty validated source-counter coverage and numerical containment
  within the guardian's capture window. This is an offline sanity check
  only, not evidence of shared boot or calibrated clock alignment.
- `tests/test_decoder_gui.py`: the RU/EN status line retains the last
  manual clock review verdict for the loaded index and clears it when a
  different trace is opened, including after failed import.
- `tests/test_process_history_tree.py`: the intentionally delayed SQLite writer
  QA fixture has a longer **test-only** completion deadline; production's
  five-second durability barrier and fail-closed status remain unchanged.
- Existing Windows/Linux/PySide6 and portable EXE suites remain mandatory.
  An Actions runner is NOT independent physical Windows 10/11, sensor
  calibration, signed provenance or full acceptance of runtime clocks.

## Future, not implemented

Before calling any trace and session "aligned" the pipeline needs
strict proof that the QPC source and session monotonic clock share the
same epoch/frequency/boot; stable process-instance identity; unmodified
source/manifest binding; brackets at suitable capture events, explicit
uncertainty/drift budgets and fail-closed mixed-source checks. A future
design may display **tentative UTC proximity**, clearly distinguished
from a verified monotonic join.

Previous stages: [Phase 1](TRACE_DECODER_PHASE1.md) ·
[Phase 2](TRACE_DECODER_PHASE2.md) ·
[Phase 3](TRACE_DECODER_PHASE3.md).
