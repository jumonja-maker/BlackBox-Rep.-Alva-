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
  and that first/last native QPC and monotonic brackets are
  structurally consistent.
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

- `tests/test_trace_clock_evidence.py`: 7 adversarial fixtures
  (bracket width, bool/negative/overflow, hash mismatch, missing/modified
  clocks, source type mismatch, non-monotonic anchors, unsupported OS).
- `tests/test_trace_guardian.py`: ownership guardian really records
  labelled clock brackets during a synthetic capture without causing
  target/recorder side effects.
- `tests/test_managed_runtime_fixture.py`: when local
  `dotnet-trace` and SDK are present, a real opt-in EventPipe capture
  checks `result.sha256` and guardian bracket markers.
- `tests/test_decoder_gui.py`: RU/EN manual journal review and
  disabled review when a replacement trace fails.
- `tests/test_decoder_index.py`: reject malformed signed QPC strings
  from untrusted intermediate JSONL; no partial index is published.
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
