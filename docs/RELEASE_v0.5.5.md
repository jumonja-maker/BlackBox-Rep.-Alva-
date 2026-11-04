# BLACK.BOX Universal v0.5.5 — One-UAC Administrator Session (R10)

This version delivers the owner-approved R10 diagnostic container on top of v0.5.4.
Source code and green CI alone do not publish an update: v0.5.5 is available
only after the public GitHub Release contains the independently verified
Windows ZIP and its SHA-256 checksum sidecar.

## Русский

- **Верхняя кнопка «Включить права администратора».** Запрос системного UAC
  только по выбору пользователя; основной GUI остаётся asInvoker.
- **Одна повышенная сессия до 900 секунд** для нескольких последовательно
  выбранных процессов. Один проверенный ограниченный Diagnostic Helper
  используется повторно без нового UAC внутри исходного срока.
  Для каждого процесса заново проверяется PID + Windows creation FILETIME,
  право и согласие. Каждое вмешательство отдельно подтверждается.
- **Подтверждение очистки и фактических результатов.** Если результат
  вмешательства или завершение контекста неизвестны, программа сохраняет
  CLEANUP_REQUIRED / RECOVERY_UNCONFIRMED, а не скрытый повтор и ложный PASS.
- **ToolDescriptor, RunContext и RunReceipt v1** дополняют существующий
  InspectorService/журнал; не создают второй движок или несовместимые
  SQLite/JSON/HTML форматы.
- Сохранены OBSERVE, Deep Inspection, Trace Decoder, Investigation Engine 3,
  user-owned локальные сеансы, обновление и удаление.

## English

- An explicit top-toolbar administrator-session control.
- One real, time-bounded elevated Diagnostic Helper for sequentially chosen,
  separately authorized process instances without redundant UAC prompts.
- Exact target identity, action-specific consent, native token checks and
  recovery evidence remain mandatory. Unknown outcomes are not retried.
- Versioned tool execution receipts preserve actual status, provenance,
  coverage, uncertainty and cleanup limitations in the existing journal.

## Download and verification

Official releases: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases

Verify BLACK.BOX-Universal-Windows.zip against the separate published
BLACK.BOX-Universal-Windows.zip.sha256 before fully extracting. This package
is built only on free GitHub-hosted Windows runners after the required
exact-main-source Windows, Linux, GUI, ETW, decoder and real R10 two-process
native tests, frozen Portable EXE/Helper, v0.5.4-to-v0.5.5 update/uninstall,
distribution inventory and ZIP/provenance/digest checks. No GitHub Actions
Artifacts upload or download is used.

## Explicit limitations

- Physical Windows 10/11 interactive UAC Secure Desktop: **NOT_TESTED**.
  The real Windows elevated token and owned native operations are tested on
  GitHub-hosted Windows, but not a physical user's Secure Desktop.
- Binaries are unsigned; no Windows SmartScreen reputation guarantee.
- Administrator permissions do not bypass Windows PPL/protected processes.
- Full external app/driver/Windows policy, Standard/Admin and 5h30 endurance
  matrices are not claimed.
- No automatic proof of the underlying cause of a third-party crash or hang;
  sources and inference limitations stay visible.
- Third-party license coverage review is still required, including native
  redistribution and Qt obligations (licenseCoverageReviewRequired).

R10 usage: docs/R10_RU.md
R10 specification: docs/specifications/R10.md
Investigation Engine 3: docs/BB_INV_003_RU.md
Validated development PR: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/30
