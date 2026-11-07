# BLACK.BOX Universal v0.6.0 — Cumulative R10–R60 / Chain Builder

This is the first cumulative public release after v0.5.4. It integrates owner-approved and independently tested improvements across R10, R20, R30, R40, R50 and R60. The intermediate v0.5.5 was never published: this release is the complete cumulative build, not a revival of the earlier R10-only authorization.

## Русский

- **R10 — диагностические действия с ограниченным админ-сеансом.** Основной GUI не получает постоянное повышение прав. У каждого действия — отдельное подтверждение пользователя и проверка экземпляра процесса (PID и creation FILETIME); неизвестное вмешательство или очистка не превращается в ложный успех.
- **R20 — происхождение доказательств и управление ресурсами.** Независимые идентификаторы источников, проверяемые записи и экспорт, безопасное владение процессами и отмена.
- **R30 — зависания, ожидания и файловый I/O.** Windows Wait Chain, FileIO/DiskIO и Critical Path с явными границами достоверности.
- **R40 — расследование аварий.** Сохранённые minidump, PE/PDB, стеки AMD64 и исходные строки там, где они доступны и проверены.
- **R50 — инциденты и сравнения.** IncidentCapture, Standard и Incident Burst, сохранённые эксперименты и явные результаты COMPARABLE/NOT_COMPARABLE/INCONCLUSIVE.
- **R60 — Chain Builder.** Управляемые пользователем диагностические цепочки с типизированными узлами, профилями, графом, условными ветками, контролем прав и ресурсов, сохранением/продолжением, отчётами и реальными адаптерами инструментов. Цепочки не запускаются автоматически при открытии.
- **Только локальная работа и осознанный контроль.** Никакого скрытого сбора, обязательного облачного сервиса или автоматического вмешательства в выбранные процессы.

## English

- **R10:** Explicit, time-bounded administrator session and separate action/target consent; never elevate the entire UI.
- **R20:** Source identity, evidence provenance, resource ownership, lossless saved outputs and conservative cleanup.
- **R30:** Waits, FileIO, DiskIO and critical-path diagnostics with explicit incomplete evidence.
- **R40:** Saved minidump, PE/PDB, AMD64 stack and bounded symbol/source-line analysis.
- **R50:** IncidentCapture, structured comparisons and saved experiment evidence.
- **R60:** Chain Builder: typed diagnostic DAG editor, real adapters to existing engines, profiles, guarded actions, bounded scheduling, checkpoint/recovery, export and independent read-back.

## Package and verification

Official stable release assets:
- BLACK.BOX-Universal-Windows.zip
- BLACK.BOX-Universal-Windows.zip.sha256

Verify the SHA-256 in the checksum sidecar against the ZIP before extracting.
The ZIP is built from one pinned source SHA by free GitHub-hosted Windows
runners; it contains the GUI, maintenance EXE, diagnostic helper, self-contained
TraceEvent decoder, license notices and verified distribution inventory.

The release gate checks exact commit/tree and embedded version 0.6.0, exact
ZIP file inventory and hashes, real release-upgrade/uninstall from the immutable
v0.5.4 baseline, and strict release-asset identity and server digests. Previous
official release v0.5.4 remains unchanged.

Release acceptance includes full Windows/Linux/native/frozen/GUI/ETW,
real third-party applications, SHA and read-back, 250k decoder reliability,
R10 and R20–R50 regression, R60 source/frozen diagnostic graphs, and the
mandatory 331-call/19,800-second R60 scheduler and recording endurance
on the exact approved release candidate, followed by full exact-main CI.

## Explicit limitations / Ограничения

- Physical Windows 10/11 on customer hardware, interactive UAC Secure
  Desktop, separate real Standard account, and all drivers: NOT_TESTED.
  Hosted native Windows QA is real but is not physical field acceptance.
- Binaries are unsigned; no Authenticode/SmartScreen reputation guarantee.
- PPL/protected processes remain inaccessible where Windows denies access.
- Imported traces may have unknown loss, clocks, symbols or trust.
  SHA-256 confirms byte identity, not trusted source origin.
- The R60 endurance proves the tested 5h30 scenario and its cleanup, not
  universal leak freedom or 8-hour production behavior.
- Chain Builder does not infer causation without direct supporting evidence.

Project: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-
