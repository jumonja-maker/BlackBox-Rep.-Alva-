# BLACK.BOX Universal v0.6.0 — UNPUBLISHED DEVELOPMENT CANDIDATE

This document describes the cumulative v0.6.0 source/development candidate across R10–R60 and the expert workflow patch. It is not a published Release, a publication authorization or evidence that every acceptance gate below passed. The latest published GitHub Release verified for this patch is v0.5.4; no published v0.6.0 package was found. The intermediate v0.5.5 was not published. Candidate/source version numbers do not determine updater availability.

**Статус: неопубликованный кандидат разработки.** Ни список возможностей, ни план проверок ниже не подтверждают публикацию v0.6.0. Точные результаты текущего патча должны сопровождаться SHA и ссылками на фактический CI в отдельном отчёте; опубликованный комплект определяется только GitHub Releases.

## Русский

- **R10 — диагностические действия с ограниченным админ-сеансом.** Основной GUI не получает постоянное повышение прав. У каждого действия — отдельное подтверждение пользователя и проверка экземпляра процесса (PID и creation FILETIME); неизвестное вмешательство или очистка не превращается в ложный успех.
- **R20 — происхождение доказательств и управление ресурсами.** Независимые идентификаторы источников, проверяемые записи и экспорт, безопасное владение процессами и отмена.
- **R30 — зависания, ожидания и файловый I/O.** Windows Wait Chain, FileIO/DiskIO и Critical Path с явными границами достоверности.
- **R40 — расследование аварий.** Сохранённые minidump, PE/PDB, стеки AMD64 и исходные строки там, где они доступны и проверены.
- **R50 — инциденты и сравнения.** IncidentCapture, Standard и Incident Burst, сохранённые эксперименты и явные результаты COMPARABLE/NOT_COMPARABLE/INCONCLUSIVE.
- **R60 — Chain Builder.** Управляемые пользователем диагностические цепочки с типизированными узлами, профилями, графом, условными ветками, контролем прав и ресурсов, сохранением/продолжением, отчётами и реальными адаптерами инструментов. Цепочки не запускаются автоматически при открытии.
- **Рабочий процесс специалиста.** Явный переход «РЕЗУЛЬТАТ» («Открыть результат записи», Ctrl+Shift+R) после завершения; папка/диапазон открытого анализа и переходы к разделам в «Отчётах»; копирование контекста в локальный буфер; навигация Ctrl+1…6 и поиск Ctrl+L. Существующие инструменты и полные технические свидетельства сохранены.
- **Только локальная работа и осознанный контроль.** Никакого скрытого сбора, обязательного облачного сервиса или автоматического вмешательства в выбранные процессы.

## English

- **R10:** Explicit, time-bounded administrator session and separate action/target consent; never elevate the entire UI.
- **R20:** Source identity, evidence provenance, resource ownership, lossless saved outputs and conservative cleanup.
- **R30:** Waits, FileIO, DiskIO and critical-path diagnostics with explicit incomplete evidence.
- **R40:** Saved minidump, PE/PDB, AMD64 stack and bounded symbol/source-line analysis.
- **R50:** IncidentCapture, structured comparisons and saved experiment evidence.
- **R60:** Chain Builder: typed diagnostic DAG editor, real adapters to existing engines, profiles, guarded actions, bounded scheduling, checkpoint/recovery, export and independent read-back.
- **Expert workflow patch:** Explicit post-recording RESULT action (Open recording result, Ctrl+Shift+R), visible analysis folder/range, Reports section navigation, local context copy, Ctrl+1…6 page navigation and Ctrl+L process search. Existing tools and full technical evidence remain available.

## Intended package and verification gates

The following asset names and checks are a release plan, not a claim of published assets or completed acceptance. Intended stable release asset names:
- BLACK.BOX-Universal-Windows.zip
- BLACK.BOX-Universal-Windows.zip.sha256

Verify the SHA-256 in the checksum sidecar against the ZIP before extracting.
Any official ZIP must be built from one pinned source SHA by GitHub-hosted Windows
runners and verified to contain the GUI, maintenance EXE, diagnostic helper, self-contained
TraceEvent decoder, license notices and verified distribution inventory.

A future authorized release gate must check exact commit/tree and embedded version 0.6.0, exact
ZIP file inventory and hashes, real release-upgrade/uninstall from the immutable
v0.5.4 baseline, and strict release-asset identity and server digests. Previous
official release v0.5.4 remains unchanged.

The intended cumulative release acceptance includes full Windows/Linux/native/frozen/GUI/ETW,
real third-party applications, SHA and read-back, 250k decoder reliability,
R10 and R20–R50 regression, R60 source/frozen diagnostic graphs, and the
mandatory 331-call/19,800-second R60 scheduler and recording endurance
on the exact approved release candidate, followed by full exact-main CI.
Do not infer completion of these gates from this document. The expert workflow patch
uses its isolated hosted checks and exact-commit CI evidence; it does not independently
claim that cumulative release publication or every historical acceptance gate completed.

## Explicit limitations / Ограничения

- Physical Windows 10/11 on customer hardware, interactive UAC Secure
  Desktop, separate real Standard account, and all drivers: NOT_TESTED.
  Hosted native Windows QA is real but is not physical field acceptance.
- Binaries are unsigned; no Authenticode/SmartScreen reputation guarantee.
- PPL/protected processes remain inaccessible where Windows denies access.
- Imported traces may have unknown loss, clocks, symbols or trust.
  SHA-256 confirms byte identity, not trusted source origin.
- Any verified R60 endurance result applies only to its recorded source SHA,
  tested 5h30 scenario and cleanup; it does not establish universal leak freedom
  or 8-hour production behavior. This note is not evidence of a new endurance run.
- Chain Builder does not infer causation without direct supporting evidence.

User workflow: [English](USER_GUIDE_EN.md) · [Русский](USER_GUIDE_RU.md) · [Границы патча](EXPERT_WORKFLOW_PATCH_RU.md)

Project: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-
