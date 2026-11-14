# BLACK.BOX Universal v0.6.1 — Expert workflow and evidence integrity

This document is the release candidate's notes until a separately verified public GitHub release `v0.6.1` exists. The immutable previously published `v0.6.0` release and its ZIP/digest remain unchanged. A branch or green CI alone does not publish the Windows build.

## Русский

- Улучшен маршрут **Процессы → Начать наблюдение → Stop → РЕЗУЛЬТАТ → Отчёты**. Новая кнопка «РЕЗУЛЬТАТ» (`Ctrl+Shift+R`) явно открывает завершённую запись; Stop сам не меняет страницу.
- «Отчёты» показывают источник, папку, PID/время создания, выбранный диапазон, состояние доказательств и ограничения. Переходы к шкале, находкам, библиотеке, действиям/SDK и сравнению; `Ctrl+1…6` и поиск процессов `Ctrl+L`.
- Исправлены поздние async-ответы, точная идентичность сохранённого сеанса, bounded SQLite/JSON/ZIP, восстановление, владение Chain Builder и очистка native-ресурсов. Никаких автоматических вмешательств.
- Исправлена среда Python для Ubuntu-релизного authorizer: `blackbox_core` читается из `src`. Прежние одноразовые workflow v0.5.5 и v0.6.0 не пытаются повторно публиковать существующие/неактуальные версии.
- Исправлены факты о публикации v0.6.0 в двух README и документации. Личное вступление и адрес обратной связи сохранены.

## English

- Explicit RESULT action after completed recording; `Ctrl+Shift+R` opens a saved session without automatically navigating on Stop.
- Source-safe Reports context, evidence/findings/Timeline/Library navigation, explicit compare/export and bounded presentation.
- Hardened native resource cleanup, async identity, saved evidence, SQLite/JSON/ZIP readback and Chain Builder contracts.
- A new guarded v0.6.1 GitHub-hosted release workflow fixes the Ubuntu authorizer import path; legacy one-shot workflows remain fail-closed.

## Release validation policy

Only a normal, owner-approved main merge with the exact release-source SHA, 11/11 GitHub-hosted Windows/Linux/native/portable source CI, UI checks and new postmerge exact-main CI can authorize publication. The Windows release job must independently build/test actual R10–R60, native ETW/EventPipe and packaged helpers, pass all three 7-Zip/PowerShell7/Notepad++ trials, verify the upgrade from **official v0.6.0** and full uninstall, verify the exact ZIP inventory, report and SHA-256 sidecar, and publish only through an authenticated verified draft ID.

The earlier R60 331-call / >=19,800-second and independent base-GUI 5.5h Standard/1h Detailed recording receipts remain bound to original `f3c4078...` source. Their use for this patch requires an independently checked, exhaustive source-diff qualification showing no changes to the sampler, recording, scheduler, helper or native resource ownership. The exact-source 1-hour Standard/Incident Burst CI is rerun; no new 5.5-hour run is inferred or claimed.

Physical Windows 10/11, Secure Desktop UAC, arbitrary 8-hour continuous operation, Authenticode reputation, full licensing audit, complete event-loss tracking, and universal leak freedom are **NOT_VERIFIED**. Imported evidence and temporal coincidence do not establish causality. Previous public [v0.6.0](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/tag/v0.6.0) stays immutable.
