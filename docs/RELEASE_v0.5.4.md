# BLACK.BOX Universal v0.5.4 — Evidence Graph & Guided Diagnostics

Owner-approved BB-INV-003 functionality, released only after exact-SHA hosted
CI on main, a freshly built and verified portable ZIP, and independently
verified GitHub Release asset size and SHA-256. GitHub Actions Artifacts
storage is not used for this publication.

## Русский

- Evidence Graph: связи сохранённых событий, потоков, модулей, стеков и
  инцидентов с явными источниками и границами достоверности.
- Частичный Critical Path Analyzer: RUNNING, BLOCKED, READY, UNKNOWN,
  INCOMPLETE без придумывания потерянных событий.
- Детерминированные гипотезы с подтверждениями, противоречиями,
  альтернативами и недостающими данными.
- Ручная проверка ДО → ДЕЙСТВИЕ → ПОСЛЕ → СРАВНЕНИЕ через
  существующий ограниченный Diagnostic Helper и отдельное согласие.
- Группировка повторяющихся случаев, осторожное сравнение запусков
  и переходы к исходным данным в Trace Decoder / Deep Inspection.
- Сохранены шесть основных вкладок, прежние форматы и local-first
  без обязательного AI, облачного сервера или скрытой телеметрии.

Проверки: точный исходный BB-INV-003 прошёл 10/10 GitHub-hosted QA,
а независимый artifactless CLMAX — 11/11 на том же функциональном
коде. Для опубликованного SHA отдельно проверяются main CI, сборка,
нативные сценарии, переносимый EXE, обновление/удаление и состав ZIP.

**Границы:** физические Windows 10/11 и интерактивный UAC Secure Desktop
не проверены; stress 250k графа основан на синтетическом формате;
полный 5ч30 endurance не повторялся, поскольку патч не изменяет
жизненный цикл sampler/helper; все кнопки нового GUI внутри frozen
EXE не покрыты одним общим clickthrough-тестом. Нельзя автоматически
установить внутреннюю причину произвольного сбоя.
User-controlled Chain Builder не входит в этот выпуск.

EXE не подписаны. Qt и сторонние бинарные зависимости требуют
отдельного анализа условий распространения; наличие скопированных
текстов лицензий не является полной юридической сертификацией.

## English

Investigation Engine 3 adds a bounded read-only evidence graph,
source-backed partial critical paths, conservative hypotheses,
user-stepped BEFORE/ACTION/AFTER/COMPARE and issue grouping.
Missing identity, clock, source coverage or unverified imports are
never upgraded into unsupported causal claims.

Hosted CI only: native Windows ETW/EventPipe, controlled file/CPU/wait
fixtures, Qt RU/EN/DPI, portable EXE, update/restart/uninstall and
verified final ZIP inventory. No physical Windows 10/11 or interactive
Secure Desktop certification; no arbitrary root-cause guarantee.
The bundled third-party notices are not a complete legal audit of
all native redistribution conditions. Artifacts are delivered as
GitHub Release assets, not GitHub Actions Artifacts.

Documents:
- https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/blob/main/docs/BB_INV_003_RU.md
- https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/blob/main/docs/BB_INV_003_EN.md
- https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/27
