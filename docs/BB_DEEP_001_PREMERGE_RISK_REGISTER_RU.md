# BB-DEEP-001 — предынтеграционный реестр рисков (RU)

**Статус:** исправления подготовлены в `patch/bb-deep-001`; приёмка требует нового
GitHub-hosted CI на точном head SHA. Это не разрешение на merge или Release.
База: опубликованный `main` v0.5.2 `3d69cc032582529b5b0533d1318279e2ea30cad1`.
Исходный PR #26: `8a63669d2c93ca430319095daed09cb8c19f80c7`.
Изолированный baseline run: `40935239740`, 8/8 успешных jobs.

## Устраняемые блокеры

| ID | Приоритет | Доказательство | Изменение | Gate |
|---|---|---|---|---|
| BB-DP-01 | P1 | Overview передавал 1 GiB, native `MAX_DUMP_BYTES` только 512 MiB | Единый лимит из native константы; normal/full GUI → Qt → helper → real dump и независимый oracle | `test_deep_inspector_gui`, `qa_deep_gui_e2e` source+frozen helper |
| BB-DP-02 | P1 | `DebugSession._cleanup` при `NO_CONFIRMED_STOP_FOR_CLEANUP` мог восстановить trap bytes и TF без наблюдаемого stopped event | При собственных эффектах отсутствие подтверждённой остановки даёт `RECOVERY_UNCONFIRMED`, сохраняет owner/guardian/ledger и отказывается изменять контекст/байты/производить detach | `test_deep_debug` fail injection + real native QA |
| BB-DP-03 | P1 release | В `main` уже выпущена v0.5.2; PR не менял version | Подготовлен уникальный кандидат 0.5.3, новый release input/gate/notes, сохранена v0.5.2 | version consistency и official 0.5.2 → candidate 0.5.3 maintenance QA |
| BB-DP-04 | P1 release | Изолированный run #40935239740: Windows full 4057 с, Linux full 1146 с; old `shell-qa.yml` caps 3900/1080 с | Main release workflow caps подняты до 90/40 минут без пропуска тестов | Full exact-merge-SHA `shell-qa.yml` |
| BB-DP-05 | P2 release | Старый `release_gate.py` не требовал Diagnostic Helper и проверял только decoder | Финальный ZIP проверяется по полному `DISTRIBUTION-INVENTORY.json`; diag EXE + внутренний provenance обязательны и сверяются с GUI; отсутствующие/добавленные/изменённые файлы запрещены | `test_release_gate`; отдельный ZIP gate в `bb-deep-qa.yml` |

## Остаточные риски, которые нельзя маскировать зелёным CI

1. **UAC Secure Desktop / другая учётная запись.** Windows hosted runner
   подтвердил HIGH/MEDIUM токены, но это не полноценный интерактивный UAC.
   Полнота физического сценария остаётся `NOT_ESTABLISHED`. Не обещать
   универсальное повышение и доступ к защищённым процессам.
2. **Debug crash / arbitrary RIP, TF.** Fail-closed предотвращает новое
   вмешательство без остановки; но принудительное завершение владельца
   в произвольной инструкции и окончание finite lease нельзя автоматически
   вернуть к первоначальному поведению. Не называть rollback гарантированным.
3. **Системные DiskIO.** Есть типизированные события, но не доказана
   физическая задержка именно контролируемого файла/потока. Сохранять
   отдельную атрибуцию и `INCOMPLETE_EVIDENCE`.
4. **Архитектуры/символы.** Native context/StackWalk поддерживает AMD64.
   WOW64/ARM64, произвольный JIT и Portable PDB ограничены отдельными
   explicit status, не подменять символы догадками.
5. **Дампы и память.** В полном дампе могут быть секреты; путь результата
   обычного пользователя, явное согласие, приватный журнал, отсутствие
   автоматического share — обязательны. 512 MiB — soft application budget,
   некоторые целевые процессы больше этого лимита.
6. **Временная привязка ETW.** Типизированные события не доказывают
   полноту записи, происхождение trace или общую временную шкалу.
7. **Различие source GUI и frozen GUI.** Qt real buttons проверяют
   настоящий источник + пакованный helper, full frozen GUI имеет smoke/
   research checks, но все кнопки Windows 10/11 не сертифицированы.
8. **Долговременная стабильность.** Изолированный 5h30 PASS старого SHA
   подтверждён, но новый engine SHA требует повторного hosted endurance.
   `[deep-endurance]` запускает его в `bb-deep-qa.yml`: 19 800 с записи,
   отдельный бюджет cleanup и upload artifact; не заявлять 8 часов.

## Минимальный gate перед слиянием

- Новый head SHA, branch/PR mergeable, отсутствие параллельных коммитов в main.
- Все Deep contracts, реальные native HIGH/MEDIUM, GUI dump normal/full,
  packaged helper, full Linux/Windows suites, ZIP manifest, official update
  и 5h30 continuous acceptance завершены SUCCESS на **одном точном SHA**.
- Отдельное independent review артефактов и ограничения `NOT_ESTABLISHED`.
- После слияния: новый main merge SHA → **новый** полный `shell-qa.yml`,
  успешная проверка zip/source tree/sha256 и *отдельное* разрешение выпуска.
- Никогда не переписывать предыдущий tag или asset v0.5.2.
- Никаких тестов на пользовательском компьютере. Автоматические тесты —
  исключительно GitHub-hosted machines.
