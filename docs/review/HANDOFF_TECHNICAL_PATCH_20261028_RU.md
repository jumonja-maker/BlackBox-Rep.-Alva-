# Передача технического патча BLACK.BOX

Единый PR: https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/25

Проверенный кандидат: `da63ea85749e9b484eb4af088de61385eb6c4caf`.
Git tree: `6e219a0a8ff40c5a8ac4bfd779cab79b49a432b3`.
База: `765156068a2d2f0171be4d048e74c7676feba143`.
Ветка: `patch/technical-audit-20261028`.

[Полный отчёт](TECHNICAL_PATCH_20261028_RU.md) · [Машинная приёмка](evidence/technical-20261028/acceptance.json) · [Hash-манифест доказательств](evidence/technical-20261028/manifest.json).

## Что передаётся

Реализованные исправления всех десяти подтверждённых BB-01–10 и дополнительных перечисленных дефектов, с воспроизводителями и положительными контролями. Это исправление актуального main, не перенос старых незавершённых веток и не заявление о завершении исторического BB-DI-001.

- Ошибка необязательного индекса не обрывает основную запись.
- Default share-очистка охватывает скалярные TEXT, JSON и detail-v2; неизвестная схема не выдаётся за очищенную. Оригиналы сохраняются.
- Экспорт и UI используют один набор находок; выбранная серия, поздние комментарии и явное согласие на пользовательские заметки учитываются.
- Stop работает при Verify/Export; модальное согласие запускает ровно один повтор анализа; завершённые Qt workers освобождаются.
- CPU-profile search ищет значения кадров, а не служебные JSON-ключи.
- Исправлены завершение guardian, cleanup потомков и ошибка запуска optional operation.
- CI использует hash-locked Python wheels, pinned Actions и undefined-name gate. Старый автоматически пишущий в main импортёр выведен из эксплуатации.
- Portable содержит реальные notice texts и проверяемый inventory. Полная legal/native SCA не сертифицирована.

## Доказательства

Полный run https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40711406662 — SUCCESS: Windows source, Linux source и Windows portable; Release job SKIPPED. Отдельный UI run40711406642 — SUCCESS.

Windows: 714 testsRun, 706 PASS, 8 SKIP, 0 FAIL/ERROR. Linux: 705 testsRun, 688 PASS, 17 skipped testcases и ещё 2 class-level skip fixtures, 0 FAIL/ERROR. Все 7 новых capture-проверок исполнились на обеих ОС. Причины пропусков и корректный подсчёт классов есть в отчёте.

Реальные Windows portable smoke/research E2E/deep, STANDARD token без admin-привилегий, native decoder и controlled update/uninstall прошли. Независимо сверены 525 файлов окончательного portable, включая 217 decoder files; SHA и provenance совпали.

## Границы интеграции

Главная ветка и релизы этим патчем не изменены. Версия приложения не повышалась ради патча. Последующий commit с отчётом/evidence помечен [skip ci], чтобы не повторять весь build ради его собственного журнала; продуктовые файлы, тесты, workflows и зависимости после проверенного SHA не меняются.

Для интеграции нужен обычный независимый review PR. Не выдавать partial native/source/format coverage за универсальную точность диагностики. Authenticode, полная license/SCA-приёмка, физическая Windows10/11 GUI-проверка, реальный аварийный WPR capture/recovery и 1h/8h endurance не объявлены выполненными. Рутинное тестирование владельца не назначается как замена автоматическим доказательствам.
