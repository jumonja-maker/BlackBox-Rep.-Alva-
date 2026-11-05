# Контролируемый native noise в QA

Это политика собственного стресс-стенда, не изменение BLACK.BOX и не доказанная
причина исторического `APP_WORKLOAD_DEADLINE` стороннего7-Zip.

На actual MAIN e30bbc4 контролируемое сжатие не завершилось за90.015s при лимите90.
Ранее та же программа в feature acceptance завершалась за16.290s. Снимки
приоритетов/CPU/I/O не удостоверяли состояние ожидания или причину.

Отдельный наблюдательный ABBA pilot033cfee/run42085110359/job127447982483 выполнялся
на одном стандартном Windows runner с одним EXE, одинаковыми8MiB и7-Zip flags.
INHERITED завершился за43.6291271s/1roundtrip и9.3850694s/1roundtrip;
DISABLED — за3.0770077s/3roundtrips и3.0364452s/3roundtrips. Все четыре импорта
достигли ожидаемого250000/MAX_EVENTS, а не полной application acceptance.
Во всех16 собственных потоках измерено INHERITED0→0 либо DISABLED0→16;
Win32-relative priorities до/после управления не менялись,32native handles и
Job Object закрыты штатно. На этом хосте90s failure не воспроизвёлся.
Причина прежнего отказа остаётся NOT_ESTABLISHED; небольшая серия не даёт
статистического или универсального причинного вывода.

Только контролируемые native A/B в `qa_decoder_budget_diagnostic.py` явно
запрашивают DISABLED у16уже принадлежащих генератору worker handles до READY.
Изменение dynamic boost меняет условия интерференции; эквивалентность прежней
интенсивности не заявляется. Default standalone fixture остаётся INHERITED,
а отдельный pilot сохраняет оба режима и исходные результаты.

Все прежние функциональные и ресурсные oracles сохранены:16непрерывно живых
потоков/Event handoffs, положительные внутренние QPC deltas каждого потока,
реальный negative250k/typedCSwitch+Ready≥10000, B≥Ahandoffs/roundtrips, все8positive
capabilities, источник/hash/самостоятельный PE, bounded JSONL/index/RSS и normal
cleanup. Вход/flags/profile/base priority/process class/affinity/алгоритм не
менялись.90/95/READY90/prelude65/C210/841/owner225/global660/step12 прежние.
Python negative и ordinary30/PowerShell60 не изменяются.

Дополнительный допуск требует C before-READY receipts, повторный oracle и
независимый live query всех16TID/creation identities. Несовпавшая политика,
неполные flags, изменённый relative priority либо неизвестная query cleanup
запрещают успех. NT ThreadBasicInformation priorities записываются отдельно
от Win32 GetThreadPriority relative values и не сравниваются как одна шкала.
Cached observations не выдаются за непрерывное измерение.

Наблюдательный workflow не заменяет полный CI. Каждый итоговый HEAD и actual
MAIN требуют прежних11+2 jobs и нового реального Standard/Incident Burst часа.
Pilot success означает завершённый сбор наблюдений; старые FAIL остаются FAIL.
Никаких Release/tag/Artifacts/cache или локальных application/native runs.
