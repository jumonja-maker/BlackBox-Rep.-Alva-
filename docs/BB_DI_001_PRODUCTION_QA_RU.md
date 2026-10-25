# Реальные стенды и измерения BB-DI-001

Эти команды являются явным QA, не запускаются обычным наблюдением. Выходная папка должна быть новой/пустой. Стенды изменяют только собственные ресурсы. Короткие автоматические проверки не доказывают 8ч/1ч, физические Windows или бюджет типового ПК.

## Реальная нагрузка

`python -m blackbox_core.qa_workloads threads OUT --count 300 --seconds 60`

Режимы: cpu (1/2/N native hashlib worker, освобождающий GIL), threads (до 512), children (до 100), memory (32 МиБ/page touch), handles (Win32 events; на POSIX явно file descriptors), io (перезаписываемый файл 1 МиБ) и longrun (heartbeat). `ready.json` появляется после создания ресурсов; target PID/birth получаются из psutil. `stop.request` завершает стенд и собственных потомков.

Через атомарную замену `command.json` можно передать `{id,op,count}`: cpu/SET_CPU_COUNT от 0 до исходного N; memory/ALLOCATE_32_MIB, RELEASE_HALF, RELEASE_ALL (предел 256 МиБ); handles/CLOSE_HALF. `state.json` содержит ack/error. Это управление стендом, а не исследуемой чужой программой. PID reuse проверяется отдельно контрактными тестами и не имитируется подменой настоящих счётчиков.

Frozen EXE: `BLACK.BOX-Universal.exe --qa-workload threads OUT --count 300 --seconds 60`.

FIX-02/03 остаются настоящими Win32/Qt GUI и mutex-cycle в `blackbox_universal/qa_fixtures.py`. FIX-08 содержит штатное завершение/контролируемое исключение в research_fixtures. FIX-09: `tools/fixtures/ManagedRuntimeProbe/Program.cs`, автономный EventSource + GC pressure. Тест собирает исходник только установленным SDK, без NuGet/network; отсутствующий SDK/dotnet-trace даёт явный SKIP. JSON ready не является доказательством GC.

## Сравнение нагрузки

`python -m blackbox_universal.production_qa benchmark --pid PID --output OUT --phase-seconds 60 --warmup-seconds 10 --sample-seconds 0.5 --expected-sha SHA`

Запускается настоящий Qt-интерфейс и штатный изолированный владелец сеанса. Фазы OFF → Standard → OFF → Detailed → OFF. Во всех фазах присутствуют GUI и idle helper. Наблюдатель — GUI и его собственные потомки; target и его дерево исключаются. Родитель самого наблюдателя как target не допускается из-за перекрытия когорт. Фактическая длительность, hardware/runtime, source SHA/tree/dirty, исходные CSV-точки, median/p95 target/observer CPU/RSS, число сменившихся экземпляров и сравнение бюджетов 1/3 машинных процентных пунктов сохраняются локально. Вызов измерителей тоже входит в observer overhead. Ушедшие между точками процессы не получают выдуманного CPU; RSS дерева может дважды учитывать shared pages.

Нет универсального PASS по короткой машине/облачному runner. Если phase_seconds <60, результат всегда SHORT_FUNCTIONAL_ONLY. Недоступные счётчики остаются NULL. Сам benchmark не заменяет реальную приёмку производительности.

## Endurance

`python -m blackbox_universal.production_qa endurance --pid PID --output OUT --profile STANDARD --expected-sha SHA`

Без duration override записывает настоящие 28800 секунд Standard (либо DETAILED — 3600 секунд). CSV потоковый, progress.json обновляется каждые 5 секунд, source/время/число точек/состояние сеанса сохраняются. Сводка памяти ограничена последними 7200 измерительными точками, полный ряд остаётся в CSV. Ранний Stop/смерть target — FAILED, а не полноценный endurance. Короткий override помечается short_run, endurance_duration_met=false. Интервал не ускоряется и timestamps не растягиваются. По завершении helper закрывается штатно.

Frozen EXE использует тот же harness: `... --qa-production benchmark|endurance ...`. Физический дисплей/DPI/Win10/11 и 8ч/1ч остаются NOT-RUN до получения реальных файлов полного испытания. NIKITA этими изменениями не использовался.

## Действия и доказательства

Анализ связывает ресурсы только внутри настоящих USER action timestamps. Выдаётся ACTION_RESOURCE_COINCIDENCE с частичным диапазоном, доступными парами, количеством/покрытием, типизированным следующим измерением и явным causal_claim=false. Настройка top_threads читается из самого сохранённого сеанса, а не из текущей цели. Непрочитанные nettrace/ETL остаются UNDECODED; сообщения SDK остаются APP statements.

## Однократное длительное испытание в GitHub Actions (отдельный QA; не релиз)

На Draft PR #17 при **одном явно помеченном** commit `Start BB-DI-001 GitHub endurance: 5h30 Standard and 1h Detailed` запускается выделенный workflow `.github/workflows/bb-di-001-endurance-qa.yml`. Следующие обычные изменения в PR **не запускают** длинное испытание повторно: в workflow есть проверка точной строки commit subject. Отдельная concurrency group не отменяет этот тест при обычных изменениях основного CI. `main` и релизы не трогаются.

- Общая **предпроверка**: Windows offscreen PySide6 с настоящим изолированным исследовательским процессом и локальным стендом `longrun`; по 90 секунд Standard/Detailed. Предпроверка — функциональная, никогда не считается 8ч/1ч.
- Два параллельных независимых hosted Windows job: `STANDARD` **19800 реальных секунд = 5ч30м**, `DETAILED` **3600 реальных секунд = 1ч**. Тайм-ауты оставляют запас перед лимитом GitHub-hosted job 6 часов. Каждый использует собственную временную папку и собственный процесс-мишень. Не запускаются ETW/dump/загрузка чужих программ.
- Скрипт `tools/qa_github_endurance.py` вызывает неизменённый production GUI-harness `blackbox_universal.production_qa endurance` с `--expected-sha` из точного PR HEAD. Каждые 5 секунд production harness обновляет `progress.json`; оболочка печатает суммарный heartbeat каждые 10 минут. Все исходные CSV и SQLite остаются в QA artifacts.
- После STOP скрипт **отдельно** читает реально сохранённые v1/v2/research SQLite, проверяет `COMPLETED/CLOSED`, идентичность, отсутствие writer drop, точное соответствие последовательных STANDARD (`schema1:N`), без замещения Detailed/Child. Проверяется доступность одной минуты в начале, середине и конце, а также **реальный экспорт** среднего интервала с хеш-проверкой неизменности исходных БД. Любой сбой/преждевременная смерть цели/GUI helper или пустая история даёт `FAIL`.
- Конечные `qa-verdict.json`, `result.json`, `samples.csv`, `progress.json`, интервальные экспорты и исходные SQLite сохраняются в отдельные GitHub Actions Artifacts на 7 дней; реальные файлы публикуются только после остановки job. Во время выполнения состояние доступно в Actions status/log heartbeat, не как уже доказанный PASS.
- **ВАЖНО:** 5ч30м Standard **не выполняет нормативные 8ч Standard (M-064)**. Его честная метка — `short_run: true`/`endurance_duration_met: false`. Часовой Detailed покрывает только требование длительности Detailed. GitHub-hosted Windows Server/offscreen — не физические Win10/11 и не полноценные off/on overhead-бенчмарки. Полная матрица 128 пунктов остаётся незакрытой.

Ручное `workflow_dispatch` не используется: для нового workflow ещё нет файла на `main`; однократный PR `synchronize` запускает его непосредственно на ветке через зафиксированный source SHA. Это **не** изменение release/default branch.
