# Реальные стенды и измерения BB-DI-001

Эти команды являются явным QA, не запускаются обычным наблюдением. Выходная папка должна быть новой/пустой. Стенды изменяют только собственные ресурсы. Короткие автоматические проверки не доказывают 8ч/1ч, физические Windows или бюджет типового ПК.

## Реальная нагрузка

`python -m blackbox_core.qa_workloads threads OUT --count 300 --seconds 60`

Режимы: cpu (1/2/N native hashlib worker, освобождающий GIL), threads (до 512), children (до 100), memory (32 МиБ/page touch), handles (Win32 events; на POSIX явно file descriptors), io (перезаписываемый файл 1 МиБ) и longrun (heartbeat). `ready.json` появляется после создания ресурсов; target PID/birth получаются из psutil. `stop.request` завершает стенд и собственных потомков.

Через атомарную замену `command.json` можно передать `{id,op,count}`: cpu/SET_CPU_COUNT от 0 до исходного N; memory/ALLOCATE_32_MIB, RELEASE_HALF, RELEASE_ALL (предел 256 МиБ); handles/CLOSE_HALF. `state.json` содержит ack/error. Это управление стендом, а не исследуемой чужой программой. PID reuse проверяется отдельно контрактными тестами и не имитируется подменой настоящих счётчиков.

Frozen EXE: `BlackBoxUniversal.exe --qa-workload threads OUT --count 300 --seconds 60` (фактическое имя EXE берётся из portable-пакета).

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
