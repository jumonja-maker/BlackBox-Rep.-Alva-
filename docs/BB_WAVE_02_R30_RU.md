# BB-WAVE-02 / R30 — ожидания и I/O

R30 расширяет существующие Trace Decoder, Evidence Graph, Critical Path и
Investigation Engine 3. Сбор данных остаётся в OBSERVE/Deep Inspection и
ограниченном R10 Helper. Повышение GUI, произвольные команды и новый
диагностический движок не добавляются.

## Что анализируется

- `CSwitch` и `ReadyThread`: прежний анализ по точным TraceLog process/thread
  lifetime indices. Recorded off-CPU, blocked и ready-queue intervals остаются
  различными величинами. Потеря, порядок, неизвестная идентичность и отсутствие
  границы ReadyThread не заменяются догадкой.
- FileIO: типизированные `Create`, `Read`, `Write`, `Cleanup`, `Close`, `Flush`,
  `SetInfo`, `Delete`, `Rename`, `QueryInfo`, `FSControl`, `DirEnum`, `DirNotify`
  и `OperationEnd` из pinned TraceEvent. Запрос связывается с его результатом
  только по уникальным наблюдённым границам kernel request token в одной трассе.
  Токен сам по себе не является именем файла или владельцем блокировки.
- NTSTATUS сохраняется в собственной области кодов. `STATUS_ACCESS_DENIED` и
  `STATUS_SHARING_VIOLATION` не выдаются за фактически прочитанный Win32
  `GetLastError`. Прямой Win32-код из другого доступного источника помечается
  как записанное заявление этого источника.
- DiskIO: прежний QPC response counter сохраняется отдельно от новой пары
  `ReadInit/WriteInit → Read/Write`. Количество перекрывающихся пар — нижняя
  граница наблюдённых отфильтрованных outstanding requests, не аппаратная
  глубина очереди. Без device-dispatch boundary queue delay и service time
  остаются неизвестными.
- WCT: владелец показывается только для явно Owned mutex/critical-section
  ребра в успешном Windows WCT snapshot. PID/TID такого владельца относятся
  только к этому снимку; отсутствующий creation FILETIME не выдумывается.
  SendMessage recipient и ReadyThread waker не превращаются во владельца.
- UI и сеть: показываются реальные записанные responsiveness observations,
  состояния/endpoint/transfer metadata и доступные ошибки. Расстояние между
  UI probes не является доказанной непрерывной длительностью зависания.
  Сетевой payload не собирается; временное совпадение не доказывает причину.

## Пользовательский маршрут

Выберите процесс и соберите доступные OBSERVE/Deep/ETW данные штатными
средствами. Для требующих прав действий используйте R10 с отдельным
подтверждением цели и воздействия. Откройте источники в Investigation Engine 3.
Представление задержек и I/O использует тот же граф и сохраняет ссылки на
исходные nodes, records и Critical Path segments. RU/EN оболочка подключает
это представление внутри существующей страницы расследования.

Экспорт JSON/HTML и собственный SQLite index содержат добавочный
`delay_investigation` (`blackbox.delay-investigation/1`). HTML также содержит
читаемую таблицу наблюдений. При повторном открытии проекция пересчитывается
из проверенного графа. Импортированный JSON не удостоверяет производителя.

## Границы достоверности

При loss/неизвестной полноте, изменении порядка, повторном request token без
результата или неизвестной идентичности вывод сохраняет неполноту. Событие
завершения может выполняться на другом потоке или в System: исходный запрос
не получает PID completion header, а completion не получает PID отправителя.
Отсутствующая граница и неподтверждённая очистка не становятся успехом.

Все проверки приложения и native/compiler/build выполняются только на
стандартных бесплатных GitHub-hosted runners. Форматные/отрицательные тесты
отдельны от реальных Windows fixtures. Готовность R30 определяется полным
exact-SHA CI и native/GUI/export/read-back/cleanup, а не наличием этого файла.
Физические Windows 10/11 и UAC Secure Desktop остаются отдельным NOT_TESTED.
