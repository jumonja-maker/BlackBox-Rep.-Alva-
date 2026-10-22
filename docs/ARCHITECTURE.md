# BLACK.BOX independent architecture

The standalone Python core `src/blackbox_core` contains process probing, contracts, SQLite storage, recording, reports and a CLI. The user interface `blackbox_universal` contains Qt screens, a read-only probe facade, local language selection, charts, release checking, maintenance and shortcuts.

Data flow: user selects an accessible process → explicit Attach → Start → periodic OS counter observations → SQLite append-only data → Stop → saved JSON and bilingual offline HTML reports → optional report comparison. Lifecycle events are stored in SQLite and shown in the interface. Missing values are represented as unknown.

No other runtime, paid SDK, local service, account or external platform is needed. There is no process injection and no assertion about unobservable internal causes of failures. The user may view and export local evidence; online requests are only for update checking and explicitly opened external links.
