# BLACK.BOX Universal current development — 2026-10-23

Version 0.3.3 introduces a safe user-selected file workflow in the Processes tab: static metadata for arbitrary files, full-path matching for PE Windows EXE, and a separately confirmed Windows EXE launch before attach. File selection itself never executes code, and monitoring still requires a live process with explicit Start.

All standalone observer, SQLite/JSON/HTML, bilingual UI and maintenance features remain. Alva integrations were removed from the current source tree in v0.3.2; the historical repository URL is unchanged. The release process is gated by Windows/Linux tests and frozen executable smoke. Physical Windows update acceptance, antivirus reputation, dependencies/licensing and EXE code signing remain separate from automated QA.

[Actions](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions?query=branch%3Amain) · [Releases](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases)
