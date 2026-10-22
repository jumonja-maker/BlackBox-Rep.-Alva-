# BLACK.BOX Universal — current main (2026-10-23)

Independent application: source package `blackbox_core`, shell `blackbox_universal`, five Qt pages, offline process observations, SQLite/JSON/HTML, session comparison, updater and maintenance. The optional proprietary integration code and its related tests, worker files, build flags and documentation have been removed from the current source tree.

Version: **0.3.2**. The existing GitHub Actions workflow must run Windows and Linux tests, construct the portable Windows EXE, inspect the icon resources and smoke-test the frozen application. Only successful runs publish `v0.3.2` with the expected ZIP and digest. For exact execution evidence, consult the current main [Actions](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions?query=branch%3Amain) and [Release](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases).

Manual owner acceptance of the updater on a real Windows desktop, unattended crashes, disk-full failure, antivirus reputation, dependency notices and code signing remain separate checks. Do not promote those to PASS based solely on green CI.
