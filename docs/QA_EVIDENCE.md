# QA evidence policy

The current version is 0.3.2. For exact-head Windows/Linux pass counts and portable EXE smoke, inspect [GitHub Actions](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions?query=branch%3Amain). A commit or a documentation statement is not evidence that a newer HEAD passed tests.

Required regression coverage: real OS process sampling; lifecycle event persistence; missing CPU/RSS; report generation and rollback on write failure; PID reuse; test report/compare; five-page bilingual GUI; update checks, ZIP security, preserved evidence, maintenance; frozen executable and accurate embedded icons.

Physical Windows end-to-end update/uninstall, clean Windows offline operation, DPI/AV, disk-full and concurrency adversarial tests: NOT RUN unless independently documented. User acceptance must be grounded in actual execution, not inferred from source or a synthetic fixture.

Version 0.3.3 adds `tests/test_file_targets.py`: synthetic PE headers, DLL/script metadata-only handling, large-file hash limits, fake EXE rejection, exact executable-path matching, and GUI no-implicit-launch safeguards. Windows-specific consent, file-modification and shell-free start scenarios are tested via mocks on the Windows runner. Look up the exact v0.3.3 main Actions run before stating pass counts.

Version 0.3.5 adds Investigation Engine 0.1.2's 60 standalone tests plus receiving-app regression tests for SQLite user markers, read-only integrity, two distinct HTML/JSON outputs and bilingual tables. Frozen EXE smoke also calls the bundled engine and verifies its offline reports. The exact CI link and SHA must be checked before claiming PASS; physical Windows update and performance acceptance remain separate.
