# BLACK.BOX Universal v0.3.6 — main

Deep-hardened standalone BLACK.BOX. PR #16 has been independently reviewed and merged with further defensive checks. Core report writes are exclusive/no-clobber, SQLite event summaries stream and classify user markers separately, ZIP staging refuses Windows alias and special-path attacks, maintenance detects reparse points in ancestors and fails closed on filesystem inspection errors, and per-process multicore CPU scales beyond 100%.

Investigation Engine 0.1.2 and the existing five RU/EN pages are preserved. Existing user session SQLite/JSON/HTML is retained on normal update/uninstall paths, with regression tests for simulated rollback on Windows CI. Qt offscreen screenshot artifacts cover 5 pages x RU/EN x four simulated DPI scales. Offscreen screenshots exhibit Qt font glyph issues in CI and are NOT physical Windows font legibility acceptance.

Release v0.3.6 is gated by Windows/Linux test suite and portable EXE smoke. Real Windows hardware DPI/keyboard/OneDrive/antivirus/update/uninstall acceptance remains NOT RUN. No separate proprietary runtime is included.
