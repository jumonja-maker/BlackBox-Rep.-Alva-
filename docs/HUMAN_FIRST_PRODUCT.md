# BLACK.BOX Universal — Human-first product contract

**Owner decision, 2026-10-22:** BLACK.BOX Universal is an offline diagnostic app **for ordinary people**, not for AI agents. Users must never need an AI account, ChatGPT, machine-readable AI transfer, or interaction with an AI model to diagnose and compare their local programs.

## User journey

**Choose an application → Start observing → Stop → Read reports / compare sessions.**

BLACK.BOX records only permitted OS-level signals through its own observer. When a session ends, it creates:
- `session.sqlite3`: durable local measurements and observer events;
- `report.json`: structured human-relevant evidence and honest limitations;
- `report.html`: browser-readable human report.

**No `ai-handoff.json` is created.** No `handoff` CLI command or AI-facing export is offered. Exports remain explicitly user-controlled. Existing old sessions with previously created `ai-handoff.json` are not modified or deleted by the new program, and prior diagnostics files remain readable as ordinary files if present.

## Diagnostics: internal Alva, not an AI feature

The optional externally authorized private Alva runtime may continue to perform:
- scoped `ComponentHost` validation of BLACK.BOX-owned operations;
- four P4 checked evidence-quality stages;
- structural review of the pipeline record;
- conservative classification and bounded report creation for BLACK.BOX's own component traces.

These operations support reliability of observations for people. No explicit `alva.build_ai_handoff()` is invoked by the BLACK.BOX P4 helper. **Alva's current `invoke_with_diagnostics` can still construct its own internal AI-oriented metadata** as part of the private platform API. BLACK.BOX does not select, serialize, display or deliver that internal metadata. Removing that internal behavior would require a separately reviewed change **in Alva**, not a cosmetic BLACK.BOX refactor.

There is **no Alva Lab** in the user interface. Alva remains private and is not bundled. Without an installed, authorized Alva runtime, BLACK.BOX still generates all ordinary reports; any private-platform validation is simply unavailable and is never fabricated.

## Product priorities

- Human-readable evidence, not AI prompts or magic root-cause claims
- Clear error/status categories and missing-data explanations
- CPU/RAM/I/O samples and process state with understandable time ranges
- Before/after session comparison with explicit uncertainty
- Offline by default, no destructive access to a target process
- User-controlled export and sharing, no automatic uploads

## Acceptance checklist

- [ ] Unit tests: Stop yields SQLite/JSON/HTML but **not** `ai-handoff.json`; CLI rejects `handoff`.
- [ ] EN/RU Qt GUI test: Reports/About text mentions no AI Handoff or separate Alva tab.
- [ ] Windows frozen EXE: end-to-end run with no private Alva, no internet and no Python installation.
- [ ] With already-authorized Alva: optional checks complete, ordinary human reports survive failures.
- [ ] Verify no unexpected AI-specific data is transmitted, persisted or exposed.
- [ ] Publish only after validating the exact reviewed SHA in GitHub Actions or a trusted Windows host.

At the time of authoring, source changes and tests are committed but **full local/Windows tests have not been executed at this SHA**. Historical QA in earlier documents is not a result for this branch.

This contract supersedes any older README or engineering note describing AI Handoff as a default BLACK.BOX feature.
