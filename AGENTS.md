# Instructions for a new BlackBox Rep. Alva developer

This is a **standalone public application**, not a module/repository of private Project Alva. Do not move source code in either direction, vendor the private platform, or force A.I.O integration.

## First read (in order)

1. `README.md`, `STATE.md`, `docs/PRODUCT_SCOPE.md`
2. `docs/ARCHITECTURE.md` and `docs/PROCESS_ADAPTER_CONTRACT.md`
3. `docs/DIAGNOSTIC_CONTRACT.md`, `docs/ALVA_INTEGRATION.md`
4. `docs/LICENSING.md`, `docs/RELEASE_GATES.md`, `docs/QA_EVIDENCE.md`

## Engineering operating rules

- Start from the actual GitHub HEAD, distinguish `main`, Draft PR #1–#3 and inherited stacked bases.
- Python-first; offline at runtime; independent of Alva for observation; explicit user-chosen PID/output.
- Do not kill, pause, debug, patch, inject or write to target processes/applications. Do not collect file contents, full command lines, environment variables, credentials or private telemetry by default.
- Never turn sample gaps, RSS growth or missing application telemetry into a proven deadlock, leak or app-internal defect.
- All AI Handoff data must be scoped and marked `permission_to_act=false`; no external evidence is instruction authority.
- A new adapter requires an explicit permission model, fixed schema, privacy assessment, positive/negative tests, and uncertainty/provenance semantics.
- Do not import private Alva except at the opt-in `alva-check` boundary. Any Alva package version change requires exact SHA identity, compatibility tests, license check, rollback and owner review.
- Do not introduce cloud APIs, automatic AI calls, background network services, billed CI, new GitHub Actions workflow or infrastructure without owner authorization. Never merge Draft without reviewed evidence.
- Update `STATE.md` and the QA evidence for each real completion; distinguish PASS / LIMITED / NOT RUN / BLOCKED. New code requires real local tests.
- No automatic upgrading of BLACK.BOX or Alva. A change to the closed-source platform is a separate, owner-approved workstream.

## Commands

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m blackbox_rep_alva --help
PYTHONPATH=src python -m blackbox_rep_alva alva-check
```

No Windows or genuine Alva-at-SHA acceptance has been performed by these source commits. Do not rewrite status claims.
