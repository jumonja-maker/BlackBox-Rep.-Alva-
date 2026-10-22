# Real Alva P4 evidence processing in BLACK.BOX (developer integration)

**Status: Draft / PREVIEW, 2026-10-22.** Source branch `feature/alva-evidence-pipeline-20261022`, stacked on the **unbranded five-screen** `feature/internal-diagnostics-unbranded-20261022`. The Alva GitHub repository stays PRIVATE. No private source or wheel is copied into BLACK.BOX or the public EXE.

## Why this exists

Previously BLACK.BOX called only three scoped `ComponentHost` operations that checked presence of observer metrics, completion status and observer errors. That was a valid narrow API consumer but did **not** meaningfully exploit Alva's verified pipeline, review, or diagnostic classification capabilities.

This integration adds a real second layer in the **authorized external Python** when Alva supports its P4 APIs. It is invoked **after session completion**, within the already existing non-UI sidecar, and does **not** re-read the target application or repeat any process mutation.

## Actual Alva features exercised

| Alva API / facility | Execution in BLACK.BOX |
|---|---|
| `Component`, `CapabilityRegistry` indirectly, `ComponentHost` lifecycle | Three registered BLACK.BOX observer operations, permissioned and closed |
| `open_scope`, `invoke_with_diagnostics` | Each scoped operation invoked once with bounded diagnostics. Alva may assemble internal metadata, but BLACK.BOX does not export an AI Handoff |
| `invoke_adapter_checked` | App-owned predicate checks shape of each scoped observation |
| `run_checked_pipeline` (P4 checked facade, invokes `run_verified_pipeline`) | Four explicitly declared in-memory data-quality stages |
| `review_pipeline_evidence` | Validates that the resulting Alva pipeline report is structurally consistent **but unauthenticated** |
| `OperationTrace` | Alva instruments the scoped and pipeline operations internally; raw data, secrets and process logs are not copied to the extended result |

### Four genuine P4 stages

1. `blackbox.evidence.samples` — confirms that a finalized inspection has samples. A zero-sample session is an **observer-evidence gap**, not proof of a bug in the observed application.
2. `blackbox.evidence.lifecycle` — confirms a finalized session was closed.
3. `blackbox.evidence.metrics` — checks that a session with samples has at least one CPU/RSS resource signal.
4. `blackbox.evidence.errors` — verifies the bounded, nonnegative count of observer errors (does **not** claim no errors existed).

Each runs at most once, in memory, over the same small bounded summary sent by the original sidecar. Alva preflights all declarations before any stage executes; at the first rejected stage, later ones do not execute. The resulting report separates `status:ok` (the diagnostic report was assembled) from `observed_pipeline_status:error` (a quality predicate rejected observer evidence).

The new wire result uses `bridge_schema:2` and `extended_diagnostics`; the parent validates exact keys, categorical values, stage count, bounded action code, `execution_attested:false`, `root_cause_proven:false`, `permission_to_act:false` and the **structurally consistent / unauthenticated** marker. Schema-1 result remains supported for older authorized Alva installations lacking the full P4 facade. If a supported facade exists but rejects or fails, the process reports an explicit failure; **it cannot silently downgrade** to a synthetic success.

## Distribution and Windows frozen build

The isolated external worker executes `python.exe -I -u alva_sidecar_worker.py` in an explicitly authorized Python environment that contains a separately installed genuine Alva package. Python `-I` intentionally hides untrusted `PYTHONPATH`, so the new **public** `alva_evidence_pipeline.py` file is loaded from a fixed location adjacent to the public sidecar via a checked importlib file spec. The existing Windows portable build definition now includes **both** public sidecar files under `_internal/alva_worker/`. This is *not* a copy of private Alva.

BLACK.BOX's own SQLite/JSON/HTML human-readable reports remain available without Python or Alva in the user's environment. The UI still exposes only **Overview / Processes / Event Log / Reports / Settings**. There is **no Alva Lab or install button**.

## Extra genuine Alva trace handling

In addition to the P4 checked pipeline, the **same already-completed** three
ComponentHost calls supply in-process `OperationTrace` witnesses. If the
installed Alva supports them, the worker invokes `classify_failure`,
`build_report` and `review_pipeline_evidence`
on the existing host evidence **without executing the component a second time**.
This yields three bounded `host_trace_checks` receipts (or none for a
partial legacy runtime) showing complete in-process coverage, the conservative
UNKNOWN classification and unauthenticated provenance. Raw traces, process
identifiers, paths, private code and exception text are not returned.

These are **BLACK.BOX component trace reports**, NEVER internal telemetry
from the foreign Windows process. A successful trace does not mean that
the observed target app was correct.

## Ordinary Reports screen (no platform tab)

After STOP, BLACK.BOX always writes its own local evidence. When an **already
authorized** private Alva Runtime is available, the background sidecar
additionally writes its P4 evidence report and returns only a bounded
`accepted_checks / declared_checks / observed_pipeline_status` summary.
The standard **Reports** page displays "Evidence checks accepted: 4/4"
(or a conservative "requires review" message). RU/EN are both supported.
**Alva is never mentioned in the visible label.** No extra navigation, user
sign-in or manual diagnostic button exists. Without Alva the Reports page
simply states the local observer report was saved; it NEVER invents a reviewed
result. A failed optional review cannot invalidate an existing SQLite report.

## Strict limits

- **No true Alva Runtime is included** for ordinary downloaders. Automatic genuine Alva execution for everyone is impossible under the current decision to keep the runtime undistributed and avoid servers. Do not claim all customers receive full Alva features.
- P4 predicates validate *app-declared observer evidence*, not the correctness of the observed arbitrary EXE. Proven application source lines, automatic crash attribution, Windows ETW, memory dumps, cloud AI and automatic repair are NOT IMPLEMENTED.
- `classify_failure` and `build_report` are applied only to BLACK.BOX's own observed component traces. `locate_source` is **not automatically applied to another application's internals**. `locate_source` would require an explicit trusted source mapping, which passive process sampling does not have. Document Engine V3 and NETALVA are intentionally unrelated/excluded.
- The private Alva project's own P4 ≥2x developer-acceleration target remains unproven; this consumer PR is not an independent benchmark.

### Repeatable authorized-runtime smoke (new)

A public source-only acceptance harness is committed at
`tools/verify_authorized_alva.py`. On a **developer/maintainer-owned**
machine with an already installed, authorized Alva in a trusted venv, run:

```powershell
py -3 tools/verify_authorized_alva.py "C:\trusted-alva-venv\Scripts\python.exe"
```

It performs two genuine isolated-Python calls: one synthetic positive
session (5 samples, 3 checked host traces and 4 P4 stages) and one synthetic
negative session (0 samples → first observed *observer-evidence* predicate
rejected). It does not open real target process files, import A.I.O, install
anything, contact a server, or prove installed package provenance. The
required `Alva` wheel must **not** be copied to the public repo or CI.
Capture results, exact SHA and wheel hash **privately**, then publish only a
bounded PASS/FAIL summary (without paths or secrets) if approved.

This script has been **created, NOT RUN** against the private library.

## Acceptance gates, not yet passed

1. Linux and Windows tests of the exact branch SHA for `tests/test_alva_p4_evidence.py` plus the full repository suite; packaged PyInstaller EXE smoke must verify **both** sidecar files are in the built archive.
2. In a **private authorized** environment with installed Alva SHA `a44297c5408628d9447bbf7db394b95ebd33fa20`, run source worker `-I` with a bounded recorded summary. Confirm schema 2, 3 scoped calls, 4 P4 stages, 3 trace summaries, completed host, conservative evidence/permission flags, and that the parent validates the result. Capture SHA and wheel digest **privately**; do not upload wheel to public CI.
3. Negative scenarios: empty samples, interrupted session, absent CPU/RSS, wrong API, malformed / injected output, no Alva environment and subprocess timeout. Original reports must survive.
4. Only after independent QA may this Draft be reviewed for merging. Previous tested commits **cannot certify** this new SHA.

**Executed status:** source code, strict v2 validation, tests and Windows packaging changes are committed. Actual full-suite local/Windows runner, Windows EXE, real installed private Alva and authenticated wheel identity **NOT RUN** as part of this PR.
