# Real Alva integration: pinned, optional, external

## Source of truth at 2026-10-22

- Private platform: `https://github.com/jumonja-maker/Alva`, `main` SHA `a44297c5408628d9447bbf7db394b95ebd33fa20`, Python >=3.11, project `jumonja-alva`, `0.0.1.dev0`, **PREVIEW, not stable**.
- Alva's private Git tree did not contain a root LICENSE file at the inspected SHA. This public repository does **not** assume Alva may be republished or bundled. An explicit distribution grant or license and a release audit are required before producing a public EXE/wheel including Alva.
- Runtime / test environment may install Alva **outside this repository** from an authorized local checkout; pin an immutable SHA and preserve its wheel SHA256 (and identity) in private QA evidence. `pip install git+...@SHA` requires access and network at *install time*, not runtime; offline installs can use a prebuilt authorized local wheel.

## Public-use commands

```sh
# Works even without Alva; uses stdlib for metadata/reporting, psutil only for sampling:
PYTHONPATH=src python -m blackbox_rep_alva alva-check
# With legitimate Alva installation already present:
PYTHONPATH=src python -m blackbox_rep_alva alva-check --diagnose sessions/session-<ID>
```

`alva-check` does not issue git checkout, network access or privilege escalation. It returns `ALVA_UNAVAILABLE` if the dependency is absent. With installed Alva it imports `Component` / `ComponentHost`; for `--diagnose`, it creates a single `blackbox.report.inspect` component, executes it within a scoped host, and exposes a bounded outcome without original file content or PID. No duplicate execution or automatic retry. The installed package version alone **does not authenticate its source SHA**; the response keeps `provenance_verified=false`.

## Existing Alva feature coverage and explicit boundaries

| Alva component/feature | Status and integration in BlackBox |
|---|---|
| P2 package, `alva init`, `alva doctor`, `run_operation` | Already present in Alva preview; BlackBox uses a normal independent install. Template scaffolding is **not** run over existing repository. |
| Versioned P3.1 JSON request/response and validation | Bridge uses actual v1 schema, one trusted operation and bounded local summary. |
| P3.2 `Component` lifecycle, P3.3 adapter boundary, P3.4 `CapabilityRegistry` | Via actual `Component` inside host. No plugin discovery or dynamic loading. |
| `ComponentHost`, scoped permissions | Bridge uses local host and `open_scope`; host is **not** thread-safe, auth, or sandbox. |
| `invoke_with_diagnostics`, `OperationTrace` and host diagnostics | Bridge requests a single diagnostic call; contract verdict covers the component boundary, not target process events. |
| Failure classification, source map, report, `build_ai_handoff`, recheck | Available as distinct Alva PREVIEW facilities but **not silently invoked** or treated as proof of native application's root cause. The app's own evidence/handoff remains plainly untrusted. Explicit integration and QA can be added independently. |
| Checked/verified pipeline, offline QA and evidence protocols | Platform-level developer tooling documented by Alva, not a sampling runtime dependency; no benchmark/acceptance claimed for this project. |
| Experimental native Document Engine V3 | **Not included**. Universal process observation does not depend on conversion. V3-02 remains ACTIVE/PARTIAL; no product claim of full DOCX/PDF support. |
| NETALVA | **Not included**. Offline by design; no server/listener or remote invocation. |
| Universal root-cause identification, independent P4 ≥2x proof, P5–P9 | **NOT PROVEN / NOT DELIVERED** by Alva; not advertised here. |

## Migration, verification, update and rollback

1. Baseline public app without Alva (`unittest`, CLI record fake+real process, reporting) and capture exact HEAD.
2. Build Alva from an **authorized private checkout**, independently verify checked-out SHA and resulting wheel hash; install in a throwaway venv with no public artifact upload.
3. Run the documented Alva host examples from the exact version and `alva-check --diagnose` on a synthetic session. Compare before/after report bytes and absence of target mutations.
4. If stable, record pinned Alva SHA + wheel hash in **non-public** local QA records; add a feature flag for approved distribution. Do not accidentally place private platform files in Git, wheels, EXE, logs or CI artifacts.
5. Every version change is an explicit small PR with negative tests, multi-OS QA and rollback to old pinned wheel. Automatic upgrades disabled. If license/distribution rights unresolved, public builds remain **standalone mode only**.

**Status**: CLI standalone tests may pass locally; genuine Alva-at-SHA integration and Windows portability must be separately witnessed. No claims that published public code includes full private Alva binaries.
