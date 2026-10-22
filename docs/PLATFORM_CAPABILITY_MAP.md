# What BlackBox can actually consume from Alva (2026-10-22)

This inventory is **about the existing external private Alva platform**, not code bundled with BlackBox. It is grounded in Alva's current `README.md`, `src/alva/__init__.py`, `pyproject.toml`, `src/alva/host.py`, and `docs/PRODUCT_CONTRACT.md`, `CAPABILITIES.md`, `COMPONENT_HOST.md`, `AI_HANDOFF.md`, `QUALITY_GATES.md` at inspected SHA `a44297c5408628d9447bbf7db394b95ebd33fa20`.

## Installed platform entry points

| Capability in existing Alva | How the independent BlackBox project could use it | This PR stack |
|---|---|---|
| `run_operation("ping")`, v1 message schema | Basic installation/contract smoke | present in private Alva; future explicit smoke |
| `Component`, state, `CapabilityRegistry` | Wrap **BlackBox-owned** report inspection in a named local component | Integrated through `ComponentHost` at opt-in CLI |
| `ComponentHost` start/close and bounded registry | Structured lifecycle/controlled invocation | Integrated bridge (real runtime not tested) |
| `open_scope(permitted_operations)` | Restrict exposed operation names and revoke on close | Integrated bridge (real runtime not tested) |
| `invoke_with_diagnostics`, `OperationTrace` | Report **component call** contract and execution state | Integrated limited diagnostic call |
| Adapter boundary `invoke_adapter_checked` | Validate adapters' known result contracts before accepting a value | Available; not yet used directly |
| `classify_failure`, `build_report`, `review_pipeline_evidence`, `recheck_rejected_stage` | Advanced evidence processing for known in-process stages | Available; **not exercised by BlackBox** |
| `build_ai_handoff` | Host-owned machine-readable report for another AI developer | Alva host internally prepares metadata; BlackBox's separate report is untrusted |
| `locate_source` / source-map | Declared association of in-process component to application Python source with hash witness | Not used for foreign processes |
| `run_checked_pipeline`, `run_verified_pipeline` | Verified local component orchestration when app needs it | No application pipeline migrated |
| `save_trace`, scoped host report file API | Optional bounded on-disk platform metadata | Not automatically enabled; BlackBox has own SQLite |
| Document Engine V3 | Experimental, **optional** conversion-related technology | Explicitly excluded from process observer |
| NETALVA | Experimental opt-in network module | Explicitly excluded (BlackBox runtime offline) |

## Fundamental limits

- A successful `ComponentHost` contract says nothing about the correctness of the observed external Windows process.
- No generic execution of another application's functions, no API injection, no source code extraction, no automatic root-cause assignment, no AI agent automatically repairing code.
- Alva is Python-first and PREVIEW. Stable third-party packaging, global cross-language support, independent P4 ≥2× acceleration and V3 Document Engine full fidelity were not proven.
- Do not misrepresent existing private Alva as included in the public MIT product. The bridge uses its **real external API** in authorized environments, when separately installed.
- These fields never grant access to target application internals; richer data requires separate opt-in producer-specific telemetry and its own provenance checks.

## Update discipline

The **Alva commit and wheel digest** must be pinned independently in the private consumer environment. Library presence/version string alone is not SHA proof. Test positive + negative on Windows and Ubuntu, compare report bytes and error behavior, and retain a rollback wheel. No unconditional automatic updater.
