# Test protocol and evidence — 2026-10-22

**Target code:** universal process observer developer preview v0.1; no native Windows binary.

Commands (repeat in isolated Python environment):

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m blackbox_rep_alva --help
PYTHONPATH=src python -m blackbox_rep_alva alva-check
```

Coverage expected: output directory boundaries, real local process sampling, synthetic process exit, WAL reporting, incomplete sessions, corrupt database, comparison uncertainty, handoff without permission, optional absence of Alva and simulated adapter contract. **The fake Alva adapter test is not proof that the real private Alva package was imported and executed**. The real platform bridge requires authorized wheel, exact SHA verification, OS QA and repeatable integration evidence.

Status labels: `PASS` = execution and environment recorded, `LIMITED` = partial scenarios, `NOT RUN` = not executed, `BLOCKED` = cannot execute due to environment/rights. Record observed results below only after actual local test execution; never infer CI from static analysis.

Known release blockers: no tested Windows process metrics/GUI/EXE, no multi-OS release matrix, no public distribution license for private Alva, no automatic native app-specific telemetry, no independent root-cause verification.
