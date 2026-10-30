# BLACK.BOX v0.5.4 — unpublished BB-INV-003 candidate

This document describes the separate `patch/bb-inv-003` development candidate
based on released v0.5.3 (`dafa9cdb4b0f4766fc8cd2d5fd0d43579459e485`).
It does not announce or authorize a Release, tag, or merge into main.

Investigation Engine 3 adds a bounded read-only evidence graph above existing
collectors, explicit source/clock/identity gaps, partial critical paths,
deterministic diagnostic hypotheses, user-stepped BEFORE/ACTION/AFTER/COMPARE,
local issue grouping and conservative version comparisons. Its seven internal
sections remain inside Overview → Deep Inspection; the six main pages and
legacy embedding API are preserved.

All imported sources remain `UNVERIFIED_IMPORT`. Matching identifiers, timestamps,
error codes or stacks do not establish root cause. Missing coverage prevents
claims that a regression has been fixed. Native interventions retain the existing
diagnostic helper, confirmation, scoped elevation and recovery reporting.

See [English guide](BB_INV_003_EN.md), [Russian guide](BB_INV_003_RU.md), and the
[owner's specification](specifications/BB-INV-003.md). Exact tested commits,
hosted CI results, independent review and remaining limits are recorded in the
separate final handoff document. Physical Windows 10/11 and Secure Desktop UAC
acceptance remain separate from GitHub-hosted runner checks.
