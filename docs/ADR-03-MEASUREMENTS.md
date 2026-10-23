# ADR-03 — measured quantities and intervals

CPU is `100*(delta cpu_user_seconds + delta cpu_system_seconds)/actual dt_s`,
not divided by host CPU count. 200% may mean two logical CPUs. The new v2 raw
cumulative counters are OS snapshots; psutil's already calculated CPU% is
separately marked DERIVED with its own internal interval semantics. The interval
reader recalculates CPU from selected adjacent cumulative pairs. First points,
reset counters, invalid/nonpositive dt and large spacing gaps get no invented
rate. Selection boundary pairs are excluded rather than prorated. Capture
brackets retain sensor timing uncertainty; a rate is not instantaneous CPU.

RSS/Working Set, private and USS are different fields. Missing private/USS is
NULL plus reason, never substituted by RSS. Handles are Windows handle count;
unsupported platforms do not receive file-descriptor counts under that name.
I/O bytes/ops are cumulative process counters; bytes/s uses positive actual dt
and nondecreasing counters, never file-operation latency. Reset is explicit.

Root, Detailed and per-child series remain distinct. Child identity is PID+
creation time; first/last observed and absence timestamps do not prove exact
birth/death. No total physical memory of the process tree is claimed: RSS sums
double-count shared pages. Short-lived children can be missed between polls.

Top TID ranks by cumulative CPU over valid pairs in **the entire selected
range**. Missing/reappearing/reset TIDs form different observed segments. Matching
numeric TID cannot exclude unobserved reuse. Presence is observed snapshots /
selected process snapshots, not continuous uptime. Top-N omission count and CPU
are explicit; recording truncation is distinct from display Top-N truncation.

Statistics stream every available selected row. Charts retain first/min/max/
last per bucket and continuity segments, so peak values survive and gaps do
not turn into zero or a connecting line. Expected schedule slots are an
estimate; exact missed OS samples remain UNKNOWN. Source status counts and
errors are displayed separately from observed values. Imported files are not
authenticated, even if a producer source string says OS_OBSERVED.

Human explanations of native HWND/WCT evidence and its limits are in ADR-04.
None of these measurements proves a leak, internal function cause or complete
deadlock diagnosis. Observer overhead and 8h/1h endurance are still unmeasured.
