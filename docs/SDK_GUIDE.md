# Voluntary local application events

The preparation wizard writes standalone Python, .NET, C++ and Node clients plus examples/config. They write a bounded local JSONL channel; no BLACK.BOX runtime dependency is added to the target. No network or hidden injection. The selected target must emit its real ready event; a generated file alone cannot verify instrumentation.

Python example after copying the generated client:

```python
import json
from pathlib import Path
from blackbox_event_client import EventWriter

config = json.loads(Path("blackbox-config.json").read_text())
events = EventWriter(config["path"], config["token"])
events.emit("blackbox.ready")
with events.operation("Save") as operation:
    with events.stage("Serialize", parent_id=operation) as stage:
        with events.io_operation("WRITE", byte_count=len(data), parent_id=stage):
            output.write(data)
```

`operation` emits linkable begin/error/end. `stage` has begin/end, parent and duration. `io_operation` supports READ/WRITE/FLUSH/CUSTOM and optional nonnegative byte count. Exceptions from target work propagate unchanged; the client's failed writes return False, increment dropped and never claim successful collection. Stage/IO wrapper validation errors indicate caller contract errors.

New Python event clocks are PYTHON_PERF_COUNTER_NS plus reported clock resolution. The high-resolution monotonic performance counter measures source durations even on Python 3.11 Windows where monotonic can be coarse. Stage/IO elapsed excludes the begin-event write, but includes ordinary wrapper overhead. It is wall duration reported by the app, not independently observed device service time.

No source clock is silently equated to the observer clock. The receiver stores receipt time and keeps original clock/seq/PID/TID metadata. OS_NATIVE TID differs from RUNTIME_THREAD_ID (for example Node threadId=0); runtime IDs are not put into native WCT as TIDs. Replay/invalid token/other PID/oversized/partial/replaced-channel cases are handled explicitly. A token routes a voluntary channel; it does not independently authenticate imported evidence.

The I/O analyzer groups completed reports by kind, computes median/p95/min/max and separately counts errors/invalid events. Short-N percentile warnings and unknown event loss remain visible. Intervals select observer receipt time, not an invented cross-clock source execution range. Bytes/s never becomes latency.

Generated .NET/C++/Node source/compilation tests use locally installed toolchains, no automatic SDK/package download. FIX-09 EventSource/GC workload is separate from this cooperative channel. A successful SDK event is an APP statement; a successful opaque EventPipe file is not proof of decoded GC pauses/allocations.

Treat configuration tokens, notes and any optional custom attributes as sensitive. Default share export removes known source/identity fields and raw spools. That transformation is not a universal secret detector. Review data before opting into raw traces, dumps or arbitrary application attributes.
