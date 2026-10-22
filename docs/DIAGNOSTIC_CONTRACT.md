# Observer evidence contract

Record PID plus process creation timestamp to resist PID reuse. Capture only readable Windows process metadata and measured counters. Unknown CPU, memory or thread values remain null. Errors are explicit and separated from lifecycle events. A report includes provenance, read-only observations and a statement that the target application's root cause has not been established.

A completed session is not marked successful if observation or persistence failed. Do not invent events, inner stack traces, or defect classifications unsupported by OS counter observations.
