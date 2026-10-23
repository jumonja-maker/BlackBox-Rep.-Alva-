# ADR-04 — real HWND timeout observations and asynchronous WCT

Status: implemented for Windows x64; native runner evidence required on every
new head. This is not ETW, a root-cause proof or physical Win10/11 acceptance.

## API and isolation

`windows_observer.WindowsNative` binds documented User32/Advapi32 functions with
explicit ctypes argtypes/restype. Windows DWORD/BOOL are 32-bit; pointer-sized
values remain 64-bit on x64. `WAITCHAIN_NODE_INFO` is exactly 280 bytes with its
union at byte 8. UTF-16 storage uses uint16, avoiding POSIX wchar ABI assumptions.
Callbacks, node arrays, count and cycle storage stay strongly referenced until
their owning WinAPI call/session cleanup returns. Node reads cap at 16 even if
Windows returns a larger required count. Unknown enum/error numbers are retained.

One `WindowCapture` worker enumerates at most 32 target top-level HWND entries,
records PID/TID/visibility and observed lifecycle, without reading any title.
Only up to four selected/visible-prioritized HWNDs are probed per cycle, normally
once every two seconds. Omitted enumeration and probe counts are explicit.
Truncated enumeration cannot falsely mark an unseen window as destroyed.
The Overview HWND selector changes this sensor's window preference, **not PID**.

`SendMessageTimeoutW` sends **only WM_NULL** with BLOCK|ABORTIFHUNG|ERRORONEXIT,
a nonzero 150 ms per-window timeout, no broadcast, and no NOTIMEOUTIFNOTHUNG.
Window PID/TID is checked before/after. Fresh process PID+creation-time checks
surround each whole observation batch before recording events. The Qt thread
never calls this API. Windows error 1460 is SENSOR_TIMEOUT, 5 ACCESS_DENIED,
1400 WINDOW_GONE. Return=0/error=0 is **UNKNOWN**, not an invented timeout.

Two independent consecutive timeouts produce UI_UNRESPONSIVE_OBSERVED, followed
by UI_RESPONSIVE_AGAIN on success. First timeout, last responsive observation,
probe brackets, thresholds, count and exact Windows code are preserved. Actual
onset and recovery time between polls remain unknown. WINDOW_GONE is separate.
No windows means NOT_APPLICABLE, not a claim that the process cannot hang.

WCT runs only after the timeout threshold, on that independent worker, through
an asynchronous session, a 300 ms result wait, and documented session cancel/
close. Nodes, owners, statuses and is_cycle come from the actual callback;
mutex/object names are never decoded. Access denied/unsupported/timeout retain
their reason and do not erase the primary timeout or stop Standard sampling.
No SeDebug privilege is silently enabled, and no elevation is requested. A
single snapshot/cycle is not a complete application root cause.

**Deadline limitation:** Microsoft documents cancellation and callback joining
for CloseThreadWaitChainSession, not an unconditional hard cleanup latency.
The worker can remain owned if OS cleanup stalls. GUI Stop waits at most 50 ms
for this sensor, records WINDOW_SENSOR_STOP_PENDING, detaches its v2 sink and
retains the worker; rebind is blocked until it exits. Native workers are non-daemon and GUI close defers while any pending capture/writer still owns resources. Complete hard shutdown /
OS watchdog acceptance remains partial. No uncontrolled per-TID threads.

## Persistence, privacy and trust

The v2 writer's dedicated native-batch entry point records normalized windows,
Win32/WCT events, status/error codes and UI incidents. Ordinary user-event DTOs
cannot select that source classification. Reopened source files are always
UNVERIFIED_IMPORT while original producer claims remain visible separately.
Default export includes safe native method/status/counter evidence; PID/TID/
HWND are redacted unless explicitly selected. No title, full path, command line,
environment, memory contents or mutex name is collected. ETW remains absent.

## Reproducible fixtures and acceptance boundary

`app.py --qa-fixture cpu|ui|waitchain --qa-output <owned-test-folder>` provides
real bounded fixture processes. CPU has two native hashlib workers; UI exposes
freeze 2s/8s buttons plus automatic 5s block/recovery; waitchain uses two Win32
mutex owners waiting on each other. Ready data is a public QA-only JSON with
real OS IDs. A local stop marker or 75-second TTL makes the fixture exit itself.
No external target is terminated. The waitchain fixture deliberately leaves
its blocked daemon waiters/handles for OS process-exit cleanup, never closes
an in-use wait handle. Source and bundled self-fixture require no SDK download.

`tests/test_bbdi_windows_observer.py` verifies fixed ABI, fake denied/unknown/
churn/identity contracts on Linux, plus actual native HWND freeze/recovery,
non-GUI enumeration and a real mutex WCT cycle **or exact permission failure**
on Windows. Native results are printed as BB_DI_001_REAL_* evidence in CI logs.
Denied WCT is a conditional path, not proof that the positive cycle was run.

`app.py --deep-smoke --qa-output <dir>` drives three real Qt action cycles,
Standard/Detailed sampling, a real auto-trigger, TID deltas, saved investigation,
full selected interval, privacy-dialog-selected ZIP, checksums and unchanged
original SQLite/JSON/HTML. Only public fixture note/file-picker UI is automated;
no sensor values or timestamps are mocked. Test CPU threshold is explicitly
1%/1000 ms through Settings for shared-runner repeatability, not a default or
defect verdict. The frozen job removes Python from PATH and runs from its
evidence directory; the target is another instance of the **same bundled EXE**.
Both source and frozen evidence capture exact requested HEAD, checkout SHA,
runtime/OS versions, SQLite, exports and actual five-page RU/EN screenshots.

Still missing: complete incident cards/pre-post burst policy, ETW, EventPipe,
manual dump import, remaining fixtures, full resource experiment comparison,
real 8h/1h endurance, physical Windows 10/11 DPI/upgrade/AV acceptance.

## Primary API sources

- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw
- https://learn.microsoft.com/en-us/windows/win32/api/wct/ns-wct-waitchain_node_info
- https://learn.microsoft.com/en-us/windows/win32/api/wct/nf-wct-getthreadwaitchain
- https://learn.microsoft.com/en-us/windows/win32/api/wct/nc-wct-pwaitchaincallback
- https://learn.microsoft.com/en-us/windows/win32/api/wct/nf-wct-closethreadwaitchainsession
