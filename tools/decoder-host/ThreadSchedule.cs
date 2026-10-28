// Typed scheduler projection. Never classify arbitrary similarly named events.
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

internal static class ThreadSchedule
{
    static object Identity(TraceLog log, int tid, int expectedPid, double time)
    {
        TraceThread? thread = tid > 0 ? log.Threads.GetThread(tid, time) : null;
        var process = thread?.Process;
        bool valid = thread != null && process != null && process.ProcessID > 0 &&
            (expectedPid < 0 || expectedPid == process.ProcessID) &&
            (int)thread.ThreadIndex >= 0 && (int)process.ProcessIndex >= 0 &&
            double.IsFinite(thread.StartTimeRelativeMSec) && double.IsFinite(thread.EndTimeRelativeMSec) &&
            thread.StartTimeRelativeMSec <= time && time <= thread.EndTimeRelativeMSec;
        return new {
            tid, pid = valid ? process!.ProcessID : expectedPid,
            thread_instance = valid ? (int?)thread!.ThreadIndex : null,
            process_instance = valid ? (int?)process!.ProcessIndex : null,
            start_ms = valid ? (double?)thread!.StartTimeRelativeMSec : null,
            end_ms = valid ? (double?)thread!.EndTimeRelativeMSec : null,
            attribution = valid ? "TRACELOG_THREAD_LIFETIME" : "UNRESOLVED_THREAD"
        };
    }

    public static object? Project(TraceEvent e, TraceLog log)
    {
        if (e.ProviderGuid != KernelTraceEventParser.ProviderGuid || (int)e.ID != 65535) return null;
        if (e is CSwitchTraceData cs && (int)e.Opcode == 36)
            return new {
                schema = "blackbox.thread-schedule/1", source = "ETW_KERNEL_SCHEDULER",
                parser = "TRACEEVENT_CSWITCH", kind = "switch", processor_index = e.ProcessorNumber,
                old_thread = Identity(log, cs.OldThreadID, cs.OldProcessID, e.TimeStampRelativeMSec),
                new_thread = Identity(log, cs.NewThreadID, cs.NewProcessID, e.TimeStampRelativeMSec),
                old_state_code = (int)cs.OldThreadState, old_state = cs.OldThreadState.ToString(),
                wait_reason_code = (int)cs.OldThreadWaitReason, wait_reason = cs.OldThreadWaitReason.ToString(),
                wait_mode = (int)cs.OldThreadWaitMode
            };
        if (e is DispatcherReadyThreadTraceData ready && (int)e.Opcode == 50)
            return new {
                schema = "blackbox.thread-schedule/1", source = "ETW_KERNEL_SCHEDULER",
                parser = "TRACEEVENT_READY_THREAD", kind = "ready", processor_index = e.ProcessorNumber,
                ready_thread = Identity(log, ready.AwakenedThreadID, ready.AwakenedProcessID, e.TimeStampRelativeMSec),
                waker_thread = Identity(log, e.ThreadID, e.ProcessID, e.TimeStampRelativeMSec)
            };
        return null;
    }
}
