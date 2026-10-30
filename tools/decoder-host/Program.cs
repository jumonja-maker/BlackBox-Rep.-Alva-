// Offline decoder only. No capture sessions, target attachment or symbol servers.
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

internal static class Program
{
    const string Protocol = "blackbox.trace-event/1";
    const long MaxInput = 256L * 1024 * 1024;
    const long MaxOutput = 384L * 1024 * 1024;
    const int MaxEvents = 250000;
    static readonly JsonSerializerOptions Json = new() { MaxDepth = 24 };

    static string Hash(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
    }
    static string Bounded(string? value, ref bool clipped, int limit = 2048)
    {
        value ??= "";
        if (value.Length <= limit) return value;
        clipped = true;
        return value[..limit];
    }
    static object? Value(object? value, ref bool clipped)
    {
        if (value == null || value is bool || value is byte || value is sbyte ||
            value is short || value is ushort || value is int || value is uint ||
            value is long || value is ulong || value is decimal) return value;
        if (value is double d && double.IsFinite(d)) return d;
        if (value is float f && float.IsFinite(f)) return f;
        if (value is string text) return Bounded(text, ref clipped);
        if (value is Enum) return value.ToString();
        // Do not invoke arbitrary object graphs or pretend an array was decoded.
        clipped = true;
        return "UNSUPPORTED_VALUE_TYPE:" + value.GetType().Name;
    }
    static Dictionary<string, object?>? Semantic(TraceEvent e)
    {
        if (e is GCStartTraceData start)
            return new() { ["kind"] = "gc_start", ["number"] = start.Count,
                ["runtime"] = start.ClrInstanceID, ["generation"] = start.Depth,
                ["gc_type"] = start.Type.ToString(), ["reason"] = start.Reason.ToString() };
        if (e is GCEndTraceData stop)
            return new() { ["kind"] = "gc_stop", ["number"] = stop.Count,
                ["runtime"] = stop.ClrInstanceID };
        if (e is GCSuspendEETraceData suspend)
            return new() { ["kind"] = "suspend_begin", ["runtime"] = suspend.ClrInstanceID,
                ["reason"] = suspend.Reason.ToString() };
        if (e.ProviderGuid == ClrTraceEventParser.ProviderGuid && e is GCNoUserDataTraceData)
        {
            string? kind = e.OpcodeName switch {
                "SuspendEEStop" => "suspend_end", "RestartEEStart" => "restart_begin",
                "RestartEEStop" => "restart_end", _ => null };
            if (kind != null) return new() { ["kind"] = kind,
                ["runtime"] = e.PayloadByName("ClrInstanceID") };
        }
        return null;
    }
    static readonly ModuleBindings Modules = new();

    static long? SourceCounterFrequency(TraceLog log)
    {
        // TraceEvent 4.0.0 persists the original source counter frequency in
        // ETLX, but exposes it only internally. Read that one pinned metadata
        // property; do not estimate a frequency from event pairs or UTC.
        // If a future engine changes it, leave the value unknown and let the
        // alignment gate refuse correlation rather than guessing OS frequency.
        var property = typeof(TraceEventSource).GetProperty("QPCFreq",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        return property?.GetValue(log) is long hz && hz > 0 ? hz : null;
    }

    static object Row(TraceEvent e, long ordinal, TraceLog log)
    {
        bool clipped = false;
        var payload = new Dictionary<string, object?>();
        var errors = new List<string>();
        var names = e.PayloadNames ?? Array.Empty<string>();
        for (int i = 0; i < Math.Min(32, names.Length); i++)
        {
            try { payload[Bounded(names[i], ref clipped, 128)] = Value(e.PayloadValue(i), ref clipped); }
            catch (Exception ex) { errors.Add("PAYLOAD:" + i + ":" + ex.GetType().Name); }
        }
        if (names.Length > 32) clipped = true;
        int? processIndex = null;
        try { var process = e.Process(); if (process != null && (int)process.ProcessIndex >= 0) processIndex = (int)process.ProcessIndex; }
        catch (Exception ex) { errors.Add("PROCESS_IDENTITY:" + ex.GetType().Name); }
        var frames = new List<object>();
        string stackStatus = "NOT_RECORDED_OR_UNAVAILABLE";
        try
        {
            var stack = e.CallStack();
            if (stack != null) stackStatus = "RECORDED_ADDRESSES_OFFLINE_NAMES";
            while (stack != null && frames.Count < 128)
            {
                var address = stack.CodeAddress;
                var frame = new Dictionary<string, object?> {
                    ["address"] = "0x" + address.Address.ToString("x", CultureInfo.InvariantCulture),
                    ["name"] = Bounded(address.FullMethodName, ref clipped, 512) };
                try
                {
                    var association = Modules.Associate(e, address);
                    frame["module_status"] = association.Status;
                    if (association.Module != null)
                    {
                        frame["module"] = association.Module;
                        frame["rva"] = association.Rva;
                    }
                }
                catch (Exception ex)
                {
                    frame["module_status"] = "MODULE_ASSOCIATION_UNAVAILABLE";
                    errors.Add("MODULE:" + ex.GetType().Name);
                }
                frames.Add(frame);
                stack = stack.Caller;
            }
            if (stack != null) { stackStatus = "TRUNCATED_128_FRAMES"; clipped = true; }
        }
        catch (Exception ex) { stackStatus = "DECODE_ERROR"; errors.Add("STACK:" + ex.GetType().Name); }
        Dictionary<string, object?>? semantic = null;
        try { semantic = Semantic(e); }
        catch (Exception ex) { errors.Add("SEMANTIC:" + ex.GetType().Name); }
        object? cpuSample = null;
        try
        {
            // Only the typed kernel profile record. GC, PMC, stackwalk and
            // similarly named arbitrary events must never become CPU weight.
            if (e is SampledProfileTraceData sample &&
                e.ProviderGuid == KernelTraceEventParser.ProviderGuid &&
                (int)e.ID == 65535 && (int)e.Opcode == 46)
                cpuSample = new {
                    schema = "blackbox.cpu-sample/1", source = "ETW_KERNEL_PROFILE",
                    parser = "TRACEEVENT_SAMPLED_PROFILE",
                    instruction_pointer = "0x" + sample.InstructionPointer.ToString("x", CultureInfo.InvariantCulture),
                    processor_index = e.ProcessorNumber,
                    executing_dpc = e.Version >= 2 ? (bool?)sample.ExecutingDPC : null,
                    executing_isr = e.Version >= 2 ? (bool?)sample.ExecutingISR : null
                };
        }
        catch (Exception ex) { errors.Add("CPU_CLASSIFICATION:" + ex.GetType().Name); }
        object? schedule = null;
        try { schedule = ThreadSchedule.Project(e, log); }
        catch (Exception ex) { errors.Add("SCHEDULER_CLASSIFICATION:" + ex.GetType().Name); }
        object? ioObservation = null;
        try {
            ioObservation = IoObservations.Project(e,
                e is DiskIOTraceData ? SourceCounterFrequency(log) : null);
        }
        catch (Exception ex) { errors.Add("IO_CLASSIFICATION:" + ex.GetType().Name); }
        // UTC is TraceEvent's reconstruction from the trace clock (QPC), NOT
        // an independently authenticated wall-clock sample or proof that this
        // trace can be aligned to another BLACK.BOX session.
        string utcTicks = e.TimeStamp.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture);
        return new { type = "event", ordinal, source_index = e.EventIndex.ToString(),
            time_ms = e.TimeStampRelativeMSec, source_ticks = e.TimeStampQPC.ToString(CultureInfo.InvariantCulture),
            utc_ticks = utcTicks, cpu_sample = cpuSample, thread_schedule = schedule,
            io_observation = ioObservation,
            pid = e.ProcessID, tid = e.ThreadID, process_instance = processIndex,
            provider = Bounded(e.ProviderName, ref clipped, 256), provider_guid = e.ProviderGuid.ToString(),
            event_id = (int)e.ID, version = e.Version, name = Bounded(e.EventName, ref clipped, 256),
            opcode = (int)e.Opcode, activity_id = e.ActivityID.ToString(),
            payload, payload_status = errors.Count > 0 ? "PARTIAL" : names.Length == 0 ? "NO_FIELDS_OR_SCHEMA" : clipped ? "BOUNDED" : "DECODED",
            raw_payload_bytes = e.EventDataLength, bounded = clipped, errors, semantic,
            stack_status = stackStatus, frames };
    }
    static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--version")
        {
            Console.WriteLine(JsonSerializer.Serialize(new { protocol = Protocol, host = "0.2.0",
                engine = "Microsoft.Diagnostics.Tracing.TraceEvent",
                version = typeof(TraceEvent).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion }));
            return 0;
        }
        if (args.Length != 2) { Console.Error.WriteLine("USAGE: BLACK.BOX-Decoder input.etl|input.nettrace output.jsonl"); return 2; }
        string input = Path.GetFullPath(args[0]), output = Path.GetFullPath(args[1]);
        string? scratch = null;
        try
        {
            string ext = Path.GetExtension(input).ToLowerInvariant();
            if (ext != ".etl" && ext != ".nettrace") throw new InvalidDataException("UNSUPPORTED_FORMAT");
            if (ext == ".etl" && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("ETL_REQUIRES_WINDOWS");
            var info = new FileInfo(input);
            if (!info.Exists || info.Length <= 0 || info.Length > MaxInput || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("INPUT_BUDGET_OR_TYPE");
            if (File.Exists(output) || Directory.Exists(output) || output == input) throw new IOException("OUTPUT_EXISTS");
            string before = Hash(input);
            scratch = Path.Combine(Path.GetDirectoryName(output)!, ".etlx-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratch);
            string etlx = Path.Combine(scratch, "trace.etlx");
            var options = new TraceLogOptions { KeepAllEvents = true, ContinueOnError = false, LocalSymbolsOnly = true };
            // Explicit scratch path: never create ETLX alongside the user's input.
            if (ext == ".nettrace") TraceLog.CreateFromEventPipeDataFile(input, etlx, options);
            else TraceLog.CreateFromEventTraceLogFile(input, etlx, options);
            using var log = new TraceLog(etlx);
            using var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.WriteLine(JsonSerializer.Serialize(new { type = "header", protocol = Protocol,
                engine = "Microsoft.Diagnostics.Tracing.TraceEvent", package_version = "4.0.0", host_version = "0.2.0",
                source_format = ext, input_sha256 = before, clock = "TRACE_RELATIVE_MILLISECONDS",
                calendar_clock = "TRACEEVENT_QPC_TO_UTC_RECONSTRUCTION_NOT_ATTESTED",
                utc_encoding = "DOTNET_DATETIME_100NS_TICKS_NOT_CAPTURE_ACCURACY",
                trace_to_blackbox_session_clock_alignment = "NOT_ESTABLISHED",
                native_module_contract = "blackbox.trace-module/1",
                trace_counter_frequency_hz = SourceCounterFrequency(log),
                trace_counter_kind = "TRACEEVENT_SOURCE_COUNTER",
                trace_counter_frequency_provenance = "TRACEEVENT_4_0_PERSISTED_SOURCE_METADATA",
                thread_schedule_contract = "blackbox.thread-schedule/1", io_contract = "blackbox.trace-io/1",
                capture_loss = (int?)null, cpu_sample_contract = "blackbox.cpu-sample/1", symbol_policy = "NO_SYMBOL_SERVER_OR_SOURCE_DOWNLOAD" }, Json));
            long count = 0; bool limited = false;
            foreach (var e in log.Events)
            {
                if (count >= MaxEvents || stream.Position > MaxOutput) { limited = true; break; }
                var row = Row(e, ++count, log);
                string line = JsonSerializer.Serialize(row, Json);
                if (Encoding.UTF8.GetByteCount(line) > 256 * 1024) throw new InvalidDataException("EVENT_OUTPUT_BUDGET");
                writer.WriteLine(line);
                if (count % 256 == 0) writer.Flush();
            }
            if (Hash(input) != before) throw new IOException("INPUT_CHANGED");
            writer.WriteLine(JsonSerializer.Serialize(new { type = "footer", protocol = Protocol,
                rows = count, status = limited ? "TRUNCATED" : "DECODED",
                decoder_reported_lost_events = log.EventsLost, capture_loss = (int?)null,
                scope = "TRACELOG_PROJECTION_NOT_PROOF_OF_COMPLETE_CAPTURE" }, Json));
            return 0;
        }
        catch (Exception ex)
        {
            // No partial output is a successful result; Python also requires a footer.
            Console.Error.WriteLine("DECODER_FAILED:" + ex.GetType().Name);
            return 1;
        }
        finally
        {
            if (scratch != null && Directory.Exists(scratch))
                try { Directory.Delete(scratch, true); } catch (IOException) { }
        }
    }
}
