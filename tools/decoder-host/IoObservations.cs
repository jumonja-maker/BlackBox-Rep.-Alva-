// Typed kernel I/O observations. Metadata remains unverified imported evidence.
using System.Globalization;
using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

internal static class IoObservations
{
    const string Schema = "blackbox.trace-io/1";

    static long Unsigned(object? value, long maximum)
    {
        if (value is not (byte or ushort or uint or ulong or sbyte or short or int or long))
            throw new InvalidDataException("IO_INTEGER_FIELD_UNAVAILABLE");
        long number = Convert.ToInt64(value, CultureInfo.InvariantCulture);
        if (number < 0 || number > maximum) throw new InvalidDataException("IO_INTEGER_FIELD_RANGE");
        return number;
    }

    static string? Address(object? value)
    {
        if (value is IPAddress address) return address.ToString();
        if (value is string text && text.Length <= 128 &&
            (text.Contains('.') || text.Contains(':')) && IPAddress.TryParse(text, out var parsed))
            return parsed.ToString();
        return null;
    }

    internal static object? Project(TraceEvent e, long? counterFrequency)
    {
        if (e.ProviderGuid != KernelTraceEventParser.ProviderGuid || (int)e.ID != 65535)
            return null;
        int opcode = (int)e.Opcode;
        if (e is DiskIOTraceData disk && (opcode == 10 || opcode == 11) &&
            e.Version >= 2 && e.Version <= 3)
        {
            // TraceEvent's documented HighResResponseTime is in source QPC
            // ticks; retain both its unit and the persisted source frequency.
            if (!counterFrequency.HasValue || counterFrequency.Value <= 0) return null;
            long ticks = disk.HighResResponseTime;
            double elapsed = disk.ElapsedTimeMSec;
            long size = disk.TransferSize;
            if (ticks < 0 || size < 0 || !double.IsFinite(elapsed) || elapsed < 0)
                throw new InvalidDataException("INVALID_TYPED_DISK_IO");
            double expected = ticks * 1000.0 / counterFrequency.Value;
            if (Math.Abs(expected - elapsed) > Math.Max(0.000001, elapsed * 1e-10))
                throw new InvalidDataException("DISK_IO_SOURCE_CLOCK_DISAGREEMENT");
            return new { schema = Schema, source = "ETW_KERNEL_DISK_IO", parser = "TRACEEVENT_DISK_IO",
                kind = "disk", operation = opcode == 10 ? "read" : "write",
                transferred_bytes = size, elapsed_ms = elapsed, response_qpc_ticks = ticks,
                counter_frequency_hz = counterFrequency.Value,
                duration_basis = "COMPLETION_EVENT_REPORTED_QPC_DURATION",
                start_boundary_observed = false, device_busy_time_established = false };
        }
        bool typedNetwork = e is TcpIpTraceData || e is TcpIpSendTraceData ||
                            e is TcpIpV6TraceData || e is TcpIpV6SendTraceData || e is UdpIpTraceData;
        if (!typedNetwork || e.Version < 1 || e.Version > 2 ||
            (opcode != 10 && opcode != 11 && opcode != 26 && opcode != 27)) return null;
        string name = e.EventName;
        string? protocol = name.StartsWith("TcpIp/", StringComparison.Ordinal) ? "TCP" :
                           name.StartsWith("UdpIp/", StringComparison.Ordinal) ? "UDP" : null;
        if (protocol is null) return null;
        string? sourceAddress = Address(e.PayloadByName("saddr"));
        string? destinationAddress = Address(e.PayloadByName("daddr"));
        return new { schema = Schema, source = "ETW_KERNEL_NETWORK",
            parser = "TRACEEVENT_" + e.GetType().Name, kind = "network", protocol,
            operation = opcode == 10 || opcode == 26 ? "send" : "receive",
            family = opcode < 26 ? "IPv4" : "IPv6",
            transferred_bytes = Unsigned(e.PayloadByName("size"), uint.MaxValue),
            source_address = sourceAddress, destination_address = destinationAddress,
            source_port = Unsigned(e.PayloadByName("sport"), ushort.MaxValue),
            destination_port = Unsigned(e.PayloadByName("dport"), ushort.MaxValue),
            address_status = sourceAddress is not null && destinationAddress is not null ? "DECODED" : "INCOMPLETE_EVIDENCE",
            byte_count_scope = "THIS_RECORDED_KERNEL_EVENT_NOT_PROCESS_OR_LINK_TOTAL",
            packet_contents = "NOT_COLLECTED" };
    }
}
