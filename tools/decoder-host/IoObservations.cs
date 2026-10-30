// Typed kernel I/O observations. Metadata remains unverified imported evidence.
using System.Buffers.Binary;
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

    static long ResponseTicks(DiskIOTraceData disk)
    {
        // Classic DiskIo_TypeGroup1 v2/v3 layout has two pointer-sized fields
        // (FileObject and Irp) before its 64-bit HighResResponseTime. TraceEvent
        // 4.0.0 exposes the latter getter privately; use the public bounded
        // EventData copy API, never reflection or ticks reconstructed from ms.
        // Layout agrees with its pinned KernelTraceEventParser implementation:
        // https://github.com/microsoft/perfview/blob/v4.0.0/src/TraceEvent/Parsers/KernelTraceEventParser.cs
        if (disk.PointerSize is not (4 or 8) || disk.Version is not (2 or 3))
            throw new InvalidDataException("UNSUPPORTED_DISK_IO_PAYLOAD_LAYOUT");
        int offset = 32 + 2 * (disk.PointerSize - 4);
        if (disk.EventDataLength < offset + sizeof(long))
            throw new InvalidDataException("TRUNCATED_DISK_IO_RESPONSE_COUNTER");
        byte[] counter = new byte[sizeof(long)];
        disk.EventData(counter, 0, offset, counter.Length);
        return BinaryPrimitives.ReadInt64LittleEndian(counter);
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
            long ticks = ResponseTicks(disk);
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
        // Bind the actual parser class to the operation/family. In pinned
        // TraceEvent the public UDP-v6 type is spelled "UpdIpV6TraceData".
        string? name = e switch {
            TcpIpSendTraceData when opcode == 10 => "TcpIp/Send",
            TcpIpTraceData when opcode == 11 => "TcpIp/Recv",
            TcpIpV6SendTraceData when opcode == 26 => "TcpIp/SendIPV6",
            TcpIpV6TraceData when opcode == 27 => "TcpIp/RecvIPV6",
            UdpIpTraceData when opcode == 10 => "UdpIp/Send",
            UdpIpTraceData when opcode == 11 => "UdpIp/Recv",
            UpdIpV6TraceData when opcode == 26 => "UdpIp/SendIPV6",
            UpdIpV6TraceData when opcode == 27 => "UdpIp/RecvIPV6",
            _ => null };
        if (name is null || name != e.EventName || e.Version < 1 || e.Version > 2 ||
            opcode >= 26 && e.Version != 2) return null;
        if (e.EventDataLength < (opcode < 26 ? 20 : 44))
            throw new InvalidDataException("TRUNCATED_TYPED_NETWORK_ENDPOINTS");
        string? protocol = name.StartsWith("TcpIp/", StringComparison.Ordinal) ? "TCP" :
                           name.StartsWith("UdpIp/", StringComparison.Ordinal) ? "UDP" : null;
        if (protocol is null) return null;
        // UDP-v6's public address properties exist, but its PayloadNames omit
        // them in TraceEvent 4.0.0. Read those properties rather than assuming
        // absence from the generic payload means no address was captured.
        string? sourceAddress = Address(e is UpdIpV6TraceData sourceV6 ? sourceV6.saddr : e.PayloadByName("saddr"));
        string? destinationAddress = Address(e is UpdIpV6TraceData destinationV6 ? destinationV6.daddr : e.PayloadByName("daddr"));
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
