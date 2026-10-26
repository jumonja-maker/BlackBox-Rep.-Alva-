using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.CompilerServices;

var source = new FixtureEvents();
for (int i = 0; i < 12; i++)
{
    source.Marker(i, "BLACKBOX_REAL_EVENTPIPE_FIXTURE");
    Work();
    GC.Collect(2, GCCollectionMode.Forced, true, true);
    GC.WaitForPendingFinalizers();
}
Console.WriteLine("FIXTURE_PID=" + Environment.ProcessId);
GC.KeepAlive(source);

[MethodImpl(MethodImplOptions.NoInlining)]
static void Work()
{
    var watch = Stopwatch.StartNew();
    while (watch.ElapsedMilliseconds < 100)
    {
        var bytes = new byte[120000];
        for (int i = 0; i < bytes.Length; i += 64) bytes[i] = (byte)i;
        GC.KeepAlive(bytes);
    }
}
[EventSource(Name = "BlackBox-Decoder-QA")]
sealed class FixtureEvents : EventSource
{
    [Event(1, Level = EventLevel.Informational)]
    public void Marker(int ordinal, string label) => WriteEvent(1, ordinal, label);
}
