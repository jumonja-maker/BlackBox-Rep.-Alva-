// FIX-09: local voluntary EventSource and actual GC pressure. No packages.
using System;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.IO;
using System.Text.Json;
using System.Threading;

[EventSource(Name="BlackBox-Controlled-Runtime-Probe")]
sealed class ProbeEvents : EventSource {
    public static readonly ProbeEvents Log = new ProbeEvents();
    [Event(1,Level=EventLevel.Informational)] public void BeginWork(int cycle) { WriteEvent(1,cycle); }
    [Event(2,Level=EventLevel.Informational)] public void EndWork(int cycle) { WriteEvent(2,cycle); }
    [Event(3,Level=EventLevel.Informational)] public void Heartbeat(int cycle,long allocated) { WriteEvent(3,cycle,allocated); }
}
class Program {
    static int Main(string[] args) {
        if(args.Length<1) return 2;
        string root=Path.GetFullPath(args[0]); Directory.CreateDirectory(root);
        double seconds=args.Length>1?double.Parse(args[1],System.Globalization.CultureInfo.InvariantCulture):30;
        if(seconds<1 || seconds>3600) return 2;
        int pid=Environment.ProcessId;
        File.WriteAllText(Path.Combine(root,"ready.json"),JsonSerializer.Serialize(new {
            fixture="FIX-09_REAL_MANAGED_RUNTIME",pid=pid,runtime=Environment.Version.ToString(),
            source="BlackBox-Controlled-Runtime-Probe",gc_events="REQUIRE_REAL_EVENTPIPE_PROVIDER_NOT_THIS_JSON"}));
        var clock=Stopwatch.StartNew();int cycle=0;
        while(clock.Elapsed.TotalSeconds<seconds && !File.Exists(Path.Combine(root,"stop.request"))) {
            ProbeEvents.Log.BeginWork(cycle);
            for(int i=0;i<32;i++) {
                byte[] data=new byte[65536];data[0]=(byte)cycle;
                GC.KeepAlive(data);
            }
            if(cycle%10==0)GC.Collect(0,GCCollectionMode.Forced,false);
            ProbeEvents.Log.EndWork(cycle);
            ProbeEvents.Log.Heartbeat(cycle,GC.GetTotalAllocatedBytes());
            cycle++;Thread.Sleep(50);
        }
        return 0;
    }
}
