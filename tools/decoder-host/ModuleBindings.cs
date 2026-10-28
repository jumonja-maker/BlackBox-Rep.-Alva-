// TraceEvent observations only; no local image/PDB loading or symbol lookup.
using System.Globalization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;

internal sealed class ModuleBindings
{
    private const int MaxProcesses = 4096;
    private const int MaxLoads = 8192;
    private readonly Dictionary<int, LoadIndex?> processes = new();

    private sealed record Load(TraceLoadedModule Module, ulong Start, ulong End);
    private sealed class LoadIndex
    {
        public Load[] Loads;
        public ulong[] PrefixEnd;
        public LoadIndex(Load[] loads)
        {
            Loads = loads.OrderBy(x => x.Start).ToArray();
            PrefixEnd = new ulong[Loads.Length];
            ulong max = 0;
            for (int i = 0; i < Loads.Length; i++)
            {
                max = Math.Max(max, Loads[i].End); PrefixEnd[i] = max;
            }
        }
    }

    public (object? Module, uint? Rva, string Status) Associate(TraceEvent e, TraceCodeAddress code)
    {
        var process = e.Process();
        if (process == null || e.ProcessID <= 0 || (int)process.ProcessIndex < 0)
            return (null, null, "PROCESS_INSTANCE_UNAVAILABLE");
        if (code.Method != null && code.Method.MethodToken != 0)
            return (null, null, "MANAGED_CODE_NOT_NATIVE_RVA");
        int processIndex = (int)process.ProcessIndex;
        if (!processes.TryGetValue(processIndex, out var index))
        {
            if (processes.Count >= MaxProcesses)
                return (null, null, "MODULE_PROCESS_BUDGET");
            var loads = new List<Load>();
            int visited = 0;
            foreach (var loaded in process.LoadedModules)
            {
                if (++visited > MaxLoads) { processes[processIndex] = null; return (null, null, "MODULE_LOAD_BUDGET"); }
                var file = loaded.ModuleFile;
                if (loaded is TraceManagedModule || loaded.ManagedModule != null || file == null ||
                    file.ManagedModule != null || file.IsReadyToRun || loaded.ImageBase == 0 ||
                    file.ImageSize <= 0 || file.ImageSize > uint.MaxValue ||
                    loaded.ImageBase > ulong.MaxValue - (ulong)file.ImageSize) continue;
                loads.Add(new Load(loaded, loaded.ImageBase, loaded.ImageBase+(ulong)file.ImageSize));
            }
            index = new LoadIndex(loads.ToArray()); processes.Add(processIndex, index);
        }
        if (index == null) return (null, null, "MODULE_LOAD_BUDGET");
        ulong address = code.Address;
        int lo = 0, hi = index.Loads.Length;
        while (lo < hi)
        {
            int mid = lo+(hi-lo)/2;
            if (index.Loads[mid].Start <= address) lo = mid+1; else hi = mid;
        }
        TraceLoadedModule? found = null;
        for (int i = lo-1; i >= 0 && index.PrefixEnd[i] > address; i--)
        {
            var entry = index.Loads[i]; var m = entry.Module;
            if (entry.Start <= address && address < entry.End &&
                m.LoadTimeRelativeMSec <= e.TimeStampRelativeMSec &&
                e.TimeStampRelativeMSec < m.UnloadTimeRelativeMSec)
            {
                if (found != null) return (null, null, "AMBIGUOUS_NATIVE_LOAD_WINDOW");
                found = m;
            }
        }
        if (found == null) return (null, null, "NATIVE_LOAD_WINDOW_NOT_RECORDED");
        var module = found.ModuleFile;
        // A conflicting TraceEvent code-to-module mapping must not be overwritten.
        if (code.ModuleFile != null && code.ModuleFile.ModuleFileIndex != module.ModuleFileIndex)
            return (null, null, "CONFLICTING_CODE_MODULE_ASSOCIATION");
        string name = module.FilePath.Replace('\\', '/').Split('/').Last();
        if (name.Length == 0 || name.Length > 255 || name.Any(c => c < 32 || c == ':') ||
            !double.IsFinite(found.LoadTimeRelativeMSec) || !double.IsFinite(found.UnloadTimeRelativeMSec) ||
            Math.Abs(found.LoadTimeRelativeMSec) >= 1e15 || Math.Abs(found.UnloadTimeRelativeMSec) >= 1e15)
            return (null, null, "MODULE_METADATA_UNAVAILABLE");
        bool hasPdb = module.PdbSignature != Guid.Empty && module.PdbAge > 0;
        return (new {
            schema = "blackbox.trace-module/1", source = "TRACEEVENT_NATIVE_LOAD_WINDOW",
            process_instance = processIndex, module_file_index = (int)module.ModuleFileIndex,
            image_base = "0x"+found.ImageBase.ToString("x", CultureInfo.InvariantCulture),
            image_size = module.ImageSize, image_timestamp = unchecked((uint)module.ImageId),
            load_time_ms = found.LoadTimeRelativeMSec, unload_time_ms = found.UnloadTimeRelativeMSec,
            pdb_guid = hasPdb ? module.PdbSignature.ToString() : null,
            pdb_age = hasPdb ? (int?)module.PdbAge : null, module_name = name
        }, checked((uint)(address-found.ImageBase)), "TRACE_NATIVE_MODULE_OBSERVED_UNVERIFIED");
    }
}
