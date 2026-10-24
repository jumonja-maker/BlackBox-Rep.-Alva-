"""Concrete local application preparation and self-event verification."""
from __future__ import annotations
import json
from pathlib import Path
import shutil
from .windows_research import capabilities


def inspect_target(pid):
    import psutil
    p=psutil.Process(pid)
    candidates=[];status="OBSERVED_MODULE_NAMES_NOT_PROOF_OF_PRIMARY_RUNTIME"
    try:
        for index,m in enumerate(p.memory_maps(grouped=True)):
            if index>=4096:status="TRUNCATED_MODULE_LIST";break
            name=Path(m.path).name.lower()
            for key,terms in (("python",("python3","libpython")),("dotnet",("coreclr","clr.dll")),
                              ("electron",("electron","chrome_elf"))):
                if any(t in name for t in terms) and key not in candidates:candidates.append(key)
    except (psutil.Error,OSError,NotImplementedError):status="MODULE_INSPECTION_UNAVAILABLE"
    return {"pid":pid,"created":p.create_time(),"runtime_candidates":candidates,
            "detection_status":status,"capabilities":capabilities(),
            "ready_event_verified":False,"source_trust":"APP_EVENTS_UNAUTHENTICATED"}


def write_preparation(folder, event_path, token):
    """Standalone clients and exact instructions; no changes to target project."""
    folder=Path(folder)
    folder.mkdir(exist_ok=False)
    shutil.copyfile(Path(__file__).with_name("instrumentation.py"),folder/"blackbox_event_client.py")
    config={"schema_version":1,"path":str(event_path),"token":token,
            "trace_output":str(Path(event_path).parent/"artifacts"/"electron-trace.pftrace")}
    (folder/"blackbox-config.json").write_text(json.dumps(config,ensure_ascii=False,indent=2),encoding="utf-8")
    py='''import json
from blackbox_event_client import EventWriter
config = json.load(open("blackbox-config.json", encoding="utf-8"))
bb = EventWriter(config["path"], config["token"])
bb.emit("blackbox.ready")
with bb.operation("Save project"):
    pass  # Place your real operation here.
'''
    (folder/"example.py").write_text(py,encoding="utf-8")
    cs=r'''using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.Runtime.InteropServices;

public sealed class BlackBoxEvents {
  [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
  readonly string path, token; readonly object sync = new object(); long seq;
  public BlackBoxEvents(string configPath) {
    using var config = JsonDocument.Parse(File.ReadAllText(configPath));
    path = config.RootElement.GetProperty("path").GetString();
    token = config.RootElement.GetProperty("token").GetString();
  }
  // Call Emit("blackbox.ready") and check BLACK.BOX's verification result.
  public bool Emit(string kind, string operationId = null, object attributes = null) {
    lock (sync) { try {
      var value = new { schema_version = 1, token, pid = Environment.ProcessId,
        tid = GetCurrentThreadId(), seq = ++seq, kind,
        source_clock = "DOTNET_STOPWATCH", source_ns =
          (long)((decimal)Stopwatch.GetTimestamp()*1000000000m/Stopwatch.Frequency),
        operation_id = operationId, parent_id = (string)null,
        attributes = attributes ?? new {}, client_dropped = 0 };
      var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)+"\n");
      if (bytes.Length>8192 || (File.Exists(path) && new FileInfo(path).Length+bytes.Length>67108864)) return false;
      using var output = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
      output.Write(bytes,0,bytes.Length); output.Flush(); return true;
    } catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { return false; } }
  }
}
'''
    (folder/"BlackBoxEvents.cs").write_text(cs,encoding="utf-8")
    cpp=r'''#pragma once
#include <windows.h>
#include <string>
#include <atomic>
#include <mutex>
// Windows C++17 client. Path/token come from blackbox-config.json.
class BlackBoxEvents {
  std::wstring path; std::string token; unsigned long long seq=0; std::mutex mutex;
  static std::string quote(const std::string& s) {
    std::string out="\""; const char* hex="0123456789abcdef";
    for (unsigned char c:s) { if (c=='"'||c=='\\') { out+='\\';out+=c; }
      else if(c<32 || c>=127) { out+="\\u00";out+=hex[c>>4];out+=hex[c&15]; } else out+=c; }
    return out+"\"";
  }
public:
  BlackBoxEvents(std::wstring file, std::string key):path(file),token(key){}
  bool emit(const std::string& kind,const std::string& operation="") {
    std::lock_guard<std::mutex> lock(mutex);
    auto line=std::string("{\"schema_version\":1,\"token\":")+quote(token)+
      ",\"pid\":"+std::to_string(GetCurrentProcessId())+",\"tid\":"+std::to_string(GetCurrentThreadId())+
      ",\"seq\":"+std::to_string(++seq)+",\"kind\":"+quote(kind)+
      ",\"source_clock\":\"WIN32_GETTICKCOUNT64\",\"source_ns\":"+std::to_string(GetTickCount64()*1000000ULL)+
      ",\"operation_id\":"+quote(operation)+",\"attributes\":{},\"client_dropped\":0}\n";
    if(line.size()>8192)return false;
    HANDLE f=CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE)return false;
    LARGE_INTEGER size; bool ok=GetFileSizeEx(f,&size) && size.QuadPart+line.size()<=67108864;
    DWORD written=0; if(ok)ok=WriteFile(f,line.data(),(DWORD)line.size(),&written,nullptr) && written==line.size();
    CloseHandle(f);return ok;
  }
};
'''
    (folder/"BlackBoxEvents.hpp").write_text(cpp,encoding="utf-8")
    js=r'''const fs = require('node:fs');
const { threadId } = require('node:worker_threads');
const { randomUUID } = require('node:crypto');
class BlackBoxEvents {
  constructor(configPath) { this.config=JSON.parse(fs.readFileSync(configPath,'utf8')); this.seq=0; this.dropped=0; }
  emit(kind, operationId=null, attributes={}) {
    try {
      const record={schema_version:1,token:this.config.token,pid:process.pid,
        tid:threadId,tid_kind:'RUNTIME_THREAD_ID',seq:++this.seq,kind,
        source_clock:'NODE_HRTIME_BIGINT',source_ns:process.hrtime.bigint().toString(),
        operation_id:operationId,parent_id:null,attributes,client_dropped:this.dropped};
      const data=Buffer.from(JSON.stringify(record)+'\n','utf8');
      if(data.length>8192 || (fs.existsSync(this.config.path) && fs.statSync(this.config.path).size+data.length>67108864)) throw Error('event budget');
      fs.appendFileSync(this.config.path,data,{mode:0o600});return true;
    } catch (_) { this.dropped++;return false; }
  }
  async operation(name, callback) {
    const id=randomUUID();this.emit('operation.begin',id,{name});
    try { return await callback(id); }
    catch (error) { this.emit('operation.error',id,{error_type:error.name});throw error; }
    finally { this.emit('operation.end',id); }
  }
  // Call only after Electron app.whenReady(); capture is explicit.
  async startChromeTrace(contentTracing) {
    await contentTracing.startRecording({included_categories:['*']});
    this.emit('chrome.trace.started');
  }
  async stopChromeTrace(contentTracing) {
    fs.mkdirSync(require('node:path').dirname(this.config.trace_output),{recursive:true});
    const path=await contentTracing.stopRecording(this.config.trace_output);
    this.emit('chrome.trace.stopped',null,{path,format:'RUNTIME_DEFINED_JSON_OR_PERFETTO'});return path;
  }
}
module.exports={BlackBoxEvents};
'''
    (folder/"blackbox-events.cjs").write_text(js,encoding="utf-8")
    instructions=("BLACK.BOX — подготовка / application preparation\n\n"
        "1. Python: copy blackbox_event_client.py and blackbox-config.json beside your program; use example.py.\n"
        "2. .NET 6+: include BlackBoxEvents.cs; construct with the config path; call Emit(\"blackbox.ready\").\n"
        "3. Windows C++17: include BlackBoxEvents.hpp; supply the path and token from config; emit blackbox.ready.\n"
        "4. Node/Electron: require blackbox-events.cjs; construct BlackBoxEvents(configPath); emit blackbox.ready.\n"
        "   After app.whenReady(), explicit startChromeTrace(contentTracing)/stopChromeTrace(contentTracing) captures the runtime's trace.\n"
        "   Other runtimes: append JSONL matching the clients' schema (8192-byte maximum per event).\n"
        "5. Run your REAL selected application; BLACK.BOX must receive blackbox.ready from its PID.\n"
        "6. Add operation.begin / operation.end using the same operation_id.\n"
        "7. Native names: keep matching PDB files with the EXACT binaries; use a local debugger to analyse a captured dump.\n"
        "8. Event clocks retain their source identity; receipt time is not execution time.\n"
        "Скопируйте клиент для своего языка и конфигурацию в проект. Отправьте blackbox.ready из выбранного процесса.\n"
        "Готовность подтверждается только после получения события. События приложения не являются доверенным подтверждением ОС.\n"
        "These files do not execute commands or modify your project automatically.\n")
    (folder/"README.txt").write_text(instructions,encoding="utf-8")
    return {"folder":str(folder),"instructions":instructions,"event_path":str(event_path),"token":token}
