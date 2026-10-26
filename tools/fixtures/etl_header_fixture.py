"""QA-only named ETW session and 12 real manifestless header events.

Only this random session is stopped. No kernel providers or global sessions.
Manifestless payload decoding is deliberately outside this fixture's contract.
"""
import ctypes as C,os,time
from ctypes import wintypes as W
from pathlib import Path
from uuid import uuid4

def capture(path):
 if os.name!='nt':raise OSError('WINDOWS_ETW_FIXTURE_REQUIRED')
 path=Path(path).absolute()
 if path.exists():raise FileExistsError(path)
 api=C.WinDLL('advapi32.dll',use_last_error=True,winmode=0x800)
 class Guid(C.Structure):_fields_=[('raw',C.c_ubyte*16)]
 class Wnode(C.Structure):
  _fields_=[('BufferSize',W.ULONG),('ProviderId',W.ULONG),('HistoricalContext',C.c_uint64),('TimeStamp',C.c_int64),('Guid',Guid),('ClientContext',W.ULONG),('Flags',W.ULONG)]
 class Properties(C.Structure):
  _fields_=[('Wnode',Wnode)]+[(n,W.ULONG) for n in ('BufferSize','MinimumBuffers','MaximumBuffers','MaximumFileSize','LogFileMode','FlushTimer','EnableFlags','AgeLimit','NumberOfBuffers','FreeBuffers','EventsLost','BuffersWritten','LogBuffersLost','RealTimeBuffersLost')]+[('LoggerThreadId',W.HANDLE),('LogFileNameOffset',W.ULONG),('LoggerNameOffset',W.ULONG)]
 class Descriptor(C.Structure):
  _fields_=[('Id',W.USHORT),('Version',W.BYTE),('Channel',W.BYTE),('Level',W.BYTE),('Opcode',W.BYTE),('Task',W.USHORT),('Keyword',C.c_uint64)]
 api.StartTraceW.argtypes=[C.POINTER(C.c_uint64),W.LPCWSTR,C.POINTER(Properties)];api.StartTraceW.restype=W.ULONG
 api.ControlTraceW.argtypes=[C.c_uint64,W.LPCWSTR,C.POINTER(Properties),W.ULONG];api.ControlTraceW.restype=W.ULONG
 api.EnableTraceEx2.argtypes=[C.c_uint64,C.POINTER(Guid),W.ULONG,W.BYTE,C.c_uint64,C.c_uint64,W.ULONG,C.c_void_p];api.EnableTraceEx2.restype=W.ULONG
 api.EventRegister.argtypes=[C.POINTER(Guid),C.c_void_p,C.c_void_p,C.POINTER(C.c_uint64)];api.EventRegister.restype=W.ULONG
 api.EventWrite.argtypes=[C.c_uint64,C.POINTER(Descriptor),W.ULONG,C.c_void_p];api.EventWrite.restype=W.ULONG
 api.EventUnregister.argtypes=[C.c_uint64];api.EventUnregister.restype=W.ULONG
 name='BLACKBOX_QA_HEADERS_'+uuid4().hex;guid=Guid.from_buffer_copy(uuid4().bytes_le)
 namebuf=C.create_unicode_buffer(name);filebuf=C.create_unicode_buffer(str(path))
 size=C.sizeof(Properties)+C.sizeof(namebuf)+C.sizeof(filebuf);raw=C.create_string_buffer(size);p=C.cast(raw,C.POINTER(Properties));v=p.contents
 v.Wnode.BufferSize=size;v.Wnode.Guid=Guid.from_buffer_copy(uuid4().bytes_le);v.Wnode.Flags=0x20000;v.Wnode.ClientContext=1
 v.BufferSize=16;v.MinimumBuffers=2;v.MaximumBuffers=4;v.MaximumFileSize=4;v.LogFileMode=1;v.FlushTimer=1
 v.LoggerNameOffset=C.sizeof(Properties);v.LogFileNameOffset=v.LoggerNameOffset+C.sizeof(namebuf)
 C.memmove(C.addressof(raw)+v.LoggerNameOffset,namebuf,C.sizeof(namebuf));C.memmove(C.addressof(raw)+v.LogFileNameOffset,filebuf,C.sizeof(filebuf))
 session=C.c_uint64();provider=C.c_uint64();started=False;registered=False;stop_code=None
 def check(code):
  if code:raise OSError(code,'REAL_ETW_HEADER_FIXTURE_FAILED')
 try:
  check(api.StartTraceW(C.byref(session),name,p));started=True
  check(api.EventRegister(C.byref(guid),None,None,C.byref(provider)));registered=True
  check(api.EnableTraceEx2(session.value,C.byref(guid),1,5,1,0,1000,None))
  event=Descriptor();event.Id=7;event.Version=1;event.Level=4;event.Keyword=1
  for _ in range(12):check(api.EventWrite(provider.value,C.byref(event),0,None));time.sleep(.01)
 finally:
  if registered:api.EventUnregister(provider.value)
  if started:stop_code=api.ControlTraceW(session.value,name,p,1)
 if stop_code:raise OSError(stop_code,'OWNED_ETW_FIXTURE_STOP_FAILED')
 return {'events_written':12,'pid':os.getpid(),'provider_guid_bytes_le':bytes(guid.raw).hex(),'session':name,
  'events_lost_reported_by_owned_session':v.EventsLost,'log_buffers_lost':v.LogBuffersLost,'api_properties_size':C.sizeof(Properties)}
