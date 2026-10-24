"""Fixed source IDs; detection is cheap and never starts a deep capture."""
from dataclasses import asdict
from .sensors import Capability

def inventory(platform_capabilities):
 c=platform_capabilities
 specs=(
  Capability('standard','PSUTIL_PROCESS_COUNTERS','AVAILABLE',accuracy='CUMULATIVE_SAMPLED_COUNTERS_NOT_CONTINUOUS'),
  Capability('threads','PSUTIL_THREAD_CPU','AVAILABLE',requires_optin=True,accuracy='SAMPLED_TID_CPU_TID_BIRTH_UNAVAILABLE'),
  Capability('memory','PSUTIL_MEMORY_FULL_INFO','BEST_EFFORT_TARGET_ACCESS',requires_optin=True,accuracy='RSS_PRIVATE_USS_HAVE_DIFFERENT_SEMANTICS'),
  Capability('process_tree','PSUTIL_DESCENDANT_INSTANCES','AVAILABLE',requires_optin=True,accuracy='PID_BIRTH_LINKED_SAMPLED_DESCENDANTS'),
  Capability('window_responsiveness','WIN32_SEND_MESSAGE_TIMEOUT',c.get('hwnd','UNAVAILABLE'),requires_optin=True,supported_os=('Windows',),accuracy='FINITE_WM_NULL_OBSERVATION_NOT_APPLICATION_STATE'),
  Capability('wct','WIN32_WCT',c.get('wct','UNAVAILABLE'),requires_optin=True,supported_os=('Windows',),permissions='TARGET_THREAD_ACCESS_BEST_EFFORT_DEBUG_PRIVILEGE',accuracy='WAIT_CHAIN_AT_QUERY_TIME_NOT_HISTORICAL_CAUSAL_TRACE'),
  Capability('etw','ETW_WPR',c.get('etw_wpr','UNAVAILABLE'),requires_optin=True,supported_os=('Windows',),permissions='WPR_PROVIDER_SPECIFIC_ADMINISTRATOR_MAY_BE_REQUIRED',accuracy='RAW_ETL_UNTIL_EXPLICIT_DECODE_LOSS_UNKNOWN'),
  Capability('runtime','EVENTPIPE_DOTNET_TRACE',c.get('dotnet_trace','UNAVAILABLE'),requires_optin=True,permissions='TARGET_DIAGNOSTIC_PORT',accuracy='NETTRACE_UNDECODED_UNTIL_PROVIDER_PAYLOAD_DECODER'),
  Capability('crash_events','WIN32_APPLICATION_EVENTLOG','AVAILABLE' if c.get('hwnd')!='UNSUPPORTED_PLATFORM' else 'UNSUPPORTED_PLATFORM',requires_optin=True,supported_os=('Windows',),accuracy='NAMED_PAYLOAD_PID_UTC_WINDOW_BIRTH_NOT_ATTESTED'),
  Capability('dump','DBGHELP_MINIDUMP',c.get('minidump','UNAVAILABLE'),requires_optin=True,supported_os=('Windows',),permissions='TARGET_READ_QUERY_VM_ACCESS',accuracy='SNAPSHOT_MAY_PAUSE_TARGET_MEMORY_IS_SENSITIVE'),
 )
 rows=[]
 for cap in specs:
  row=asdict(cap);row.update(capability_id=cap.sensor_id,source_id=cap.source,privilege_level=cap.permissions,accuracy_notes=cap.accuracy,
   failure_reason=cap.reason,detector_starts_capture=False);rows.append(row)
 for name,source in (('network','FUTURE_PID_NETWORK_PROVIDER'),('gpu','FUTURE_PID_GPU_ENGINE_PROVIDER'),('frames','FUTURE_TARGET_FRAME_PROVIDER')):
  rows.append({'capability_id':name,'source_id':source,'availability':'FUTURE_NOT_IMPLEMENTED','privilege_level':'SOURCE_NOT_SELECTED',
   'requires_optin':True,'supported_os':['Windows'],'accuracy_notes':'REQUIRES_PROVEN_TARGET_INSTANCE_ATTRIBUTION',
   'failure_reason':'NO_VALIDATED_PER_PROCESS_PROVIDER','detector_starts_capture':False,
   'system_total_fallback':False,'value':None,'nonblocking_future_contract':True})
 return rows
