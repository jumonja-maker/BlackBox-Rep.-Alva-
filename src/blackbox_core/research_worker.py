"""Isolated session owner and bounded JSON-lines command protocol.

All process probing, SQLite, native calls, report IO and packaging happen in
this child. The desktop never passes SQLite connections between threads.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from collections import deque
import queue
import sys
from threading import Thread,Event
import time
from uuid import uuid4

from .casebook import CaseBook, compact, episode, evidence_page, export_case, compare_cases, verify_package, recover_case
from .instrumentation import EventTail
from .preparation import inspect_target, write_preparation
from .windows_research import capabilities, window_observations, wait_chain, enable_debug_privilege, minidump, WprCapture
from .runtime_trace import DotnetTrace
from .trace_owner import TraceSupervisor
from .optional_jobs import OptionalJobs
from .operation_worker import OPERATIONS, TARGET_OPERATIONS
from .sensors import Capability, CallbackSensor, SensorRegistry
from .capture_policy import validate_policy,profile_description
from .contracts import ObserverError
from .user_markers import UserMarkers
from .capability_catalog import inventory
from .observer_budget import ObserverBudget


class ResearchSession:
    def __init__(self, output_root=None):
        from blackbox_universal.monitor import ReadOnlyProbe
        self.probe=ReadOnlyProbe(output_root=Path(os.path.abspath(output_root)) if output_root is not None else None)
        self.book=None;self.tail=None;self.wpr=None
        self.runtime_trace=None;self._capabilities=capabilities();self._capability_inventory=inventory(self._capabilities);self._optional_source_results={}
        self._last_detail_capture=None
        self.jobs=OptionalJobs()
        self.sensors=None
        self._cancelled_operations=deque(maxlen=8)
        self.cancel=Event()
        self.interval_ms=1000;self.native_enabled=False;self.observer_budget=ObserverBudget();self._cpu_health_primed=False;self._overhead_notified=False
        self.context={"scenario":"","scenario_version":"","workload":"","target_version":"","profile":"STANDARD","interval_ms":1000,"warmup_count":0}
        self.library_error=None;self._library_started_ns=None;self._library_experiment={};self._configuration_changed=False
        self.capture_policy=validate_policy();self.profile_info=profile_description(self.capture_policy);self.markers=UserMarkers();self._burst_until=None;self._burst_owned=False
        self._ui_seen=set()
        self._library_budget=None;self._library_budget_at=0
        self.budget_bytes=1024**3;self.last_health=0;self.native_at=0
        self.last_command=None;self.command_latency_ms=None
        self.last_app_health=None
        self.app_source_error=None
        self.research_state="NO_SESSION";self.research_error=None
        try:
            import psutil
        except ImportError:
            from .contracts import ObserverError
            raise ObserverError("DEPENDENCY_MISSING","attach") from None
        self._observer=self._frontend=None
        try:
            self._observer=psutil.Process()
            self._frontend=self._observer.parent()
            self._observer.cpu_percent(None)
            if self._frontend:self._frontend.cpu_percent(None)
        except psutil.Error:
            # A denied/broken self sensor must not disable the investigation.
            self._observer=self._frontend=None

    def snapshot(self):
        p=self.probe
        data=p.snapshot()
        detail=p.detailed_capture or self._last_detail_capture
        state,windows=p.window_capture.snapshot() if p.window_capture is not None else ("DISABLED",[])
        data["recent_samples"]=data["recent_samples"][-360:]
        data.update(name=p.name,pid=p.pid,last_error=p.last_error or self.research_error,
            action_ready=p.actions.ready_to_start(),
            detail_enabled=p.detailed_capture is not None,incident_enabled=p.incident_capture is not None,
            incident_policy={"threshold":p.incident_capture.threshold,"min_duration_ms":p.incident_capture.min_duration_ms} if p.incident_capture is not None else None,
            detail_sample_count=detail.samples if detail is not None else 0,
            window_capture_enabled=p.window_capture is not None,window_capture_status=state,
            observed_windows=windows,selected_hwnd=p.window_capture.selected_hwnd if p.window_capture else None,
            detail_status=detail.status if detail is not None else "DISABLED",
            report_result=p.report_result,capabilities=self._capabilities,capability_inventory=self._capability_inventory,
            experiment_context=self.context,native_enabled=self.native_enabled,
            wpr_active=bool(self.wpr and self.wpr.active),
            eventpipe_active=bool(self.runtime_trace and self.runtime_trace.process is not None),
            app_ready=bool(self.tail and self.tail.ready),
            app_source_error=self.app_source_error,
            helper_pid=os.getpid(),last_command=self.last_command,
            research_state=self.research_state,research_error=self.research_error,
            command_latency_ms=self.command_latency_ms,
            optional_jobs=self.jobs.health(), sensor_health=self.sensors.health() if self.sensors else {},
            capture_policy=self.capture_policy,profile_description=self.profile_info,active_stages=self.markers.snapshot(),
            library_health={"status":"INDEX_ERROR" if self.library_error else "AVAILABLE", "error":self.library_error})
        data['observer_budget']=self.observer_budget.latest
        return data

    def _start_policy(self):
        c=self.capture_policy;p=self.probe
        p.detail_policy={'interval_s':c['detail_interval_ms']/1000,'thread_limit':c['thread_limit'],
            'child_limit':c['child_limit'],'max_bytes':self.budget_bytes}
        if c['profile']=='DETAILED':p.set_detailed_capture(True)
        if c['windows_enabled']:p.set_window_capture(True)
        if c['incident_enabled'] or c['profile']=='INCIDENT_BURST':p.set_incident_capture(True,policy=c['incident'])

    def _policy_tick(self):
        p=self.probe;c=self.capture_policy
        if self._burst_until and time.monotonic()>=self._burst_until:
            if self._burst_owned and p.detailed_capture:self._last_detail_capture=p.detailed_capture;p.set_detailed_capture(False)
            elif p.detailed_capture:p.detailed_capture.interval_s=c['detail_interval_ms']/1000
            self._burst_until=None;self.book.put('observer.burst_stopped',{'reason':'TTL_EXPIRED'})
        if c['session_seconds'] and time.monotonic_ns()-p._recording_origin_ns>=c['session_seconds']*10**9:
            self.book.put('observer.time_limit',{'seconds':c['session_seconds']});self.stop('TIME_LIMIT_REACHED');return False
        return True

    def _maybe_burst(self):
        p=self.probe;c=self.capture_policy;trigger=False
        while p.incident_events:
            event=p.incident_events.popleft()
            trigger=trigger or event['code']=='AUTO_INCIDENT_STARTED'
        if p.window_capture:
            rows=p.window_capture.snapshot()[1];current={(r['hwnd'],r['tid']) for r in rows if r.get('unresponsive_observed')}
            trigger=trigger or bool(current-self._ui_seen) and 'UI_TIMEOUT' in c['incident']['enabled_triggers'];self._ui_seen=current
        if c['profile']!='INCIDENT_BURST' or not trigger or self._burst_until:return
        self._burst_owned=p.detailed_capture is None
        if self._burst_owned:p.set_detailed_capture(True)
        p.detailed_capture.interval_s=c['burst_interval_ms']/1000
        self._burst_until=time.monotonic()+c['burst_seconds']
        self.book.put('observer.burst_started',{'duration_seconds':c['burst_seconds'],'etw_started':False,'dump_started':False})

    def _changed_configuration(self):
        self._configuration_changed=True
        if self.book:self.book.set_context("configuration_changed",True)

    def _index_recording(self,*,finalized=False):
        """Optional lifecycle checkpoint; no history scan or per-sample work."""
        from .library_catalog import LibraryCatalog
        p=self.probe
        if self._library_started_ns is None or p.session_folder is None:return
        try:
            LibraryCatalog(p.output_root).record_owned(p.session_folder,{
                **self._library_experiment,"started_ns":self._library_started_ns,
                "state":self.research_state if finalized or self.book else "FINALIZATION_UNCONFIRMED",
                "target_name":p.name,"samples":p.total_samples,"completed_runs":p.actions.completed_total,
                "configuration_changed":self._configuration_changed,"owner_pid":os.getpid(),
                "owner_created":self._observer.create_time() if self._observer else None},finalized=finalized)
            self.library_error=None
        except Exception as exc:
            # An unavailable/full/locked optional index must not stop recording.
            self.library_error=(type(exc).__name__+": "+str(exc))[:300]

    def _recording_resources_closed(self):
        p=self.probe
        return (not p.active and p._store is None and
            not any(cap and cap.thread.is_alive() for cap in
                (p._pending_detailed,p._pending_windows,p._pending_v2)) and
            not (self.wpr and self.wpr.active) and
            not (self.runtime_trace and self.runtime_trace.process is not None))

    def _identity(self):
        import psutil
        core=self.probe._core
        if core is None or abs(psutil.Process(self.probe.pid).create_time()-core.created)>0.000001:
            raise ValueError("TARGET_INSTANCE_CHANGED")

    def _health(self):
        if self.book is None:return
        import psutil
        p=self._observer
        helper_rss=helper_cpu=None
        if p is not None:
            try:
                helper_rss=p.memory_info().rss;helper_cpu=p.cpu_percent(None)
            except psutil.Error:pass
        from .storage_budget import recording_size
        measured=recording_size(self.probe.session_folder);size=measured['bytes']
        if self._library_budget is None or time.monotonic()-self._library_budget_at>=60:
            from .library_catalog import LibraryCatalog
            try:self._library_budget=LibraryCatalog(self.probe.output_root).storage_budget(exclude_folder=self.probe.session_folder)
            except (OSError,ValueError,sqlite3.Error):self._library_budget={'status':'INDEX_UNAVAILABLE'}
            self._library_budget_at=time.monotonic()
        frontend_rss=frontend_cpu=None
        if self._frontend:
            try:
                if self._frontend.is_running():
                    frontend_rss=self._frontend.memory_info().rss
                    frontend_cpu=self._frontend.cpu_percent(None)
            except psutil.Error:pass
        if self._cpu_health_primed:
            self._observe_overhead(helper_cpu,frontend_cpu,cores=psutil.cpu_count() or 1,frontend_expected=self._frontend is not None)
        self._cpu_health_primed=True
        self.book.put("observer.health",{"helper_rss_bytes":helper_rss,
            "helper_cpu_percent":helper_cpu,"session_top_level_bytes":size,
            "helper_sensor_status":"OBSERVED" if helper_rss is not None else "NOT_OBSERVED",
            "frontend_rss_bytes":frontend_rss,"frontend_cpu_percent":frontend_cpu,
            "disk_budget_bytes":self.budget_bytes,"storage_measurement":measured,"library_budget":self._library_budget,"budget_check_interval_s":5,"app_invalid_lines":self.tail.invalid if self.tail else None,
            "app_client_dropped":self.tail.client_dropped if self.tail else None,
            "event_loss_from_other_sources":None,
            "sensor_registry":self.sensors.health() if self.sensors else {},
            "optional_jobs":self.jobs.health(),
            "overhead_scope":"DIRECT_HELPER_USAGE_NOT_TOTAL_OBSERVER_EFFECT"})
        library=self._library_budget or {};maximum=library.get('policy',{}).get('max_bytes',0)
        local_exceeded=size is not None and size>=self.budget_bytes
        global_exceeded=maximum and size is not None and library.get('known_bytes',0)+size>=maximum
        if local_exceeded or global_exceeded:
            self.book.put('observer.disk_budget',{'status':'BUDGET_EXHAUSTED','scope':'SESSION' if local_exceeded else 'LIBRARY_CACHED_KNOWN_BYTES',
                'measurement':measured,'library':library,'hard_filesystem_quota':False,'deletion_performed':False})
            self.stop('STORAGE_LIMIT_REACHED')

    def _observe_overhead(self,helper_cpu,frontend_cpu,*,cores,frontend_expected=False):
        if not self.observer_budget.observe(helper_cpu,frontend_cpu,cores=cores,profile=self.capture_policy['profile'],frontend_expected=frontend_expected):return
        before=self.interval_ms;detail=self.probe.detailed_capture;old_detail=detail.interval_s if detail else None
        if self.capture_policy['adaptive_throttle']:
            self.interval_ms=max(before,min(5000,max(2000,before*2)))
            if detail:detail.interval_s=max(detail.interval_s,min(5.,detail.interval_s*2))
        changed=self.interval_ms!=before or detail is not None and detail.interval_s!=old_detail
        self.observer_budget.latest.update(adaptive_enabled=self.capture_policy['adaptive_throttle'],interval_ms=self.interval_ms,
            detail_interval_s=detail.interval_s if detail else None,frequency_reduced=changed)
        if changed:self._changed_configuration()
        if self.book and (changed or not self._overhead_notified):
            self.book.put('observer.usage_warning',self.observer_budget.latest,source='PSUTIL_OBSERVER_SELF_COUNTERS',quality='SAMPLED_USAGE_NOT_OFF_ON_EFFECT')
            self._overhead_notified=True

    def tick(self):
        p=self.probe
        if not p.active:return
        if not self._policy_tick():return
        if self.sensors:
            if self.sensors.sample("base",budget_s=self.interval_ms/1000) is None:
                raise RuntimeError("BASE_SENSOR_UNAVAILABLE")
        else:p.tick(requested_interval_ms=self.interval_ms)
        if self.book:
            self.book.sync_legacy()
            if self.wpr:
                trace_result=self.wpr.poll()
                if trace_result:self.book.put("trace.stopped",trace_result,source="ETW_WPR",quality=trace_result["status"])
            if self.runtime_trace:
                result=self.runtime_trace.poll()
                if result:self.book.put("eventpipe.stopped",result,source="EVENTPIPE_DOTNET_TRACE",quality=result["status"])
            if self.sensors:
                for name in self.sensors.entries:
                    if name=='base':continue
                    self.sensors.sample(name, budget_s=.1)
            else:self._application_events()
            try:self._maybe_burst()
            except (OSError,ValueError,RuntimeError) as exc:
                self.book.put('observer.burst_unavailable',{'error':str(exc)[:200]},quality='UNAVAILABLE')
            if time.monotonic()-self.last_health>=5:
                self.last_health=time.monotonic();self._health()
        if not p.active and self.book:self.stop(p.session_state)

    def _application_events(self, max_bytes=65536):
        if not self.book or not self.tail or self.app_source_error:return
        try:
            rows=self.tail.poll(max_bytes=max_bytes)
        except (OSError,ValueError) as exc:
            # One unusable cooperative source must not end the base recorder.
            self.app_source_error=(type(exc).__name__+": "+str(exc))[:300]
            self.tail.ready=False
            self.book.put("application.source_failed",{"error":self.app_source_error},
                          source="APPLICATION_EVENT_READER",quality="SOURCE_FAILED")
            return
        for r in rows:
            # Source clocks are retained, not silently equated to ours.
            self.book.put(r["kind"],r,source="APPLICATION_EVENT",
                quality="APP_SUPPLIED_UNAUTHENTICATED",tid=r["tid"] if r.get("tid_kind","OS_NATIVE")=="OS_NATIVE" else None,
                operation_id=r.get("operation_id"))

    def _drain_application_events(self):
        if not self.tail:return {}
        t=self.tail;cutoff=None
        if not self.app_source_error:
            try:
                if not t.path.exists():cutoff=0
                elif t.path.is_symlink() or not t.path.is_file():raise ValueError("INVALID_APPLICATION_EVENT_FILE")
                else:cutoff=t.path.stat().st_size
                # Freeze the byte boundary. The target may continue emitting;
                # never wait for it or drain an infinite live file at Stop.
                deadline=time.monotonic()+2;budget=1024*1024
                while cutoff is not None and t.offset<cutoff and budget>0 and time.monotonic()<deadline:
                    n=min(65536,cutoff-t.offset,budget);before=t.offset
                    self._application_events(n);budget-=max(0,t.offset-before)
                    if t.offset<=before or self.app_source_error:break
            except (OSError,ValueError) as exc:
                self.app_source_error=(type(exc).__name__+": "+str(exc))[:300];t.ready=False
        return {"application_source_error":self.app_source_error,
            "application_stop_byte_boundary":cutoff,
            "application_unread_bytes_at_stop":max(0,cutoff-t.offset) if cutoff is not None else None,
            "application_partial_line_bytes":len(t.pending),
            "application_source_discontinuities":t.discontinuities}

    def _start_registry(self):
        self.sensors=SensorRegistry(("base", "application", "detail", "windows", "optional",'threads','memory','process_tree','wct','etw','runtime','dump','crash_events'))
        def base(deadline):
            result=self.probe.tick(requested_interval_ms=self.interval_ms,track_cadence=True)
            return {"status":"OBSERVED" if result is not None else self.probe.session_state,
                "committed_sample_seq":self.probe.total_samples}
        self.sensors.register(CallbackSensor(Capability("base","PSUTIL_PROCESS_COUNTERS","AVAILABLE","PRIMARY_RECORDING"),base))
        def application(deadline):
            self._application_events()
            return {"status":"SOURCE_FAILED" if self.app_source_error else "READY" if self.tail.ready else "WAITING_FOR_CONTROL_EVENT"}
        self.sensors.register(CallbackSensor(Capability("application", "APPLICATION_EVENT_READER", "AVAILABLE",requires_optin=True), application))
        self.sensors.register(CallbackSensor(Capability("detail", "PSUTIL_DETAILED", "AVAILABLE", "EXISTING_WORKER_HEALTH",requires_optin=True),
            lambda deadline:{"status":self.probe.detailed_capture.status,
                "error":self.probe.detailed_capture.error,
                "producer_heartbeat_ns":(self.probe.detailed_capture.latest_metrics or {}).get("time_ns")}, enabled=lambda:self.probe.detailed_capture is not None))
        self.sensors.register(CallbackSensor(Capability("windows", "WIN32_HWND_WCT", "AVAILABLE" if os.name=="nt" else "UNSUPPORTED_PLATFORM", "EXISTING_WORKER_HEALTH",requires_optin=True,supported_os=("Windows",)),
            lambda deadline:{"status":self.probe.window_capture.snapshot()[0],
                "producer_heartbeat_ns":self.probe.window_capture.last_poll_completed_ns}, enabled=lambda:self.probe.window_capture is not None))
        self.sensors.register(CallbackSensor(Capability("optional", "DISPOSABLE_OPERATION_PROCESS", "AVAILABLE", "EXPLICIT_OPT_IN", "OWNED_PROCESS_HARD_DEADLINE",requires_optin=True),
            lambda deadline:self.jobs.health()))
        def detail_health(deadline):
            capture=self.probe.detailed_capture
            return {'status':capture.status,'error':capture.error,'producer_heartbeat_ns':(capture.latest_metrics or {}).get('time_ns')}
        def optional_health(key):
            capture=self.wpr if key=='wpr' else self.runtime_trace if key=='eventpipe' else None
            if capture is not None:
                process=capture.process
                if process is not None and process.poll() is None:return {'status':'GUARDIAN_ALIVE_CAPTURE_HANDSHAKE_NOT_ATTESTED','producer_heartbeat_ns':None}
                return {'status':capture.data.get('state','UNCONFIRMED'),'error':capture.data.get('error')}
            return self._optional_source_results.get(key,{'status':'NOT_REQUESTED'})
        caps={r['capability_id']:r for r in self._capability_inventory}
        for name in ('threads','memory','process_tree'):
            r=caps[name]
            self.sensors.register(CallbackSensor(Capability(name,r['source_id'],r['availability'],'EXISTING_WORKER_HEALTH',
                requires_optin=True,accuracy=r['accuracy_notes']),detail_health,enabled=lambda:self.probe.detailed_capture is not None))
        for name,key in (('wct','native'),('etw','wpr'),('runtime','eventpipe'),('dump','dump'),('crash_events','crash_events')):
            r=caps[name]
            self.sensors.register(CallbackSensor(Capability(name,r['source_id'],r['availability'],'EXPLICIT_PROVIDER_HEALTH',
                permissions=r['privilege_level'],requires_optin=True,supported_os=tuple(r['supported_os']),accuracy=r['accuracy_notes']),
                lambda deadline,k=key:optional_health(k)))
        self.sensors.start(self.context)

    def _receive_command(self,command):
        self.last_command=command.get("op");self.command_latency_ms=None
        issued=command.get("issued_ns")
        if issued is None:return None
        latency=time.monotonic_ns()-issued if type(issued) is int else -1
        if not 0<=latency<=300_000_000_000:raise ValueError("INVALID_COMMAND_ISSUE_TIME")
        self.command_latency_ms=latency/1_000_000
        return issued

    def submit_optional(self, command):
        self._receive_command(command)
        op=command.get("op");a=command.get("args", {})
        if type(a) is not dict:raise ValueError("INVALID_COMMAND_ARGUMENTS")
        if op in ("native", "dump", "prepare_client", "inspect_dump") and not self.book:raise ValueError("START_RECORDING_FIRST")
        if op in TARGET_OPERATIONS:self._identity()
        # Context and token are sent directly to our own disposable process;
        # neither is returned in the sensor health or command audit record.
        packet={"op":op,"args":a,"pid":self.probe.pid,
            "created":self.probe._core.created if self.probe._core else None,
            "folder":str(self.probe.session_folder) if self.probe.session_folder else None,
            "end_ms":self.probe.last_elapsed_ms or 1,"library_root":str(self.probe.output_root)}
        if op=="prepare_client":packet.update(event_path=str(self.tail.path),event_token=self.tail.token)
        self.jobs.submit(command, packet, seconds=300 if op in ("export","export_recover","library_export") else 120 if op in ("library_plan_trash","library_apply_trash","library_plan_purge","library_apply_purge","library_trace_recover") else 75 if op in ("inspect_dump","verify","recover","library_scan","library_compare","investigation","incident_card","events_query","decode_trace") else 15)
        if self.book:
            self.book.put("observer.operation_queued", {"op":op,"command_id":command.get("id"),
                "issued_ns":command.get("issued_ns")}, source="BLACKBOX_COMMAND_OWNER")

    def poll_optional(self):
        results=list(self._cancelled_operations);self._cancelled_operations.clear()
        results+=self.jobs.poll()
        for result in results:
            command=result["command"];op=command.get("op")
            if not result.get("error") and op in TARGET_OPERATIONS:
                try:self._identity()
                except Exception:result["result"]=None;result["error"]="TARGET_INSTANCE_CHANGED_RESULT_NOT_COMMITTED"
            if not self.book:continue
            value=result.get("result")
            if op in ('native','dump','crash_events','decode_trace'):
                self._optional_source_results[op]={'status':'OPERATION_FAILED' if result.get('error') else value.get('status','SNAPSHOT_RETURNED'),
                    'error':result.get('error'),'producer_heartbeat_ns':time.monotonic_ns()}
            if result.get("error"):
                self.book.put("observer.operation_failed", {"op":op,"error":result["error"],
                    "operation_ms":result.get("operation_ms")}, source="DISPOSABLE_OPERATION_PROCESS", quality="NOT_CONFIRMED")
            elif op=="native":
                r=value["windows"];self.book.put("windows.response",r,source="WIN32_HWND",quality=r["status"])
                for r in value["wait_chains"]:self.book.put("thread.wait_chain",r,source="WIN32_WCT",quality=r["status"],tid=r.get("tid"))
                self._changed_configuration()
            elif op in ("dump","symbols","inspect_dump"):
                kind,source={"dump":("snapshot.captured","DBGHELP_MINIDUMP"),"symbols":("symbols.identity","DBGHELP_SYMSRV_FILE_INDEX"),
                    "inspect_dump":("stack.offline","CDB_OFFLINE_DUMP")}[op]
                self.book.put(kind,value,source=source,quality=value.get("status","OBSERVED"))
            elif op in ('crash_events','decode_trace'):
                key='events' if op=='crash_events' else 'rows'
                rows=value.get(key,[])
                summary={**value,key:rows[:16],'items_omitted_from_evidence_preview':max(0,len(rows)-16),'full_items_location':value.get('supplemental_artifact'),
                    'timeline_timestamp_semantics':'OBSERVER_RECEIPT_NOT_SOURCE_EVENT_CLOCK'}
                self.book.put('crash.system_events' if op=='crash_events' else 'trace.decoded',summary,
                    source='WIN32_APPLICATION_EVENTLOG' if op=='crash_events' else 'ETW_TRACERPT',quality=value.get('status','NOT_CONFIRMED'))
        return results

    def capture_native(self):
        import psutil
        self._identity()
        windows=window_observations(self.probe.pid)
        self.book.put("windows.response",windows,source="WIN32_HWND",quality=windows["status"])
        rows=[]
        tids=[r["tid"] for r in windows.get("windows",[])][:4]
        try:
            threads=sorted(psutil.Process(self.probe.pid).threads(),key=lambda r:r.user_time+r.system_time,reverse=True)
            tids=list(dict.fromkeys(tids+[t.id for t in threads]))[:8]
        except psutil.Error:pass
        enable_debug_privilege()
        for tid in tids:
            result=wait_chain(tid)
            self.book.put("thread.wait_chain",result,source="WIN32_WCT",quality=result["status"],tid=tid)
            rows.append(result)
        self.native_at=time.monotonic()
        return {"windows":windows,"wait_chains":rows}

    def stop(self, reason="USER_STOPPED"):
        p=self.probe;errors=[]
        self._cancelled_operations.extend(self.jobs.cancel())
        if self.sensors:self.sensors.stop()
        self._burst_until=None
        if self.book and (not p.active or p._store is None):self.book.on_evidence=None
        if self.book:
            try:self.markers.close(self.book,reason=reason)
            except (OSError,ValueError,sqlite3.Error,ObserverError) as exc:errors.append('USER_STAGES_FINALIZATION_UNCONFIRMED: '+str(exc)[:100])
        app_coverage=self._drain_application_events() if self.book else {}
        if self.tail and (self.app_source_error or self.tail.invalid or self.tail.client_dropped or
                self.tail.discontinuities or app_coverage.get("application_unread_bytes_at_stop") or
                app_coverage.get("application_partial_line_bytes")):
            errors.append("APPLICATION_EVENT_COVERAGE_INCOMPLETE")
        if self.book:self.book.on_evidence=None
        if p.active:p.stop(reason,defer_report=True)
        if self.runtime_trace:
            result=self.runtime_trace.stop()
            if result and self.book:self.book.put("eventpipe.stopped",result,source="EVENTPIPE_DOTNET_TRACE",quality=result["status"])
            if result and result.get('status')!='COMPLETED':errors.append('EVENTPIPE_'+result.get('status','CLEANUP_UNCONFIRMED'))
        if self.wpr:
            try:
                r=self.wpr.stop()
                if r and self.book:self.book.put("trace.stopped",r,source="ETW_WPR",quality=r["status"])
                if r and r["status"]!="COMPLETED":errors.append("WPR_"+r["status"])
            except (OSError,ValueError) as exc:errors.append(str(exc)[:300])
        if p.session_folder and p.report_result is None:p.generate_report()
        if self.book:
            book=self.book;self.book=None
            try:
                book.sync_legacy(drain=True)
                book.set_context("capture_health",{"finalization_errors":errors,
                    **app_coverage,
                    "application_event_ready":bool(self.tail and self.tail.ready),
                    "app_invalid_lines":self.tail.invalid if self.tail else None,
                    "app_client_dropped":self.tail.client_dropped if self.tail else None,
                    "app_file_discontinuities":self.tail.discontinuities if self.tail else None})
                book.close("INCOMPLETE" if errors or p.last_error else p.session_state)
                self.research_state="INCOMPLETE" if errors or p.last_error else p.session_state
                self.research_error="; ".join(errors) if errors else p.last_error
                self._index_recording(finalized=self._recording_resources_closed())
            except BaseException:
                self.research_state="FINALIZATION_UNCONFIRMED"
                self.research_error="RESEARCH_FINALIZATION_UNCONFIRMED"
                book.db.close();raise
        return {"state":self.research_state,"base_recording_state":p.session_state,"errors":errors}

    def command(self, command):
        op=command.get("op");a=command.get("args",{})
        if type(a) is not dict:raise ValueError("INVALID_COMMAND_ARGUMENTS")
        issued=self._receive_command(command)
        if op=='capture_policy':
            if a:
                if self.probe.active:raise ValueError('STOP_BEFORE_RECONFIGURING')
                if set(a)!={'policy'}:raise ValueError('INVALID_CAPTURE_POLICY')
                self.capture_policy=validate_policy(a['policy']);self.profile_info=profile_description(self.capture_policy);self.budget_bytes=self.capture_policy['max_session_mb']*1024**2
                self.context.update(profile=self.capture_policy['profile'],capture_policy=self.capture_policy)
            return {'policy':self.capture_policy,'description':profile_description(self.capture_policy)}
        if op=='user_marker':return self.markers.write(self.book,self.probe,a,issued_ns=issued)
        if op=="attach":
            if self.book:self.stop()
            return self.probe.attach(int(a["pid"]))
        if op=="configure":
            if self.probe.active:raise ValueError("STOP_BEFORE_RECONFIGURING")
            for key in ("scenario","scenario_version","workload","target_version","profile"):
                if key in a:
                    if key=='profile':
                        self.capture_policy=validate_policy({**self.capture_policy,'profile':a[key]});self.profile_info=profile_description(self.capture_policy)
                    self.context[key]=str(a[key])[:256]
            if "warmup_count" in a:
                n=a["warmup_count"]
                if type(n) is not int or not 0<=n<=10000:raise ValueError("INVALID_WARMUP_COUNT")
                self.context["warmup_count"]=n
            if "budget_mb" in a:
                n=a["budget_mb"]
                if type(n) is not int or not 16<=n<=1024*1024:raise ValueError("INVALID_DISK_BUDGET")
                self.budget_bytes=n*1024**2;self.capture_policy["max_session_mb"]=n
            return self.context
        if op=="interval":
            n=a["milliseconds"]
            if type(n) is not int or not 100<=n<=60000:raise ValueError("INVALID_INTERVAL")
            self.interval_ms=n;self.context["interval_ms"]=n
            if self.book:
                self.book.put("observer.interval_changed",{"interval_ms":n})
                self._changed_configuration()
            return n
        if op=="start":
            self._capabilities=capabilities();self._capability_inventory=inventory(self._capabilities);self._optional_source_results={}
            self.observer_budget=ObserverBudget();self._cpu_health_primed=False;self._overhead_notified=False
            self.markers=UserMarkers();self._ui_seen=set();self._burst_until=None;self._library_budget=None
            self.context.update(profile=self.capture_policy["profile"],capture_policy=self.capture_policy)
            self.probe.start()
            self.probe._store.v2.max_bytes=self.budget_bytes
            self.native_enabled=False;self.runtime_trace=None;self.wpr=None;self._last_detail_capture=None
            self.app_source_error=None
            self.research_state="RECORDING";self.research_error=None
            self._configuration_changed=False;self._library_started_ns=None
            try:
                self.book=CaseBook(self.probe.session_folder,self.probe.pid,self.probe._core.created,
                                  {**self.context,"origin_monotonic_ns":self.probe._recording_origin_ns},
                                  on_evidence=self.probe._store.write_event)
                self.book.origin=self.probe._recording_origin_ns
                self._library_started_ns=self.book.anchor.utc_ns
                self._library_experiment=dict(self.context)
                self.book.set_context("capabilities",self._capabilities)
                self.tail=EventTail(self.probe.session_folder/"application-events.jsonl",uuid4().hex,self.probe.pid)
                self.book.set_context("application_event_path",str(self.tail.path))
                self.book.set_context("worker_pid",os.getpid())
                self._start_policy()
                self._start_registry()
                import psutil
                try:self.book.set_context("worker_created",psutil.Process().create_time())
                except psutil.Error:self.book.set_context("worker_created",None)
            except BaseException:
                self.research_state="INCOMPLETE";self.research_error="RESEARCH_SETUP_FAILED"
                if self.book:self.book.on_evidence=None
                self.probe.stop('STORAGE_ERROR')
                if self.book:
                    book=self.book;self.book=None
                    try:book.close('INCOMPLETE')
                    except Exception:book.db.close()
                raise
            self._index_recording()
            return {"folder":str(self.probe.session_folder)}
        if op=="stop":
            result=self.stop(a.get("reason","USER_STOPPED"));self.cancel.clear();return result
        if op in ("prepare","begin","end"):
            previous=self.probe.actions.clock
            # Preserve actual GUI command timestamp, including transport delay.
            if type(issued) is int and self.command_latency_ms is not None:
                self.probe.actions.clock=lambda:issued
            try:
                result={"prepare":self.probe.prepare_action,"begin":self.probe.begin_action,
                        "end":self.probe.finish_action}[op](**({"baseline_ms":a["baseline_ms"]} if op=="prepare" and "baseline_ms" in a else {}))
            finally:self.probe.actions.clock=previous
            return result
        if op=="mark":return self.probe.mark_problem(a.get("note",""),
            issued_ns=issued if type(issued) is int and self.command_latency_ms is not None else None)
        if op=="detailed":
            if self.probe.detailed_capture is not None:self._last_detail_capture=self.probe.detailed_capture
            result=self.probe.set_detailed_capture(bool(a["enabled"]))
            if self.probe.detailed_capture is not None:
                self._last_detail_capture=self.probe.detailed_capture
                self.probe.detailed_capture.max_bytes=self.budget_bytes
            self._changed_configuration()
            return result
        if op=="incidents":
            result=self.probe.set_incident_capture(bool(a["enabled"]),policy=a.get("policy"))
            if self.book:
                self.book.put("observer.incident_policy",{"enabled":bool(a["enabled"]),"policy":a.get("policy")})
                self._changed_configuration()
            return result
        if op=="windows":
            result=self.probe.set_window_capture(bool(a["enabled"]))
            if self.book:self._changed_configuration()
            return result
        if op=="select_window":
            cap=self.probe.window_capture
            if cap is None:raise ValueError("WINDOW_CAPTURE_REQUIRES_RECORDING")
            hwnd=a.get("hwnd")
            if hwnd is not None and (type(hwnd) is not int or not any(w["hwnd"]==hwnd for w in cap.snapshot()[1])):
                raise ValueError("WINDOW_NO_LONGER_AVAILABLE")
            cap.selected_hwnd=hwnd;return {"hwnd":hwnd}
        if op=="inspect":return inspect_target(self.probe.pid)
        if op=="symbols":
            import psutil
            from .symbols import verify_symbols
            self._identity()
            result=verify_symbols(psutil.Process(self.probe.pid).exe(),a["pdb"])
            if self.book:self.book.put("symbols.identity",result,source="DBGHELP_SYMSRV_FILE_INDEX",quality=result["status"])
            return result
        if op=="inspect_dump":
            from .symbols import inspect_dump
            if not self.probe.session_folder:raise ValueError("START_RECORDING_FIRST")
            artifacts=self.probe.session_folder/"artifacts";artifacts.mkdir(exist_ok=True)
            result=inspect_dump(a["dump"],artifacts,a.get("symbols"))
            if self.book:self.book.put("stack.offline",result,source="CDB_OFFLINE_DUMP",quality=result["status"])
            return result
        if op=="prepare_client":
            if not self.book:raise ValueError("START_RECORDING_FIRST")
            result=write_preparation(self.probe.session_folder/("preparation-"+uuid4().hex[:8]),self.tail.path,self.tail.token)
            return result
        if op=="native":
            if not self.book:raise ValueError("START_RECORDING_FIRST")
            self._changed_configuration()
            # Continuous HWND/WCT observation is owned by WindowCapture.
            # This explicit snapshot must not start a second periodic sampler.
            return self.capture_native()
        if op=="wpr":
            if not self.book:raise ValueError("START_RECORDING_FIRST")
            artifacts=self.probe.session_folder/"artifacts";artifacts.mkdir(exist_ok=True)
            if a.get("enabled"):
                if self.wpr and self.wpr.active:raise ValueError("WPR_ALREADY_ACTIVE")
                self._identity()
                self.wpr=TraceSupervisor(artifacts,seconds=a.get("seconds",30),
                    max_output_bytes=a.get("max_output_bytes",self.capture_policy["max_trace_mb"]*1024**2),
                    target={"pid":self.probe.pid,"created":self.probe._core.created})
                result=self.wpr.start()
                self.book.set_context("wpr_instance",self.wpr.instance)
            else:
                if not self.wpr:raise ValueError("WPR_NOT_ACTIVE")
                self.wpr.request_stop();result={"source":"ETW_WPR","status":"STOP_REQUESTED","instance":self.wpr.instance}
            self.book.put("trace.state",result,source="ETW_WPR")
            self._changed_configuration()
            return result
        if op=="eventpipe":
            if not self.book:raise ValueError("START_RECORDING_FIRST")
            self._identity()
            if self.runtime_trace and self.runtime_trace.process is not None:raise ValueError("EVENTPIPE_ALREADY_ACTIVE")
            artifacts=self.probe.session_folder/"artifacts";artifacts.mkdir(exist_ok=True)
            self.runtime_trace=DotnetTrace(artifacts,self.probe.pid,a.get("seconds",10),profile=a.get("profile","gc-collect"),max_bytes=self.capture_policy["max_trace_mb"]*1024**2)
            try:result=self.runtime_trace.start()
            except Exception as exc:
                self.book.put('eventpipe.start_failed',{'error':str(exc)[:200]},source='EVENTPIPE_DOTNET_TRACE',quality='UNAVAILABLE');raise
            finally:self._changed_configuration()
            self.book.put('eventpipe.started',result,source='EVENTPIPE_DOTNET_TRACE')
            self._changed_configuration()
            return result
        if op=="dump":
            if not self.book:raise ValueError("START_RECORDING_FIRST")
            self._identity()
            artifacts=self.probe.session_folder/"artifacts";artifacts.mkdir(exist_ok=True)
            result=minidump(self.probe.pid,artifacts/("snapshot-"+uuid4().hex+".dmp"),full=bool(a.get("full",False)))
            self.book.put("snapshot.captured",result,source="DBGHELP_MINIDUMP")
            return result
        if op=="episode":
            folder=a.get("folder") or self.probe.session_folder
            return episode(folder,int(a.get("start_ms",0)),int(a.get("end_ms",self.probe.last_elapsed_ms or 1)))
        if op=="evidence_page":
            return evidence_page(a.get("folder") or self.probe.session_folder,
                start_ms=int(a["start_ms"]),end_ms=int(a["end_ms"]),
                after_id=int(a.get("after_id",0)),before_id=a.get("before_id"))
        if op=="export":return export_case(a.get("folder") or self.probe.session_folder,a["destination"],include_sensitive=bool(a.get("include_sensitive",False)),cancel=self.cancel.is_set)
        if op=="compare":
            if (Path(a["before"])/"research.sqlite3").is_file() and (Path(a["after"])/"research.sqlite3").is_file():
                return compare_cases(a["before"],a["after"])
            from .report import compare
            return compare(Path(a["before"]),Path(a["after"]))
        if op=="verify":return verify_package(a["path"])
        if op=="recover":return recover_case(a["folder"],a["destination"])
        if op=="processes":
            from blackbox_universal.monitor import available_processes
            return available_processes()
        if op=="snapshot_export":
            from blackbox_universal.monitor import save_snapshot
            save_snapshot(Path(a["destination"]),self.probe.snapshot())
            return {"path":a["destination"]}
        if op=="status":return self.snapshot()
        if op.startswith("library_") and op in OPERATIONS:
            from .operation_worker import execute
            return execute({"op":op,"args":a,"library_root":str(self.probe.output_root)})
        if op=="quit":return self.stop("UI_CLOSED")
        raise ValueError("UNKNOWN_RESEARCH_COMMAND")


def _streams():
    # A PyInstaller --windowed child has None Python streams. QProcess supplies
    # real inherited Windows pipe handles; explicitly reopen those, only here.
    if os.name=="nt" and (sys.stdin is None or sys.stdout is None):
        import ctypes,msvcrt
        k=ctypes.WinDLL("kernel32",use_last_error=True)
        k.GetStdHandle.argtypes=[ctypes.c_ulong];k.GetStdHandle.restype=ctypes.c_void_p
        if sys.stdin is None:
            sys.stdin=os.fdopen(msvcrt.open_osfhandle(k.GetStdHandle(-10 & 0xffffffff),os.O_RDONLY),"r",encoding="utf-8")
        if sys.stdout is None:
            sys.stdout=os.fdopen(msvcrt.open_osfhandle(k.GetStdHandle(-11 & 0xffffffff),os.O_WRONLY),"w",encoding="utf-8",buffering=1)
    return sys.stdin,sys.stdout


def main(output_root=None):
    inp,out=_streams();commands=queue.Queue(maxsize=64);cancel=Event()
    def read():
        while True:
            line=inp.readline(16385)
            if not line:
                cancel.set()
                commands.put({"id":"eof","op":"quit"});return
            if len(line)>16384 or not line.endswith("\n"):
                # Malformed local protocol terminates the helper, never evals.
                commands.put({"id":"invalid","op":"quit"});return
            try:
                item=json.loads(line)
                if type(item) is not dict:raise ValueError()
                if item.get("op") in ("stop","quit"):cancel.set()
                commands.put(item)
            except (ValueError,TypeError):
                commands.put({"id":"invalid","op":"quit"});return
    Thread(target=read,name="blackbox-command-reader",daemon=True).start()
    session=ResearchSession(output_root);session.cancel=cancel;next_tick=time.monotonic()
    def emit(packet):
        out.write(compact(packet)+"\n");out.flush()
    emit({"type":"snapshot","snapshot":session.snapshot()})
    def acknowledge(command, result=None, error=None):
        emit({"type":"result","id":command.get("id"),"op":command.get("op"),"result":result,"error":error})
    try:
        while True:
            finished_operations=session.poll_optional()
            for finished in finished_operations:
                acknowledge(finished["command"],finished.get("result"),finished.get("error"))
            if finished_operations:emit({"type":"snapshot","snapshot":session.snapshot()})
            try:command=commands.get(timeout=0.1)
            except queue.Empty:command=None
            if command:
                try:
                    if command.get("op") in OPERATIONS:
                        session.submit_optional(command)
                        emit({"type":"snapshot","snapshot":session.snapshot()})
                        continue
                    if command.get("op") in ("attach","start","stop","quit"):
                        for pending in session.jobs.cancel():
                            acknowledge(pending["command"],None,pending["error"])
                    result=session.command(command)
                    if session.book:session.book.sync_legacy()
                    emit({"type":"result","id":command.get("id"),"op":command.get("op"),"result":result,"error":None})
                except Exception as exc:
                    emit({"type":"result","id":command.get("id"),"op":command.get("op"),"result":None,
                          "error":getattr(exc,"code",None) or (type(exc).__name__+": "+str(exc))[:512]})
                emit({"type":"snapshot","snapshot":session.snapshot()})
                if command.get("op")=="quit":break
            if session.probe.active and time.monotonic()>=next_tick:
                try:session.tick()
                except Exception as exc:
                    emit({"type":"error","error":str(exc)[:512]})
                    session.stop("STORAGE_ERROR")
                # Preserve an absolute recorder cadence; never run a burst of
                # catch-up samples or call skipped local slots lost OS events.
                interval=session.interval_ms/1000
                now=time.monotonic();next_tick+=interval
                if next_tick<=now:next_tick+=((now-next_tick)//interval+1)*interval
                emit({"type":"snapshot","snapshot":session.snapshot()})
    finally:
        session.jobs.cancel()
        session.stop("UI_CLOSED")
    return 0


if __name__=="__main__":raise SystemExit(main())
