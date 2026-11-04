"""Real owned CPU/memory/file bursts through R50 recording and safe read-back."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time

from tools.qa_deep_inspection import file_hash, require, save
from tools.qa_wave02_fixture import WaveProbe


def command(session, operation, **arguments):
    return session.command({'op': operation, 'args': arguments,
                            'issued_ns': time.monotonic_ns()})


def policy(*, tiny=False):
    return {'profile': 'INCIDENT_BURST', 'incident_enabled': True,
        'windows_enabled': False, 'adaptive_throttle': False,
        'burst_seconds': 3, 'burst_interval_ms': 500,
        'incident': {'threshold': 20., 'min_duration_ms': 0,
            'pre_ms': 2000, 'post_ms': 1000, 'cooldown_ms': 1000,
            'growth_window_ms': 1000, 'memory_growth_bytes': 8*1024**2,
            'io_rate_bytes_s': 1024, 'max_incidents': 100,
            'max_buffer_samples': 2 if tiny else 512,
            'max_buffer_bytes': 1024 if tiny else 1024**2,
            'enabled_triggers': ['CPU_SUSTAINED', 'RSS_GROWTH', 'IO_BURST',
                                 'MANUAL_PROBLEM', 'CRASH_OBSERVED']}}


def sample_for(session, seconds):
    started = time.monotonic()
    while True:
        session.tick()
        require(session.probe.active, 'WAVE02_R50_RECORDING_STOPPED_UNEXPECTEDLY')
        if time.monotonic() - started >= seconds:
            return
        time.sleep(.5)


def read_recording(folder):
    """Independent SQLite oracle after the real writer and sidecars are closed."""
    path = folder / 'session-v2.sqlite3'; before = file_hash(path)
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',),
                'WAVE02_R50_RECORDING_DATABASE_CORRUPTED')
        count, first, last = db.execute("SELECT count(*),min(monotonic_ns),max(monotonic_ns) "
            "FROM samples WHERE series='STANDARD'").fetchone()
        completed = db.execute("SELECT count(*) FROM action_intervals WHERE state='COMPLETED'").fetchone()[0]
        rows = db.execute('SELECT incident_id,trigger_code,status,context_json,root_cause FROM incidents').fetchall()
        incidents = [{'incident_id': q[0], 'trigger_code': q[1], 'status': q[2],
                      'context': json.loads(q[3]), 'root_cause': q[4]} for q in rows]
        events = [json.loads(q[0]) for q in db.execute("SELECT detail_json FROM events "
            "WHERE event_type IN ('AUTO_INCIDENT_STARTED','AUTO_INCIDENT_COMPLETED')")]
    require(file_hash(path) == before and count >= 8 and first < last,
            'WAVE02_R50_REAL_PERSISTED_SAMPLES_REQUIRED')
    require(all(q['root_cause'] == 'UNKNOWN' for q in incidents),
            'WAVE02_R50_THRESHOLD_IS_NOT_PROVEN_ROOT_CAUSE')
    return {'sha256': before, 'sample_count': count, 'first_ns': first, 'last_ns': last,
            'completed_actions': completed, 'incidents': incidents, 'incident_events': events}


def recording(executable, output, *, workload='native-burst-v1', repeats=2, tiny=False):
    from blackbox_core.research_worker import ResearchSession
    from blackbox_core.casebook import context
    fixture = WaveProbe(executable, output / 'target')
    session = None
    stopped = None; successful = False
    try:
        session = ResearchSession(output / 'recordings')
        command(session, 'attach', pid=fixture.ready['pid'])
        command(session, 'configure', scenario='BB-WAVE-02-RARE-NATIVE-BURST',
                scenario_version='1', workload=workload, target_version='owned-source-v1')
        command(session, 'capture_policy', policy=policy(tiny=tiny))
        command(session, 'interval', milliseconds=500)
        folder = Path(command(session, 'start')['folder'])
        identity = session.context['run_identity']
        require(identity['identity_status'] == 'OS_OBSERVED_EXACT_FILETIME' and
                identity['process_identity'] == {'pid': fixture.ready['pid'],
                    'created_100ns': fixture.ready['created_100ns']} and
                identity['image']['source_sha256'] == file_hash(executable),
                'WAVE02_R50_RUN_IMAGE_OR_EXACT_BIRTH_NOT_MATCHED_TO_ORACLE')
        sample_for(session, 2.5)
        baseline=session.probe.incident_capture.coverage()
        require(baseline['incidents_completed']==0 and baseline['active'] is False,
                'WAVE02_R50_ACTUAL_IDLE_BASELINE_PRODUCED_UNEXPECTED_INCIDENT')
        # Manual context is user declared and must persist independently of CPU.
        command(session, 'mark', note='owned QA manual problem, cause unknown')
        sample_for(session, 2)
        bursts = []
        for repeat in range(repeats):
            command(session, 'prepare', baseline_ms=0)
            command(session, 'begin')
            session.tick()  # First real cumulative counters inside action boundary.
            fixture.send('burst')
            begun = fixture.receive('burst_begin')
            sample_for(session, 6.5)
            done = fixture.receive('burst_done', timeout=10)
            session.tick()
            command(session, 'end')
            require(done['pid'] == fixture.ready['pid'] and
                    done['created_100ns'] == fixture.ready['created_100ns'] and
                    done['end_qpc'] > begun['start_qpc'] and done['worker_exit_verified'] is True and
                    done['worker_threads'] == 4 and done['io_bytes'] > 0 and
                    done['allocated_bytes'] >= 64*1024**2,
                    'WAVE02_R50_REAL_BURST_COMPLETION_ORACLE_REQUIRED')
            bursts.append({'begin': begun, 'done': done})
            sample_for(session, 2)
            require(session.probe.actions.state == 'COMPLETED',
                    'WAVE02_R50_ACTUAL_ACTION_NOT_COMPLETED')
        stopped = command(session, 'stop')
        metadata = context(folder)
        require(stopped['cleanup_required'] is False and not stopped['errors'] and
                metadata['capture_health']['recording_resources_closed'] is True and
                not metadata['capture_health']['finalization_errors'],
                'WAVE02_R50_RECORDER_OWNERSHIP_FINALIZATION_NOT_CONFIRMED')
        coverage = metadata['capture_health']['incident_coverage']
        require(coverage['retained_samples'] <= coverage['max_buffer_samples'] and
                coverage['accounted_buffer_bytes'] <= coverage['max_buffer_bytes'] and
                coverage['raw_recording_deleted'] is False,
                'WAVE02_R50_PREHISTORY_BUDGET_OR_RAW_RECORDING_CONTRACT_BROKEN')
        actual = read_recording(folder)
        require(actual['completed_actions'] == repeats and
                any(q['trigger_code'] == 'MANUAL_PROBLEM' for q in actual['incidents']) and
                any(q['trigger_code'] in {'CPU_SUSTAINED','RSS_GROWTH','IO_BURST'}
                    or set(q['context'].get('secondary_signals',{})) &
                       {'CPU_SUSTAINED','RSS_GROWTH','IO_BURST'} for q in actual['incidents']),
                'WAVE02_R50_ACTUAL_MANUAL_AND_MEASURED_BURST_INCIDENTS_REQUIRED')
        require(not any(q['trigger_code'] == 'CRASH_OBSERVED' for q in actual['incidents']),
                'WAVE02_R50_NORMAL_LIVE_WORKLOAD_FABRICATED_OS_CRASH')
        if tiny:
            require(coverage['samples_not_retained'] > 0 and
                    any(q['context'].get('capture_coverage',{}).get('prehistory_complete') is False
                        for q in actual['incidents']),
                    'WAVE02_R50_ACTUAL_UNRETAINED_PREHISTORY_WAS_CALLED_COMPLETE')
        else:
            require(coverage['samples_not_retained'] == 0 and coverage['capacity_evictions'] == 0,
                    'WAVE02_R50_NORMAL_NATIVE_REPEATS_LOST_PREHISTORY')
        from blackbox_core.investigation_v2 import incident_card
        cards = [incident_card(folder, q['incident_id'], pre_seconds=2, post_seconds=1)
                 for q in actual['incidents'][:4]]
        require(cards and all(q['status'] == 'OBSERVATION_ONLY' and
                q['root_cause'] == 'UNKNOWN' and q['root_cause_proven'] is False for q in cards),
                'WAVE02_R50_INCIDENT_CARD_CAUSE_OR_SOURCE_SCOPE_OVERCLAIM')
        save(output / 'recording-proof.json', {'status':'PASS','ready':fixture.ready,
            'baseline_no_incident_observed':True,
            'run_identity':identity, 'coverage':coverage, 'actual':actual,
            'bursts':bursts, 'cards':cards, 'stop':stopped})
        successful = True
        return {'folder':str(folder),'run_identity':identity, 'coverage':coverage,
                'baseline_no_incident_observed':True,
                'sample_count':actual['sample_count'],'incident_count':len(actual['incidents']),
                'completed_actions':repeats,'source_sha256':actual['sha256']}
    finally:
        try:
            if session is not None and (session.book is not None or session.probe.active):
                stopped = session.stop('QA_FAILURE')
        finally:
            fixture.close(kill=not successful)
        if session is not None:
            require(session._recording_resources_closed(), 'WAVE02_R50_OWNED_RECORDER_RESOURCE_NOT_CLOSED')


def check_r50(executable, output, args):
    from blackbox_core.casebook import compare_cases, export_comparison, load_comparison
    from blackbox_core.investigation_v3 import create_investigation
    from tools.qa_wave02 import export_case, verify_case
    root = Path(output) / 'R50'; root.mkdir()
    first = recording(executable, root / 'before')
    second = recording(executable, root / 'after')
    changed = recording(executable, root / 'changed-workload',
                        workload='native-burst-v2-EXPLICIT-NEGATIVE', repeats=1, tiny=True)
    compared = compare_cases(first['folder'], second['folder'])
    require(compared['comparison_status'] == 'COMPARABLE' and
            compared['comparability']['process_relation'] == 'DISTINCT_EXACT_INSTANCES' and
            compared['speedup_proven'] is False and compared['causal_link_proven'] is False,
            'WAVE02_R50_EQUAL_MEASURED_REPEATS_NOT_COMPARABLE_OR_IDENTITIES_MERGED')
    negative = compare_cases(first['folder'], changed['folder'])
    require(negative['comparison_status'] == 'NOT_COMPARABLE' and
            'workload' in negative['context_mismatches'],
            'WAVE02_R50_DIFFERENT_WORKLOAD_WAS_COMPARABLE')
    before_hashes = {str(Path(q['folder']) / filename):file_hash(Path(q['folder']) / filename)
        for q in (first,second,changed) for filename in
        ('session.sqlite3','session-v2.sqlite3','research.sqlite3')}
    exports = {}
    for kind in ('json','html'):
        destination = root / ('comparison.'+kind)
        receipt = export_comparison(first['folder'],second['folder'],destination,format=kind)
        loaded = load_comparison(destination)
        require(receipt['readback_verified'] is True and receipt['source_revalidated'] is True and
                receipt['sha256'] == file_hash(destination) and
                receipt['run_receipt']['operation'] == 'research.export_comparison' and
                loaded['comparison']['comparison_status'] == 'COMPARABLE' and
                loaded['source_trust'] == 'UNVERIFIED_IMPORT' and loaded['causal_link_proven'] is False,
                'WAVE02_R50_COMPARISON_EXPORT_OR_REAL_UNTRUSTED_READBACK_FAILED')
        if kind == 'json':
            require(json.loads(destination.read_text(encoding='utf-8'))['comparison']['comparison_status']
                    == 'COMPARABLE','WAVE02_R50_INDEPENDENT_COMPARISON_JSON_FAILED')
        digest = file_hash(destination)
        try: export_comparison(first['folder'],second['folder'],destination,format=kind)
        except FileExistsError: pass
        else: raise AssertionError('WAVE02_R50_COMPARISON_CLOBBERED_EXISTING_DESTINATION')
        require(file_hash(destination) == digest, 'WAVE02_R50_EXISTING_COMPARISON_CHANGED')
        exports[kind] = {'sha256':digest,'readback_verified':True,'no_clobber_verified':True}
    case = create_investigation([{'source_type':'SESSION','path':first['folder']}],
        scenario={'scenario':'BB-WAVE-02-RARE-NATIVE-BURST'},budget={'timeout_seconds':120},
        index_path=root / 'case.sqlite3')
    verify_case(case)
    require(any(q['observation_type'] == 'INCIDENT' for q in case['nodes']),
            'WAVE02_R50_REAL_INCIDENT_DID_NOT_REACH_INV3_GRAPH')
    graph_exports = export_case(case, root)
    require(all(file_hash(Path(path)) == digest for path,digest in before_hashes.items()),
            'WAVE02_R50_COMPARISON_OR_EXPORT_MODIFIED_SOURCE_RECORDINGS')
    save(root / 'comparison-actual.json',compared)
    save(root / 'comparison-negative.json',negative)
    print('WAVE02_R50_NATIVE_FACTS '+json.dumps({'status':'PASS','case_id':case['case_id'],
        'before':{key:first[key] for key in ('baseline_no_incident_observed','sample_count','incident_count','completed_actions','source_sha256','coverage')},
        'after':{key:second[key] for key in ('baseline_no_incident_observed','sample_count','incident_count','completed_actions','source_sha256','coverage')},
        'changed_workload':{key:changed[key] for key in ('baseline_no_incident_observed','sample_count','incident_count','completed_actions','source_sha256','coverage')},
        'comparison_status':compared['comparison_status'],'process_relation':compared['comparability']['process_relation'],
        'negative_status':negative['comparison_status'],'negative_context_mismatches':negative['context_mismatches'],
        'source_hashes_unchanged':True,'exports':exports,'graph_exports':graph_exports},sort_keys=True),flush=True)
    return {'status':'PASS','case_index':str(root/'case.sqlite3'),
        'before':first,'after':second,'changed_workload':changed,
        'comparison_status':compared['comparison_status'],
        'negative_status':negative['comparison_status'],'exports':exports,
        'graph_exports':graph_exports,'source_hashes_unchanged':True,
        'root_cause':'UNKNOWN','physical_windows_10_11':'NOT_TESTED'}
