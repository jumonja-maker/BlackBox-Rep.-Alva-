"""Artifactless same-job ABBA observations; never substitutes for full acceptance."""
from pathlib import Path
import argparse
import json
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from tools import qa_decoder_apps as apps
from tools import qa_decoder_budget_diagnostic as diagnostic
from tools.qa_decoder_noise_fixture import load_prepared_native_noise
from tools.qa_deep_inspection import require_hosted_windows
from tools.qa_noise_boost_control import fully_differing_boost_controls
from blackbox_universal.provenance import source_identity

PILOT_SECONDS=1800
ORDER=('INHERITED','DISABLED','DISABLED','INHERITED')


def case_facts(case):
    small=case.get('small_facts',{});workload=small.get('workload',{})
    image=case.get('application_sha256')
    if not isinstance(image,str) or len(image)!=64:image=workload.get('application_sha256')
    digest=case.get('input_sha256')
    if not isinstance(digest,str) or len(digest)!=64:digest=small.get('actual_input_file',{}).get('sha256')
    return {'input_sha256':digest,'application_sha256':image,'roundtrips_verified':case.get('roundtrips_verified',workload.get('roundtrips_verified')),
        'workload_failure':small.get('workload_failure'),'native_timing':case.get('native_timing'),
        'native_thread_boost_control':case.get('native_thread_boost_control'),
        'native_output':case.get('native_output'),'noise_handoffs':case.get('noise_handoffs')}


def run(args):
    require_hosted_windows()
    identity=source_identity(args.source_sha)
    apps.require(identity['source_identity_status']=='VERIFIED_EXPECTED_HEAD','PILOT_SOURCE_IDENTITY')
    started=time.monotonic();deadline=started+PILOT_SECONDS
    output=diagnostic.diagnostic_output_root(args.output,prepared=True)
    proof={'schema':'blackbox.native-noise-policy-pilot/1','status':'NOT_ESTABLISHED',
        'source_identity':identity,'case_order':list(ORDER),'cases':[],
        'scope':'TWO_SAME_JOB_PAIRS_ABBA_NOT_STATISTICAL_OR_GENERAL_CAUSAL_PROOF',
        'application_acceptance':False,'release_acceptance':False,'historical_cause':'NOT_ESTABLISHED',
        'fixed_limits':{'process_seconds':90,'aggregate_qpc_seconds':95,'ready_to_work_seconds':90,
            'native_ttl_seconds':210,'native_progress':841,'native_owner_seconds':225,
            'product_caps_changed':False,'workload_input_bytes':8*1024**2,'pairs':8,'worker_threads':16},
        'pilot_deadline_seconds':PILOT_SECONDS,'diagnostic_completion_is_application_pass':False}
    exit_code=1
    try:
        native=load_prepared_native_noise(output/'native-build',args.source_sha,
            expected_manifest_sha256=args.prepared_build_sha256)
        initial=dict(native['prepared_validation']);proof['prepared_initial']=initial
        proof['prepared_compile_seconds']=native['prepared_build_elapsed_seconds']
        deadline-=native['prepared_build_elapsed_seconds']
        helper=args.helper.resolve(strict=True)
        for ordinal,mode in enumerate(ORDER,1):
            apps.require(time.monotonic()<deadline,'PILOT_ACTIVE_DEADLINE')
            producer={**native,'thread_boost_policy':mode}
            case=diagnostic.run_case(output/f'{ordinal:02d}-{mode.lower()}',helper,args.source_sha,deadline,
                'schedule',producer,'NATIVE_BUDGET_NEGATIVE')
            facts=case_facts(case)
            result={'ordinal':ordinal,'policy':mode,'status':case['status'],'reason_code':case.get('reason_code'),
                'rows':case.get('rows'),'decoder_status':case.get('decoder_status'),
                'noise_cleanup':case.get('noise_cleanup'),'capture_cleanup':case.get('capture_cleanup'),
                'receipt_reader_cleanup':case.get('receipt_reader_cleanup'),'facts':facts}
            proof['cases'].append(result)
            apps.require(case.get('noise_cleanup',{}).get('status')=='COMPLETED' and
                case.get('capture_cleanup',{}).get('cleanup_required') is False and
                case.get('receipt_reader_cleanup',{}).get('retained_handles')==0 and
                not (isinstance(facts['workload_failure'],dict) and facts['workload_failure'].get('cleanup_error')),
                'PILOT_OWNED_CLEANUP_UNCONFIRMED')
            control=facts['native_thread_boost_control'] or {}
            apps.require(control.get('requested')==mode and
                control.get('ready',{}).get('status')=='VERIFIED_CACHED_BEFORE_READY_CONTROL' and
                control.get('oracle',{}).get('status')=='VERIFIED_CACHED_BEFORE_READY_CONTROL' and
                control.get('live_ready',{}).get('status')=='VERIFIED_LIVE_OWNED_WORKER_QUERY_AFTER_READY',
                'PILOT_ACTUAL_BOOST_CONTROL_NOT_ESTABLISHED')
            live=sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
            apps.require(live<=diagnostic.MAX_OUTPUT and time.monotonic()<deadline,'PILOT_OWNED_OUTPUT_OR_TIME_BUDGET')
            apps.write_json(output/'pilot-observations.json',proof)
            print('NATIVE_NOISE_POLICY_PILOT_CASE '+json.dumps(result,sort_keys=True),flush=True)
        inputs=[c['facts']['input_sha256'] for c in proof['cases']]
        images=[c['facts']['application_sha256'] for c in proof['cases']]
        apps.require(all(isinstance(v,str) and len(v)==64 for v in inputs+images) and
            len(set(inputs))==len(set(images))==1,'PILOT_IDENTICAL_INPUT_AND_APPLICATION_NOT_ESTABLISHED')
        final=load_prepared_native_noise(output/'native-build',args.source_sha,
            expected_manifest_sha256=args.prepared_build_sha256)
        proof['prepared_final']=diagnostic.validate_prepared_recheck(native,final)
        apps.require(proof['prepared_final']==initial and not diagnostic._RETAINED_RECEIPT_HANDLES,
                     'PILOT_PREPARED_OR_READER_CLEANUP_UNCONFIRMED')
        inherited=[c for c in proof['cases'] if c['policy']=='INHERITED']
        disabled=[c for c in proof['cases'] if c['policy']=='DISABLED']
        good=lambda c:c['status']=='EXPECTED_NATIVE_BUDGET_NEGATIVE' and c['decoder_status']=='TRUNCATED' and c['rows']==250000 and (c['facts']['native_output'] or {}).get('native_truncation_reason')=='MAX_EVENTS'
        discriminating=fully_differing_boost_controls(
            [c['facts']['native_thread_boost_control']['ready'] for c in inherited],
            [c['facts']['native_thread_boost_control']['ready'] for c in disabled])
        proof['interpretation']={'inherited_actual_statuses':[c['status'] for c in inherited],
            'disabled_actual_statuses':[c['status'] for c in disabled],
            'inherited_all_completed_row_negative':all(good(c) for c in inherited),
            'disabled_all_completed_row_negative':all(good(c) for c in disabled),
            'baseline_had_boosts_enabled_in_all_workers':discriminating,
            'candidate_evidence':'SUPPORTED_ON_THIS_HOST_ONLY' if discriminating and
                all(good(c) for c in disabled) and any(not good(c) for c in inherited) else 'INCONCLUSIVE',
            'underlying_cause':'NOT_ESTABLISHED','all_old_failures_remain_failures':True,
            'not_full_native_positive_acceptance':True,'new_full_ci_still_required':True}
        proof['status']='OBSERVATIONS_COMPLETED_NOT_APPLICATION_ACCEPTANCE'
        exit_code=0
    except BaseException as error:
        proof.update(status='DIAGNOSTIC_INCOMPLETE',error_type=type(error).__name__,reason_code=apps._qa_code(str(error)))
    finally:
        proof['elapsed_active_seconds']=time.monotonic()-started+proof.get('prepared_compile_seconds',0)
        proof['final_source_identity']=source_identity(args.source_sha)
        apps.write_json(output/'pilot-observations.json',proof)
        print('NATIVE_NOISE_POLICY_PILOT '+json.dumps(proof,sort_keys=True),flush=True)
    return exit_code


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--helper',type=Path,required=True)
    p.add_argument('--source-sha',required=True);p.add_argument('--prepared-build-sha256',required=True)
    raise SystemExit(run(p.parse_args()))
