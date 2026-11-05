"""Finite typed attestation for the optional owned-native-noise diagnostic control.

No application acceptance, scheduling equivalence or historical cause is inferred.
"""
POLICIES = ('INHERITED', 'DISABLED')
SCOPE = 'OWNED_WORKERS_BEFORE_READY_RELEASE_CACHED_NOT_CONTINUOUS'


def fully_differing_boost_controls(inherited, disabled):
    """Both pairs must witness enabled inheritance and an actual disabled change."""
    def exact(row, before, after):
        return (type(row) is dict and type(row.get('disabled_before_count')) is int and
                type(row.get('disabled_after_count')) is int and
                row['disabled_before_count'] == before and row['disabled_after_count'] == after)
    return (len(inherited) == len(disabled) == 2 and all(exact(r, 0, 0) for r in inherited) and
            all(exact(r, 0, 16) for r in disabled))


def require(value, code):
    if not value:
        raise AssertionError(code)


def requested_policy(producer):
    if 'thread_boost_policy' not in producer:
        return None  # Existing inherited benchmark remains unchanged until reviewed evidence.
    value = producer['thread_boost_policy']
    require(producer.get('implementation') == 'NATIVE_WIN32' and type(value) is str and value in POLICIES,
            'NOISE_THREAD_BOOST_REQUEST_INVALID')
    return value


def validate_cached_control(receipt, expected):
    require(type(expected) is str and expected in POLICIES and type(receipt) is dict and
        receipt.get('thread_boost_policy') == expected and receipt.get('thread_boost_observation_scope') == SCOPE,
        'NOISE_THREAD_BOOST_RECEIPT_POLICY')
    workers = receipt.get('workers')
    require(type(workers) is list and len(workers) == 16 and all(type(w) is dict and
        type(w.get('tid')) is int and 0 < w['tid'] <= 2**32-1 for w in workers) and
        len({w['tid'] for w in workers}) == 16, 'NOISE_THREAD_BOOST_WORKER_IDENTITIES')
    for worker in workers:
        before, after = worker.get('boost_disabled_before'), worker.get('boost_disabled_after')
        low, high = worker.get('relative_priority_before'), worker.get('relative_priority_after')
        require(type(before) is bool and type(after) is bool and worker.get('boost_control_verified') is True and
            type(low) is int and type(high) is int and -15 <= low <= 15 and low == high and
            (after is True if expected == 'DISABLED' else before is after), 'NOISE_THREAD_BOOST_CONTROL_UNCONFIRMED')
    return {'status': 'VERIFIED_CACHED_BEFORE_READY_CONTROL', 'policy': expected, 'scope': SCOPE,
        'worker_count': 16, 'disabled_before_count': sum(w['boost_disabled_before'] for w in workers),
        'disabled_after_count': sum(w['boost_disabled_after'] for w in workers),
        'all_relative_priorities_unchanged': True}


def validate_live_control(observation, ready, expected):
    cached = validate_cached_control(ready, expected)
    require(type(observation) is dict and observation.get('status') == 'OBSERVED' and
        observation.get('process_identity_verified_before') is True and
        observation.get('process_identity_verified_after') is True and observation.get('errors') == [] and
        type(observation.get('query_handles_opened')) is int and
        type(observation.get('query_handles_closed')) is int and
        observation['query_handles_opened'] == observation['query_handles_closed'] == 16 and
        observation.get('query_handles_closed_verified') is True and
        type(observation.get('retained_query_handles_after')) is int and
        observation['retained_query_handles_after'] == 0, 'NOISE_THREAD_BOOST_LIVE_QUERY_UNCONFIRMED')
    rows = observation.get('threads'); wanted = {w['tid']: w for w in ready['workers']}
    require(type(rows) is list and len(rows) == 16 and all(type(r) is dict and type(r.get('tid')) is int for r in rows) and
        {r['tid'] for r in rows} == set(wanted), 'NOISE_THREAD_BOOST_LIVE_WORKERS_UNCONFIRMED')
    for row in rows:
        recorded = wanted[row['tid']]
        require(row.get('status') == 'OBSERVED' and type(row.get('priority_boost_disabled')) is bool and
            row['priority_boost_disabled'] is recorded['boost_disabled_after'] and
            type(row.get('base_priority')) is int and 0 <= row['base_priority'] <= 31 and
            type(row.get('priority')) is int and 0 <= row['priority'] <= 31,
            'NOISE_THREAD_BOOST_LIVE_FLAGS_OR_NT_PRIORITY_UNAVAILABLE')
    return {**cached, 'status': 'VERIFIED_LIVE_OWNED_WORKER_QUERY_AFTER_READY',
        'scope': 'ONE_NONATOMIC_READONLY_LIVE_SNAPSHOT_NOT_CONTINUOUS_OR_CAUSAL',
        'priority_fields_scope': 'LIVE_NT_THREAD_BASIC_VALUES_NOT_COMPARABLE_TO_C_CACHED_WIN32_RELATIVE_PRIORITY',
        'process_priority_class': observation.get('priority_class'),
        'process_boost_disabled': observation.get('priority_boost_disabled'),
        'process_identity_verified_before': True, 'process_identity_verified_after': True,
        'affinity': observation.get('affinity'), 'query_handles_closed_verified': True,
        'retained_query_handles_after': 0,
        'workers': [{k: r.get(k) for k in ('tid','base_priority','priority','priority_boost_disabled','status')} for r in rows]}


def validate_controlled_native_boost_pair(first, second):
    """Additional policy admission; original native/content/resource oracles remain separate."""
    for case in (first, second):
        control=case.get('native_thread_boost_control',{})
        require(type(control) is dict and control.get('requested')=='DISABLED',
                'CONTROLLED_NATIVE_BOOST_POLICY_NOT_REQUESTED')
        ready,oracle,live=(control.get(k) for k in ('ready','oracle','live_ready'))
        require(type(ready) is dict and ready==oracle and
            ready.get('status')=='VERIFIED_CACHED_BEFORE_READY_CONTROL' and ready.get('policy')=='DISABLED' and
            ready.get('scope')==SCOPE and type(ready.get('worker_count')) is int and ready['worker_count']==16 and
            type(ready.get('disabled_before_count')) is int and 0<=ready['disabled_before_count']<=16 and
            type(ready.get('disabled_after_count')) is int and ready['disabled_after_count']==16 and
            ready.get('all_relative_priorities_unchanged') is True,
            'CONTROLLED_NATIVE_BOOST_CACHED_ATTESTATION_MISSING')
        require(type(live) is dict and live.get('status')=='VERIFIED_LIVE_OWNED_WORKER_QUERY_AFTER_READY' and
            live.get('policy')=='DISABLED' and live.get('query_handles_closed_verified') is True and
            type(live.get('retained_query_handles_after')) is int and live['retained_query_handles_after']==0 and
            live.get('process_identity_verified_before') is True and
            live.get('process_identity_verified_after') is True, 'CONTROLLED_NATIVE_BOOST_LIVE_ATTESTATION_MISSING')
        rows=live.get('workers')
        require(type(rows) is list and len(rows)==16 and all(type(r) is dict and type(r.get('tid')) is int and
            0<r['tid']<=2**32-1 and r.get('status')=='OBSERVED' and r.get('priority_boost_disabled') is True for r in rows) and
            len({r['tid'] for r in rows})==16, 'CONTROLLED_NATIVE_BOOST_LIVE_FLAGS_UNCONFIRMED')
    return {'status':'CONTROLLED_NATIVE_BASELINE_ATTESTED','policy':'DISABLED_FOR_OWNED_NATIVE_WORKERS_ONLY',
        'cached_scope':SCOPE,'live_scope':'TWO_NONATOMIC_START_SNAPSHOTS_NOT_CONTINUOUS_OR_CAUSAL',
        'legacy_inherited_condition_equivalent':False,'historical_deadline_cause':'NOT_ESTABLISHED'}
