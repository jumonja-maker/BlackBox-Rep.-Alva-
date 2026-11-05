"""Finite typed attestation for the optional owned-native-noise diagnostic control.

No application acceptance, scheduling equivalence or historical cause is inferred.
"""
POLICIES = ('INHERITED', 'DISABLED')
SCOPE = 'OWNED_WORKERS_BEFORE_READY_RELEASE_CACHED_NOT_CONTINUOUS'


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
        observation.get('query_handles_opened') == observation.get('query_handles_closed') == 16 and
        observation.get('query_handles_closed_verified') is True and
        observation.get('retained_query_handles_after') == 0, 'NOISE_THREAD_BOOST_LIVE_QUERY_UNCONFIRMED')
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
        'affinity': observation.get('affinity'), 'query_handles_closed_verified': True,
        'retained_query_handles_after': 0,
        'workers': [{k: r.get(k) for k in ('tid','base_priority','priority','priority_boost_disabled','status')} for r in rows]}
