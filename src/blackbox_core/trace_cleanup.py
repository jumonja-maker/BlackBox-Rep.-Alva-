"""Read-only interpretation of recorded trace cleanup acknowledgments.

This validates a journal's internal scope/identity consistency, not its
authenticity or the current liveness of its owner/guardian. It performs no OS
query and cannot grant a live parent the private cleanup authority it retains.
"""
from __future__ import annotations

import re


def terminal_cleanup_proven(data, *, journal=None):
    """Whether a terminal journal carries a matching exact cleanup proof.

    Legacy terminal labels alone remain unknown. The old guardian's separate
    NAMED_CANCEL_CONFIRMED acknowledgment is recognized for a failed WPR
    capture only, provided no newer/contradictory cleanup result is present.
    ``journal`` optionally binds the basename without accessing a filesystem.
    """
    if type(data) is not dict or data.get('consent')!='EXPLICIT_USER_COMMAND':return False
    instance,uid=data.get('instance'),data.get('uid')
    if type(instance) is str and re.fullmatch(r'BLACKBOX_[0-9a-f]{32}',instance) and uid is None:
        kind,trace_id,filename='WPR',instance,instance+'.trace.json'
    elif type(uid) is str and re.fullmatch(r'[0-9a-f]{32}',uid) and instance is None:
        kind,trace_id,filename='EVENTPIPE',uid,'EVENTPIPE_'+uid+'.trace.json'
    else:return False
    if journal is not None and journal!=filename:return False
    state=data.get('state')
    if state not in ('COMPLETED','FAILED','RECOVERED_NAMED_CANCEL','RECOVERED_OWNED_TOOL_STOP'):
        return False
    if state in ('COMPLETED','FAILED') and data.get('cleanup_error'):return False
    if 'resource_cleanup' not in data:
        return (kind=='WPR' and state=='FAILED' and
                data.get('cleanup')=='NAMED_CANCEL_CONFIRMED')
    proof=data['resource_cleanup']
    if type(proof) is not dict or proof.get('confirmed') is not True:return False
    scope=proof.get('scope')
    if state in ('COMPLETED','FAILED'):
        return ((kind=='WPR' and scope=='EXACT_NAMED_WPR_INSTANCE' and
                 proof.get('instance')==trace_id) or
                (kind=='EVENTPIPE' and scope=='EXACT_OWNED_EVENTPIPE_PROCESS_BOUNDARY' and
                 proof.get('uid')==trace_id))
    recovered=data.get('recovered_utc_ns')
    return (scope=='EXPLICIT_EXACT_NAMED_RECOVERY' and proof.get('trace_id')==trace_id and
            data.get('recovery_consent')=='EXPLICIT_USER_COMMAND' and
            type(recovered) is int and recovered>=0 and
            state==('RECOVERED_NAMED_CANCEL' if kind=='WPR' else 'RECOVERED_OWNED_TOOL_STOP'))
