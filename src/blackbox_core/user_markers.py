"""Durable user markers with actual command time, never OS observations."""
import time
from uuid import uuid4
class UserMarkers:
 def __init__(self):self.active={}
 def snapshot(self):return list(self.active.values())
 def write(self,book,probe,args,*,issued_ns=None):
  if book is None or not probe.active:raise ValueError('START_RECORDING_FIRST')
  kind=args.get('kind');name=args.get('name','');note=args.get('note','');now=time.monotonic_ns()
  if kind not in ('PROBLEM','STAGE_BEGIN','STAGE_END','COMMENT') or type(name) is not str or len(name)>128 or type(note) is not str or len(note)>2048:raise ValueError('INVALID_USER_MARKER')
  stamp=now if issued_ns is None else issued_ns
  if type(stamp) is not int or not probe._recording_origin_ns<=stamp<=now:raise ValueError('INVALID_USER_MARKER_TIME')
  row={'kind':kind,'name':name,'note':note,'timestamp_monotonic_ns':stamp,'received_monotonic_ns':now,
   'sample_seq':probe.total_samples,'source':'USER_MARKER','verification_class':'USER_DECLARED'}
  code={'PROBLEM':'user.problem','COMMENT':'user.comment','STAGE_BEGIN':'user.stage_begin','STAGE_END':'user.stage_end'}[kind]
  if kind=='STAGE_BEGIN':
   if not name.strip() or len(self.active)>=32:raise ValueError('USER_STAGE_LIMIT_OR_NAME')
   row['stage_id']=uuid4().hex
  elif kind=='STAGE_END':
   previous=self.active.get(args.get('stage_id'))
   if not previous or stamp<previous['timestamp_monotonic_ns']:raise ValueError('USER_STAGE_NOT_ACTIVE')
   row.update(stage_id=previous['stage_id'],name=previous['name'],duration_ns=stamp-previous['timestamp_monotonic_ns'])
  evidence=book.put(code,row,source='USER_MARKER',quality='USER_DECLARED',at_ns=stamp)
  if kind=='STAGE_BEGIN':self.active[row['stage_id']]=row
  elif kind=='STAGE_END':del self.active[row['stage_id']]
  return {**row,'evidence_id':evidence}
 def close(self,book,*,reason):
  for row in list(self.active.values()):
   book.put('user.stage_aborted',{**row,'stop_reason':reason,'completion_confirmed':False},source='USER_MARKER',quality='USER_DECLARED')
   del self.active[row['stage_id']]

