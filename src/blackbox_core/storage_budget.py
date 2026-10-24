"""Bounded logical-size observation. No deletion and no filesystem-quota claim."""
from pathlib import Path
import time
def recording_size(folder,*,max_entries=4096,max_seconds=.1):
 pending=[Path(folder)];deadline=time.monotonic()+max_seconds;size=0;count=0
 while pending:
  parent=pending.pop()
  if parent.is_symlink():return {'bytes':None,'status':'UNSAFE_PATH','entries':count}
  try:
   for p in parent.iterdir():
    count+=1
    if count>max_entries or time.monotonic()>deadline:return {'bytes':None,'status':'METADATA_BUDGET_EXHAUSTED','entries':count}
    if p.is_symlink():return {'bytes':None,'status':'UNSAFE_PATH','entries':count}
    if p.is_dir():pending.append(p)
    elif p.is_file():size+=p.stat().st_size
  except OSError:return {'bytes':None,'status':'SIZE_UNAVAILABLE','entries':count}
 return {'bytes':size,'status':'OBSERVED_LOGICAL_FILE_BYTES','entries':count}

