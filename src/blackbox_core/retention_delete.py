"""Explicit, one-use, resumable purge of finalized app-marked Trash only."""
from contextlib import closing
import hashlib,json,os,re,time
from pathlib import Path
from uuid import uuid4
from .library_files import checked,read_json,atomic_json
from .owned_unlink import file_identity,remove_entry
def inventory(root):
 root=checked(root);rows=[];stack=[root];deadline=time.monotonic()+10
 while stack:
  parent=stack.pop()
  for path in parent.iterdir():
   if len(rows)>=10000 or time.monotonic()>deadline:raise ValueError('PURGE_INVENTORY_BUDGET')
   path=checked(path);rel=path.relative_to(root).as_posix()
   if len(Path(rel).parts)>12:raise ValueError('PURGE_DEPTH_LIMIT')
   ident=file_identity(path);st=path.stat();rows.append({'relative':rel,'identity':ident,'bytes':st.st_size if not ident['directory'] else None,'mtime_ns':st.st_mtime_ns if not ident['directory'] else None})
   if ident['directory']:stack.append(path)
 return sorted(rows,key=lambda r:(len(Path(r['relative']).parts),r['relative']),reverse=True)
def fingerprint(rows):
 return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def _alive(journal):
 import psutil
 try:return abs(psutil.Process(journal['owner_pid']).create_time()-journal['owner_created'])<.000001
 except (psutil.NoSuchProcess,KeyError,TypeError):return False
 except psutil.AccessDenied:return True
def _paths(catalog,row):
 if row['origin']!='LOCAL_APP_MARKED' or row['state'] not in ('TRASH','PURGING','PURGE_PARTIAL'):raise ValueError('PURGE_REQUIRES_OWNED_TRASH')
 if not re.fullmatch('[0-9a-f]{32}',row.get('trash_name') or ''):raise ValueError('PURGE_INVALID_TRASH_ID')
 container=checked(catalog._trash_root()/row['trash_name']);payload=checked(container/'payload')
 return container,payload
def _review(catalog,row):
 container,payload=_paths(catalog,row);path=container/'purge-manifest.json';journal_path=container/'purge-state.json'
 if journal_path.exists():
  journal=read_json(journal_path)
  if journal.get('state')=='PURGING' and _alive(journal):raise ValueError('PURGE_OWNER_STILL_ACTIVE')
 if path.exists():
  manifest=read_json(path,8*1024**2)
  if manifest.get('entry_id')!=row['entry_id'] or manifest.get('marker_uid')!=row['marker_uid'] or manifest.get('root_id')!=catalog._owner()['root_id']:raise ValueError('PURGE_MANIFEST_IDENTITY_CHANGED')
 else:
  marker=catalog._marker(payload,row)
  if marker.get('lifecycle')!='FINALIZED':raise ValueError('LIBRARY_FINALIZATION_UNCONFIRMED')
  from .library_catalog import recording_metadata,TERMINAL
  if recording_metadata(payload)['state'] not in TERMINAL:raise ValueError('LIBRARY_FINALIZATION_UNCONFIRMED')
  artifacts=payload/'artifacts'
  if artifacts.exists():
   for journal in artifacts.glob('*.trace.json'):
    if read_json(journal,65536).get('state') not in ('COMPLETED','FAILED','RECOVERED_NAMED_CANCEL','RECOVERED_OWNED_TOOL_STOP'):raise ValueError('LIBRARY_TRACE_STILL_ACTIVE')
  manifest={'kind':'BLACKBOX_PURGE_MANIFEST','schema_version':1,'entry_id':row['entry_id'],'marker_uid':row['marker_uid'],
   'root_id':catalog._owner()['root_id'],'payload_identity':file_identity(payload),'entries':inventory(payload)}
  atomic_json(path,manifest,exclusive=True,max_bytes=8*1024**2)
 if payload.exists():
  if file_identity(payload)!=manifest['payload_identity']:raise ValueError('PURGE_PAYLOAD_CHANGED')
  actual=inventory(payload);known={r['relative']:r for r in manifest['entries']}
  if any(r['relative'] not in known or r['identity']!=known[r['relative']]['identity'] for r in actual):raise ValueError('PURGE_NEW_OR_REPLACED_FILE')
 else:actual=[]
 return {'entry_id':row['entry_id'],'folder':str(payload),'marker_uid':row['marker_uid'],
  'remaining_entries':len(actual),'logical_bytes':sum(r['bytes'] or 0 for r in actual),
  'remaining_fingerprint':fingerprint(actual),'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def plan_purge(catalog,entry_ids):
 if type(entry_ids) is not list or not 1<=len(entry_ids)<=50 or len(set(entry_ids))!=len(entry_ids):raise ValueError('LIBRARY_INVALID_SELECTION')
 items=[_review(catalog,catalog.entry(eid)) for eid in entry_ids];token=uuid4().hex+uuid4().hex;now=time.time_ns()
 payload={'operation':'PURGE','root_id':catalog._owner()['root_id'],'items':items}
 with closing(catalog._connect(write=True)) as db:
  db.execute('DELETE FROM plans WHERE expires_ns<? OR used=1',(now,))
  if db.execute('SELECT count(*) FROM plans').fetchone()[0]>=128:raise ValueError('LIBRARY_CONFIRMATION_QUEUE_FULL')
  db.execute('INSERT INTO plans VALUES(?,?,?,?,0)',(hashlib.sha256(token.encode()).hexdigest(),now,now+300*10**9,json.dumps(payload)));db.commit()
 return {'confirmation_token':token,'expires_ns':now+300*10**9,'operation':'PERMANENT_DELETE_TRASH','items':items,'automatic_deletion':False,'bytes_freed':None}
def apply_purge(catalog,token):
 if type(token) is not str or not re.fullmatch('[0-9a-f]{64}',token):raise ValueError('LIBRARY_INVALID_CONFIRMATION')
 with closing(catalog._connect(write=True)) as db:
  db.execute('BEGIN IMMEDIATE');plan=db.execute('SELECT * FROM plans WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
  if not plan or plan['used'] or plan['expires_ns']<time.time_ns():raise ValueError('LIBRARY_CONFIRMATION_EXPIRED_OR_USED')
  payload=json.loads(plan['payload'])
  if payload.get('operation')!='PURGE' or payload.get('root_id')!=catalog._owner()['root_id']:raise ValueError('LIBRARY_WRONG_CONFIRMATION_OPERATION')
  for item in payload['items']:
   if _review(catalog,catalog.entry(item['entry_id']))!=item:raise ValueError('LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN')
  db.execute('UPDATE plans SET used=1 WHERE token_hash=?',(plan['token_hash'],));db.commit()
 results=[]
 import psutil
 for item in payload['items']:
  row=catalog.entry(item['entry_id']);container,folder=_paths(catalog,row);path=container/'purge-state.json'
  journal={'state':'PURGING','owner_pid':os.getpid(),'owner_created':psutil.Process().create_time(),'entry_id':row['entry_id'],'started_utc_ns':time.time_ns()}
  atomic_json(path,journal)
  with closing(catalog._connect(write=True)) as db:
   changed=db.execute("UPDATE entries SET state='PURGING' WHERE entry_id=? AND state=?",(row['entry_id'],row['state'])).rowcount;db.commit()
  if changed!=1:raise ValueError('PURGE_CLAIM_CHANGED')
  try:
   manifest=read_json(container/'purge-manifest.json',8*1024**2)
   if folder.exists():
    actual=inventory(folder)
    if fingerprint(actual)!=item['remaining_fingerprint']:raise ValueError('PURGE_RECORDING_CHANGED')
    for entry in actual:remove_entry(folder,entry['relative'],entry['identity'],manifest['payload_identity'])
    remove_entry(folder,'.',manifest['payload_identity'],manifest['payload_identity'])
   journal['state']='PURGED'
  except (OSError,ValueError) as exc:journal.update(state='PURGE_PARTIAL',error=str(exc)[:300])
  atomic_json(path,journal)
  with closing(catalog._connect(write=True)) as db:
   db.execute('UPDATE entries SET state=?,updated_ns=?,last_error=? WHERE entry_id=?',(journal['state'],time.time_ns(),journal.get('error'),row['entry_id']));db.commit()
  results.append({'entry_id':row['entry_id'],'status':journal['state'],'error':journal.get('error')})
 return {'results':results,'bytes_freed':None,'physical_free_space_measured':False,'automatic_deletion':False}

