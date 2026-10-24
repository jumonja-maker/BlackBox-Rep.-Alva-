"""Crash-safe export journal. Publication never overwrites an existing file.
Recovery requires explicit confirmation, a dead owner, native identities and
SHA-256. Original recordings are never edited; unknown staged files are kept.
"""
from contextlib import contextmanager
import hashlib,os,re,time
from pathlib import Path
from uuid import uuid4
from .library_files import checked,atomic_json,read_json,move_no_replace
from .owned_unlink import file_identity,remove_entry
from .retention_delete import inventory
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def same(a,b):
 return isinstance(a,dict) and isinstance(b,dict) and a.get('identity')==b.get('identity') and a.get('directory')==b.get('directory')
def owner_alive(data):
 import psutil
 try:return abs(psutil.Process(data['owner_pid']).create_time()-data['owner_created'])<.000001
 except (psutil.NoSuchProcess,KeyError,TypeError,ValueError):return False
 except psutil.AccessDenied:return True
def validate(output,stage,data,*,ready):
 if data.get('kind')!='BLACKBOX_EXPORT_TRANSACTION' or data.get('schema_version')!=1 or not re.fullmatch('[0-9a-f]{32}',str(data.get('uid'))):raise ValueError('EXPORT_INVALID_JOURNAL')
 if stage.parent!=output or stage.name!='.bb-export-'+data['uid'] or file_identity(stage)!=data.get('stage_identity') or file_identity(output)!=data.get('output_identity'):raise ValueError('EXPORT_RECOVERY_IDENTITY_CHANGED')
 if ready and (data.get('prepared') is not True or not data.get('files')):raise ValueError('EXPORT_RECOVERY_BUILD_INCOMPLETE')
 if ready and data.get('state') not in ('READY_TO_PUBLISH','COMMITTED','INTERRUPTED'):raise ValueError('EXPORT_RECOVERY_BUILD_INCOMPLETE')
 rows=data.get('files')
 if type(rows) is not list or len(rows)>100:raise ValueError('EXPORT_INVALID_JOURNAL')
 names=set();finals=set()
 for row in rows:
  for key in ('stage_name','destination'):
   text=row.get(key)
   if type(text) is not str or not text or len(text)>256 or Path(text).name!=text:raise ValueError('EXPORT_INVALID_JOURNAL')
  if row['stage_name'] in names or row['destination'] in finals:raise ValueError('EXPORT_INVALID_JOURNAL')
  names.add(row['stage_name']);finals.add(row['destination'])
  source=checked(stage/row['stage_name']);dest=checked(output/row['destination'])
  if dest.exists() and not same(file_identity(dest),row.get('identity')):raise FileExistsError('EXPORT_DESTINATION_EXISTS')
  present=dest if dest.exists() else source
  if not present.is_file() or not same(file_identity(present),row.get('identity')) or digest(present)!=row.get('sha256'):raise ValueError('EXPORT_RECOVERY_FILE_CHANGED')
  if source.exists() and not same(file_identity(source),row['identity']):raise ValueError('EXPORT_RECOVERY_FILE_CHANGED')
def cleanup(output,stage,data):
 if file_identity(stage)!=data['stage_identity']:raise ValueError('EXPORT_RECOVERY_IDENTITY_CHANGED')
 known={r['relative']:r for r in data.get('cleanup_inventory',[])};actual=inventory(stage)
 if any(r['relative'] not in known or r['identity']!=known[r['relative']]['identity'] for r in actual):raise ValueError('EXPORT_RECOVERY_BUILD_INCOMPLETE')
 for r in actual:remove_entry(stage,r['relative'],r['identity'],data['stage_identity'])
 remove_entry(output,stage.name,data['stage_identity'],data['output_identity'])
class ExportTransaction:
 def __init__(self,output,*,kind):
  import psutil
  self.output=checked(output)
  if not self.output.is_dir():raise ValueError('EXPORT_DIRECTORY_REQUIRED')
  uid=uuid4().hex;self.stage=self.output/('.bb-export-'+uid);self.stage.mkdir(mode=0o700)
  self.journal=self.output/(self.stage.name+'.json')
  self.data={'schema_version':1,'kind':'BLACKBOX_EXPORT_TRANSACTION','export_kind':kind,'uid':uid,
   'state':'BUILDING','stage_identity':file_identity(self.stage),'output_identity':file_identity(self.output),
   'owner_pid':os.getpid(),'owner_created':psutil.Process().create_time(),'created_utc_ns':time.time_ns(),
   'prepared':False,'files':[],'cleanup_inventory':[],'published':[],'automatic_deletion':False}
  atomic_json(self.journal,self.data,exclusive=True)
 def save(self):atomic_json(self.journal,self.data,max_bytes=8*1024**2)
 def reserve(self,name,*,directory=False):
  relative=Path(name)
  if relative.is_absolute() or not relative.parts or any(p in ('.','..') for p in relative.parts):raise ValueError('EXPORT_INVALID_STAGE_FILE')
  path=checked(self.stage/relative)
  if directory:path.mkdir(mode=0o700)
  else:
   with path.open('xb'):pass
  self.data['cleanup_inventory'].append({'relative':relative.as_posix(),'identity':file_identity(path)});self.save()
  return path
 def prepare(self,files):
  if not files or len(files)>100:raise ValueError('EXPORT_FILE_COUNT_LIMIT')
  rows=[]
  for final,path in files.items():
   path=checked(path)
   if path.parent!=self.stage or Path(final).name!=final or not final or len(final)>256:raise ValueError('EXPORT_INVALID_STAGE_FILE')
   dest=checked(self.output/final)
   if dest.exists() or dest.is_symlink():raise FileExistsError('EXPORT_DESTINATION_EXISTS')
   with path.open('rb+') as f:os.fsync(f.fileno())
   rows.append({'stage_name':path.name,'destination':final,'identity':file_identity(path),'bytes':path.stat().st_size,'sha256':digest(path)})
  self.data.update(files=rows,cleanup_inventory=inventory(self.stage),state='READY_TO_PUBLISH',prepared=True);self.save()
 def publish(self):
  validate(self.output,self.stage,self.data,ready=True)
  # A crash after link but before journal save is reconciled by native ID/hash.
  existing=[]
  for r in self.data['files']:
   dest=checked(self.output/r['destination'])
   if dest.exists():
    if not same(file_identity(dest),r['identity']) or digest(dest)!=r['sha256']:raise FileExistsError('EXPORT_DESTINATION_EXISTS')
    existing.append(r['destination'])
  self.data['published']=existing
  for r in self.data['files']:
   if r['destination'] in self.data['published']:continue
   source=self.stage/r['stage_name'];dest=self.output/r['destination']
   if os.name=='nt':move_no_replace(source,dest)
   else:os.link(source,dest)
   self.data['published'].append(r['destination']);self.save()
  self.data['state']='COMMITTED';self.save();cleanup(self.output,self.stage,self.data);self.journal.unlink()
 def abort(self):
  self.data['state']='INTERRUPTED';self.save()
  for r in self.data['files']:
   dest=self.output/r['destination']
   if r['destination'] in self.data['published'] and dest.exists():remove_entry(self.output,dest.name,r['identity'],self.data['output_identity'])
  self.data['published']=[];self.save();cleanup(self.output,self.stage,self.data);self.journal.unlink()
@contextmanager
def export_stage(output,*,kind):
 tx=ExportTransaction(output,kind=kind)
 try:yield tx
 except BaseException:
  try:tx.abort()
  except (OSError,ValueError):pass
  raise
def scan_exports(output,*,limit=50):
 if type(limit) is not int or not 1<=limit<=100:raise ValueError('EXPORT_INVALID_QUERY')
 output=checked(output);rows=[]
 for path in output.glob('.bb-export-*.json'):
  if len(rows)>=limit:break
  try:
   data=read_json(path,8*1024**2)
   if path.name!='.bb-export-'+str(data.get('uid'))+'.json' or data.get('kind')!='BLACKBOX_EXPORT_TRANSACTION':raise ValueError('EXPORT_INVALID_JOURNAL')
   rows.append({'journal':str(path),'state':data.get('state'),'kind':data.get('export_kind'),
    'owner_active':owner_alive(data),'can_finish':data.get('prepared') is True and bool(data.get('files')),'files':len(data.get('files',[])),'created_utc_ns':data.get('created_utc_ns')})
  except (OSError,ValueError):rows.append({'journal':str(path),'state':'INVALID_RETAINED','owner_active':None})
 return {'rows':rows,'scan_limit':limit,'automatic_deletion':False}
def recover_export(journal,*,action,confirmed=False):
 if confirmed is not True or action not in ('FINISH','DISCARD'):raise ValueError('EXPORT_RECOVERY_CONFIRMATION_REQUIRED')
 path=checked(journal);data=read_json(path,8*1024**2);output=path.parent;stage=output/('.bb-export-'+str(data.get('uid')))
 if path.name!=stage.name+'.json':raise ValueError('EXPORT_INVALID_JOURNAL')
 if owner_alive(data):raise ValueError('EXPORT_RECOVERY_OWNER_ACTIVE')
 validate(output,stage,data,ready=action=='FINISH')
 tx=object.__new__(ExportTransaction);tx.output=output;tx.stage=stage;tx.journal=path;tx.data=data
 data['published']=[r['destination'] for r in data['files'] if (output/r['destination']).exists()]
 if action=='FINISH':tx.publish()
 else:tx.abort()
 return {'status':'RECOVERED' if action=='FINISH' else 'DISCARDED_OWNED_OUTPUTS',
  'files':[str(output/r['destination']) for r in data['files']] if action=='FINISH' else [],'source_modified':False}

