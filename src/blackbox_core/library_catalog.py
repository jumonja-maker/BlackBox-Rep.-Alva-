"""Indexed local research library and explicitly confirmed reversible storage.

Browsing reads only this index. Directory scans are explicit, bounded jobs;
lifecycle writes happen at Start/Stop, never per sample. Original observations
are read-only. Trash moves whole app-marked directories and never deletes data.
"""
from __future__ import annotations
from contextlib import closing
from datetime import datetime,timezone
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time
from uuid import uuid4

from .library_files import checked,read_json,atomic_json,identity,tree_summary,move_no_replace

APP_ID=0x42424C31
OWNER='blackbox-library-owner.json'
MARKER='blackbox-session.json'
TRASH='blackbox-trash'
TERMINAL=frozenset({'COMPLETED','INTERRUPTED','PROCESS_EXITED','PID_REUSED','ACCESS_DENIED',
    'SAMPLE_UNAVAILABLE','STORAGE_ERROR','INCOMPLETE','RECOVERED_INCOMPLETE','TIME_LIMIT_REACHED','STORAGE_LIMIT_REACHED'})
SESSION_NAME=re.compile(r'session-[0-9a-f]{32}\Z')
DDL='''
CREATE TABLE IF NOT EXISTS library_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries(
 entry_id TEXT PRIMARY KEY,locator TEXT NOT NULL UNIQUE,folder_name TEXT,external_path TEXT,
 origin TEXT NOT NULL,marker_uid TEXT,started_ns INTEGER NOT NULL,ended_ns INTEGER,state TEXT NOT NULL,
 target_name TEXT,scenario TEXT,scenario_version TEXT,target_version TEXT,workload TEXT,profile TEXT,
 interval_ms INTEGER,samples INTEGER,completed_runs INTEGER,size_bytes INTEGER,size_status TEXT,
 updated_ns INTEGER NOT NULL,search_text TEXT NOT NULL,owner_pid INTEGER,owner_created REAL,
 configuration_changed INTEGER NOT NULL DEFAULT 0,trash_name TEXT,previous_state TEXT,last_error TEXT);
CREATE INDEX IF NOT EXISTS ix_library_time ON entries(started_ns DESC,entry_id DESC);
CREATE INDEX IF NOT EXISTS ix_library_state ON entries(state,started_ns DESC,entry_id DESC);
CREATE INDEX IF NOT EXISTS ix_library_target ON entries(target_name,started_ns DESC);
CREATE TABLE IF NOT EXISTS plans(token_hash TEXT PRIMARY KEY,created_ns INTEGER NOT NULL,
 expires_ns INTEGER NOT NULL,payload TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0);
'''


def _text(value):return str(value or '')[:256]


def _uuid(value):return isinstance(value,str) and bool(re.fullmatch('[0-9a-f]{32}',value))


def _reader(path):
    path=checked(path)
    if not path.is_file():raise ValueError('LIBRARY_RECORDING_NOT_FOUND')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.1)
    try:
        db.row_factory=sqlite3.Row;db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,65536)
        db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
        deadline=time.monotonic()+2
        db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
        return db
    except BaseException:db.close();raise


def recording_metadata(folder):
    """Explicit import/refresh only. No stored source string authenticates it."""
    folder=checked(folder)
    with closing(_reader(folder/'session.sqlite3')) as db:
        rows=db.execute('SELECT * FROM metadata LIMIT 2').fetchall()
        if len(rows)!=1 or rows[0]['schema_version']!=1:raise ValueError('LIBRARY_UNSUPPORTED_RECORDING')
        row=dict(rows[0]);aggregate=db.execute('SELECT count(*),max(elapsed_ms) FROM samples').fetchone()
    try:stamp=int(datetime.fromisoformat(row['started_utc'].replace('Z','+00:00')).timestamp()*1e9)
    except (TypeError,ValueError,OverflowError):raise ValueError('LIBRARY_INVALID_RECORDING_CLOCK') from None
    if not 0<=stamp<=2**63-1:raise ValueError('LIBRARY_INVALID_RECORDING_CLOCK')
    context={};runs=None
    if (folder/'research.sqlite3').is_file():
        with closing(_reader(folder/'research.sqlite3')) as db:
            for r in db.execute("SELECT key,data FROM context WHERE key IN ('experiment','state','worker_pid','worker_created','configuration_changed') LIMIT 8"):
                context[r['key']]=json.loads(r['data'])
            runs=db.execute('SELECT count(*) FROM action_runs').fetchone()[0]
    experiment=context.get('experiment',{})
    if not isinstance(experiment,dict):raise ValueError('LIBRARY_INVALID_RECORDING_CONTEXT')
    result={k:_text(experiment.get(k)) for k in ('scenario','scenario_version','target_version','workload','profile')}
    result.update(started_ns=stamp,state=_text(context.get('state') or row['exit_code'] or 'RECORDING'),
        samples=aggregate[0],duration_ms=aggregate[1],completed_runs=runs,owner_pid=context.get('worker_pid'),
        owner_created=context.get('worker_created'),interval_ms=experiment.get('interval_ms'),
        configuration_changed=bool(context.get('configuration_changed')),target_name='')
    if (folder/'session-v2.sqlite3').is_file():
        with closing(_reader(folder/'session-v2.sqlite3')) as db:
            r=db.execute('SELECT executable_name FROM targets WHERE target_id=1').fetchone()
            if r:result['target_name']=_text(r[0])
    return result


class LibraryCatalog:
    def __init__(self,root):
        self.root=checked(root);self.path=self.root/'blackbox-library.sqlite3'

    def _owner(self,create=False):
        if create:self.root.mkdir(parents=True,exist_ok=True);checked(self.root)
        path=self.root/OWNER
        if create and not path.exists():
            data={'schema_version':1,'kind':'BLACKBOX_LIBRARY_ROOT','root_id':uuid4().hex}
            try:atomic_json(path,data,exclusive=True)
            except FileExistsError:pass
        data=read_json(path)
        if data.get('kind')!='BLACKBOX_LIBRARY_ROOT' or not _uuid(data.get('root_id')):
            raise ValueError('LIBRARY_ROOT_NOT_MARKED')
        return data

    def _connect(self,write=False):
        owner=self._owner(create=write);checked(self.path)
        if not write and not self.path.is_file():raise ValueError('LIBRARY_INDEX_NOT_FOUND')
        if write:
            db=sqlite3.connect(self.path,timeout=.05)
        else:db=sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,timeout=.1)
        try:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA trusted_schema=OFF')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,1024*1024);db.execute('PRAGMA cache_size=-2048')
            deadline=time.monotonic()+3
            db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
            app=db.execute('PRAGMA application_id').fetchone()[0]
            if app not in (0,APP_ID):raise ValueError('LIBRARY_WRONG_DATABASE')
            if write and app==0:
                # Schema, application ID and root identity commit together. An
                # interrupted first creation must not leave half-owned tables.
                db.execute('BEGIN IMMEDIATE')
                current=db.execute('PRAGMA application_id').fetchone()[0]
                if current==0:
                    if db.execute("SELECT count(*) FROM sqlite_schema WHERE type='table'").fetchone()[0]:
                        raise ValueError('LIBRARY_WRONG_DATABASE')
                    for statement in DDL.split(';'):
                        if statement.strip():db.execute(statement)
                    db.execute('PRAGMA application_id='+str(APP_ID));db.execute('PRAGMA user_version=1')
                    db.execute("INSERT INTO library_meta VALUES('root_id',?)",(owner['root_id'],))
                elif current!=APP_ID:raise ValueError('LIBRARY_WRONG_DATABASE')
                db.commit()
            elif app!=APP_ID:raise ValueError('LIBRARY_WRONG_DATABASE')
            if db.execute('PRAGMA user_version').fetchone()[0]!=1:raise ValueError('LIBRARY_UNSUPPORTED_SCHEMA')
            recorded=db.execute("SELECT value FROM library_meta WHERE key='root_id'").fetchone()
            if recorded is None or recorded[0]!=owner['root_id']:raise ValueError('LIBRARY_ROOT_ID_MISMATCH')
            if write:db.execute('PRAGMA synchronous=FULL')
            else:db.execute('PRAGMA query_only=ON')
            return db
        except BaseException:db.close();raise

    def _folder(self,row):
        if row['state'] in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED') and row['trash_name']:
            return checked(self.root/TRASH/row['trash_name']/'payload')
        if row['origin']=='LOCAL_APP_MARKED':
            name=row['folder_name']
            if not SESSION_NAME.fullmatch(name or ''):raise ValueError('LIBRARY_INVALID_LOCAL_PATH')
            return checked(self.root/name)
        return checked(row['external_path'])

    def _marker(self,folder,row=None):
        marker=read_json(folder/MARKER);owner=self._owner()
        if (marker.get('kind')!='BLACKBOX_OWNED_SESSION' or marker.get('root_id')!=owner['root_id'] or
                not _uuid(marker.get('marker_uid')) or marker.get('session_name')!=(row['folder_name'] if row else folder.name)):
            raise ValueError('LIBRARY_SESSION_NOT_MARKED')
        if row is not None and marker['marker_uid']!=row['marker_uid']:raise ValueError('LIBRARY_SESSION_ID_CHANGED')
        return marker

    def _upsert(self,db,entry,meta,size):
        now=time.time_ns();fields={k:_text(meta.get(k)) for k in ('target_name','scenario','scenario_version','target_version','workload','profile')}
        state=_text(meta.get('state')) or 'UNKNOWN'
        started=meta.get('started_ns')
        if type(started) is not int or not 0<=started<=2**63-1:raise ValueError('LIBRARY_INVALID_RECORDING_CLOCK')
        values={**entry,**fields,'started_ns':started,'ended_ns':now if state in TERMINAL else None,'state':state,
            'interval_ms':meta.get('interval_ms'),'samples':meta.get('samples'),'completed_runs':meta.get('completed_runs'),
            'size_bytes':size.get('bytes'),'size_status':size.get('status'),'updated_ns':now,
            'search_text':' '.join(fields.values()).casefold(),'owner_pid':meta.get('owner_pid'),
            'owner_created':meta.get('owner_created'),'configuration_changed':int(bool(meta.get('configuration_changed')))}
        for key in ('interval_ms','samples','completed_runs','owner_pid'):
            if values[key] is not None and (type(values[key]) is not int or not 0<=values[key]<=2**63-1):values[key]=None
        if type(values['owner_created']) not in (int,float) or not math.isfinite(values['owner_created']) or values['owner_created']<0:values['owner_created']=None
        columns=tuple(values);update=','.join(k+'=excluded.'+k for k in columns if k not in ('entry_id','locator'))
        db.execute('INSERT INTO entries('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+') '
            'ON CONFLICT(locator) DO UPDATE SET '+update,tuple(values.values()));db.commit()
        return dict(db.execute('SELECT * FROM entries WHERE locator=?',(entry['locator'],)).fetchone())

    def record_owned(self,folder,metadata,*,finalized=False):
        folder=checked(folder)
        if folder.parent!=self.root or not SESSION_NAME.fullmatch(folder.name):raise ValueError('LIBRARY_INVALID_LOCAL_PATH')
        if not checked(folder/'session.sqlite3').is_file():raise ValueError('LIBRARY_RECORDING_NOT_FOUND')
        owner=self._owner(create=True);marker_path=folder/MARKER
        if not marker_path.exists():
            atomic_json(marker_path,{'schema_version':1,'kind':'BLACKBOX_OWNED_SESSION','root_id':owner['root_id'],
                'session_name':folder.name,'marker_uid':uuid4().hex,'lifecycle':'ACTIVE'},exclusive=True)
        marker=self._marker(folder)
        marker['lifecycle']='FINALIZED' if finalized else 'ACTIVE'
        atomic_json(marker_path,marker)
        size=tree_summary(folder) if finalized else {'bytes':None,'status':'ACTIVE_SIZE_UNKNOWN'}
        with closing(self._connect(write=True)) as db:
            return self._upsert(db,{'entry_id':marker['marker_uid'],'locator':'LOCAL:'+folder.name,
                'folder_name':folder.name,'external_path':None,'origin':'LOCAL_APP_MARKED','marker_uid':marker['marker_uid']},metadata,size)

    def register(self,folder):
        folder=checked(folder)
        if folder.is_relative_to(self.root/TRASH):raise ValueError('LIBRARY_RESTORE_BEFORE_OPEN');meta=recording_metadata(folder);size=tree_summary(folder)
        with closing(self._connect(write=True)) as db:
            local=db.execute('SELECT * FROM entries WHERE locator=?',('LOCAL:'+folder.name,)).fetchone() if folder.parent==self.root else None
            if local:
                self._marker(folder,local)
                entry={k:local[k] for k in ('entry_id','locator','folder_name','external_path','origin','marker_uid')}
            else:entry={'entry_id':uuid4().hex,'locator':'EXTERNAL:'+os.path.normcase(str(folder)),
                'folder_name':None,'external_path':str(folder),'origin':'USER_SELECTED_UNVERIFIED','marker_uid':None}
            return self._present(self._upsert(db,entry,meta,size))

    def query(self,*,search='',state='ALL',after=None,limit=50):
        if type(search) is not str or len(search)>256 or type(limit) is not int or not 1<=limit<=100:
            raise ValueError('LIBRARY_INVALID_QUERY')
        if state not in ('ALL','COMPLETED','INCOMPLETE','ACTIVE','TRASH'):raise ValueError('LIBRARY_INVALID_QUERY')
        if not self.path.exists():return {'rows':[],'has_more':False,'next_cursor':None,'status':'EMPTY_INDEX','disk_scan':False}
        where=[];params=[]
        if state=='TRASH':where.append("state IN ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED')")
        else:where.append("state NOT IN ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED')")
        if state=='COMPLETED':where.append("state='COMPLETED'")
        elif state=='ACTIVE':where.append("state IN ('RECORDING','FINALIZATION_UNCONFIRMED')")
        elif state=='INCOMPLETE':where.append("state NOT IN ('RECORDING','COMPLETED','FINALIZATION_UNCONFIRMED')")
        if search:
            escaped=search.casefold().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            where.append("search_text LIKE ? ESCAPE '\\'");params.append('%'+escaped+'%')
        if after is not None:
            if not isinstance(after,list) or len(after)!=2 or type(after[0]) is not int or not _uuid(after[1]):
                raise ValueError('LIBRARY_INVALID_CURSOR')
            where.append('(started_ns,entry_id)<(?,?)');params.extend(after)
        with closing(self._connect()) as db:
            rows=db.execute('SELECT * FROM entries WHERE '+' AND '.join(where)+' ORDER BY started_ns DESC,entry_id DESC LIMIT ?',(*params,limit+1)).fetchall()
        selected=[self._present(dict(r)) for r in rows[:limit]]
        return {'rows':selected,'has_more':len(rows)>limit,
            'next_cursor':[selected[-1]['started_ns'],selected[-1]['entry_id']] if selected else None,
            'status':'INDEX_SNAPSHOT','disk_scan':False,'size_quality':'CACHED_METADATA_ESTIMATE_NOT_LIVE_DISK_QUOTA'}

    def _present(self,row):
        row=dict(row)
        # Rendering an indexed page does not stat every recording directory.
        if row['origin']=='LOCAL_APP_MARKED':
            if not SESSION_NAME.fullmatch(row['folder_name'] or ''):raise ValueError('LIBRARY_INVALID_LOCAL_PATH')
            path=self.root/row['folder_name']
            if row['state'] in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED') and row['trash_name']:
                if not _uuid(row['trash_name']):raise ValueError('LIBRARY_INVALID_LOCAL_PATH')
                path=self.root/TRASH/row['trash_name']/'payload'
        else:path=Path(row['external_path'])
        row['folder']=str(path)
        row['file_trust']='LOCAL_MARKER_UNSIGNED' if row['origin']=='LOCAL_APP_MARKED' else 'UNVERIFIED_IMPORT'
        row['trash_eligible']=row['origin']=='LOCAL_APP_MARKED' and row['state'] in TERMINAL
        return row

    def entry(self,entry_id):
        if not _uuid(entry_id):raise ValueError('LIBRARY_INVALID_ENTRY')
        with closing(self._connect()) as db:r=db.execute('SELECT * FROM entries WHERE entry_id=?',(entry_id,)).fetchone()
        if r is None:raise ValueError('LIBRARY_ENTRY_NOT_FOUND')
        return self._present(r)

    def open_entry(self,entry_id,*,completed=False):
        """Resolve an indexed identifier, without changing the observed target."""
        row=self.entry(entry_id)
        if row['state'] in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED'):
            raise ValueError('LIBRARY_RESTORE_BEFORE_OPEN')
        folder=self._folder(row)
        if row['origin']=='LOCAL_APP_MARKED':self._marker(folder,row)
        meta=recording_metadata(folder)
        if completed and meta['state'] not in TERMINAL:raise ValueError('LIBRARY_STOP_BEFORE_COMPARE')
        return {'entry':row,'folder':str(folder),'metadata':meta,
            'has_research':checked(folder/'research.sqlite3').is_file(),
            'source_trust':'UNVERIFIED_IMPORT','source_observations_modified':False}

    def scan(self,*,after='',limit=50):
        if type(after) is not str or '/' in after or '\\' in after or type(limit) is not int or not 1<=limit<=100:
            raise ValueError('LIBRARY_INVALID_SCAN')
        if not self.root.is_dir():return {'added':0,'errors':[],'has_more':False,'cursor':after}
        checked(self.root)
        with os.scandir(self.root) as entries:
            names=heapq.nsmallest(limit+1,(e.name for e in entries if SESSION_NAME.fullmatch(e.name) and e.name>after))
        added=0;errors=[];cursor=after;deadline=time.monotonic()+5
        for name in names[:limit]:
            if time.monotonic()>deadline:break
            try:self.register(self.root/name);added+=1
            except (OSError,ValueError,sqlite3.Error) as exc:
                if len(errors)<10:errors.append({'folder_name':name,'error':type(exc).__name__+': '+str(exc)[:200]})
            cursor=name
        return {'added':added,'errors':errors,'has_more':len(names)>limit or cursor!=(names[min(len(names),limit)-1] if names else after),
            'cursor':cursor,'scope':'EXPLICIT_SINGLE_LEVEL_SCAN','automatic_scan':False}

    def policy(self,values=None):
        default={'days':0,'max_bytes':0,'automatic_deletion':False}
        if values is not None:
            if type(values.get('days')) is not int or not 0<=values['days']<=36500 or type(values.get('max_bytes')) is not int or not 0<=values['max_bytes']<=2**60:
                raise ValueError('LIBRARY_INVALID_RETENTION_POLICY')
            if values.get('automatic_deletion',False):raise ValueError('LIBRARY_AUTOMATIC_DELETION_NOT_SUPPORTED')
            data={**default,**{k:values[k] for k in ('days','max_bytes')}}
            with closing(self._connect(write=True)) as db:
                db.execute("INSERT OR REPLACE INTO library_meta VALUES('policy',?)",(json.dumps(data),));db.commit()
            return data
        if not self.path.exists():return default
        with closing(self._connect()) as db:row=db.execute("SELECT value FROM library_meta WHERE key='policy'").fetchone()
        return json.loads(row[0]) if row else default

    def retention_preview(self,*,limit=50):
        if type(limit) is not int or not 1<=limit<=100:raise ValueError('LIBRARY_INVALID_QUERY')
        policy=self.policy();deadline=time.time_ns()-policy['days']*86400*10**9 if policy['days'] else None
        if not self.path.exists():return {'policy':policy,'candidates':[],'automatic_deletion':False,'bytes_freed':0}
        with closing(self._connect()) as db:
            totals=db.execute("SELECT sum(size_bytes),sum(size_bytes IS NULL),count(*) FROM entries WHERE origin='LOCAL_APP_MARKED' AND state NOT IN ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED')").fetchone()
            known=totals[0] or 0;excess=max(0,known-policy['max_bytes']) if policy['max_bytes'] else 0
            rows=db.execute("SELECT * FROM entries WHERE origin='LOCAL_APP_MARKED' AND state IN ("+','.join('?' for _ in TERMINAL)+") ORDER BY started_ns,entry_id LIMIT ?",(*sorted(TERMINAL),limit+1)).fetchall()
        candidates=[];selected=0
        for raw in rows[:limit]:
            row=dict(raw);reasons=[]
            if deadline is not None and row['started_ns']<deadline:reasons.append('OLDER_THAN_SELECTED_DAYS')
            if excess>selected and row['size_bytes'] is not None:reasons.append('KNOWN_SIZE_ABOVE_SELECTED_LIMIT')
            if reasons:
                candidates.append({**self._present(row),'reasons':reasons});selected+=row['size_bytes'] or 0
        return {'policy':policy,'candidates':candidates,'known_live_bytes':known,'unknown_size_entries':totals[1] or 0,
            'entries':totals[2],'preview_limited':len(rows)>limit,'automatic_deletion':False,'bytes_freed':0,
            'limitation':'TRASH_IS_REVERSIBLE_AND_DOES_NOT_FREE_DISK_SPACE'}

    def _trash_root(self,create=False):
        folder=checked(self.root/TRASH)
        if create:folder.mkdir(mode=0o700,exist_ok=True)
        path=folder/'trash-owner.json';owner=self._owner()
        if create and not path.exists():
            if any(folder.iterdir()):raise ValueError('LIBRARY_TRASH_NOT_MARKED')
            atomic_json(path,{'kind':'BLACKBOX_TRASH','root_id':owner['root_id']},exclusive=True)
        data=read_json(path)
        if data.get('kind')!='BLACKBOX_TRASH' or data.get('root_id')!=owner['root_id']:raise ValueError('LIBRARY_TRASH_NOT_MARKED')
        return folder

    def _safe_finalized(self,row):
        if row['origin']!='LOCAL_APP_MARKED' or row['state'] not in TERMINAL:raise ValueError('LIBRARY_ACTIVE_OR_EXTERNAL_RECORDING')
        folder=self._folder(row);marker=self._marker(folder,row)
        if marker.get('lifecycle')!='FINALIZED':raise ValueError('LIBRARY_FINALIZATION_UNCONFIRMED')
        meta=recording_metadata(folder)
        if meta['state'] not in TERMINAL:raise ValueError('LIBRARY_FINALIZATION_UNCONFIRMED')
        artifacts=folder/'artifacts'
        if artifacts.exists():
            for n,journal in enumerate(artifacts.glob('BLACKBOX_*.trace.json')):
                if n>=64:raise ValueError('LIBRARY_TRACE_JOURNAL_BUDGET')
                if read_json(journal).get('state') not in ('COMPLETED','FAILED'):raise ValueError('LIBRARY_TRACE_STILL_ACTIVE')
        size=tree_summary(folder,max_seconds=2)
        if size['fingerprint'] is None:raise ValueError('LIBRARY_TREE_CHECK_INCOMPLETE')
        return folder,marker,size

    def plan_trash(self,entry_ids):
        if not isinstance(entry_ids,list) or not 1<=len(entry_ids)<=50 or len(set(entry_ids))!=len(entry_ids):raise ValueError('LIBRARY_INVALID_SELECTION')
        items=[]
        for entry_id in entry_ids:
            row=self.entry(entry_id);folder,marker,size=self._safe_finalized(row)
            items.append({'entry_id':entry_id,'folder_name':row['folder_name'],'marker_uid':marker['marker_uid'],
                'identity':identity(folder),'fingerprint':size['fingerprint'],'bytes':size['bytes'],'folder':str(folder)})
        token=uuid4().hex+uuid4().hex;now=time.time_ns();payload={'operation':'TRASH','root_id':self._owner()['root_id'],'items':items}
        with closing(self._connect(write=True)) as db:
            db.execute('DELETE FROM plans WHERE expires_ns<? OR used=1',(now,))
            if db.execute('SELECT count(*) FROM plans').fetchone()[0]>=128:raise ValueError('LIBRARY_CONFIRMATION_QUEUE_FULL')
            db.execute('INSERT INTO plans VALUES(?,?,?,?,0)',(hashlib.sha256(token.encode()).hexdigest(),now,now+300*10**9,json.dumps(payload)));db.commit()
        return {'confirmation_token':token,'expires_ns':now+300*10**9,'items':items,'bytes_freed':0,
            'operation':'MOVE_TO_REVERSIBLE_TRASH','automatic_deletion':False}

    def apply_trash(self,token):
        if not isinstance(token,str) or not re.fullmatch('[0-9a-f]{64}',token):raise ValueError('LIBRARY_INVALID_CONFIRMATION')
        with closing(self._connect(write=True)) as db:
            db.execute('BEGIN IMMEDIATE')
            plan=db.execute('SELECT * FROM plans WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not plan or plan['used'] or plan['expires_ns']<time.time_ns():raise ValueError('LIBRARY_CONFIRMATION_EXPIRED_OR_USED')
            payload=json.loads(plan['payload'])
            if payload.get('operation','TRASH')!='TRASH':raise ValueError('LIBRARY_WRONG_CONFIRMATION_OPERATION')
            if payload['root_id']!=self._owner()['root_id']:raise ValueError('LIBRARY_ROOT_ID_MISMATCH')
            # Validate the entire selection before consuming consent/moving any item.
            for item in payload['items']:
                row=self.entry(item['entry_id']);folder,marker,size=self._safe_finalized(row)
                if identity(folder)!=item['identity'] or marker['marker_uid']!=item['marker_uid'] or size['fingerprint']!=item['fingerprint']:
                    raise ValueError('LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN')
            db.execute('UPDATE plans SET used=1 WHERE token_hash=?',(plan['token_hash'],));db.commit()
        trash=self._trash_root(create=True);results=[]
        for item in payload['items']:
            name=uuid4().hex;container=trash/name;container.mkdir(mode=0o700)
            journal={'schema_version':1,'root_id':payload['root_id'],'entry_id':item['entry_id'],
                'folder_name':item['folder_name'],'marker_uid':item['marker_uid'],'state':'MOVING_TO_TRASH'}
            atomic_json(container/'entry.json',journal,exclusive=True)
            try:
                with closing(self._connect(write=True)) as db:
                    db.execute('BEGIN IMMEDIATE')
                    row=dict(db.execute('SELECT * FROM entries WHERE entry_id=?',(item['entry_id'],)).fetchone())
                    if row['state'] not in TERMINAL or row['origin']!='LOCAL_APP_MARKED':
                        raise ValueError('LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN')
                    db.execute("UPDATE entries SET previous_state=state,state='MOVING_TO_TRASH',trash_name=? WHERE entry_id=?",(name,item['entry_id']));db.commit()
                folder,_,size=self._safe_finalized(row)
                if identity(folder)!=item['identity'] or size['fingerprint']!=item['fingerprint']:raise ValueError('LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN')
                move_no_replace(folder,container/'payload')
                with closing(self._connect(write=True)) as db:
                    db.execute("UPDATE entries SET state='TRASH',updated_ns=? WHERE entry_id=?",(time.time_ns(),item['entry_id']));db.commit()
                journal['state']='TRASH';atomic_json(container/'entry.json',journal)
                results.append({'entry_id':item['entry_id'],'status':'MOVED_TO_TRASH'})
            except (OSError,ValueError,sqlite3.Error) as exc:
                results.append({'entry_id':item['entry_id'],'status':'MOVE_UNCONFIRMED','error':str(exc)[:300]})
        return {'results':results,'bytes_freed':0,'original_observations_deleted':False}

    def restore(self,entry_id):
        row=self.entry(entry_id)
        if row['origin']!='LOCAL_APP_MARKED' or row['state']!='TRASH' or not _uuid(row['trash_name']):raise ValueError('LIBRARY_NOT_IN_TRASH')
        trash=self._trash_root();container=checked(trash/row['trash_name']);journal=read_json(container/'entry.json')
        if journal.get('root_id')!=self._owner()['root_id'] or journal.get('marker_uid')!=row['marker_uid'] or journal.get('entry_id')!=entry_id:
            raise ValueError('LIBRARY_TRASH_ID_MISMATCH')
        source=checked(container/'payload');self._marker(source,row);destination=checked(self.root/row['folder_name'])
        if destination.exists():raise FileExistsError('LIBRARY_DESTINATION_EXISTS')
        with closing(self._connect(write=True)) as db:
            changed=db.execute("UPDATE entries SET state='RESTORING' WHERE entry_id=? AND state='TRASH' AND trash_name=? AND marker_uid=?",
                (entry_id,row['trash_name'],row['marker_uid'])).rowcount
            if changed!=1:raise ValueError('LIBRARY_RECORDING_CHANGED_REVIEW_AGAIN')
            db.commit()
        move_no_replace(source,destination)
        with closing(self._connect(write=True)) as db:
            db.execute('UPDATE entries SET state=previous_state,previous_state=NULL,trash_name=NULL,last_error=NULL,updated_ns=? WHERE entry_id=?',(time.time_ns(),entry_id));db.commit()
        journal['state']='RESTORED';atomic_json(container/'entry.json',journal)
        return {'entry_id':entry_id,'status':'RESTORED','folder':str(destination)}

    def reconcile(self):
        if not self.path.exists():return {'results':[]}
        with closing(self._connect()) as db:
            rows=[dict(r) for r in db.execute("SELECT * FROM entries WHERE state IN ('MOVING_TO_TRASH','RESTORING') LIMIT 50")]
        results=[]
        for row in rows:
            if not _uuid(row['trash_name']):continue
            source=checked(self.root/row['folder_name']);payload=checked(self._trash_root()/row['trash_name']/'payload')
            present=source.is_dir(),payload.is_dir()
            state='TRASH' if present==(False,True) else row['previous_state'] if present==(True,False) else None
            if state:
                self._marker(payload if state=='TRASH' else source,row)
                with closing(self._connect(write=True)) as db:
                    db.execute('UPDATE entries SET state=?,trash_name=?,previous_state=?,last_error=NULL WHERE entry_id=?',
                        (state,row['trash_name'] if state=='TRASH' else None,row['previous_state'] if state=='TRASH' else None,row['entry_id']));db.commit()
                results.append({'entry_id':row['entry_id'],'state':state})
            else:results.append({'entry_id':row['entry_id'],'state':'MANUAL_RECOVERY_REQUIRED_NO_FILES_CHANGED'})
        return {'results':results,'scope':'INDEX_RECONCILIATION_ONLY_NO_DELETE'}

    def plan_purge(self,entry_ids):
        from .retention_delete import plan_purge
        return plan_purge(self,entry_ids)

    def apply_purge(self,token):
        from .retention_delete import apply_purge
        return apply_purge(self,token)

    def storage_budget(self,*,exclude_folder=None):
        policy=self.policy()
        if not self.path.exists():return {'policy':policy,'known_bytes':0,'unknown_entries':0,'source':'CACHED_METADATA_NOT_PHYSICAL_QUOTA'}
        where="origin='LOCAL_APP_MARKED' AND state!='PURGED'";params=[]
        if exclude_folder is not None:where+=' AND folder_name!=?';params.append(Path(exclude_folder).name)
        with closing(self._connect()) as db:
            row=db.execute('SELECT coalesce(sum(size_bytes),0),coalesce(sum(size_bytes IS NULL),0) FROM entries WHERE '+where,params).fetchone()
        return {'policy':policy,'known_bytes':row[0],'unknown_entries':row[1],'source':'CACHED_METADATA_NOT_PHYSICAL_QUOTA'}
