"""Default share-copy redaction. Original evidence is never changed.

This removes known sensitive fields and recognizable paths/URLs, not arbitrary
secrets hidden in free text. Raw application attributes and debugger previews
are opt-in. Reports declare that this is not a universal secret detector.
"""
from __future__ import annotations
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3

_PRIVATE={'note','comment','application_event_path','command_line','cmdline','environment_variables','environ',
    'window_title','title_text','url','full_path','pdb_path','dump_path','source_folder','preview'}
_PATH=re.compile(r'(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\|https?://|file://|/(?:home|workspace|Users|tmp|var|opt)/)[^\s\"<>]*',re.IGNORECASE)


def redact(value,*,key=None):
    if key in _PRIVATE:return '[OMITTED_BY_DEFAULT_PRIVACY_POLICY]'
    if key=='attributes':return {'privacy':'APPLICATION_ATTRIBUTES_OMITTED_BY_DEFAULT'}
    if isinstance(value,dict):return {k:redact(v,key=k) for k,v in value.items()}
    if isinstance(value,list):return [redact(v,key=key) for v in value]
    if isinstance(value,str):return _PATH.sub('[PATH_OR_URL_OMITTED]',value)
    return value


def redact_copies(folder):
    folder=Path(folder);changed=0
    # Only known JSON columns in databases we just produced via SQLite backup.
    for filename,tables in (
        ('research.sqlite3',(('context','key','data'),('evidence','id','data'))),
        ('session.sqlite3',(('events','seq','data'),)),
        ('session-v2.sqlite3',(('events','event_id','detail_json'),('incidents','incident_id','context_json')))):
        path=folder/filename
        if not path.is_file():continue
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA secure_delete=ON')
            db.execute('PRAGMA journal_mode=DELETE')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,1024*1024)
            for table,identity,column in tables:
                # Fixed SQL identifiers only. Imported JSON is never SQL/code.
                cursor=None
                while True:
                    where=f'WHERE {identity}>?' if cursor is not None else ''
                    args=(cursor,) if cursor is not None else ()
                    rows=db.execute(f'SELECT {identity},{column} FROM {table} {where} ORDER BY {identity} LIMIT 100',args).fetchall()
                    if not rows:break
                    for ident,raw in rows:
                        value=json.loads(raw)
                        new=redact(value,key=ident if table=='context' else None)
                        encoded=json.dumps(new,ensure_ascii=True,allow_nan=False,separators=(',',':'))
                        if encoded!=raw:db.execute(f'UPDATE {table} SET {column}=? WHERE {identity}=?',(encoded,ident));changed+=1
                    db.commit();cursor=rows[-1][0]
            # A share copy must not retain old payloads in freed SQLite pages.
            db.execute('VACUUM')
    return {'policy':'SHARE_COPY_DEFAULT_V1','json_rows_rewritten':changed,
        'original_modified':False,'raw_application_attributes':'OMITTED',
        'known_paths_urls':'REDACTED','universal_secret_detection':False}
