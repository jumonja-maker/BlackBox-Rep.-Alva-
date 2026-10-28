"""Default share-copy redaction. Original evidence is never changed.

All stored text values in the copied product databases follow the same policy,
including event kinds/provenance and JSON keys. This is recognizable path/URL
redaction, not a claim to detect arbitrary secrets in free text.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3

_PRIVATE={'note','comment','application_event_path','command_line','cmdline','environment_variables','environ',
    'window_title','title_text','url','full_path','pdb_path','dump_path','source_folder','preview'}
_PATH=re.compile(r'(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\|[A-Za-z][A-Za-z0-9+.-]*://|/(?:home|workspace|Users|tmp|var|opt|etc|root|mnt|media|Volumes|run|srv|data|private|usr)/)[^\s\"<>]*',re.IGNORECASE)


def _text(value, salt):
    # Distinct IDs that happen to contain paths must not collapse into the same
    # SQL primary key or JSON key. The export-local nonce is never persisted;
    # matching references share a token only inside this one exported copy.
    def token(match):
        digest=hashlib.sha256(salt+match[0].encode('utf-8',errors='surrogatepass')).hexdigest()[:24]
        return '[PATH_OR_URL_OMITTED:'+digest+']'
    # A field that begins with an absolute path may itself be a full filename
    # containing spaces. Do not leave its basename after the first whitespace.
    if _PATH.match(value.lstrip()):
        digest=hashlib.sha256(salt+value.encode('utf-8',errors='surrogatepass')).hexdigest()[:24]
        return '[PATH_OR_URL_OMITTED:'+digest+']'
    return _PATH.sub(token,value)


def _redact(value, key, include_notes, salt):
    if key in _PRIVATE and not (include_notes and key in {'note','comment'}):
        return '[OMITTED_BY_DEFAULT_PRIVACY_POLICY]'
    if key=='attributes':return {'privacy':'APPLICATION_ATTRIBUTES_OMITTED_BY_DEFAULT'}
    if isinstance(value,dict):
        result={}
        for k,v in value.items():
            target=_text(k,salt) if isinstance(k,str) else k
            if target in result:raise ValueError('PRIVACY_KEY_COLLISION')
            result[target]=_redact(v,k,include_notes,salt)
        return result
    if isinstance(value,list):return [_redact(v,key,include_notes,salt) for v in value]
    if isinstance(value,str):return _text(value,salt)
    return value


def redact(value,*,key=None,include_notes=False):
    """Explicit notes never imply consent for raw application attributes."""
    return _redact(value,key,include_notes,secrets.token_bytes(32))


def _quoted(identifier):
    return '"'+identifier.replace('"','""')+'"'


def redact_copies(folder,*,cancel=None):
    folder=Path(folder);json_rows=text_cells=tables_checked=0;salt=secrets.token_bytes(32)
    for filename in ('research.sqlite3','session.sqlite3','session-v2.sqlite3','detail-v2.sqlite3'):
        path=folder/filename
        if not path.is_file():continue
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA secure_delete=ON')
            db.execute('PRAGMA journal_mode=DELETE')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,1024*1024)
            objects=db.execute("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").fetchall()
            # Native product DBs have ordinary rowid tables and indexes. Never
            # execute imported triggers/virtual-table modules during redaction.
            if any(kind not in ('table','index') or _PATH.search(name) or _PATH.search(sql or '')
                    or kind=='table' and re.search(r'\b(?:VIRTUAL|WITHOUT\s+ROWID)\b',sql or '',re.I)
                    for kind,name,sql in objects):
                raise ValueError('UNSUPPORTED_SHARE_COPY_SCHEMA')
            for kind,table,_ in objects:
                if kind!='table':continue
                tables_checked+=1;identifier=_quoted(table)
                info=db.execute('PRAGMA table_xinfo('+identifier+')').fetchall()
                if not info or any(row[6] != 0 for row in info):
                    raise ValueError('UNSUPPORTED_SHARE_COPY_SCHEMA')
                columns=[row[1] for row in info]
                # _rowid_ is never a native product column; reject ambiguous
                # imports instead of accidentally updating a different row.
                if any(name.casefold() in ('rowid','_rowid_','oid') for name in columns):
                    raise ValueError('UNSUPPORTED_SHARE_COPY_SCHEMA')
                cursor=None
                while True:
                    if cancel is not None and cancel():raise InterruptedError('RESEARCH_OPERATION_CANCELLED')
                    where='WHERE _rowid_>?' if cursor is not None else ''
                    args=(cursor,) if cursor is not None else ()
                    rows=db.execute(f'SELECT _rowid_,* FROM {identifier} {where} ORDER BY _rowid_ LIMIT 100',args).fetchall()
                    if not rows:break
                    for row in rows:
                        updates={}
                        original=dict(zip(columns,row[1:]))
                        for column,value in original.items():
                            if not isinstance(value,str):continue
                            is_json=column.endswith('_json') or column=='data' and table in ('context','evidence','events')
                            if column in _PRIVATE or column=='attributes':
                                new=_redact(value,column,False,salt)
                                transformed=json.dumps(new,ensure_ascii=True,separators=(',',':')) if isinstance(new,dict) else new
                                if transformed!=value:text_cells+=1
                            elif is_json:
                                decoded=json.loads(value)
                                key=original.get('key') if table=='context' else None
                                new=_redact(decoded,key,False,salt)
                                transformed=json.dumps(new,ensure_ascii=True,allow_nan=False,separators=(',',':'))
                                if transformed!=value:json_rows+=1
                            else:
                                transformed=_redact(value,column,False,salt)
                                if not isinstance(transformed,str):
                                    transformed=json.dumps(transformed,ensure_ascii=True,allow_nan=False,separators=(',',':'))
                                if transformed!=value:text_cells+=1
                            if transformed!=value:updates[column]=transformed
                        if updates:
                            fields=','.join(_quoted(name)+'=?' for name in updates)
                            db.execute(f'UPDATE {identifier} SET {fields} WHERE _rowid_=?',(*updates.values(),row[0]))
                    db.commit();cursor=rows[-1][0]
            # Old payloads and scalar text must not survive in freed SQLite pages.
            db.execute('VACUUM')
    return {'policy':'SHARE_COPY_DEFAULT_V2','json_rows_rewritten':json_rows,
        'text_cells_rewritten':text_cells,'tables_checked':tables_checked,
        'original_modified':False,'raw_application_attributes':'OMITTED',
        'known_paths_urls':'REDACTED','universal_secret_detection':False}
