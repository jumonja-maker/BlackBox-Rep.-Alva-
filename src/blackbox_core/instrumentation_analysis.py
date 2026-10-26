"""Voluntary SDK latency; never inferred from bytes or relabelled as OS facts."""
from contextlib import closing
import json,sqlite3,tempfile
from pathlib import Path
from .casebook import readonly
def io_latency_statistics(folder,*,start_ns=0,end_ns=2**63-1):
 base={'source':'APPLICATION_EVENT_UNAUTHENTICATED','status':'NOT_OBSERVED','groups':[],
  'file_trust':'UNVERIFIED_IMPORT','interval_semantics':'OBSERVER_RECEIPT_TIME_NOT_SOURCE_EXECUTION_WINDOW','lost_events':None,
  'limitations':['APP_SUPPLIED_WALL_LATENCY_NOT_DEVICE_SERVICE_TIME','SOURCE_CLOCK_NOT_SILENTLY_ALIGNED','NO_LATENCY_INFERRED_FROM_IO_BYTES']}
 path=Path(folder)/'research.sqlite3'
 if not path.is_file():return base
 invalid=0;refs=[];groups=[]
 with closing(readonly(path)) as source:
  query="SELECT id,substr(data,1,8193) AS detail,length(data) AS size FROM evidence WHERE kind='io.operation.end' AND source='APPLICATION_EVENT' AND monotonic_ns BETWEEN ? AND ? ORDER BY id"
  if not source.execute("SELECT 1 FROM evidence WHERE kind='io.operation.end' AND source='APPLICATION_EVENT' AND monotonic_ns BETWEEN ? AND ? LIMIT 1",(start_ns,end_ns)).fetchone():return base
  with tempfile.TemporaryDirectory(prefix='bb-app-io-') as temp,closing(sqlite3.connect(Path(temp)/'quantiles.sqlite3')) as db:
   db.execute('PRAGMA cache_size=-1024');db.execute('CREATE TABLE value(kind TEXT,ns INTEGER,status TEXT)')
   for row in source.execute(query,(start_ns,end_ns)):
    try:
     if row['size']>8192:raise ValueError('IMPORTED_EVENT_SIZE_LIMIT')
     data=json.loads(row['detail']);attributes=data['attributes'];latency=attributes['latency_ns'];kind=attributes['io_kind'];status=attributes['status']
     if kind not in ('READ','WRITE','FLUSH','CUSTOM') or type(latency) is not int or not 0<=latency<=86400*10**9 or status not in ('COMPLETED','ERROR') or not data.get('operation_id'):raise ValueError('INVALID_IO_EVENT')
     db.execute('INSERT INTO value VALUES(?,?,?)',(kind,latency,status))
     if len(refs)<20:refs.append('research.sqlite3:evidence:'+str(row['id']))
    except (ValueError,TypeError,KeyError):invalid+=1
   db.execute('CREATE INDEX ix_io_order ON value(kind,status,ns)');db.commit()
   for kind in ('READ','WRITE','FLUSH','CUSTOM'):
    n=db.execute("SELECT count(*) FROM value WHERE kind=? AND status='COMPLETED'",(kind,)).fetchone()[0]
    errors=db.execute("SELECT count(*) FROM value WHERE kind=? AND status='ERROR'",(kind,)).fetchone()[0]
    if not n and not errors:continue
    def q(frac):
     if not n:return None
     pos=(n-1)*frac;lo=int(pos);hi=min(lo+1,n-1)
     values=[r[0] for r in db.execute("SELECT ns FROM value WHERE kind=? AND status='COMPLETED' ORDER BY ns LIMIT ? OFFSET ?",(kind,hi-lo+1,lo))]
     return values[0]+(values[-1]-values[0])*(pos-lo)
    groups.append({'io_kind':kind,'completed_events':n,'error_events':errors,'unit':'nanoseconds',
     'median':q(.5),'p95':q(.95),'minimum':q(0),'maximum':q(1),'warning':'P95_UNSTABLE_SMALL_SAMPLE' if n<20 else None})
 return {**base,'status':'APP_REPORTED_LATENCIES' if groups else 'NOT_OBSERVED','groups':groups,'invalid_events':invalid,'evidence_references_preview':refs}

