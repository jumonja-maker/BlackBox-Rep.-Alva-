"""Resource history by process instance; root and observed tree stay separate."""
from .session_view import _validated_process_instance


def resource_tree_page(view,start,end,*,after=0,limit=100):
 result=view.process_page(after=after,limit=limit)
 if not view.is_v2:return result
 ids=[r['instance_id'] for r in result['rows']];result['total_instances']=view.db.execute('SELECT count(*) FROM process_instances').fetchone()[0]
 if not ids:return result
 root=view.reader.root_instance
 root_series='STANDARD' if view.db.execute("SELECT 1 FROM samples WHERE instance_id=? AND series='STANDARD' AND monotonic_ns BETWEEN ? AND ? LIMIT 1",(root,start,end)).fetchone() else 'DETAILED'
 marks=','.join('?' for _ in ids)
 rows=view.db.execute('''WITH source AS (
  SELECT *,lag(monotonic_ns) OVER w AS prior_ns,lag(series_seq) OVER w AS prior_seq,
  lag(cpu_user_s) OVER w AS prior_user,lag(cpu_system_s) OVER w AS prior_system
  FROM samples WHERE instance_id IN ('''+marks+''') AND monotonic_ns BETWEEN ? AND ?
  AND series=CASE WHEN instance_id=? THEN ? ELSE 'CHILD' END
  WINDOW w AS (PARTITION BY instance_id,series ORDER BY monotonic_ns,sample_id))
  SELECT instance_id,count(*) AS resource_samples,max(rss_bytes) AS rss_peak_bytes,
  max(private_bytes) AS private_peak_bytes,max(uss_bytes) AS uss_peak_bytes,
  max(handle_count) AS handles_peak,max(thread_count) AS threads_peak,
  max(CASE WHEN series_seq=prior_seq+1 AND monotonic_ns>prior_ns
   AND monotonic_ns-prior_ns<=max(2*requested_interval_ns,requested_interval_ns+500000000)
   AND cpu_user_s>=prior_user AND cpu_system_s>=prior_system
   THEN (cpu_user_s-prior_user+cpu_system_s-prior_system)*100000000000.0/(monotonic_ns-prior_ns) END)
   AS cpu_peak_percent_one_cpu,
  sum(CASE WHEN series_seq=prior_seq+1 AND monotonic_ns>prior_ns
   AND monotonic_ns-prior_ns<=max(2*requested_interval_ns,requested_interval_ns+500000000)
   AND cpu_user_s>=prior_user AND cpu_system_s>=prior_system
   THEN cpu_user_s-prior_user+cpu_system_s-prior_system END) AS cpu_seconds,
  sum(rss_bytes IS NULL) AS rss_missing_samples FROM source GROUP BY instance_id''',(*ids,start,end,root,root_series))
 resources={r['instance_id']:dict(r) for r in rows}
 if root in resources:
  values=view.db.execute("SELECT max(private_bytes),max(uss_bytes),max(handle_count),max(thread_count) FROM samples WHERE instance_id=? AND series='DETAILED' AND monotonic_ns BETWEEN ? AND ?",(root,start,end)).fetchone()
  for key,value in zip(('private_peak_bytes','uss_peak_bytes','handles_peak','threads_peak'),values):
   if value is not None:resources[root][key]=value
 for item in result['rows']:
  item['resources']=resources.get(item['instance_id'],{'status':'NOT_OBSERVED_IN_SELECTED_INTERVAL'})
  _parent_link(view,item)
 # A page can begin below its parent. Include a bounded ancestor context,
 # without another resource aggregation or a scan of every saved process.
 # Context nodes are explicitly not additional rows in the keyset page.
 context={};known={r['instance_id']:r for r in result['rows']}
 pending=[r.get('parent_instance_candidate') for r in result['rows']]
 truncated=False
 while pending:
  identity=pending.pop()
  if identity is None or identity in known or identity in context:continue
  if len(context)>=256:
   truncated=True;break
  raw=view.db.execute('''SELECT instance_id,pid,creation_time,parent_pid,
   substr(executable_name,1,512) AS executable_name,first_observed_ns,last_observed_ns,
   absence_observed_ns,substr(source_kind,1,64) AS source_kind
   FROM process_instances WHERE instance_id=?''',(identity,)).fetchone()
  if raw is None:continue
  item=_validated_process_instance(raw);item['context_only']=True
  item['resources']={'status':'ANCESTOR_CONTEXT_NOT_RESOURCE_PAGE'}
  _parent_link(view,item);context[identity]=item
  pending.append(item.get('parent_instance_candidate'))
 result.update(selected_interval_ns=[start,end],source_trust='UNVERIFIED_IMPORT',
  root_instance_id=root,ancestors=list(context.values()),ancestor_context_truncated=truncated)
 return result

def _parent_link(view,item):
 """PPID/lifetime overlap is a candidate, never attested parent birth."""
 import math
 item['parent_instance_candidate']=None
 item['parent_link_quality']='PARENT_NOT_OBSERVED'
 if item['instance_id']==view.reader.root_instance:
  item['parent_link_quality']='RECORDING_ROOT'
 else:
  parents=view.db.execute('''SELECT instance_id FROM process_instances WHERE pid=?
   AND instance_id<>? AND creation_time<=? AND first_observed_ns<=?
   AND coalesce(absence_observed_ns,9223372036854775807)>=?
   ORDER BY creation_time DESC LIMIT 2''',(item['parent_pid'],item['instance_id'],
   item['creation_time'],item['last_observed_ns'],item['first_observed_ns'])).fetchall()
  if len(parents)==1:
   item['parent_instance_candidate']=parents[0][0]
   item['parent_link_quality']='OBSERVED_PPID_LIFETIME_CANDIDATE_NOT_CONTINUOUS_PROOF'
  elif parents:item['parent_link_quality']='AMBIGUOUS_PARENT_INSTANCE'
 meta=view.metadata
 age=(meta['anchor_utc_ns']+item['last_observed_ns']-meta['anchor_monotonic_ns'])/1e9-item['creation_time']
 item['age_at_last_observation_s']=age if math.isfinite(age) and age>=0 else None
 item['age_quality']='ANCHORED_UTC_ESTIMATE_SYSTEM_CLOCK_ADJUSTMENT_UNKNOWN'
def tree_totals(view,start,end):
 if not view.is_v2:return {'status':'LEGACY_LIMITED_DATA'}
 row=view.db.execute('''WITH cohort AS (
  SELECT p.sample_id,p.rss_bytes AS root_rss,p.children_total,p.children_omitted,
  count(c.sample_id) AS observed_children,sum(c.rss_bytes) AS children_rss,sum(c.rss_bytes IS NULL) AS missing_child_rss
  FROM samples p LEFT JOIN child_process_samples link ON link.parent_sample_id=p.sample_id
  LEFT JOIN samples c ON c.sample_id=link.child_sample_id
  WHERE p.instance_id=? AND p.series='DETAILED' AND p.monotonic_ns BETWEEN ? AND ? GROUP BY p.sample_id)
  SELECT count(*),max(root_rss),max(CASE WHEN observed_children>0 THEN root_rss+children_rss WHEN children_total=0 THEN root_rss END),
  max(observed_children),sum(CASE WHEN children_total IS NULL OR children_omitted IS NULL OR children_omitted>0 OR observed_children<children_total
  OR root_rss IS NULL OR (observed_children>0 AND missing_child_rss>0) THEN 1 ELSE 0 END) FROM cohort''',(view.reader.root_instance,start,end)).fetchone()
 return {'status':'OBSERVED_COHORT_SUM_NOT_UNIQUE_MEMORY' if row[0] else 'NOT_OBSERVED','root_rss_peak_bytes':row[1],
  'observed_tree_rss_peak_bytes':row[2],'root_capture_count':row[0],'max_observed_children':row[3],'incomplete_cohorts':row[4] if row[0] else None,
  'includes_root_once':True,'sums_individual_peaks':False,'source':'PSUTIL_LINKED_CAPTURE_COHORTS',
  'limitations':['RSS_SUM_DOUBLE_COUNTS_SHARED_PAGES','OMITTED_CHILDREN_NOT_ZERO','CHILDREN_NOT_READ_AT_IDENTICAL_NANOSECOND','BETWEEN_CAPTURE_PROCESSES_MAY_BE_MISSED']}

