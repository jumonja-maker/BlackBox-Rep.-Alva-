"""Resource history by process instance; root and observed tree stay separate."""
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
  parent=view.db.execute('SELECT instance_id FROM process_instances WHERE pid=? AND creation_time<=? AND first_observed_ns<=? AND coalesce(absence_observed_ns,9223372036854775807)>=? ORDER BY creation_time DESC LIMIT 1',(item['parent_pid'],item['creation_time'],item['last_observed_ns'],item['first_observed_ns'])).fetchone()
  item['parent_instance_candidate']=parent[0] if parent else None;item['parent_link_quality']='OBSERVED_PPID_LIFETIME_CANDIDATE_NOT_CONTINUOUS_PROOF'
 result.update(selected_interval_ns=[start,end],source_trust='UNVERIFIED_IMPORT');return result
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

