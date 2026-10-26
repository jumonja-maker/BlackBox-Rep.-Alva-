"""Explicit CI-only real WPR guardian acceptance on a disposable Windows runner."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import time


def run(output):
    from blackbox_core.trace_owner import TraceSupervisor,_read
    from blackbox_core.windows_research import privilege,wpr_tool
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    result={'scope':'ACTUAL_WPR_RAW_ETL_NOT_WPA_CONTENT_ACCEPTANCE',
        'privilege':privilege(),'tool_available':bool(wpr_tool()),'status':'NOT_AVAILABLE',
        'source_sha':os.environ.get('BB_QA_SOURCE_SHA'),'loss_count':None}
    if os.name!='nt' or privilege()['mode']!='ADMINISTRATOR' or not wpr_tool():
        (output/'qa.json').write_text(json.dumps(result,indent=2));return 0
    trace=TraceSupervisor(output,seconds=2,max_output_bytes=256*1024**2,
        target={'pid':os.getpid(),'purpose':'OWNED_CI_CPU_DISK_FIXTURE'})
    try:
        trace.start();deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            state=_read(trace.path)['state']
            if state=='RECORDING':break
            if not trace.active:raise RuntimeError('REAL_WPR_START_FAILED: '+json.dumps(_read(trace.path)))
            time.sleep(.05)
        if state!='RECORDING':raise RuntimeError('REAL_WPR_START_DEADLINE')
        data=b'BLACKBOX-QA'*102400
        with (output/'owned-io-fixture.bin').open('xb') as f:
            for _ in range(4):f.write(data)
            f.flush();os.fsync(f.fileno())
        # Fixed bounded CPU work while the actual trace is recording.
        deadline=time.monotonic()+.3
        while time.monotonic()<deadline:sum(i*i for i in range(10000))
        # Do not request Stop: exercise the real guardian TTL.
        trace.process.wait(timeout=85);capture=trace.poll()
        journal=_read(trace.path)
        if journal.get('state')!='COMPLETED' or journal.get('stop_reason')!='TTL_EXPIRED':
            raise RuntimeError('REAL_WPR_TTL_NOT_CONFIRMED: '+json.dumps(journal))
        if not journal.get('result',{}).get('sha256') or journal['result']['bytes']<=0:
            raise RuntimeError('REAL_ETL_ARTIFACT_UNCONFIRMED')
        result.update(status='PASS_RAW_CAPTURE',capture=capture,
            content_coverage='GENERALPROFILE_LIGHT_CONFIGURED_PROVIDER_CONTENT_NOT_INDEPENDENTLY_DECODED')
    finally:
        if trace.active:result['cleanup']=trace.stop()
        (output/'qa.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return 0


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output');raise SystemExit(run(p.parse_args().output))
