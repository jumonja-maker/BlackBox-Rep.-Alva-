"""Local reproducible research commands; no model or network dependency."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import time


def main(argv=None):
    p=argparse.ArgumentParser(prog="blackbox research")
    sub=p.add_subparsers(dest="command",required=True)
    r=sub.add_parser("record");r.add_argument("--pid",type=int,required=True);r.add_argument("--output",type=Path,required=True)
    r.add_argument("--seconds",type=float,default=10);r.add_argument("--interval",type=float,default=1)
    r.add_argument("--detailed",action="store_true");r.add_argument("--scenario",default="CLI recording")
    e=sub.add_parser("export");e.add_argument("session",type=Path);e.add_argument("destination",type=Path);e.add_argument("--raw",action="store_true")
    v=sub.add_parser("verify");v.add_argument("package",type=Path)
    c=sub.add_parser("compare");c.add_argument("before",type=Path);c.add_argument("after",type=Path)
    rec=sub.add_parser("recover");rec.add_argument("session",type=Path);rec.add_argument("destination",type=Path)
    f=sub.add_parser("fixture");f.add_argument("arguments",nargs=argparse.REMAINDER)
    a=p.parse_args(argv)
    from .casebook import export_case,verify_package,compare_cases,recover_case
    if a.command=="record":
        if not 0<a.seconds<=7*86400 or not .1<=a.interval<=60:raise ValueError("INVALID_RECORDING_POLICY")
        from .research_worker import ResearchSession
        session=ResearchSession(a.output)
        session.command({"op":"attach","args":{"pid":a.pid}})
        session.command({"op":"configure","args":{"scenario":a.scenario}})
        session.command({"op":"interval","args":{"milliseconds":int(a.interval*1000)}})
        session.command({"op":"start"})
        if a.detailed:session.command({"op":"detailed","args":{"enabled":True}})
        end=time.monotonic()+a.seconds
        try:
            while session.probe.active and time.monotonic()<end:
                session.tick();time.sleep(min(a.interval,max(0,end-time.monotonic())))
        finally:session.stop()
        result={"folder":str(session.probe.session_folder),"state":session.probe.session_state,
                "wall_seconds_requested":a.seconds,"samples":session.probe.total_samples}
    elif a.command=="export":result=export_case(a.session,a.destination,include_sensitive=a.raw)
    elif a.command=="verify":result=verify_package(a.package)
    elif a.command=="compare":result=compare_cases(a.before,a.after)
    elif a.command=="recover":result=recover_case(a.session,a.destination)
    else:
        from .research_fixtures import main as fixture
        return fixture(a.arguments)
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0


if __name__=="__main__":raise SystemExit(main())
