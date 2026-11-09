"""Real Windows fixtures and compiled standalone instrumentation clients."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from blackbox_core.instrumentation import EventTail
from blackbox_core.preparation import write_preparation
from blackbox_core.windows_research import window_observations,wait_chain,enable_debug_privilege,WprCapture,privilege


@unittest.skipUnless(os.name=="nt","Windows native fixture acceptance")
class NativeFixtureTests(unittest.TestCase):
    def fixture(self,kind,folder):
        ready=Path(folder)/"ready.json"
        child=subprocess.Popen([sys.executable,"-m","blackbox_core.research_fixtures",kind,"--seconds","5","--ready",str(ready)])
        self.addCleanup(lambda:self.stop_child(child))
        deadline=time.monotonic()+5
        while not ready.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(ready.is_file(),"Native fixture failed to initialize")
        return child,json.loads(ready.read_text())
    @staticmethod
    def stop_child(child):
        if child.poll() is None:child.terminate()
        child.wait(timeout=5)
    def test_known_window_block_is_observed(self):
        with tempfile.TemporaryDirectory() as folder:
            child,info=self.fixture("gui-hang",folder)
            result=window_observations(child.pid)
            rows=[r for r in result["windows"] if r["hwnd"]==info["hwnd"]]
            self.assertEqual(len(rows),1);self.assertEqual(rows[0]["tid"],info["tid"])
            self.assertNotEqual(rows[0]["status"],"RESPONDED")
    def test_known_mutex_wait_has_native_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            child,info=self.fixture("wait-chain",folder);enable_debug_privilege()
            result=wait_chain(info["wait_tid"])
            if result["status"] not in ("OK","TRUNCATED"):
                self.skipTest("Native WCT unavailable on this token: "+json.dumps(result))
            self.assertTrue(any(r.get("tid")==info["wait_tid"] for r in result["nodes"]))
            self.assertTrue(any(r.get("object_type")==3 for r in result["nodes"]),result)
    def test_real_named_wpr_roundtrip(self):
        if not shutil.which("wpr.exe") or privilege()["mode"]!="ADMINISTRATOR":
            self.skipTest("WPR or administrator token unavailable")
        with tempfile.TemporaryDirectory() as folder:
            capture=WprCapture(folder)
            try:
                try:capture.start()
                except OSError as exc:self.skipTest("WPR start unavailable on runner: "+str(exc))
                result=capture.stop();self.assertEqual(result["status"],"CAPTURED")
                self.assertGreater((Path(folder)/result["path"]).stat().st_size,0)
            finally:
                if capture.active:capture.cancel()

    def test_real_exact_named_wpr_absence_is_an_explicit_recovery_ack(self):
        from blackbox_core.trace_cleanup import terminal_cleanup_proven
        from blackbox_core.trace_recovery import recover
        from blackbox_core.windows_research import wpr_tool,WPR_NO_ACTIVE_PROFILES
        if not wpr_tool() or privilege()['mode']!='ADMINISTRATOR':
            self.skipTest('WPR or administrator token unavailable: named absence unverified')
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);artifacts=folder/'artifacts';artifacts.mkdir()
            # This random named instance was never started. The existing WPR
            # invocation still addresses only this exact unique instance.
            instance=WprCapture(artifacts).instance;path=artifacts/(instance+'.trace.json')
            path.write_text(json.dumps({'instance':instance,'state':'COMPLETED',
                'consent':'EXPLICIT_USER_COMMAND','owner_pid':0,'guardian_pid':0}))
            retained=artifacts/'retained.etl';retained.write_bytes(b'RECOVERY_MUST_NOT_DELETE')
            class Catalog:
                def entry(self,entry_id):return {'origin':'LOCAL_APP_MARKED','state':'COMPLETED'}
                def _folder(self,row):return folder
                def _marker(self,*args):pass
            result=recover(Catalog(),'native-fixture',path.name,confirmed=True)
            self.assertEqual(result['resource_cleanup']['observation'],'NAMED_INSTANCE_ABSENT_CONFIRMED')
            self.assertEqual(result['resource_cleanup']['wpr_returncode'],WPR_NO_ACTIVE_PROFILES)
            self.assertTrue(terminal_cleanup_proven(json.loads(path.read_text()),journal=path.name))
            self.assertEqual(retained.read_bytes(),b'RECOVERY_MUST_NOT_DELETE')
            self.assertFalse(result['capture_complete']);self.assertFalse(result['target_terminated'])


@unittest.skipUnless(os.name=="nt" and shutil.which("dotnet"),"Windows .NET SDK required")
class DotnetClientTests(unittest.TestCase):
    def test_generated_client_compiles_and_emits_offline(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/"client";event=root/"event.jsonl"
            write_preparation(folder,event,"a"*32)
            versions=subprocess.run(["dotnet","--list-sdks"],capture_output=True,text=True,check=True,timeout=20).stdout
            majors=[int(line.split('.')[0]) for line in versions.splitlines() if line[:1].isdigit()]
            if not majors:self.skipTest("No usable installed .NET SDK")
            major=max(majors)
            (folder/"Client.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net{major}.0</TargetFramework><EnableDefaultCompileItems>true</EnableDefaultCompileItems></PropertyGroup></Project>')
            (folder/"NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
            from tools.qa_sdk_clients import CS_FAILURE_PROGRAM
            (folder/"Program.cs").write_text(CS_FAILURE_PROGRAM)
            env={**os.environ,"DOTNET_CLI_TELEMETRY_OPTOUT":"1","DOTNET_SKIP_FIRST_TIME_EXPERIENCE":"1"}
            build=subprocess.run(["dotnet","build","Client.csproj","--configuration","Release","--output","out","--verbosity","quiet"],cwd=folder,env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(build.returncode,0,build.stdout[-4000:]+build.stderr[-4000:])
            child=subprocess.Popen(["dotnet",str(folder/"out"/"Client.dll")],cwd=folder,env=env)
            self.assertEqual(child.wait(timeout=15),0)
            tail=EventTail(event,"a"*32,child.pid);rows=tail.poll()
            self.assertTrue(tail.ready);self.assertEqual(rows[0]["source_clock"],"DOTNET_STOPWATCH")
            self.assertEqual(rows[0]['seq'],3);self.assertEqual(rows[0]['client_dropped'],2)
            self.assertEqual(tail.client_dropped,2)


@unittest.skipUnless(os.name=="nt","Windows C++ compiler client acceptance")
class NativeClientTests(unittest.TestCase):
    def test_generated_cpp_client_compiles_and_emits(self):
        vswhere=Path(os.environ.get("ProgramFiles(x86)","C:/Program Files (x86)"))/"Microsoft Visual Studio/Installer/vswhere.exe"
        if not vswhere.is_file():self.skipTest("Visual Studio locator unavailable")
        result=subprocess.run([str(vswhere),"-latest","-products","*","-requires","Microsoft.VisualStudio.Component.VC.Tools.x86.x64","-property","installationPath"],capture_output=True,text=True,timeout=20)
        install=result.stdout.strip()
        if not install:self.skipTest("MSVC toolchain not installed")
        dev=Path(install)/"Common7/Tools/VsDevCmd.bat"
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/"client";event=Path(temp)/"event.jsonl"
            write_preparation(folder,event,"a"*32)
            # All literal paths are controlled test paths; always quote cmd paths.
            from tools.qa_sdk_clients import cpp_failure_program
            source=cpp_failure_program(event,'a'*32)
            (folder/"main.cpp").write_text(source)
            (folder/"build.cmd").write_text('@echo off\ncall "'+str(dev)+'" -no_logo -arch=x64\nif errorlevel 1 exit /b 1\ncl /nologo /EHsc /Zi /Fd:compile.pdb /std:c++17 main.cpp /Fe:client.exe /link /DEBUG /PDB:client.pdb\n',encoding="utf-8")
            build=subprocess.run(["cmd","/c","build.cmd"],cwd=folder,capture_output=True,text=True,timeout=90)
            self.assertEqual(build.returncode,0,build.stdout[-4000:]+build.stderr[-4000:])
            child=subprocess.Popen([str(folder/"client.exe")],cwd=folder);self.assertEqual(child.wait(timeout=15),0)
            tail=EventTail(event,"a"*32,child.pid);rows=tail.poll();self.assertTrue(tail.ready)
            self.assertEqual(rows[0]['seq'],3);self.assertEqual(rows[0]['client_dropped'],2)
            self.assertEqual(tail.client_dropped,2)
            from blackbox_core.symbols import verify_symbols
            self.assertEqual(verify_symbols(folder/"client.exe",folder/"client.pdb")["status"],"MATCH")


if __name__=="__main__":unittest.main()
