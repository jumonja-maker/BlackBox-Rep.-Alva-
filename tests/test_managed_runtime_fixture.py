"""Offline build of actual EventSource/GC workload; no fake GC evidence."""
import json,os,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from blackbox_core.runtime_trace import DotnetTrace

@unittest.skipUnless(shutil.which('dotnet'),'Installed .NET SDK required; no automatic download')
class ManagedRuntimeFixtureTests(unittest.TestCase):
 def build(self,root):
  versions=subprocess.run(['dotnet','--list-sdks'],capture_output=True,text=True,check=True,timeout=15).stdout
  majors=[int(line.split('.')[0]) for line in versions.splitlines() if line[:1].isdigit()]
  if not majors:self.skipTest('Installed runtime has no SDK')
  source=Path(__file__).resolve().parents[1]/'tools'/'fixtures'/'ManagedRuntimeProbe'/'Program.cs'
  shutil.copyfile(source,root/'Program.cs')
  (root/'Probe.csproj').write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net{max(majors)}.0</TargetFramework></PropertyGroup></Project>')
  (root/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
  env={**os.environ,'DOTNET_CLI_TELEMETRY_OPTOUT':'1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1'}
  done=subprocess.run(['dotnet','build','Probe.csproj','-c','Release','-o','out','--verbosity','quiet'],cwd=root,env=env,capture_output=True,text=True,timeout=90)
  self.assertEqual(done.returncode,0,(done.stdout+done.stderr)[-4000:]);return root/'out'/'Probe.dll'
 def launch(self,root):
  dll=self.build(root);state=root/'run';state.mkdir()
  process=subprocess.Popen(['dotnet',str(dll),str(state),'30'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  deadline=time.monotonic()+8
  while not (state/'ready.json').is_file() and process.poll() is None and time.monotonic()<deadline:time.sleep(.02)
  self.assertTrue((state/'ready.json').is_file(),'Managed fixture failed to initialize')
  return process,state,json.loads((state/'ready.json').read_text())
 @staticmethod
 def finish(process,state):
  if process.poll() is None:
   (state/'stop.request').touch()
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
  if process.stderr:process.stderr.close()
 def test_source_compiles_offline_and_real_runtime_exits_cooperatively(self):
  with tempfile.TemporaryDirectory() as temp:
   process,state,info=self.launch(Path(temp))
   try:self.assertEqual(info['fixture'],'FIX-09_REAL_MANAGED_RUNTIME');self.assertIsNone(process.poll())
   finally:self.finish(process,state)
   self.assertEqual(process.returncode,0)
 @unittest.skipUnless(shutil.which('dotnet-trace'),'Local dotnet-trace not installed; no invented GC capture')
 def test_real_optin_eventpipe_file_remains_honestly_undecoded(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);process,state,info=self.launch(root);artifacts=root/'artifacts';artifacts.mkdir();trace=DotnetTrace(artifacts,info['pid'],seconds=2)
   try:
    trace.start();deadline=time.monotonic()+15;result=None
    while result is None and time.monotonic()<deadline:result=trace.poll();time.sleep(.05)
    self.assertIsNotNone(result);self.assertEqual(result['status'],'COMPLETED',result)
    self.assertFalse(result['decoded']);self.assertIsNone(result['lost_events']);self.assertIsNone(process.poll())
    captured=next(artifacts.glob('*.nettrace'))
    self.assertGreater(captured.stat().st_size,0)
    import hashlib
    expected=hashlib.sha256(captured.read_bytes()).hexdigest()
    recorded=result['details']['result']
    self.assertEqual(recorded['sha256'],expected)
    anchors=result['details']['clock_anchors']
    for name in ('before_tool_spawn','after_tool_spawn','after_tool_exit',
                 'guardian_finally'):
     self.assertEqual(anchors[name]['trace_to_session_alignment'],'NOT_ESTABLISHED')
    self.assertEqual(anchors['before_tool_spawn']['schema'],
                     'blackbox.trace-clock-bracket/1')
   finally:trace.stop();self.finish(process,state)
if __name__=='__main__':unittest.main()
