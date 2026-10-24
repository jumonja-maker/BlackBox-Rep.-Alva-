"""Actual prematurely exiting exporters, not mocked completion evidence."""
import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from blackbox_core.export_recovery import ExportTransaction,scan_exports,recover_export
class ExportRecoveryTests(unittest.TestCase):
 def test_native_destination_race_keeps_file_exists_contract_and_win32_code(self):
  from blackbox_core.library_files import windows_move_error
  import errno
  for code in (80,183):
   error=windows_move_error(code,'TEST_ONLY_DESTINATION')
   self.assertIsInstance(error,FileExistsError);self.assertEqual(error.errno,errno.EEXIST);self.assertEqual(error.winerror,code)
  error=windows_move_error(5,'TEST_ONLY_DESTINATION');self.assertNotIsInstance(error,FileExistsError);self.assertEqual(error.winerror,5)
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def interrupted(self,prepare=True):
  code="""from blackbox_core.export_recovery import ExportTransaction
import os,sys
t=ExportTransaction(sys.argv[1],kind='TEST_ONLY_INTERRUPTION')
a=t.reserve('a.txt');a.write_text('actual exporter bytes')
b=t.reserve('b.txt');b.write_text('second file')
if sys.argv[2]=='1':t.prepare({'out-a.txt':a,'out-b.txt':b})
os._exit(0)
"""
  subprocess.run([sys.executable,'-c',code,str(self.root),'1' if prepare else '0'],check=True,timeout=10)
  return Path(scan_exports(self.root)['rows'][0]['journal'])
 def test_ready_export_finishes_after_actual_owner_exit(self):
  journal=self.interrupted();self.assertFalse(scan_exports(self.root)['rows'][0]['owner_active'])
  r=recover_export(journal,action='FINISH',confirmed=True);self.assertEqual(r['status'],'RECOVERED')
  self.assertEqual((self.root/'out-a.txt').read_text(),'actual exporter bytes');self.assertEqual(len(list(self.root.iterdir())),2)
 def test_partial_build_requires_explicit_consent_and_never_finishes_empty(self):
  journal=self.interrupted(False)
  with self.assertRaisesRegex(ValueError,'CONFIRMATION'):recover_export(journal,action='DISCARD')
  with self.assertRaisesRegex(ValueError,'BUILD_INCOMPLETE'):recover_export(journal,action='FINISH',confirmed=True)
  recover_export(journal,action='DISCARD',confirmed=True);self.assertEqual(list(self.root.iterdir()),[])
 def test_recovery_does_not_overwrite_competing_destination(self):
  journal=self.interrupted();(self.root/'out-b.txt').write_text('KEEP')
  with self.assertRaises(FileExistsError):recover_export(journal,action='FINISH',confirmed=True)
  self.assertEqual((self.root/'out-b.txt').read_text(),'KEEP');self.assertFalse((self.root/'out-a.txt').exists())
 def test_unknown_stage_file_is_retained(self):
  journal=self.interrupted();data=json.loads(journal.read_text());stage=self.root/('.bb-export-'+data['uid']);(stage/'KEEP.bin').write_bytes(b'new')
  with self.assertRaisesRegex(ValueError,'BUILD_INCOMPLETE'):recover_export(journal,action='DISCARD',confirmed=True)
  self.assertEqual((stage/'KEEP.bin').read_bytes(),b'new')
 def test_dump_retry_only_handles_bad_length_without_weakening_other_errors(self):
  from blackbox_core.windows_research import _write_dump_bounded
  import io
  attempts=[];stream=io.BytesIO()
  def write(out):
   attempts.append(1);out.write(b'partial' if len(attempts)<2 else b'MDMP verified')
   return len(attempts)>=2,0x80070018
  result=_write_dump_bounded(write,stream)
  self.assertEqual(result['attempts'],2);self.assertEqual(stream.getvalue(),b'MDMP verified')
  with self.assertRaises(OSError):_write_dump_bounded(lambda out:(False,5),io.BytesIO())
 def test_active_export_owner_cannot_be_claimed(self):
  t=ExportTransaction(self.root,kind='TEST_ONLY_ACTIVE')
  with self.assertRaisesRegex(ValueError,'OWNER_ACTIVE'):recover_export(t.journal,action='DISCARD',confirmed=True)
  t.abort();self.assertEqual(list(self.root.iterdir()),[])
 def test_actual_exit_after_stage_cleanup_reconciles_committed_outputs_without_republication(self):
  code="""from blackbox_core.export_recovery import ExportTransaction
from pathlib import Path
import os,sys
t=ExportTransaction(sys.argv[1],kind='TEST_ONLY_POST_CLEANUP_EXIT')
a=t.reserve('a.txt');a.write_text('COMMITTED BY REAL CHILD')
t.prepare({'a.txt':a})
original=Path.unlink
def crash(path,*args,**kwargs):
 if path==t.journal:os._exit(0)
 return original(path,*args,**kwargs)
Path.unlink=crash
t.publish()
"""
  subprocess.run([sys.executable,'-c',code,str(self.root)],check=True,timeout=10)
  journal=Path(scan_exports(self.root)['rows'][0]['journal'])
  self.assertFalse(any(p.is_dir() for p in self.root.iterdir()))
  with self.assertRaisesRegex(ValueError,'COMMITTED_REQUIRES_FINISH'):recover_export(journal,action='DISCARD',confirmed=True)
  r=recover_export(journal,action='FINISH',confirmed=True)
  self.assertEqual(r['status'],'RECONCILED_COMMITTED');self.assertEqual((self.root/'a.txt').read_text(),'COMMITTED BY REAL CHILD')
  self.assertFalse(journal.exists())
if __name__=='__main__':unittest.main()

