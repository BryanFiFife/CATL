import os,sys,unittest,tempfile,socket,stat
from unittest.mock import patch,MagicMock
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from catl.platform_proofs import PlatformProofError,linux_self_confinement_proof,macos_peer_uid,windows_current_token_proof,protected_unix_socket_path
class TestPlatform(unittest.TestCase):
 def setUp(self):
  self.status='Name:\tcatl\nUid:\t1001 1001 1001 1001\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
 def runcheck(self,**kw):return linux_self_confinement_proof(proc_status=kw.get('proc_status',self.status),cgroup_memory=kw.get('memory','786432000'),cgroup_pids=kw.get('pids','64'))
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_good_status(self):self.assertEqual(self.runcheck()['non_root_uid'],1001)
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_root_rejected(self):
  with self.assertRaises(PlatformProofError):self.runcheck(proc_status=self.status.replace('1001 1001 1001 1001','0 0 0 0'))
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_caps_rejected(self):
  with self.assertRaises(PlatformProofError):self.runcheck(proc_status=self.status.replace('CapBnd:\t0000000000000000','CapBnd:\t0000000000000100'))
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_seccomp_rejected(self):
  with self.assertRaises(PlatformProofError):self.runcheck(proc_status=self.status.replace('Seccomp:\t2','Seccomp:\t0'))
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_no_new_privs_rejected(self):
  with self.assertRaises(PlatformProofError):self.runcheck(proc_status=self.status.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'))
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_cgroup_unbounded(self):
  with self.assertRaises(PlatformProofError):self.runcheck(memory='max')
 @unittest.skipUnless(sys.platform=='linux','linux only')
 def test_pids_unbounded(self):
  with self.assertRaises(PlatformProofError):self.runcheck(pids='1000')
 def test_windows_fails_closed_non_windows(self):
  if sys.platform=='win32':self.skipTest('run native platform tests separately')
  with self.assertRaisesRegex(PlatformProofError,'windows'):windows_current_token_proof()
 def test_macos_fails_closed_non_mac(self):
  if sys.platform=='darwin':self.skipTest('real mac tests required')
  with self.assertRaisesRegex(PlatformProofError,'macos'):macos_peer_uid(MagicMock(),1001)
 def test_macos_peer_exact_uid_simulated(self):
  mock=MagicMock();mock.family=socket.AF_UNIX;mock.type=socket.SOCK_STREAM;mock.getpeereid.return_value=(1001,1002)
  with patch('catl.platform_proofs.sys.platform','darwin'):
   self.assertEqual(macos_peer_uid(mock,1001)['gid'],1002)
   with self.assertRaisesRegex(PlatformProofError,'mismatch'):macos_peer_uid(mock,1003)
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   actual=Path(d)/'real';actual.write_text('');alias=Path(d)/'alias';alias.symlink_to(actual)
   with self.assertRaises(PlatformProofError):protected_unix_socket_path(alias,expected_owner=1001)
if __name__=='__main__':unittest.main()

class TestHostGates(unittest.TestCase):
 def test_windows_pipe_inspector_fails_closed_elsewhere(self):
  from catl.platform_proofs import windows_named_pipe_acl_proof
  if sys.platform=='win32':self.skipTest('requires actual Windows host')
  with self.assertRaises(PlatformProofError):
   windows_named_pipe_acl_proof(r'\\.\pipe\CATL-Test',exact_allowed_sids={'S-1-5-18'})
 def test_live_unconfined_root_process_rejected(self):
  if sys.platform!='linux' or os.geteuid()!=0:self.skipTest('only meaningful in this root Linux test container')
  with self.assertRaises(PlatformProofError):
   linux_self_confinement_proof(cgroup_memory='786432000',cgroup_pids='64')
