"""CATL acceptance: local report path attacks (disposable Git fixtures)."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('catl_native_v7',ROOT/'tools'/'offline_native_acceptance.py')
acceptance=importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)

class NativeReportSecurity(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='catl-report-v7-');self.addCleanup(self.t.cleanup)
        self.base=Path(self.t.name)
        self.repo=self.base/'source';(self.repo/'src'/'catl').mkdir(parents=True);(self.repo/'tests').mkdir()
        files={'src/catl/__init__.py':b'',
               'tests/test_smoke.py':b'import unittest\nclass Smoke(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n'}
        for name,data in files.items():(self.repo/name).write_bytes(data)
        digest={p:hashlib.sha256(b).hexdigest() for p,b in files.items()}
        (self.repo/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':digest}))
        (self.repo/'SHA256SUMS.txt').write_text(''.join(f'{d}  {n}\n' for n,d in sorted(digest.items())))
        env=os.environ.copy();env.update(GIT_AUTHOR_NAME='CATL Test',GIT_AUTHOR_EMAIL='test@example.invalid',GIT_COMMITTER_NAME='CATL Test',GIT_COMMITTER_EMAIL='test@example.invalid')
        for cmd in (['git','init','-q'],['git','add','.'],['git','commit','-qm','fixture']):
            subprocess.run(cmd,cwd=self.repo,env=env,check=True,stdout=subprocess.DEVNULL)
        self.commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.repo,text=True).strip()
        self.out=self.base/'reports'
    def run_it(self):
        return acceptance.run(self.repo,self.out,timeout=10,expected_commit=self.commit)
    def _replace_smoke_and_commit(self, source: str) -> None:
        self.repo.joinpath('tests/test_smoke.py').write_text(source)
        paths=('src/catl/__init__.py','tests/test_smoke.py')
        digest={n:hashlib.sha256((self.repo/n).read_bytes()).hexdigest() for n in paths}
        (self.repo/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':digest}))
        (self.repo/'SHA256SUMS.txt').write_text(''.join(f'{d}  {n}\n' for n,d in sorted(digest.items())))
        env=os.environ.copy();env.update(GIT_AUTHOR_NAME='CATL Test',GIT_AUTHOR_EMAIL='test@example.invalid',GIT_COMMITTER_NAME='CATL Test',GIT_COMMITTER_EMAIL='test@example.invalid')
        subprocess.run(['git','add','.'],cwd=self.repo,check=True,env=env,capture_output=True)
        subprocess.run(['git','commit','-qm','test variant'],cwd=self.repo,check=True,env=env,capture_output=True)
        self.commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.repo,text=True).strip()
    def test_massive_test_output_must_be_bounded_during_execution(self):
        source=('import sys,unittest\nclass Flood(unittest.TestCase):\n'
                ' def test_output(self):\n'
                '  for i in range(34): sys.stdout.write("X"*1048576)\n')
        self._replace_smoke_and_commit(source)
        result=acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit)
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY')
        self.assertLessEqual((self.out/'native-unittest.log').stat().st_size,32*1024*1024)
    def test_background_child_cannot_hold_native_run_open_or_be_ignored(self):
        source=('import subprocess,sys,unittest\n'
                'class Child(unittest.TestCase):\n'
                ' def test_child(self):\n'
                '  subprocess.Popen([sys.executable,"-c","import time;time.sleep(5)"])\n')
        self._replace_smoke_and_commit(source)
        result=acceptance.run(self.repo,self.out,timeout=1,expected_commit=self.commit)
        self.assertEqual(result['result'],'FAIL',result)
        self.assertEqual(result.get('exit_code'),124,result)
    def test_clean_private_report_directory_and_permissions(self):
        result=self.run_it()
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(self.out.stat().st_mode & 0o777,0o700)
        for filename in ('native-unittest.log','acceptance.json'):
            self.assertEqual((self.out/filename).stat().st_mode & 0o777,0o600)
    def test_existing_symlinked_log_cannot_clobber_victim(self):
        self.out.mkdir(mode=0o700)
        victim=self.base/'valuable.txt';victim.write_text('STAY_UNTOUCHED')
        (self.out/'native-unittest.log').symlink_to(victim)
        try: result=self.run_it()
        except (OSError,PermissionError,FileExistsError):result={'result':'FAIL'}
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY')
        self.assertEqual(victim.read_text(),'STAY_UNTOUCHED')
    def test_existing_symlinked_report_cannot_clobber_victim(self):
        self.out.mkdir(mode=0o700)
        victim=self.base/'valuable.txt';victim.write_text('STAY_UNTOUCHED')
        (self.out/'acceptance.json').symlink_to(victim)
        try: result=self.run_it()
        except (OSError,PermissionError,FileExistsError):result={'result':'FAIL'}
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY')
        self.assertEqual(victim.read_text(),'STAY_UNTOUCHED')
    def test_existing_regular_log_not_overwritten(self):
        self.out.mkdir(mode=0o700)
        victim=self.out/'native-unittest.log';victim.write_text('PREVIOUS_EVIDENCE')
        try:self.run_it()
        except (OSError,PermissionError,FileExistsError):pass
        self.assertEqual(victim.read_text(),'PREVIOUS_EVIDENCE')
    def test_existing_report_not_overwritten(self):
        self.out.mkdir(mode=0o700)
        report=self.out/'acceptance.json';report.write_text('PREVIOUS_EVIDENCE')
        try:self.run_it()
        except (OSError,PermissionError,FileExistsError):pass
        self.assertEqual(report.read_text(),'PREVIOUS_EVIDENCE')
    def test_symlink_directory_not_accepted(self):
        target=self.base/'redirected';target.mkdir(mode=0o700)
        self.out.symlink_to(target,target_is_directory=True)
        with self.assertRaises((OSError,PermissionError,ValueError)):
            self.run_it()
        self.assertFalse((target/'acceptance.json').exists())
    def test_world_writable_report_directory_denied(self):
        self.out.mkdir(mode=0o700);self.out.chmod(0o777)
        with self.assertRaises((OSError,PermissionError,ValueError)):
            self.run_it()
    def test_untrusted_group_writable_parent_denied(self):
        unsafe=self.base/'untrusted';unsafe.mkdir(mode=0o700);unsafe.chmod(0o770)
        self.out=unsafe/'report'
        with self.assertRaises((OSError,PermissionError,ValueError)):
            self.run_it()
    def test_sticky_tmp_parent_accepted(self):
        result=self.run_it()
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY')
    @unittest.skipUnless(os.name=='posix','POSIX hardlink test')
    def test_hardlinked_log_victim_not_clobbered(self):
        self.out.mkdir(mode=0o700)
        victim=self.base/'valuable.txt';victim.write_text('STAY_UNTOUCHED')
        os.link(victim,self.out/'native-unittest.log')
        try:self.run_it()
        except (OSError,PermissionError,FileExistsError):pass
        self.assertEqual(victim.read_text(),'STAY_UNTOUCHED')

if __name__=='__main__':unittest.main()
