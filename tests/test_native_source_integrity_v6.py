"""Native acceptance must not bless tampered tracked or untracked executable source."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

LAB = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('acceptance_v6', LAB/'tools'/'offline_native_acceptance.py')
acceptance=importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)
ENV={**os.environ, 'GIT_AUTHOR_NAME':'CATL release lab',
     'GIT_AUTHOR_EMAIL':'catl-lab@example.invalid',
     'GIT_COMMITTER_NAME':'CATL release lab',
     'GIT_COMMITTER_EMAIL':'catl-lab@example.invalid'}

@unittest.skipUnless(os.name == 'posix', 'Linux/POSIX native acceptance lab')
class NativeSourceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='catl-integrity-',dir=str(Path.home()))
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.repo=self.root/'repo';self.repo.mkdir()
        (self.repo/'src'/'catl').mkdir(parents=True)
        (self.repo/'tests').mkdir()
        self.written={
          'src/catl/__init__.py':b'ACTIVE = "reviewed"\n',
          'tests/test_clean.py':b'import unittest\nclass Smoke(unittest.TestCase):\n    def test_sanity(self):self.assertTrue(True)\n',
          'README.md':b'CATL source test fixture\n',
          '.gitignore':b'src/catl/extra.py\n'
        }
        for rel,content in self.written.items():
            (self.repo/rel).write_bytes(content)
        self._write_indexes()
        self.git('init','-q');self.git('add','.');self.git('commit','-qm','reviewed fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        self.out=self.root/'reports'

    def git(self,*args):
        return subprocess.run(['git',*args],cwd=self.repo,env=ENV,check=True,text=True,capture_output=True)

    def _write_indexes(self):
        files={p:hashlib.sha256(x).hexdigest() for p,x in self.written.items()}
        (self.repo/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':files},sort_keys=True)+'\n')
        (self.repo/'SHA256SUMS.txt').write_text(''.join(f'{digest}  {name}\n' for name,digest in sorted(files.items())))

    def result(self):
        return acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit)

    def test_clean_control_passes_unit_suite_only(self):
        output=self.result()
        self.assertEqual(output['result'],'PASS_UNIT_SUITE_ONLY',output)
        self.assertEqual(output['test_count'],1)

    def test_skip_worktree_source_and_indexes_cannot_forge_success(self):
        self.written['src/catl/__init__.py']=b'ACTIVE = "silently_modified"\n'
        (self.repo/'src'/'catl'/'__init__.py').write_bytes(self.written['src/catl/__init__.py'])
        self._write_indexes()
        self.git('update-index','--skip-worktree','src/catl/__init__.py','RELEASE_MANIFEST.json','SHA256SUMS.txt')
        self.assertEqual(self.git('status','--porcelain','--untracked-files=no').stdout,'')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertNotIn('command', result, 'tampered source must be denied before unittest starts')
        self.assertIn('native_source_not_equal_committed_blob', result.get('failure',''))

    def test_ignored_untracked_python_source_cannot_execute_in_accepted_suite(self):
        (self.repo/'src'/'catl'/'extra.py').write_text('UNREVIEWED = True\n')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)

    def test_ignored_bytecode_cannot_be_present_at_release_check(self):
        (self.repo/'src'/'catl'/'__pycache__').mkdir()
        (self.repo/'src'/'catl'/'__pycache__'/'__init__.cpython-313.pyc').write_bytes(b'opaque bytecode')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)

    def test_source_symlink_outside_git_denied(self):
        (self.repo/'src'/'catl'/'aux.py').symlink_to('/etc/hosts')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)

    def test_trusted_root_only_untracked_file_denied(self):
        (self.repo/'sitecustomize.py').write_text('print("unreviewed import hook")\n')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)


    def test_skipped_assume_unchanged_source_and_manifest_denied(self):
        self.written['src/catl/__init__.py']=b'ACTIVE = "wrong_source"\n'
        (self.repo/'src'/'catl'/'__init__.py').write_bytes(self.written['src/catl/__init__.py'])
        self._write_indexes()
        self.git('update-index','--assume-unchanged','src/catl/__init__.py','RELEASE_MANIFEST.json','SHA256SUMS.txt')
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertNotIn('command',result)

    def test_replacement_hardlink_denied(self):
        target=self.repo/'src'/'catl'/'__init__.py'
        outside=self.root/'saved.py'
        os.link(target,outside)
        result=self.result()
        self.assertIn('native_source_untrusted_file',result.get('failure',''))

    def test_untracked_non_python_payload_in_tests_denied(self):
        (self.repo/'tests'/'payload.json').write_text('{"malicious":"fixture"}')
        result=self.result()
        self.assertIn('native_source_untracked_or_nonregular',result.get('failure',''))

    def test_untracked_unsafe_directory_denied(self):
        (self.repo/'src'/'catl'/'newpkg').mkdir()
        (self.repo/'src'/'catl'/'newpkg'/'__init__.py').write_text('X=True')
        result=self.result()
        self.assertIn('native_source_untracked_directory',result.get('failure',''))

    def test_missing_tracked_file_denied(self):
        (self.repo/'README.md').unlink()
        self.git('update-index','--skip-worktree','README.md')
        result=self.result()
        self.assertIn('native_source_tracked_file_missing',result.get('failure',''))

    def test_executable_mode_flip_denied(self):
        p=self.repo/'src'/'catl'/'__init__.py'
        p.chmod(0o755)
        self.git('update-index','--skip-worktree','src/catl/__init__.py')
        result=self.result()
        self.assertIn('native_source_file_mode_changed',result.get('failure',''))

    def test_sha256_git_repository_passes_when_supported(self):
        if subprocess.run(['git','init','--object-format=sha256','-q',str(self.root/'sha256')],
                          capture_output=True).returncode:
            self.skipTest('Git SHA-256 repositories unsupported')
        repo=self.root/'sha256'
        (repo/'src'/'catl').mkdir(parents=True)
        (repo/'tests').mkdir()
        for rel,payload in self.written.items():
            p=repo/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(payload)
        files={name:hashlib.sha256(payload).hexdigest() for name,payload in self.written.items()}
        (repo/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':files}))
        (repo/'SHA256SUMS.txt').write_text(''.join(f'{digest}  {name}\n' for name,digest in sorted(files.items())))
        for command in [('add','.'),('commit','-qm','SHA256 fixture')]:
            subprocess.run(['git',*command],cwd=repo,env=ENV,check=True,capture_output=True)
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo).decode().strip()
        result=acceptance.run(repo,self.root/'sha256-reports',timeout=15,expected_commit=commit)
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(result['git_object_format'],'sha256')

    def test_user_site_and_bytecode_writes_disabled_for_suite(self):
        # The run report documents the sanitized command environment but
        # actual child env is inspected through an innocuous unit test.
        target=self.repo/'tests'/'test_clean.py'
        content=(b'import os,unittest\n'
                 b'class Smoke(unittest.TestCase):\n'
                 b'    def test_sanity(self):\n'
                 b'        self.assertEqual(os.getenv("PYTHONNOUSERSITE"),"1")\n'
                 b'        self.assertEqual(os.getenv("PYTHONDONTWRITEBYTECODE"),"1")\n')
        target.write_bytes(content)
        self.written['tests/test_clean.py']=content
        self._write_indexes()
        self.git('add','.')
        self.git('commit','-qm','test sanitized subprocess env')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        result=self.result()
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)

    def test_forged_stdout_unittest_count_cannot_replace_real_summary(self):
        # A committed, no-test module prints a counterfeit success summary.
        # The unit runner must use its real final summary, not the first one.
        script=(b'print("Ran 900 tests in 0.001s\\nOK", flush=True)\n')
        target=self.repo/'tests'/'test_clean.py'
        target.write_bytes(script)
        self.written['tests/test_clean.py']=script
        self._write_indexes()
        self.git('add','.');self.git('commit','-qm','no-test fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(result['test_count'],0,result)

    def test_output_log_spoof_cannot_inflate_reported_test_count(self):
        script=(b'import unittest\n'
                b'print("Ran 999 tests in 0.001s\\nOK", flush=True)\n'
                b'class Smoke(unittest.TestCase):\n'
                b'    def test_real(self):self.assertTrue(True)\n')
        target=self.repo/'tests'/'test_clean.py';target.write_bytes(script)
        self.written['tests/test_clean.py']=script
        self._write_indexes()
        self.git('add','.');self.git('commit','-qm','spoof count fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        result=self.result()
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(result['test_count'],1,result)

    def test_tests_that_write_new_source_fail_post_run_integrity(self):
        script=(b'import pathlib,unittest\n'
                b'class Smoke(unittest.TestCase):\n'
                b'    def test_write(self):\n'
                b'        pathlib.Path("src/catl/unreviewed_runtime.py").write_text("X=True")\n'
                b'        self.assertTrue(True)\n')
        target=self.repo/'tests'/'test_clean.py';target.write_bytes(script)
        self.written['tests/test_clean.py']=script
        self._write_indexes()
        self.git('add','.');self.git('commit','-qm','source write fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertIn('native_source_untracked',result.get('failure',''))

    def test_release_minimum_count_fail_closed(self):
        result=acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit,minimum_tests=480)
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(result['test_count'],1)
        self.assertEqual(result['minimum_tests'],480)

    def test_skipped_only_suite_is_not_a_pass(self):
        content=(b'import unittest\n'
                 b'@unittest.skip("no tests executed")\n'
                 b'class Smoke(unittest.TestCase):\n'
                 b'    def test_noop(self):self.assertTrue(True)\n')
        target=self.repo/'tests'/'test_clean.py';target.write_bytes(content)
        self.written['tests/test_clean.py']=content
        self._write_indexes()
        self.git('add','.');self.git('commit','-qm','skipped-only fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        result=self.result()
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertEqual(result['test_count'],1)
        self.assertEqual(result['skipped'],1)

    def test_xvfb_remote_display_is_rejected_when_opted_in(self):
        authority=self.root/'Xauthority';authority.write_bytes(b'cookie');authority.chmod(0o600)
        from unittest.mock import patch
        with patch.dict(os.environ,{'DISPLAY':'evil.invalid:0','XAUTHORITY':str(authority)}):
            result=acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit,
                                  allow_local_xvfb=True)
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)
        self.assertIn('native_xvfb_must_be_local',result.get('failure',''))

    def test_xvfb_local_private_auth_file_is_accepted(self):
        authority=self.root/'Xauthority';authority.write_bytes(b'cookie');authority.chmod(0o600)
        # The fixture doesn't open a display, but checks the opt-in environment.
        content=(b'import os,unittest\n'
                 b'class Smoke(unittest.TestCase):\n'
                 b'    def test_display(self):\n'
                 b'        self.assertEqual(os.getenv("DISPLAY"),":98")\n'
                 b'        self.assertEqual(__import__("pathlib").Path(os.getenv("XAUTHORITY","")).read_bytes(),b"cookie")\n')
        target=self.repo/'tests'/'test_clean.py';target.write_bytes(content)
        self.written['tests/test_clean.py']=content;self._write_indexes()
        self.git('add','.');self.git('commit','-qm','local xvfb fixture')
        self.commit=self.git('rev-parse','HEAD').stdout.strip()
        from unittest.mock import patch
        with patch.dict(os.environ,{'DISPLAY':':98','XAUTHORITY':str(authority)}):
            result=acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit,
                                  allow_local_xvfb=True)
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY',result)

    def test_xvfb_group_writable_auth_file_denied(self):
        authority=self.root/'Xauthority';authority.write_bytes(b'cookie');authority.chmod(0o666)
        from unittest.mock import patch
        with patch.dict(os.environ,{'DISPLAY':':98','XAUTHORITY':str(authority)}):
            result=acceptance.run(self.repo,self.out,timeout=15,expected_commit=self.commit,
                                  allow_local_xvfb=True)
        self.assertIn('native_xauthority_permissions_untrusted',result.get('failure',''))

    def test_wrong_commit_denied(self):
        result=acceptance.run(self.repo,self.out,timeout=15,expected_commit='0'*40)
        self.assertNotEqual(result['result'],'PASS_UNIT_SUITE_ONLY')

if __name__=='__main__':unittest.main()
