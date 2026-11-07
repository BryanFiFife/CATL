"""Isolated tests for the offline CATL native acceptance runner."""
import importlib.util
import hashlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1]/'tools'/'offline_native_acceptance.py'
spec=importlib.util.spec_from_file_location('offline_native_acceptance',RUNNER)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OfflineAcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        self.repo=self.base/'checkout';self.repo.mkdir()
        (self.repo/'src'/'catl').mkdir(parents=True)
        (self.repo/'tests').mkdir()
        (self.repo/'src'/'catl'/'__init__.py').write_text('')
        (self.repo/'tests'/'test_sample.py').write_text('import unittest\nclass TestExample(unittest.TestCase):\n def test_good(self):self.assertTrue(True)\n')
        subprocess.run(['git','init','-q'],cwd=self.repo,check=True)
        subprocess.run(['git','config','user.email','test@example.invalid'],cwd=self.repo,check=True)
        subprocess.run(['git','config','user.name','CATL Fixture'],cwd=self.repo,check=True)
        self._rebuild()

    def _rebuild(self):
        tracked = list((self.repo/'src').rglob('*.py'))+list((self.repo/'tests').rglob('*.py'))
        names=sorted(str(p.relative_to(self.repo)) for p in tracked)
        data={name:hashlib.sha256((self.repo/name).read_bytes()).hexdigest() for name in names}
        (self.repo/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':data}))
        (self.repo/'SHA256SUMS.txt').write_text(''.join(f'{value}  {name}\n' for name,value in data.items()))
        subprocess.run(['git','add','.'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','fixture'],cwd=self.repo,check=True)

    def test_pass_reports_actual_test_count(self):
        result=mod.run(self.repo,self.base/'result')
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY')
        self.assertEqual(result['test_count'],1)
        self.assertEqual(result['github_actions'],'NOT_INVOKED')
        self.assertEqual(result['full_host_e2e'],'NOT_RUN')

    def test_tampered_source_fails_before_execution(self):
        (self.repo/'tests'/'test_sample.py').write_text('this is malicious text')
        result=mod.run(self.repo,self.base/'result')
        self.assertEqual(result['result'],'FAIL')
        self.assertIn('tracked_source_dirty',result['failure'])
        self.assertNotIn('log_sha256',result)

    def test_checksum_tamper_refused(self):
        p=self.repo/'SHA256SUMS.txt'
        p.write_text(p.read_text().replace('  ', '  broken/'))
        # The source snapshot must be clean; commit manipulated index for this fixture.
        subprocess.run(['git','add','.'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','tampered-sum'],cwd=self.repo,check=True)
        result=mod.run(self.repo,self.base/'result')
        self.assertIn('checksum_index_mismatch',result['failure'])

    def test_bad_manifest_type_fails_closed_and_reports(self):
        p=self.repo/'RELEASE_MANIFEST.json'
        p.write_text('[]')
        subprocess.run(['git','add','.'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','bad-manifest'],cwd=self.repo,check=True)
        result=mod.run(self.repo,self.base/'result')
        self.assertEqual(result['result'],'FAIL')
        self.assertIn('manifest_schema_invalid',result['failure'])

    def test_duplicate_manifest_keys_fail_closed(self):
        p=self.repo/'RELEASE_MANIFEST.json'
        p.write_text('{"algorithm":"sha256","algorithm":"sha256","files":{}}')
        subprocess.run(['git','add','.'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','duplicate-manifest'],cwd=self.repo,check=True)
        result=mod.run(self.repo,self.base/'result')
        self.assertIn('manifest_duplicate_key',result['failure'])

    def test_mismatched_commit_refused(self):
        result=mod.run(self.repo,self.base/'result',expected_commit='a'*40)
        self.assertIn('unexpected_checkout_commit',result['failure'])

    def test_suite_failure_detected(self):
        p=self.repo/'tests'/'test_sample.py'
        p.write_text('import unittest\nclass TestExample(unittest.TestCase):\n def test_bad(self):self.fail("intentional")\n')
        self._rebuild()
        result=mod.run(self.repo,self.base/'result')
        self.assertEqual(result['result'],'FAIL')
        self.assertIn('native_unit_suite_incomplete_or_failed',result['failure'])
        self.assertEqual(result['test_count'],1)

    def test_test_suite_timeout_is_bounded(self):
        p=self.repo/'tests'/'test_sample.py'
        p.write_text('import time,unittest\nclass TestSleep(unittest.TestCase):\n def test_hang(self):time.sleep(30)\n')
        self._rebuild()
        result=mod.run(self.repo,self.base/'result',timeout=1)
        self.assertEqual(result['result'],'FAIL')
        self.assertEqual(result['failure'],'native_unit_suite_incomplete_or_failed')
        self.assertEqual(result['exit_code'],124)

    def test_shell_environment_secrets_not_inherited(self):
        p=self.repo/'tests'/'test_sample.py'
        p.write_text('import os,unittest\nclass TestEnv(unittest.TestCase):\n def test_no_secret(self):self.assertNotIn("CATL_OPERATOR_SECRET",os.environ)\n')
        self._rebuild()
        with patch.dict('os.environ',{'CATL_OPERATOR_SECRET':'should-not-export'}):
            result=mod.run(self.repo,self.base/'result')
        self.assertEqual(result['result'],'PASS_UNIT_SUITE_ONLY')

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX fixture")
    def test_unexpected_symlink_denied(self):
        (self.repo/'src'/'catl'/'__init__.py').unlink()
        (self.repo/'src'/'catl'/'__init__.py').symlink_to(self.repo/'tests'/'test_sample.py')
        with self.assertRaises(ValueError):
            mod._safe_source_path(self.repo,'src/catl/__init__.py')

    def test_path_traversal_denied(self):
        for name in ('../outside','src//catl/__init__.py','/etc/passwd','src/catl/../catl/__init__.py','src\\catl\\__init__.py'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                mod._safe_source_path(self.repo,name)

    def test_output_inside_repo_denied(self):
        with self.assertRaisesRegex(ValueError,'outside_repo'):
            mod.run(self.repo,self.repo/'out')


if __name__=='__main__':
    unittest.main()
