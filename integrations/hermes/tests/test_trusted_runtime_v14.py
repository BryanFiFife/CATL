"""Adversarial checks for trust of the *importable environment*, not just Python."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hermes_effective_guard as guard


class RuntimeEvidenceHardening(unittest.TestCase):
    def setUp(self):
        self.home=Path('/opt/catl-test-profile')
        self.digest='a'*64
        self.snapshot={
            'version':1, 'uid':1001, 'home':str(self.home),
            'config_sha256_before':self.digest,'config_sha256_after':self.digest,
            'resolved_toolsets':['catl'],
            'tool_names':sorted(guard.EXPECTED_NAMES),
        }

    def check(self,data):
        return guard.inspect_snapshot(data,config_sha256=self.digest,
                                     home=self.home,expected_uid=1001)

    def test_boolean_version_is_not_a_valid_protocol_version(self):
        self.assertTrue(self.check(self.snapshot)['passed'])
        self.assertFalse(self.check({**self.snapshot, 'version':True})['passed'])

    def test_uid_must_be_exact_integer_not_boolean(self):
        self.assertFalse(self.check({**self.snapshot,'uid':True})['passed'])
        self.assertFalse(self.check({**self.snapshot,'uid':'1001'})['passed'])

    def test_untrusted_python_diagnostic_must_not_exit_success(self):
        with mock.patch.object(guard,'verify_hermes',return_value={
             'passed':True,'errors':[],'observed_tools':sorted(guard.EXPECTED_NAMES)}):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                rc=guard.main(['--hermes-python','/tmp/agent-python',
                               '--hermes-home',str(self.home),
                               '--agent-uid','1001','--allow-untrusted-python'])
            data=json.loads(out.getvalue())
            self.assertEqual(rc,1)
            self.assertFalse(data['passed'])
            self.assertTrue(data['diagnostic_result_only'])
            self.assertTrue(data['low_assurance'])

    @unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Requires disposable root-owned test directories')
    def test_agent_writable_imports_cannot_be_trusted(self):
        with tempfile.TemporaryDirectory(prefix='catl-env-v14-',dir='/opt') as td:
            root=Path(td); root.chmod(0o755)
            env=root/'venv';(env/'bin').mkdir(parents=True);(env/'lib'/'python3.13'/'site-packages').mkdir(parents=True)
            cfg=env/'pyvenv.cfg';cfg.write_text('home = /usr/bin\n')
            script=env/'bin'/'python';script.write_text('interpreter surrogate\n')
            pkg=env/'lib'/'python3.13'/'site-packages'/'model_tools.py';pkg.write_text('safe_registry = True\n')
            for node in env.rglob('*'):
                if node.is_dir():node.chmod(0o755)
                elif node.is_file():node.chmod(0o644)
            self.assertEqual(guard._trusted_venv_tree(script),[])
            pkg.chmod(0o666)
            bad=guard._trusted_venv_tree(script)
            self.assertTrue(any('venv_untrusted_writable' in x for x in bad),bad)
            # Demonstrate a nonroot process can actually edit the importable module.
            proc=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-c',
                   f'open({str(pkg)!r}, "a").write("# external agent injection\\n")'],
                   capture_output=True,text=True,timeout=6)
            self.assertEqual(proc.returncode,0,proc.stderr)
            pkg.chmod(0o644)
            malicious=env/'lib'/'python3.13'/'site-packages'/'outside.pth'
            malicious.symlink_to(Path('/tmp'))
            errs=guard._trusted_venv_tree(script)
            self.assertTrue(any('venv_untrusted_target_parent' in x or 'venv_untrusted_writable' in x for x in errs),errs)
            malicious.unlink()
            self.assertEqual(guard._trusted_venv_tree(script),[])
            self.assertTrue(guard._trusted_venv_tree(script,max_entries=2))

    @unittest.skipUnless(sys.platform=='linux','Linux process groups only')
    def test_orphaned_stdout_descendant_killed_after_parent_exit(self):
        with tempfile.TemporaryDirectory(prefix='catl-child-v14-') as td:
            marker=Path(td)/'child.pid'
            child_code='import time; time.sleep(25)'
            parent_code=(
                'import os,sys,subprocess;'
                f'p=subprocess.Popen([sys.executable,"-c",{child_code!r}],stdout=sys.stdout,stderr=sys.stderr);'
                f'open({str(marker)!r},"w").write(str(p.pid));'
                'sys.exit(0)'
            )
            with self.assertRaises(TimeoutError):
                guard._run_bounded([sys.executable,'-c',parent_code],env=dict(os.environ),timeout=1)
            self.assertTrue(marker.exists())
            pid=int(marker.read_text())
            # On Linux a killed grandchild can be briefly a zombie; either a
            # missing PID or Z state establishes no remaining execution.
            stat_path=Path('/proc')/str(pid)/'stat'
            deadline=time.monotonic()+3
            state='missing'
            while time.monotonic()<deadline:
                if not stat_path.exists():
                    state='missing';break
                state=stat_path.read_text().split(') ',1)[1][0]
                if state=='Z':break
                time.sleep(.05)
            self.assertIn(state,('Z','missing'),'Timeout leaked a still-running grandchild')

if __name__=='__main__':unittest.main()
