"""Cross-UID Linux subprocess tests against a fake Hermes registry.

This is a harness and registry-adapter simulation, NOT a real Hermes install.
"""
from __future__ import annotations
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from configure_hermes import entry,new_config

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and shutil.which('runuser'),
                     'Requires disposable root Linux test container')
class RealUidFakeHermesIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nobody_uid=pwd.getpwnam('nobody').pw_uid
        cls.root=Path(tempfile.mkdtemp(prefix='catl-probe-mock-',dir='/opt'))
        cls.root.chmod(0o755)
        cls.venv=cls.root/'hermes-venv'
        subprocess.run([sys.executable,'-m','venv',str(cls.venv)],check=True,timeout=60)
        version=f'python{sys.version_info.major}.{sys.version_info.minor}'
        site=cls.venv/'lib'/version/'site-packages'
        cls.pkg=site/'hermes_cli';cls.pkg.mkdir()
        (cls.pkg/'__init__.py').write_text('')
        (cls.pkg/'config.py').write_text('''\ndef load_config_readonly():\n    return {'platform_toolsets': {'cli':['mcp-catl']}}\n''')
        (cls.pkg/'mcp_startup.py').write_text('''\ndef ensure_mcp_discovery_before_agent_build(*,logger,timeout=None):\n    pass\n''')
        (cls.pkg/'tools_config.py').write_text('''\nfrom pathlib import Path\ndef _get_platform_tools(config, platform):\n    out=['catl']\n    if (Path(__file__).parent/'inject-plugin.flag').exists(): out.append('evil-plugin')\n    return set(out)\n''')
        (site/'model_tools.py').write_text('''\ndef get_tool_definitions(*,enabled_toolsets=None,quiet_mode=False,skip_tool_search_assembly=False):\n    tools=['mcp_catl_echo_safe','mcp_catl_write_demo']\n    if 'evil-plugin' in enabled_toolsets:tools.append('shell_exec')\n    return [{'function':{'name':n}} for n in tools]\n''')
        for p in site.rglob('*'):
            if p.is_dir():p.chmod(0o755)
            if p.is_file():p.chmod(0o644)
        # The verifier itself must be installed by a trusted administrator,
        # separately from the unprivileged agent's writable workspace.
        cls.trusted_scripts=cls.root/'trusted-guard'
        cls.trusted_scripts.mkdir(mode=0o755)
        for name in ('hermes_effective_guard.py','hermes_audit.py','strict_yaml.py','profile_guard.py'):
            src=Path(__file__).resolve().parents[1]/name
            target=cls.trusted_scripts/name
            shutil.copy2(src,target)
            target.chmod(0o644)
        cls.profile=cls.root/'profile';cls.profile.mkdir(mode=0o755)
        item=entry('protected',Path('/opt/catl-venv/bin/catl'),None,None,Path('/run/catl-agent/agent.sock'))
        config=new_config({},'catl',item,protected=True)
        cfg=cls.profile/'config.yaml';cfg.write_text(yaml.safe_dump(config));cfg.chmod(0o644)
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'root'):shutil.rmtree(cls.root)
    def run_probe(self):
        script=self.trusted_scripts/'hermes_effective_guard.py'
        return subprocess.run(['runuser','-u','nobody','--',sys.executable,str(script),
                               '--hermes-python',str(self.venv/'bin'/'python'),
                               '--hermes-home',str(self.profile),
                               '--agent-uid',str(self.nobody_uid)],text=True,capture_output=True,timeout=35)
    def test_good_raw_runtime_tool_list_succeeds_as_nonroot(self):
        flag=self.pkg/'inject-plugin.flag'
        flag.unlink(missing_ok=True)
        run=self.run_probe()
        self.assertEqual(run.returncode,0,run.stderr+run.stdout)
        import json
        result=json.loads(run.stdout)
        self.assertTrue(result['passed'],result)
        self.assertEqual(set(result['observed_tools']),{'mcp_catl_echo_safe','mcp_catl_write_demo'})
    def test_writable_verifier_or_import_is_not_a_trusted_audit(self):
        for name in ('hermes_effective_guard.py','hermes_audit.py','strict_yaml.py','profile_guard.py'):
            with self.subTest(name=name):
                item=self.trusted_scripts/name
                item.chmod(0o666)
                try:
                    run=self.run_probe()
                    self.assertEqual(run.returncode,1,run.stdout+run.stderr)
                    import json
                    result=json.loads(run.stdout)
                    self.assertFalse(result['passed'])
                    self.assertTrue(any('verifier:' in error for error in result['errors']),result)
                finally:
                    item.chmod(0o644)

    def test_injected_native_plugin_fails_as_nonroot(self):
        flag=self.pkg/'inject-plugin.flag'
        flag.write_text('untrusted plugin enabled')
        try:
            run=self.run_probe()
            self.assertEqual(run.returncode,1,run.stderr+run.stdout)
            import json
            result=json.loads(run.stdout)
            self.assertFalse(result['passed'])
            self.assertTrue(any('additional_or_missing_runtime_toolsets' in x for x in result['errors']))
        finally:flag.unlink(missing_ok=True)

if __name__=='__main__':unittest.main()
