"""Fail-closed regression tests for CATL's privileged four-UID E2E harness.

Runs as an ordinary user without actually launching the four privileged services.
Actual four-UID acceptance still must be run on a disposable Linux target.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
E2E = ROOT / 'tests' / 'integration_rootless_e2e.py'


class RootlessHarnessSecurityTests(unittest.TestCase):
    def load_module(self):
        spec = importlib.util.spec_from_file_location('catl_test_e2e_harness', E2E)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    def test_no_inherited_shell_secrets(self):
        canary = 'never-share-private-test-secret'
        with patch.dict(os.environ, {
            'CATL_SECRET_CANARY': canary,
            'AWS_SECRET_ACCESS_KEY': canary,
            'GITHUB_TOKEN': canary,
            'SSH_AUTH_SOCK': '/tmp/attacker-ssh-agent.sock',
            'PYTHONSTARTUP': '/tmp/attacker-startup.py',
            'LD_PRELOAD': '/tmp/attacker-library.so',
            'PYTHONOPTIMIZE': '2',
            'GIT_CONFIG_COUNT': '1',
        }):
            actual = self.load_module().ENV
        for hostile in ('CATL_SECRET_CANARY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN',
                        'SSH_AUTH_SOCK', 'PYTHONSTARTUP', 'LD_PRELOAD',
                        'PYTHONOPTIMIZE', 'GIT_CONFIG_COUNT'):
            self.assertNotIn(hostile, actual)
        self.assertEqual(actual['PYTHONDONTWRITEBYTECODE'], '1')
        self.assertEqual(actual['PYTHONNOUSERSITE'], '1')
        self.assertEqual(actual['PYTHONSAFEPATH'], '1')
        self.assertEqual(actual['PYTHONPATH'], str(ROOT / 'src'))

    def test_child_process_sees_only_sanitised_environment(self):
        with patch.dict(os.environ, {'CATL_SECRET_CANARY': 'private'}, clear=False):
            env = self.load_module().ENV
            proc = subprocess.run([sys.executable, '-c',
                                   'import os,json; print(json.dumps(dict(os.environ)))'],
                                  env=env, capture_output=True, text=True, check=True, timeout=5)
        import json
        child = json.loads(proc.stdout)
        self.assertNotIn('CATL_SECRET_CANARY', child)
        self.assertNotIn('PYTHONOPTIMIZE', child)
        self.assertEqual(child.get('PYTHONPATH'), str(ROOT / 'src'))

    def test_python_optimisation_must_fail_before_spawning_uids(self):
        env = {**os.environ, 'PYTHONOPTIMIZE': '1'}
        proc = subprocess.run([sys.executable, '-O', str(E2E)],
                              env=env, capture_output=True, text=True, timeout=8)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('integration_assertions_disabled', proc.stderr)

    def test_main_refuses_running_if_assertions_disabled(self):
        proc = subprocess.run([sys.executable, '-OO', str(E2E)],
                              env=os.environ.copy(), capture_output=True, text=True, timeout=8)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('integration_assertions_disabled', proc.stderr)


if __name__ == '__main__':
    unittest.main()
