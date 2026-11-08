"""CATL v13 regression: untrusted Git configuration must never execute commands.

Creates disposable git repos only.  No external network or GitHub Actions.
"""
from __future__ import annotations
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import release_pack, verify_source_artifact, release_sealed, offline_native_acceptance

class GitIsolationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='catl-v13-git-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / 'src'
        self.repo.mkdir()
        (self.repo / 'test.txt').write_text('original\n')
        for command in [
            ('init','-q'), ('config','user.name','Test'),
            ('config','user.email','fixture@example.invalid'),
            ('add','test.txt'), ('commit','-qm','initial')
        ]:
            subprocess.run(['git', *command], cwd=self.repo, check=True,
                           capture_output=True, timeout=10)
        self.script = self.root / 'probe.sh'
        self.marker = self.root / 'probe-ran'
        self.script.write_text('#!/bin/sh\ntouch "' + str(self.marker) + '"\nprintf "\\n"\n')
        self.script.chmod(0o700)
        self.original_root = release_pack.ROOT
        release_pack.ROOT = self.repo
        self.addCleanup(setattr, release_pack, 'ROOT', self.original_root)

    def _call_all(self):
        self.assertTrue(release_pack._git('rev-parse','HEAD'))
        self.assertTrue(release_pack._tracked_files()[0])
        self.assertTrue(verify_source_artifact._git(self.repo, 'ls-files', '-z'))
        self.assertTrue(offline_native_acceptance._git_files(self.repo))
        self.assertTrue(offline_native_acceptance._git(self.repo, 'rev-parse', 'HEAD'))

    def test_inherited_git_config_cannot_execute_script(self):
        with patch.dict(os.environ, {
                'GIT_CONFIG_COUNT':'1',
                'GIT_CONFIG_KEY_0':'core.fsmonitor',
                'GIT_CONFIG_VALUE_0':str(self.script)}):
            self._call_all()
        self.assertFalse(self.marker.exists(), 'Git invoked environment-controlled program')

    def test_local_git_config_cannot_execute_script(self):
        subprocess.run(['git','config','core.fsmonitor',str(self.script)],
                       cwd=self.repo, check=True)
        self._call_all()
        self.assertFalse(self.marker.exists(), 'Git invoked repository-controlled program')

    def test_inherited_path_cannot_replace_git_executable(self):
        fakebin = self.root / 'fakebin'
        fakebin.mkdir()
        fakegit = fakebin / 'git'
        fakegit.write_text('#!/bin/sh\ntouch "' + str(self.marker) + '"\nexit 1\n')
        fakegit.chmod(0o700)
        with patch.dict(os.environ, {'PATH':str(fakebin) + ':' + os.environ.get('PATH','')}):
            self._call_all()
        self.assertFalse(self.marker.exists(), 'Git was resolved from attacker PATH')

    def test_inherited_git_dir_cannot_redirect_checkout(self):
        with patch.dict(os.environ, {'GIT_DIR':str(self.root/'missing.git'),
                                  'GIT_WORK_TREE':str(self.root/'wrong')}):
            self._call_all()

    def test_repository_clean_filter_cannot_execute_during_source_verification(self):
        # Git's worktree diff normally invokes filter.clean even when the
        # caller disables fsmonitor, external diffs, and textconv.
        (self.repo / '.gitattributes').write_text('test.txt filter=attacker\n')
        subprocess.run(['git','add','.gitattributes'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','attributes fixture'],cwd=self.repo,check=True)
        subprocess.run(['git','config','filter.attacker.clean',str(self.script)],
                       cwd=self.repo,check=True)
        (self.repo / 'test.txt').write_text('uncommitted modification\n')
        with self.assertRaisesRegex(ValueError,'release_tracked_blob_mismatch'):
            list(release_pack.release_files())
        self.assertFalse(self.marker.exists(), 'Git worktree diff invoked attacker clean filter')
        with self.assertRaisesRegex(ValueError,'native_source_not_equal_committed_blob'):
            head = offline_native_acceptance._git(self.repo,'rev-parse','HEAD')
            offline_native_acceptance.verify_exact_git_source(self.repo,head)
        self.assertFalse(self.marker.exists(), 'Native source check invoked attacker clean filter')

    def test_signer_toolchain_uses_protected_git(self):
        # Isolate _verified_signing_toolchain's calls to git with a minimal
        # reviewed source tree and two custom scripts; the main package has
        # the exact four expected files.
        for path in ('tools/release_pack.py', 'tools/verify_source_artifact.py',
                     'tools/release_attest.py', 'tools/release_sealed.py'):
            out = self.repo/path
            out.parent.mkdir(parents=True,exist_ok=True)
            out.write_text('reviewed\n')
        subprocess.run(['git','add','tools'],cwd=self.repo,check=True)
        subprocess.run(['git','commit','-qm','signing-tools'],cwd=self.repo,check=True)
        head=subprocess.run(['git','rev-parse','HEAD'],cwd=self.repo,
                            check=True,capture_output=True,text=True).stdout.strip()
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT':'1',
                                     'GIT_CONFIG_KEY_0':'core.fsmonitor',
                                     'GIT_CONFIG_VALUE_0':str(self.script)}):
            release_sealed._verified_signing_toolchain(self.repo,head)
        self.assertFalse(self.marker.exists())

if __name__ == '__main__':unittest.main()
