"""Regression: Git replace refs must never alter reviewed source provenance.

The attack substitutes a different commit tree behind an unchanged reviewed
commit SHA. A compromised local Git checkout can report a clean status while
returning arbitrary file contents for that supposedly immutable commit.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'


def _import(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GitReplaceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='catl-git-replace-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        (self.repo / 'tools').mkdir(parents=True)
        for name in ('release_pack.py', 'verify_source_artifact.py',
                     'release_sealed.py'):
            shutil.copy2(TOOLS / name, self.repo / 'tools' / name)
        (self.repo / 'tools' / 'release_attest.py').write_text('# reviewed stub\n')
        (self.repo / 'pyproject.toml').write_text(
            '[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        (self.repo / 'README.md').write_text('APPROVED ORIGINAL SOURCE\n')
        self.env = dict(os.environ)
        self.env.update(GIT_AUTHOR_NAME='CATL isolated test',
                        GIT_AUTHOR_EMAIL='test@example.invalid',
                        GIT_COMMITTER_NAME='CATL isolated test',
                        GIT_COMMITTER_EMAIL='test@example.invalid')
        self.env.pop('GIT_NO_REPLACE_OBJECTS', None)
        self.git('init', '-q')
        self.git('add', '.')
        self.git('commit', '-qm', 'reviewed original')
        self.reviewed = self.git('rev-parse', 'HEAD')
        self.real_tree = self.git('rev-parse', 'HEAD^{tree}')
        (self.repo / 'README.md').write_text('ATTACKER SUBSTITUTED SOURCE\n')
        p = self.repo / 'tools' / 'release_sealed.py'
        p.write_text(p.read_text() + '\n# ATTACKER SIGNER CHANGE\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'attacker source')
        attacker = self.git('rev-parse', 'HEAD')
        self.attacker_tree = self.git('rev-parse', 'HEAD^{tree}')
        self.git('checkout', '-q', '--detach', self.reviewed)
        self.git('replace', self.reviewed, attacker)
        self.git('reset', '--hard', self.reviewed)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.reviewed)
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), self.attacker_tree)
        self.assertEqual(self.git('status', '--porcelain'), '')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, env=self.env,
                              check=True, capture_output=True, text=True).stdout.strip()

    def test_builder_refuses_replaced_commit_even_if_status_clean(self):
        target = self.root / 'must-not-build.zip'
        result = subprocess.run([sys.executable, str(self.repo/'tools'/'release_pack.py'),
                                 '--output', str(target)], cwd=self.repo,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(target.exists())

    def test_verifier_rejects_forged_zip_with_original_commit_claim(self):
        # Simulate the *old* unguarded builder for attack setup only. This
        # constructs a canonical ZIP, with internally valid hashes, while
        # claiming a commit that does not contain the ZIP's source content.
        module = _import(self.repo / 'tools' / 'release_pack.py', 'replace_test_pack')
        def unsafe_git(*args):
            return subprocess.run(['git', *args], cwd=self.repo, env=self.env,
                                  check=True, capture_output=True).stdout
        module._git = unsafe_git
        target = self.root / 'forged.zip'
        module.make(target)
        with zipfile.ZipFile(target) as z:
            self.assertEqual(json.loads(z.read('RELEASE_MANIFEST.json'))['source_commit'], self.reviewed)
            self.assertEqual(z.read('README.md'), b'ATTACKER SUBSTITUTED SOURCE\n')
        result = subprocess.run([sys.executable, str(self.repo/'tools'/'verify_source_artifact.py'),
                                 '--archive', str(target), '--checkout', str(self.repo),
                                 '--commit', self.reviewed], cwd=self.repo,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('source_git_blob_mismatch', result.stderr)

    def test_signing_toolchain_rejects_replaced_signer_source(self):
        sys.path.insert(0, str(TOOLS))
        self.addCleanup(lambda: sys.path.remove(str(TOOLS)))
        from release_sealed import _verified_signing_toolchain, ReleaseGateDenied
        with self.assertRaisesRegex(ReleaseGateDenied, 'signing_tool_source_modified'):
            _verified_signing_toolchain(self.repo, self.reviewed)

    def test_native_acceptance_git_reader_ignores_replacements(self):
        path = ROOT / 'tools' / 'offline_native_acceptance.py'
        if not path.exists():
            self.skipTest('offline native acceptance runner not installed')
        runner = _import(path, 'replace_test_native')
        self.assertEqual(runner._git(self.repo, 'rev-parse', self.reviewed+'^{tree}'), self.real_tree)

if __name__ == '__main__':
    unittest.main()
