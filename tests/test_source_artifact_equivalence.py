"""Deterministic offline adversarial tests for ZIP-to-Git-object equivalence."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from verify_source_artifact import verify_source_artifact

ENV = {**os.environ, 'GIT_AUTHOR_NAME': 'CATL local acceptance',
       'GIT_AUTHOR_EMAIL': 'offline@example.invalid',
       'GIT_COMMITTER_NAME': 'CATL local acceptance',
       'GIT_COMMITTER_EMAIL': 'offline@example.invalid'}

class SourceArtifactEquivalence(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix='catl-source-proof-')
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        self.repo = self.tmp / 'repo'
        (self.repo / 'tools').mkdir(parents=True)
        for tool in ('release_pack.py', 'verify_source_artifact.py'):
            shutil.copyfile(ROOT / 'tools' / tool, self.repo / 'tools' / tool)
        (self.repo / 'pyproject.toml').write_text(
            '[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        (self.repo / 'README.md').write_text('original git source payload\n')
        self.git('init', '-q'); self.git('add', '.'); self.git('commit', '-qm', 'baseline')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.archive = self.tmp / 'release.zip'
        built = self.build()
        self.assertEqual(built.returncode, 0, built.stderr)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, env=ENV, check=True,
                              text=True, capture_output=True).stdout

    def build(self):
        return subprocess.run([sys.executable, 'tools/release_pack.py', '--output', str(self.archive)],
                              cwd=self.repo, env=ENV, text=True, capture_output=True, timeout=25)

    def check(self, commit=None):
        return verify_source_artifact(self.archive, self.repo, commit or self.commit)

    def rewrite_with_manifest_hashes(self, change):
        with zipfile.ZipFile(self.archive) as z:
            manifest = json.loads(z.read('RELEASE_MANIFEST.json'))
            source = {name: z.read(name) for name in z.namelist()
                      if name not in ('RELEASE_MANIFEST.json', 'SHA256SUMS.txt')}
        change(source, manifest)
        manifest['files'] = {name: hashlib.sha256(data).hexdigest()
                             for name, data in source.items()}
        source['RELEASE_MANIFEST.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        source['SHA256SUMS.txt'] = ''.join(f'{digest}  {name}\n'
                                           for name, digest in sorted(manifest['files'].items())).encode()
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in sorted(source.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 11, 7, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, data)

    def test_exact_git_objects_verify(self):
        outcome = self.check()
        self.assertTrue(outcome['verified'])
        self.assertEqual(outcome['tracked_files'], 4)
        self.assertEqual(outcome['source_commit'], self.commit)
        self.assertEqual(outcome['archive_members'], 6)

    def test_independent_verification_does_not_trust_dirty_worktree(self):
        # An immutable release can be verified after someone locally modifies
        # a source file; its committed Git object is authoritative.
        (self.repo / 'README.md').write_text('uncommitted modified worktree\n')
        self.assertTrue(self.check()['verified'])

    def test_detached_release_claim_cannot_substitute_other_commit(self):
        with self.assertRaisesRegex(ValueError, 'source_reviewed_checkout_head_mismatch'):
            self.check('f' * 40)

    def test_self_consistent_forged_source_bytes_fail(self):
        self.rewrite_with_manifest_hashes(
            lambda source, m: source.__setitem__('README.md', b'substituted uncommitted source\n'))
        with self.assertRaisesRegex(ValueError, 'source_git_blob_mismatch:README.md'):
            self.check()

    def test_self_consistent_forged_new_source_file_fail(self):
        self.rewrite_with_manifest_hashes(
            lambda source, m: source.__setitem__('unexpected.py', b'print(42)\n'))
        with self.assertRaisesRegex(ValueError, 'source_git_tree_file_set_mismatch'):
            self.check()

    def test_file_mode_mismatch_cannot_be_hidden_by_content_hashes(self):
        (self.repo / 'run.sh').write_text('#!/bin/sh\nexit 0\n')
        (self.repo / 'run.sh').chmod(0o755)
        self.git('add', '.'); self.git('commit', '-qm', 'executable')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(self.build().returncode, 0)
        with zipfile.ZipFile(self.archive) as archive:
            self.assertEqual((archive.getinfo('run.sh').external_attr >> 16) & 0o777, 0o755)
        # Repack with all entries mode 0644 and consistent member CRC/hash.
        self.rewrite_with_manifest_hashes(lambda _source, _manifest: None)
        with self.assertRaisesRegex(ValueError, 'source_git_file_mode_mismatch:run.sh'):
            self.check()

    def test_missing_git_object_fails_closed(self):
        # A broken object database must not be mistaken for a matching build.
        (self.repo / '.git' / 'objects').rename(self.repo / '.git' / 'objects-hidden')
        with self.assertRaises(ValueError):
            self.check()

    def test_sha256_git_repository_supported(self):
        # Re-initialise the synthetic tree in SHA-256 mode if Git supports it.
        shutil.rmtree(self.repo / '.git')
        try:
            self.git('init', '-q', '--object-format=sha256')
        except subprocess.CalledProcessError:
            self.skipTest('Git SHA-256 object format unavailable')
        self.git('add', '.'); self.git('commit', '-qm', 'sha256 baseline')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(len(self.commit), 64)
        self.assertEqual(self.build().returncode, 0)
        self.assertEqual(self.check()['git_object_format'], 'sha256')

if __name__ == '__main__':
    unittest.main()
