"""Offline CATL packaging adversarial tests (isolated temporary Git repositories).

Never touches the real checkout, credentials, external endpoints or GitHub Actions.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HARDENED = Path(__file__).resolve().parents[1] / 'tools' / 'release_pack.py'
ENV = {**os.environ,
       'GIT_AUTHOR_NAME': 'CATL local test', 'GIT_AUTHOR_EMAIL': 'local@example.invalid',
       'GIT_COMMITTER_NAME': 'CATL local test', 'GIT_COMMITTER_EMAIL': 'local@example.invalid'}


class ReleasePackSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='catl-pack-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        (self.root / 'tools').mkdir()
        shutil.copyfile(HARDENED, self.root / 'tools' / 'release_pack.py')
        (self.root / 'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion = "0.11.0rc1"\n')
        (self.root / 'README.md').write_text('synthetic CATL release source\n')
        (self.root / '.gitignore').write_text('.env\n*.sqlite\n__pycache__/\n')
        self._git('init', '-q')
        self._git('add', 'tools/release_pack.py', 'pyproject.toml', 'README.md', '.gitignore')
        self._git('commit', '-qm', 'synthetic trusted baseline')
        self.output = Path(self.tmp.name) / 'out.zip'

    def _git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, env=ENV,
                              check=True, text=True, capture_output=True).stdout

    def _run(self, *args):
        return subprocess.run([sys.executable, str(self.root / 'tools' / 'release_pack.py'), *args],
                              cwd=self.root, env=ENV, text=True, capture_output=True)

    def _build(self):
        return self._run('--output', str(self.output))

    def _verified(self):
        return self._run('--verify', str(self.output))

    def _rewrite_archive(self, mutator):
        with zipfile.ZipFile(self.output) as original:
            items = [(i.filename, original.read(i.filename)) for i in original.infolist()]
        items = mutator(items)
        with zipfile.ZipFile(self.output, 'w') as revised:
            for name, content in items:
                item = zipfile.ZipInfo(name, date_time=(2026, 11, 7, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.external_attr = (0o100644 << 16)
                revised.writestr(item, content)

    def test_clean_source_is_deterministic_and_verified(self):
        first = self._build()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_hash = hashlib.sha256(self.output.read_bytes()).hexdigest()
        self.assertEqual(self._verified().returncode, 0)
        self.assertEqual(self._build().returncode, 0)
        self.assertEqual(first_hash, hashlib.sha256(self.output.read_bytes()).hexdigest())

    def test_untracked_dotenv_never_enters_zip(self):
        (self.root / '.env').write_text('LOCAL_SECRET_EXAMPLE_NOT_REAL=supersecret\n')
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.output) as archive:
            self.assertNotIn('.env', archive.namelist())
            self.assertNotIn(b'LOCAL_SECRET_EXAMPLE', b''.join(archive.read(x) for x in archive.namelist()))

    def test_untracked_nonignored_source_never_enters_zip(self):
        (self.root / 'unreviewed.py').write_text('print("this should not ship")\n')
        self.assertEqual(self._build().returncode, 0)
        with zipfile.ZipFile(self.output) as archive:
            self.assertNotIn('unreviewed.py', archive.namelist())

    def test_tracked_dotenv_is_explicitly_rejected(self):
        (self.root / '.env').write_text('SYNTHETIC_ONLY=1\n')
        self._git('add', '-f', '.env')
        self._git('commit', '-qm', 'tracked secret fixture')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_sensitive_tracked_path', result.stderr)
        self.assertFalse(self.output.exists())

    def test_tracked_private_key_extension_rejected(self):
        (self.root / 'key.pem').write_text('TEST DUMMY ONLY\n')
        self._git('add', 'key.pem')
        self._git('commit', '-qm', 'dummy key fixture')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_sensitive_tracked_path', result.stderr)

    def test_dirty_source_refused(self):
        (self.root / 'README.md').write_text('changed without commit\n')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_tracked_source_dirty', result.stderr)

    def test_staged_changes_refused(self):
        (self.root / 'README.md').write_text('changed staged\n')
        self._git('add', 'README.md')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_tracked_source_dirty', result.stderr)

    def test_git_checkout_required(self):
        shutil.rmtree(self.root / '.git')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_git_checkout_required', result.stderr)

    def test_symlinked_tracked_content_denied(self):
        target = Path(self.tmp.name) / 'outside.txt'
        target.write_text('dummy external content')
        (self.root / 'external.txt').symlink_to(target)
        self._git('add', 'external.txt')
        self._git('commit', '-qm', 'symlink fixture')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue('release_source_open_failed' in result.stderr or 'release_unsafe_git_tree_entry' in result.stderr)

    def test_skip_worktree_hidden_modification_is_denied(self):
        # Real Git index flags can hide a changed file from `git diff HEAD`.
        (self.root / 'README.md').write_text('FAKE_PRIVATE_KEY=DO_NOT_SHIP\n')
        self._git('update-index', '--skip-worktree', 'README.md')
        self.assertEqual(self._git('diff', '--name-only', 'HEAD'), '')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_tracked_blob_mismatch:README.md', result.stderr)
        self.assertFalse(self.output.exists())

    def test_assume_unchanged_hidden_modification_is_denied(self):
        (self.root / 'README.md').write_text('FAKE_SECRET=DO_NOT_SHIP\n')
        self._git('update-index', '--assume-unchanged', 'README.md')
        self.assertEqual(self._git('diff', '--name-only', 'HEAD'), '')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_tracked_blob_mismatch:README.md', result.stderr)
        self.assertFalse(self.output.exists())

    def test_precreated_predictable_temp_symlink_cannot_clobber_target(self):
        protected = Path(self.tmp.name) / 'protected-canary.txt'
        protected.write_text('UNTOUCHED_CANARY\n')
        vulnerable = self.output.with_name(self.output.name + '.tmp')
        vulnerable.symlink_to(protected)
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(protected.read_text(), 'UNTOUCHED_CANARY\n')
        self.assertEqual(self._verified().returncode, 0)

    def test_metadata_symlink_never_follows_target(self):
        protected = Path(self.tmp.name) / 'outside-canary.txt'
        protected.write_text('UNTOUCHED_CANARY\n')
        (self.root / 'RELEASE_MANIFEST.json').symlink_to(protected)
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_metadata_target_untrusted', result.stderr)
        self.assertEqual(protected.read_text(), 'UNTOUCHED_CANARY\n')
        self.assertFalse(self.output.exists())

    def test_executable_source_retains_executable_mode(self):
        executable = self.root / 'run-check.sh'
        executable.write_text('#!/bin/sh\nprintf ok\n')
        executable.chmod(0o755)
        self._git('add', 'run-check.sh')
        self._git('commit', '-qm', 'tracked executable fixture')
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.output) as archive:
            mode = (archive.getinfo('run-check.sh').external_attr >> 16) & 0o777
            self.assertEqual(mode, 0o755)
        self.assertEqual(self._verified().returncode, 0)

    def test_hardlinked_tracked_source_denied(self):
        external = Path(self.tmp.name) / 'outside.txt'
        external.write_text('hardlink')
        os.link(external, self.root / 'hardlink.txt')
        self._git('add', 'hardlink.txt')
        self._git('commit', '-qm', 'hardlink fixture')
        result = self._build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_unsafe_source_file', result.stderr)

    def test_output_inside_source_denied(self):
        result = self._run('--output', str(self.root / 'release.zip'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_output_must_be_outside_source', result.stderr)

    def test_untrusted_archive_containing_tracked_secret_is_rejected(self):
        self.assertEqual(self._build().returncode, 0)
        def modify(items):
            manifest = json.loads(next(x[1] for x in items if x[0] == 'RELEASE_MANIFEST.json'))
            secret = b'DUMMY_UNSAFE_FILE=not-real-secret\n'
            manifest['files']['.env'] = hashlib.sha256(secret).hexdigest()
            rewritten = []
            for name, data in items:
                if name == 'RELEASE_MANIFEST.json': data = (json.dumps(manifest) + '\n').encode()
                if name == 'SHA256SUMS.txt':
                    data = ''.join(f'{digest}  {f}\n' for f, digest in sorted(manifest['files'].items())).encode()
                rewritten.append((name, data))
            rewritten.append(('.env', secret))
            return rewritten
        self._rewrite_archive(modify)
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_zip_sensitive_member', result.stderr)

    def test_modified_archive_payload_denied(self):
        self.assertEqual(self._build().returncode, 0)
        def modify(items):
            return [(name, b'tampered\n' if name == 'README.md' else data) for name, data in items]
        self._rewrite_archive(modify)
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('file_hash_mismatch', result.stderr)

    def test_duplicate_manifest_keys_denied(self):
        self.assertEqual(self._build().returncode, 0)
        def modify(items):
            revised = []
            for name, data in items:
                if name == 'RELEASE_MANIFEST.json':
                    data = data.replace(b'"signed": false', b'"signed": false, "signed": false')
                revised.append((name, data))
            return revised
        self._rewrite_archive(modify)
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_duplicate_manifest_key', result.stderr)

    def test_oversized_compressed_member_refused_before_decompression(self):
        self.assertEqual(self._build().returncode, 0)
        big = b'X' * (16 * 1024 * 1024 + 1)
        def modify(items):
            manifest = json.loads(next(x[1] for x in items if x[0] == 'RELEASE_MANIFEST.json'))
            manifest['files']['README.md'] = hashlib.sha256(big).hexdigest()
            rewritten = []
            for name, data in items:
                if name == 'README.md': data = big
                if name == 'RELEASE_MANIFEST.json': data = (json.dumps(manifest) + '\n').encode()
                if name == 'SHA256SUMS.txt':
                    data = ''.join(f'{digest}  {f}\n' for f, digest in sorted(manifest['files'].items())).encode()
                rewritten.append((name, data))
            return rewritten
        self._rewrite_archive(modify)
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_zip_member_oversized', result.stderr)

    def test_missing_metadata_refused(self):
        self.assertEqual(self._build().returncode, 0)
        self._rewrite_archive(lambda items: [(name, data) for name, data in items if name != 'SHA256SUMS.txt'])
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release_zip_metadata_missing', result.stderr)

    def test_duplicate_archive_member_refused(self):
        self.assertEqual(self._build().returncode, 0)
        with zipfile.ZipFile(self.output, 'a') as z:
            with self.assertWarns(UserWarning):
                z.writestr('README.md', 'duplicate')
        result = self._verified()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('duplicate_zip_member', result.stderr)


if __name__ == '__main__':
    unittest.main()
