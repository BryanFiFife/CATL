"""Mutation-based ZIP-envelope sanity check without network or secrets."""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from release_pack import verify

ENV = {**os.environ, 'GIT_AUTHOR_NAME': 'CATL local acceptance',
       'GIT_AUTHOR_EMAIL': 'offline@example.invalid',
       'GIT_COMMITTER_NAME': 'CATL local acceptance',
       'GIT_COMMITTER_EMAIL': 'offline@example.invalid'}

class ArchiveHeaderMutations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='catl-zip-mutation-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        (self.root / 'tools').mkdir(parents=True)
        shutil.copy2(ROOT / 'tools' / 'release_pack.py', self.root / 'tools' / 'release_pack.py')
        (self.root / 'README.md').write_text('original signed payload\n')
        (self.root / 'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        for cmd in (['init', '-q'], ['add', '.'], ['commit', '-qm', 'baseline']):
            subprocess.run(['git', *cmd], cwd=self.root, check=True, capture_output=True, env=ENV)
        self.output = Path(self.tmp.name) / 'verified.zip'
        result = subprocess.run([sys.executable, str(self.root / 'tools/release_pack.py'),
                                 '--output', str(self.output)], cwd=self.root,
                                env=ENV, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.blob = self.output.read_bytes()
        with zipfile.ZipFile(self.output) as z:
            self.central_offset = z.start_dir
            self.first_member = z.infolist()[0]

    def test_mutation_of_local_central_and_eocd_headers_is_detected(self):
        self.assertEqual(verify(self.output), 5)
        positions = (list(range(self.first_member.header_offset, self.first_member.header_offset + 30)) +
                     list(range(self.central_offset, self.central_offset + 46)) +
                     list(range(len(self.blob) - 22, len(self.blob))))
        self.assertEqual(len(positions), 98)
        for position in positions:
            with self.subTest(offset=position):
                attack = bytearray(self.blob)
                attack[position] ^= 0x01
                self.output.write_bytes(attack)
                try:
                    with self.assertRaises((ValueError, OSError, zipfile.BadZipFile, EOFError,
                                            RuntimeError, UnicodeError)):
                        verify(self.output)
                finally:
                    self.output.write_bytes(self.blob)

if __name__ == '__main__':
    unittest.main()
