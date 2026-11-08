"""Adversarial tests for unindexed bytes inside otherwise self-consistent release ZIPs.

No network and no real signing keys. Every fixture uses disposable tracked source.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

PACK = Path(__file__).resolve().parents[1] / 'tools' / 'release_pack.py'
ENV = {**os.environ, 'GIT_AUTHOR_NAME': 'CATL local acceptance',
       'GIT_AUTHOR_EMAIL': 'offline@example.invalid',
       'GIT_COMMITTER_NAME': 'CATL local acceptance',
       'GIT_COMMITTER_EMAIL': 'offline@example.invalid'}

class ZipEnvelopeAttacks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='catl-zip-envelope-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        (self.root / 'tools').mkdir(parents=True)
        shutil.copyfile(PACK, self.root / 'tools' / 'release_pack.py')
        (self.root / 'README.md').write_text('clean source\n')
        (self.root / 'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        self.output = Path(self.tmp.name) / 'release.zip'
        for argv in (['init', '-q'], ['add', '.'], ['commit', '-qm', 'baseline']):
            subprocess.run(['git', *argv], cwd=self.root, env=ENV, check=True, capture_output=True)
        self.assertEqual(self.command('--output', str(self.output)).returncode, 0)
        self.original = self.output.read_bytes()

    def command(self, *argv):
        return subprocess.run([sys.executable, str(self.root / 'tools' / 'release_pack.py'), *argv],
                              capture_output=True, text=True, env=ENV, timeout=20)

    def refuse(self, raw, reason):
        self.output.write_bytes(raw)
        verdict = self.command('--verify', str(self.output))
        self.assertNotEqual(verdict.returncode, 0, f'{reason} was accepted: {verdict.stdout}')

    def test_unmodified_archive_valid(self):
        result = self.command('--verify', str(self.output))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_script_zip_preamble_denied(self):
        self.refuse(b'#!/bin/sh\necho "not part of release"\n' + self.original,
                    'executable ZIP polyglot preamble')

    def test_unlisted_archive_trailer_denied(self):
        self.refuse(self.original + b'EXTRA_UNTRACKED_DATA_NOT_IN_MANIFEST',
                    'trailing unindexed data')

    def test_zip_global_comment_denied(self):
        with zipfile.ZipFile(self.output, 'a') as z:
            z.comment = b'NON_MANIFEST_PAYLOAD'
        self.refuse(self.output.read_bytes(), 'archive comment')

    def test_file_comment_denied(self):
        self.rewrite(lambda info: setattr(info, 'comment', b'UNINDEXED_FILE_COMMENT') if info.filename == 'README.md' else None)
        self.refuse(self.output.read_bytes(), 'file comment')

    def test_file_extra_field_denied(self):
        def put_extra(info):
            if info.filename == 'README.md':
                info.extra = b'\xfe\xca\x02\x00ZZ'
        self.rewrite(put_extra)
        self.refuse(self.output.read_bytes(), 'filename extra field')

    def test_header_filename_conflict_denied(self):
        marker = b'README.md'
        self.assertIn(marker, self.original)
        self.output.write_bytes(self.original.replace(marker, b'README.tx', 1))
        self.refuse(self.output.read_bytes(), 'conflicting local-vs-central filename')

    def test_local_header_gap_denied(self):
        # Insert an unindexed byte between the first local entry and next, while
        # retaining the archive tail. Python normally tolerates some gaps.
        with zipfile.ZipFile(self.output) as z:
            members = z.infolist()
            self.assertGreater(len(members), 1)
            boundary = members[1].header_offset
        raw = self.original[:boundary] + b'X' + self.original[boundary:]
        self.refuse(raw, 'unindexed hidden byte between members')

    def test_modified_checksum_payload_still_denied(self):
        # A valid signature must never be issued on an envelope with hidden
        # bytes even when ALL listed archive member hashes remain correct.
        self.refuse(b'#!/bin/sh\nexit 0\n' + self.original, 'valid-manifest polyglot')

    def test_hidden_bytes_inside_valid_deflate_member_denied(self):
        """A hidden suffix still passes Python zipfile and all extracted hashes."""
        import struct
        raw = bytearray(self.original)
        with zipfile.ZipFile(self.output) as z:
            members = z.infolist()
            last = max(members, key=lambda i: i.header_offset)
            directory_start = z.start_dir
        name_bytes = struct.unpack_from('<H', raw, last.header_offset + 26)[0]
        extra_bytes = struct.unpack_from('<H', raw, last.header_offset + 28)[0]
        end_of_last = (last.header_offset + 30 + name_bytes + extra_bytes + last.compress_size)
        self.assertEqual(end_of_last, directory_start)
        directory = bytearray(raw[directory_start:-22])
        central = 0
        while central < len(directory):
            self.assertEqual(directory[central:central + 4], b'PK\x01\x02')
            nlen, elen, clen = struct.unpack_from('<HHH', directory, central + 28)
            filename = directory[central + 46:central + 46 + nlen].decode('utf-8')
            if filename == last.filename:
                break
            central += 46 + nlen + elen + clen
        self.assertEqual(filename, last.filename)
        hidden = b'HIDDEN_PAYLOAD_AFTER_DEFLATE_END'
        struct.pack_into('<I', raw, last.header_offset + 18, last.compress_size + len(hidden))
        struct.pack_into('<I', directory, central + 20, last.compress_size + len(hidden))
        eocd = bytearray(raw[-22:])
        struct.pack_into('<I', eocd, 16, directory_start + len(hidden))
        forged = bytes(raw[:directory_start]) + hidden + bytes(directory) + bytes(eocd)
        self.output.write_bytes(forged)
        # The built-in ZIP parser accepts the manipulated archive and exposes
        # precisely the original source, so hash-only verification is unsafe.
        with zipfile.ZipFile(self.output) as z:
            self.assertTrue(z.read(last.filename))
        self.refuse(forged, 'deflate suffix hidden inside member compressed_size')

    def test_recomputed_checksums_cannot_add_excluded_source_members(self):
        import hashlib
        import json
        import stat
        for injected in ('.git/hooks/post-checkout', 'build/installer.py',
                         '__pycache__/sitecustomize.pyc', '.pytest_cache/source.py',
                         'dist/evil.whl'):
            with self.subTest(injected=injected):
                self.output.write_bytes(self.original)
                with zipfile.ZipFile(self.output) as z:
                    files = {name: z.read(name) for name in z.namelist()
                             if name not in ('RELEASE_MANIFEST.json', 'SHA256SUMS.txt')}
                    manifest = json.loads(z.read('RELEASE_MANIFEST.json'))
                files[injected] = b'TEST DATA NOT FOR DISTRIBUTION\n'
                manifest['files'] = {name: hashlib.sha256(data).hexdigest()
                                     for name, data in files.items()}
                files['RELEASE_MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
                files['SHA256SUMS.txt'] = ''.join(
                    f'{digest}  {name}\n' for name, digest in sorted(manifest['files'].items())).encode()
                with zipfile.ZipFile(self.output, 'w', compression=zipfile.ZIP_DEFLATED) as z:
                    for name, data in sorted(files.items()):
                        item = zipfile.ZipInfo(name, date_time=(2026, 11, 7, 0, 0, 0))
                        item.compress_type = zipfile.ZIP_DEFLATED
                        item.external_attr = (stat.S_IFREG | 0o644) << 16
                        z.writestr(item, data)
                self.refuse(self.output.read_bytes(), 'forged tracked-source-excluded path')

    def test_canonical_zip_metadata_rejects_os_attribute_and_timestamp_changes(self):
        with zipfile.ZipFile(self.output) as z:
            directory_offset = z.start_dir
            first = z.infolist()[0]
            self.assertEqual(first.create_system, 3)
            self.assertEqual(first.date_time, (2026, 11, 7, 0, 0, 0))
        # All three changes leave the extracted contents AND their SHA hashes
        # untouched. They must not survive canonical release verification.
        for label, offset, value in (
                ('foreign creator operating system', directory_offset + 5, 0),
                ('noncanonical central internal attributes', directory_offset + 36, 12),
                ('noncanonical DOS external attributes', directory_offset + 38, 99),
                ('local-header date/time mismatch', first.header_offset + 10, 99)):
            with self.subTest(label=label):
                forged = bytearray(self.original)
                forged[offset] = value
                self.refuse(bytes(forged), label)

    def rewrite(self, amend_info):
        with zipfile.ZipFile(self.output) as z:
            entries = [(info, z.read(info.filename)) for info in z.infolist()]
        with zipfile.ZipFile(self.output, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for info, content in entries:
                amend_info(info)
                z.writestr(info, content)

if __name__ == '__main__':
    unittest.main()
