"""Local full package -> verify -> detached signature integration with >16K manifests.

All repositories, keys and ZIPs are synthetic. Nothing touches GitHub or CATL live state.
"""
from __future__ import annotations
import hashlib
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
sys.path.insert(0, str(ROOT / 'tools'))
from release_attest import (MAX_ATTEST_BYTES, MAX_INTERNAL_MANIFEST_BYTES,
                            _read_unique_json, keygen, sign, verify, validate_release_zip)

VERSION = '0.11.0rc1'


class ReleaseToAttestationCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = tempfile.TemporaryDirectory(prefix='catl-end-to-end-', dir=('/root' if os.geteuid()==0 else Path.home()))
        cls.root = Path(cls.t.name)
        cls.repo = cls.root/'repo'
        cls.repo.mkdir()
        (cls.repo/'tools').mkdir()
        shutil.copy2(ROOT/'tools'/'release_pack.py', cls.repo/'tools'/'release_pack.py')
        (cls.repo/'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion = "0.11.0rc1"\n')
        for i in range(180):
            folder=cls.repo/'docs'; folder.mkdir(exist_ok=True)
            (folder/f'evidence-{i:03}.md').write_text(f'Test-only CATL document {i:03} with unique data\n')
        cls.env = {**os.environ,
                   'GIT_AUTHOR_NAME':'CATL local fixture', 'GIT_AUTHOR_EMAIL':'fixture@example.invalid',
                   'GIT_COMMITTER_NAME':'CATL local fixture', 'GIT_COMMITTER_EMAIL':'fixture@example.invalid'}
        def git(*args):
            return subprocess.run(['git',*args],cwd=cls.repo,env=cls.env,
                                  check=True,capture_output=True,text=True).stdout.strip()
        git('init','-q');git('add','.');git('commit','-qm','fixture')
        cls.commit = git('rev-parse','HEAD')
        cls.zip = cls.root/'built.zip'
        proc=subprocess.run([sys.executable,'tools/release_pack.py','--output',str(cls.zip)],
                            cwd=cls.repo,env=cls.env,capture_output=True,text=True)
        if proc.returncode:
            raise AssertionError(f'package construction failed: {proc.stderr}')
        cls.manifest_size=(cls.repo/'RELEASE_MANIFEST.json').stat().st_size
        cls.private=cls.root/'signing.pem'
        cls.public=cls.root/'signing-public.hex'
        cls.pin=keygen(cls.private, cls.public)['public_key_fingerprint_sha256']
        cls.signature=cls.root/'attestation.json'
        sign(cls.zip,cls.private,cls.signature,source_commit=cls.commit,version=VERSION)

    @classmethod
    def tearDownClass(cls):
        cls.t.cleanup()

    def trusted_verification(self, archive=None, signature=None, **changes):
        opts={'expected_public_key_fingerprint':self.pin,
              'expected_commit':self.commit,'expected_version':VERSION}
        opts.update(changes)
        return verify(archive or self.zip,signature or self.signature,self.public,**opts)

    def test_actual_builder_emits_larger_than_sixteen_k_manifest(self):
        self.assertGreater(self.manifest_size, MAX_ATTEST_BYTES)
        self.assertLess(self.manifest_size, MAX_INTERNAL_MANIFEST_BYTES)

    def test_manifest_commit_matches_the_actual_git_head(self):
        with zipfile.ZipFile(self.zip) as archive:
            manifest=json.loads(archive.read('RELEASE_MANIFEST.json'))
        self.assertEqual(manifest['source_commit'], self.commit)

    def test_source_commit_mismatch_fails_during_signing(self):
        with self.assertRaisesRegex(ValueError, 'claimed_commit_mismatches_embedded_source_commit'):
            sign(self.zip,self.private,self.root/'mismatched-attestation.json',
                 source_commit='b'*40,version=VERSION)
        self.assertFalse((self.root/'mismatched-attestation.json').exists())

    def test_complete_zip_sign_verify_happy_path(self):
        self.assertGreaterEqual(validate_release_zip(self.zip)['verified_members'],180)
        verified=self.trusted_verification()
        self.assertTrue(verified['passed'])
        self.assertEqual(verified['source_commit'],self.commit)
        self.assertEqual(verified['members'],validate_release_zip(self.zip)['verified_members'])

    def test_detached_signature_still_uses_small_fixed_document(self):
        self.assertLess(self.signature.stat().st_size,MAX_ATTEST_BYTES)
        with self.assertRaisesRegex(ValueError, 'attestation_oversized'):
            _read_unique_json(b'{"padding":"'+b'X'*MAX_ATTEST_BYTES+b'"}')

    def test_signed_wrong_commit_and_pin_refused(self):
        for option in ({'expected_commit':'b'*40},
                       {'expected_public_key_fingerprint':'0'*64},
                       {'expected_version':'0.11.0rc2'}):
            with self.subTest(option=option),self.assertRaises(ValueError):
                self.trusted_verification(**option)

    def test_mutated_zip_refused_without_changing_original(self):
        tampered=self.root/'tampered.zip'
        shutil.copyfile(self.zip,tampered)
        with zipfile.ZipFile(tampered,'a') as z:
            z.writestr('unexpected.bin',b'not in signed manifest')
        with self.assertRaises(ValueError):self.trusted_verification(archive=tampered)
        self.assertTrue(self.trusted_verification()['passed'])

    def test_bad_signature_refused(self):
        tampered=self.root/'bad-signature.json'
        document=json.loads(self.signature.read_text())
        document['signature_hex']='0'*128
        tampered.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError,'signature_invalid'):
            self.trusted_verification(signature=tampered)

    def test_oversized_internal_manifest_rejected(self):
        oversize=self.root/'too-large.zip'
        with zipfile.ZipFile(oversize,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('README.md',os.urandom(1024))
            z.writestr('RELEASE_MANIFEST.json',os.urandom(MAX_INTERNAL_MANIFEST_BYTES+1))
            z.writestr('SHA256SUMS.txt',b'empty\n')
        with self.assertRaisesRegex(ValueError,'internal_release_metadata_oversized'):
            validate_release_zip(oversize)

    def test_sha256_git_object_format_round_trips_through_attestation(self):
        repo=self.root/'sha256-repo'
        repo.mkdir(exist_ok=True)
        (repo/'tools').mkdir(exist_ok=True)
        shutil.copy2(ROOT/'tools'/'release_pack.py',repo/'tools'/'release_pack.py')
        (repo/'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        (repo/'README.md').write_text('SHA-256 object format fixture\n')
        def git(*args):
            return subprocess.run(['git',*args],cwd=repo,env=self.env,capture_output=True,text=True,check=True).stdout.strip()
        try:
            git('init','-q','--object-format=sha256')
        except subprocess.CalledProcessError:
            self.skipTest('git SHA256 repository format unavailable')
        git('add','.');git('commit','-qm','fixture')
        commit=git('rev-parse','HEAD')
        self.assertEqual(len(commit),64)
        packed=self.root/'sha256-repo.zip'
        proc=subprocess.run([sys.executable,'tools/release_pack.py','--output',str(packed)],
                            cwd=repo,env=self.env,capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stderr)
        signature=self.root/'sha256-attestation.json'
        sign(packed,self.private,signature,source_commit=commit,version=VERSION)
        result=verify(packed,signature,self.public,expected_public_key_fingerprint=self.pin,
                      expected_commit=commit,expected_version=VERSION)
        self.assertTrue(result['passed'])

    def test_signer_rejects_self_consistent_secret_forged_zip(self):
        for name in ('.env','backups/secrets.toml','keys/dev.pem','nested/.npmrc'):
            with self.subTest(name=name):
                forged=self.root/('forged-'+str(abs(hash(name)))+'.zip')
                with zipfile.ZipFile(self.zip) as original:
                    manifest=json.loads(original.read('RELEASE_MANIFEST.json'))
                    payload=b'SYNTHETIC_ONLY_NOT_A_REAL_SECRET=1\n'
                    manifest['files'][name]=hashlib.sha256(payload).hexdigest()
                    sums=''.join(f'{digest}  {filename}\n' for filename,digest in sorted(manifest['files'].items())).encode()
                    with zipfile.ZipFile(forged,'w',compression=zipfile.ZIP_DEFLATED) as output:
                        for member in original.infolist():
                            data=original.read(member)
                            if member.filename=='RELEASE_MANIFEST.json':
                                data=(json.dumps(manifest,sort_keys=True)+'\n').encode()
                            elif member.filename=='SHA256SUMS.txt':
                                data=sums
                            output.writestr(member,data)
                        output.writestr(name,payload)
                with self.assertRaisesRegex(ValueError,'release_contains_sensitive_member'):
                    validate_release_zip(forged)

    def test_bad_sha256sums_rejected(self):
        corrupted=self.root/'bad-sums.zip'
        with zipfile.ZipFile(self.zip) as original, zipfile.ZipFile(corrupted,'w',compression=zipfile.ZIP_DEFLATED) as output:
            for info in original.infolist():
                content=original.read(info)
                if info.filename=='SHA256SUMS.txt':content=b'bad\n'
                output.writestr(info,content)
        with self.assertRaisesRegex(ValueError,'invalid_internal_sha256sums'):
            validate_release_zip(corrupted)


if __name__=='__main__':unittest.main()
