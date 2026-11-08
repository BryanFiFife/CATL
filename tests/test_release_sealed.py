"""Offline adversarial tests for required source-equivalence before release signing.

A disposable Ed25519 signer simulates the release_attest API. These tests
validate gating/wiring, not the upstream release_attest implementation itself.
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
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from release_sealed import ReleaseGateDenied, sign_checked, verify_checked

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ENV = {**os.environ, 'GIT_AUTHOR_NAME': 'CATL offline lab',
       'GIT_AUTHOR_EMAIL': 'test@example.invalid',
       'GIT_COMMITTER_NAME': 'CATL offline lab',
       'GIT_COMMITTER_EMAIL': 'test@example.invalid'}


def _sha_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class FakeAttestation(types.ModuleType):
    """In-process replacement with real Ed25519 cryptography, not upstream code."""
    def __init__(self):
        super().__init__('release_attest')
        self.events=[]
        self.after_sign=None

    def _public_key(self, path):
        raw = bytes.fromhex(Path(path).read_text().strip())
        return Ed25519PublicKey.from_public_bytes(raw),hashlib.sha256(raw).hexdigest()

    def sign(self, archive, private, output, *, source_commit, version):
        self.events.append('sign')
        key=serialization.load_pem_private_key(Path(private).read_bytes(),password=None)
        payload={'commit':source_commit,'version':version,'sha256':_sha_file(archive)}
        body=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
        signed={'payload':payload,'signature':key.sign(body).hex()}
        Path(output).write_text(json.dumps(signed))
        Path(output).chmod(0o600)
        if self.after_sign is not None:
            self.after_sign(archive, output)

    def verify(self, archive, attestation, public, *, expected_public_key_fingerprint, expected_commit, expected_version):
        self.events.append('verify')
        pub, pin=self._public_key(public)
        if pin!=expected_public_key_fingerprint:
            raise ValueError('key_pin_mismatch')
        signed=json.loads(Path(attestation).read_text())
        payload=signed['payload']
        if payload != {'commit':expected_commit,'version':expected_version,'sha256':_sha_file(archive)}:
            raise ValueError('signature_payload_mismatch')
        body=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
        pub.verify(bytes.fromhex(signed['signature']),body)
        return {'zip_sha256':payload['sha256'],'source_commit':payload['commit'],'version':payload['version']}


class SealedReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='catl-sealed-release-', dir=str(Path.home()))
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.repo=self.home/'repo';self.repo.mkdir()
        (self.repo/'tools').mkdir()
        for tool in ('release_pack.py','verify_source_artifact.py','release_sealed.py'):
            shutil.copy2(ROOT/'tools'/tool,self.repo/'tools'/tool)
        (self.repo/'tools'/'release_attest.py').write_text('# upstream signer API stub for fixture; test double is injected\n')
        (self.repo/'README.md').write_text('CATL test fixture\n')
        (self.repo/'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        for command in (('init','-q'),('add','.'),('commit','-qm','fixture')):
            subprocess.run(['git',*command],cwd=self.repo,env=ENV,check=True,capture_output=True)
        self.commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.repo).decode().strip()
        self.archive=self.home/'archive.zip'
        build=subprocess.run([sys.executable,str(self.repo/'tools'/'release_pack.py'),
                              '--output',str(self.archive)],cwd=self.repo,env=ENV,text=True,capture_output=True)
        self.assertEqual(build.returncode,0,build.stderr)
        self.private_dir=self.home/'private';self.private_dir.mkdir(mode=0o700)
        self.private=self.private_dir/'key.pem';self.public=self.private_dir/'public.hex'
        key=Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.public.write_text(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()+'\n')
        self.pin=hashlib.sha256(bytes.fromhex(self.public.read_text().strip())).hexdigest()
        self.signature=self.private_dir/'signed.json'
        self.fake=FakeAttestation()
        module=patch.dict(sys.modules,{'release_attest':self.fake})
        module.start();self.addCleanup(module.stop)
        self.common=dict(archive=self.archive,checkout=self.repo,reviewed_commit=self.commit,
                         public_key=self.public,expected_key_fingerprint=self.pin,version='0.11.0rc1')

    def sign(self, **kw):
        args=dict(self.common,private_key=self.private,output=self.signature)
        args.update(kw)
        return sign_checked(**args)

    def verify(self, **kw):
        args=dict(self.common,attestation=self.signature)
        args.update(kw)
        return verify_checked(**args)

    def test_valid_source_binding_sign_then_verify(self):
        signed=self.sign()
        self.assertTrue(signed['passed']);self.assertEqual(signed['commit'],self.commit)
        self.assertEqual(self.fake.events,['sign','verify'])
        self.assertTrue(self.verify()['passed'])
        self.assertEqual(self.fake.events,['sign','verify','verify'])

    def test_wrong_reviewed_commit_denied_before_sign(self):
        with self.assertRaises(ReleaseGateDenied):self.sign(reviewed_commit='0'*40)
        self.assertEqual(self.fake.events,[])
        self.assertFalse(self.signature.exists())

    def test_missing_or_invalid_commit_denied(self):
        for commit in ('','HEAD','a'*39,'a'*65):
            with self.subTest(commit=commit):
                with self.assertRaises(ReleaseGateDenied):self.sign(reviewed_commit=commit)
        self.assertEqual(self.fake.events,[])

    def test_wrong_public_key_pin_denied_before_sign(self):
        with self.assertRaises(ReleaseGateDenied):self.sign(expected_key_fingerprint='a'*64)
        self.assertEqual(self.fake.events,[])

    def test_missing_public_key_pin_denied(self):
        with self.assertRaises(ReleaseGateDenied):self.sign(expected_key_fingerprint='')
        self.assertEqual(self.fake.events,[])

    def test_modified_archive_denied_even_with_integral_zip(self):
        self.archive.write_bytes(self.archive.read_bytes()+b'UNLISTED PAYLOAD')
        with self.assertRaises(ValueError):self.sign()
        self.assertEqual(self.fake.events,[])

    def test_output_inside_checkout_denied(self):
        with self.assertRaises(ReleaseGateDenied):self.sign(output=self.repo/'attestation.json')

    def test_output_in_world_writable_directory_denied(self):
        with self.assertRaises(ReleaseGateDenied):self.sign(output=Path('/tmp')/'catl-public-attestation-lab.json')

    def test_archive_from_world_writable_directory_denied(self):
        alt=Path('/tmp') / ('catl-untrusted-' + self.commit[:12] + '.zip')
        # Unit test does not need to create any file in a shared directory;
        # the trust check rejects the parent before opening a public archive.
        if alt.exists(): self.skipTest('path already exists in shared /tmp')
        shutil.copy2(self.archive, alt)
        self.addCleanup(lambda:alt.unlink(missing_ok=True))
        with self.assertRaises(ReleaseGateDenied):self.sign(archive=alt)
        self.assertEqual(self.fake.events,[])

    def test_private_signer_key_inside_checkout_denied(self):
        moved=self.repo/'operator.pem'
        shutil.copy2(self.private,moved)
        moved.chmod(0o600)
        with self.assertRaises(ReleaseGateDenied):self.sign(private_key=moved)
        self.assertEqual(self.fake.events,[])

    def test_archive_symlink_parent_denied(self):
        sym=self.home/'archive-link';sym.symlink_to(self.home,target_is_directory=True)
        with self.assertRaises(ReleaseGateDenied):self.sign(archive=sym/'archive.zip')
        self.assertEqual(self.fake.events,[])

    def test_existing_attestation_not_overwritten(self):
        self.signature.write_text('already exists')
        with self.assertRaises(ReleaseGateDenied):self.sign()
        self.assertEqual(self.signature.read_text(),'already exists')

    def test_symlink_output_parent_denied(self):
        sym=self.home/'symlink';sym.symlink_to(self.private_dir,target_is_directory=True)
        with self.assertRaises(ReleaseGateDenied):self.sign(output=sym/'signed.json')

    def test_dirty_signing_tool_denied_before_sign(self):
        signer=self.repo/'tools'/'release_attest.py'
        signer.write_text(signer.read_text() + '# injected backdoor\n')
        with self.assertRaisesRegex(ReleaseGateDenied, 'signing_tool_source_modified'):
            self.sign()
        self.assertEqual(self.fake.events, [])

    def test_dirty_release_gate_denied_even_with_git_skip_worktree(self):
        gate=self.repo/'tools'/'release_sealed.py'
        subprocess.run(['git', 'update-index', '--skip-worktree', 'tools/release_sealed.py'],
                       cwd=self.repo, check=True, capture_output=True)
        gate.write_text(gate.read_text() + '# tampered while skip-worktree\n')
        with self.assertRaisesRegex(ReleaseGateDenied, 'signing_tool_source_modified'):
            self.sign()
        self.assertEqual(self.fake.events, [])

    def test_wrong_signature_or_mutated_archive_denied(self):
        self.sign()
        signed=json.loads(self.signature.read_text());signed['signature']='0'*128
        self.signature.write_text(json.dumps(signed))
        with self.assertRaises(Exception):self.verify()

    def test_source_changes_during_signing_cleans_up_signature(self):
        self.fake.after_sign=lambda archive,_out: archive.write_bytes(archive.read_bytes()+b'evil')
        with self.assertRaises(Exception):self.sign()
        self.assertFalse(self.signature.exists())

    def test_signer_world_readable_attestation_is_refused_and_cleaned(self):
        self.fake.after_sign=lambda _archive,out:Path(out).chmod(0o644)
        with self.assertRaisesRegex(ReleaseGateDenied, 'signed_attestation_output_untrusted'):
            self.sign()
        self.assertFalse(self.signature.exists())

    def test_signer_failure_after_writing_cleans_up_signature(self):
        def raise_after(_archive,_out):
            raise RuntimeError('interrupted after signature written')
        self.fake.after_sign=raise_after
        with self.assertRaises(RuntimeError):self.sign()
        self.assertFalse(self.signature.exists())

    def test_verified_signed_archive_must_still_match_git(self):
        self.sign()
        self.archive.write_bytes(self.archive.read_bytes()+b'extra')
        with self.assertRaises(ValueError):self.verify()

    def test_wrong_attestation_key_denied(self):
        self.sign()
        other=Ed25519PrivateKey.generate()
        self.public.write_text(other.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())
        with self.assertRaises(ReleaseGateDenied):self.verify()

    def test_signer_cannot_be_reached_with_malicious_output_path(self):
        self.private_dir.chmod(0o777)
        self.addCleanup(lambda:self.private_dir.chmod(0o700))
        with self.assertRaises(ReleaseGateDenied):self.sign()
        self.assertEqual(self.fake.events,[])

    def test_sha256_format_git_repository_sign_and_verify(self):
        shutil.rmtree(self.repo/'.git')
        for command in (('init','-q','--object-format=sha256'),('add','.'),('commit','-qm','sha256 fixture')):
            subprocess.run(['git',*command],cwd=self.repo,env=ENV,check=True,capture_output=True)
        sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.repo).decode().strip()
        self.assertEqual(len(sha),64)
        self.common['reviewed_commit']=sha
        build=subprocess.run([sys.executable,str(self.repo/'tools'/'release_pack.py'),
                              '--output',str(self.archive)],cwd=self.repo,env=ENV,text=True,capture_output=True)
        self.assertEqual(build.returncode,0,build.stderr)
        self.assertTrue(self.sign()['passed'])
        self.assertTrue(self.verify()['passed'])

    def test_missing_signer_source_refused_before_any_signing(self):
        (self.repo/'tools'/'release_attest.py').unlink()
        with self.assertRaises(ReleaseGateDenied):self.sign()
        self.assertEqual(self.fake.events,[])

    def test_unpinned_archive_source_commit_rejected(self):
        # All claims must be bound to separately supplied Git object ID.
        self.sign()
        with self.assertRaises(ReleaseGateDenied):self.verify(reviewed_commit='f'*40)

if __name__=='__main__':unittest.main()
