"""CATL v9: reject untrusted writers within verified evidence path."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[1]/'src'/'catl'/'verifier.py'
spec=importlib.util.spec_from_file_location('catl_v9_verifier',MODULE)
verifier=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=verifier
spec.loader.exec_module(verifier)

class WriteBoundaryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base=Path(t.name)
        self.root=self.base/'reports'
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.payload=b'public-output'
        self.expected=hashlib.sha256(self.payload).hexdigest()
        self.config={'kind':'file_sha256','root':str(self.root),
                     'path_pointer':'/path','digest_pointer':'/digest'}
        self.args={'path':'output.txt','digest':self.expected}
    def model(self):return verifier.FileDigestVerifier.from_dict(self.config)
    def test_private_workflow_allowed(self):
        (self.root/'output.txt').write_bytes(self.payload)
        self.assertTrue(self.model().verify(self.args)['verified'])
    def test_group_writable_root_rejected_before_dispatch(self):
        self.root.chmod(0o770)
        with self.assertRaisesRegex((PermissionError,ValueError),'(writable|untrusted|permissions)'):
            self.model().preflight(self.args)
    def test_world_writable_root_rejected_before_dispatch(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex((PermissionError,ValueError),'(writable|untrusted|permissions)'):
            self.model().preflight(self.args)
    def test_group_writable_parent_rejected_before_dispatch(self):
        p=self.root/'nested';p.mkdir();p.chmod(0o770)
        self.args['path']='nested/output.txt'
        with self.assertRaisesRegex((PermissionError,ValueError),'(writable|untrusted|permissions)'):
            self.model().preflight(self.args)
    def test_world_writable_existing_target_rejected_before_dispatch(self):
        p=self.root/'output.txt';p.write_bytes(self.payload);p.chmod(0o666)
        with self.assertRaisesRegex((PermissionError,ValueError),'(writable|untrusted|permissions)'):
            self.model().preflight(self.args)
    def test_post_dispatch_target_chmod_rejected(self):
        p=self.root/'output.txt';p.write_bytes(self.payload)
        m=self.model()
        orig=verifier.os.read
        altered=[False]
        def flip(fd,n):
            data=orig(fd,n)
            if data and not altered[0]:
                altered[0]=True
                p.chmod(0o666)
            return data
        with patch.object(verifier.os,'read',side_effect=flip):
            with self.assertRaisesRegex((PermissionError,ValueError),'(changed|writable|permissions)'):
                m.verify(self.args)
        self.assertTrue(altered[0])
    def test_private_nested_target_allowed(self):
        p=self.root/'nested';p.mkdir(mode=0o700)
        (p/'output.txt').write_bytes(self.payload)
        self.args['path']='nested/output.txt'
        self.assertTrue(self.model().verify(self.args)['verified'])

if __name__=='__main__':unittest.main()

class PermissionRaceTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base=Path(t.name)
        self.root=self.base/'protected'; self.root.mkdir(); self.root.chmod(0o700)
        self.nested=self.root/'nested';self.nested.mkdir();self.nested.chmod(0o700)
        self.target=self.nested/'record.txt';self.target.write_bytes(b'validated')
        self.arg={'path':'nested/record.txt','digest':hashlib.sha256(b'validated').hexdigest()}
        self.v=verifier.FileDigestVerifier.from_dict({'kind':'file_sha256',
            'root':str(self.root),'path_pointer':'/path','digest_pointer':'/digest'})

    def test_root_chmod_during_file_read_rejected(self):
        orig=verifier.os.read
        hit=[False]
        def attack(fd,n):
            data=orig(fd,n)
            if data and not hit[0]:
                hit[0]=True
                self.root.chmod(0o777)
            return data
        with patch.object(verifier.os,'read',side_effect=attack):
            with self.assertRaisesRegex(ValueError,'postcondition_evidence_writable_by_untrusted'):
                self.v.verify(self.arg)
        self.assertTrue(hit[0])

    def test_subdir_chmod_during_file_read_rejected(self):
        orig=verifier.os.read
        hit=[False]
        def attack(fd,n):
            data=orig(fd,n)
            if data and not hit[0]:
                hit[0]=True
                self.nested.chmod(0o777)
            return data
        with patch.object(verifier.os,'read',side_effect=attack):
            with self.assertRaisesRegex(ValueError,'postcondition_evidence_writable_by_untrusted'):
                self.v.verify(self.arg)
        self.assertTrue(hit[0])

    def test_subdir_chmod_after_preflight_rejected(self):
        orig=verifier.os.open
        hit=[False]
        def attack(path,flags,*args,**kwargs):
            fd=orig(path,flags,*args,**kwargs)
            if str(path)=='nested' and not hit[0]:
                hit[0]=True
                self.nested.chmod(0o777)
            return fd
        with patch.object(verifier.os,'open',side_effect=attack):
            with self.assertRaisesRegex(ValueError,'postcondition_evidence_writable_by_untrusted'):
                self.v.verify(self.arg)
        self.assertTrue(hit[0])

class PreDispatchRootPinTests(unittest.TestCase):
    def test_replaced_approved_root_refused_before_backend_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            root=base/'approved'; root.mkdir(mode=0o700)
            original=verifier.FileDigestVerifier.from_dict({'kind':'file_sha256',
                'root':str(root),'path_pointer':'/path','digest_pointer':'/sha256'})
            root.rename(base/'formerly-approved')
            root.mkdir(mode=0o700)
            args={'path':'output.txt','sha256':hashlib.sha256(b'x').hexdigest()}
            with self.assertRaisesRegex(ValueError,'postcondition_root_replaced'):
                original.preflight(args)
