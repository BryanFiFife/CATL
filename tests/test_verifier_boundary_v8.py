"""CATL v8 postcondition verifier regression against authentic source blob."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('catl_v8_verifier', ROOT/'src'/'catl'/'verifier.py')
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class VerifierBoundaryV8(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.allowed = self.base/'allowed'; self.allowed.mkdir()
        self.verifier = mod.FileDigestVerifier.from_dict({'kind':'file_sha256','root':str(self.allowed),
                    'path_pointer':'/path','digest_pointer':'/hash'})

    @staticmethod
    def digest(data:bytes)->str:
        return hashlib.sha256(data).hexdigest()

    def call(self,path:str,content:bytes):
        return self.verifier.verify({'path':path, 'hash':self.digest(content)})

    def test_regular_file_verifies(self):
        (self.allowed/'report.txt').write_bytes(b'good record')
        r=self.call('report.txt',b'good record')
        self.assertTrue(r['verified'])
        self.assertEqual(r['bytes'],11)

    def test_bad_digest_returns_not_verified(self):
        (self.allowed/'report.txt').write_bytes(b'wrong')
        self.assertFalse(self.call('report.txt',b'expected')['verified'])

    def test_nested_file_verifies(self):
        (self.allowed/'sub').mkdir()
        (self.allowed/'sub'/'report.txt').write_bytes(b'hello')
        self.assertTrue(self.call('sub/report.txt',b'hello')['verified'])

    @unittest.skipUnless(hasattr(os,'link'), 'hardlinks required')
    def test_outside_hardlink_denied(self):
        outside=self.base/'confidential'; outside.write_bytes(b'known data')
        os.link(outside,self.allowed/'record.txt')
        with self.assertRaisesRegex(ValueError,'postcondition_file_hardlinked'):
            self.call('record.txt',b'known data')

    @unittest.skipUnless(hasattr(os,'link'), 'hardlinks required')
    def test_inner_hardlink_denied(self):
        original=self.allowed/'one.txt'; original.write_bytes(b'same')
        os.link(original,self.allowed/'two.txt')
        with self.assertRaisesRegex(ValueError,'postcondition_file_hardlinked'):
            self.call('two.txt',b'same')

    def test_parent_symlink_denied(self):
        (self.allowed/'sub').symlink_to(self.base, target_is_directory=True)
        (self.base/'record.txt').write_bytes(b'same')
        with self.assertRaises((ValueError,OSError)):
            self.call('sub/record.txt',b'same')

    def test_unexpected_file_type_denied(self):
        path=self.allowed/'report.txt'
        path.mkdir()
        with self.assertRaises((ValueError,OSError)):
            self.call('report.txt',b'')

    @unittest.skipUnless(os.name == 'posix', 'root rename test requires POSIX')
    def test_root_directory_replaced_during_read_denied(self):
        (self.allowed/'report.txt').write_bytes(b'initial')
        raw_read=mod.os.read
        fired=[False]
        def attacking_read(fd,n):
            out=raw_read(fd,n)
            if out and not fired[0]:
                fired[0]=True
                self.allowed.rename(self.base/'old-allowed')
                self.allowed.mkdir()
                (self.allowed/'report.txt').write_bytes(b'initial')
            return out
        with patch.object(mod.os,'read',side_effect=attacking_read):
            with self.assertRaisesRegex(ValueError,'postcondition_parent_replaced_during_read'):
                self.call('report.txt',b'initial')
        self.assertTrue(fired[0])

    def test_final_path_swapped_for_symlink_during_read_denied(self):
        path=self.allowed/'report.txt'; path.write_bytes(b'initial')
        raw_read=mod.os.read
        fired=[False]
        def attacking_read(fd,n):
            out=raw_read(fd,n)
            if out and not fired[0]:
                fired[0]=True
                path.rename(self.allowed/'moved.txt')
                path.symlink_to(self.allowed/'moved.txt')
            return out
        with patch.object(mod.os,'read',side_effect=attacking_read):
            with self.assertRaisesRegex(ValueError,'postcondition_file_replaced_during_read'):
                self.call('report.txt',b'initial')
        self.assertTrue(fired[0])

    def test_empty_file_verified(self):
        (self.allowed/'empty.txt').write_bytes(b'')
        self.assertTrue(self.call('empty.txt',b'')['verified'])

    def test_long_file_multichunk_verified(self):
        data=(bytes(range(256))*1024) + b'end'
        (self.allowed/'report.bin').write_bytes(data)
        self.assertTrue(self.call('report.bin',data)['verified'])

    def test_oversized_file_denied(self):
        target=self.allowed/'huge.bin'
        with target.open('wb') as f:
            f.truncate(mod.MAX_VERIFIABLE_BYTES+1)
        with self.assertRaises(ValueError):
            self.call('huge.bin',b'')

    def test_preflight_allows_missing_output(self):
        target,expected=self.verifier.preflight({'path':'created.txt','hash':self.digest(b'hello')})
        self.assertEqual(target,self.allowed/'created.txt')
        self.assertEqual(expected,self.digest(b'hello'))

    def test_preflight_regular_existing_output(self):
        (self.allowed/'existing.txt').write_bytes(b'old')
        target,_=self.verifier.preflight({'path':'existing.txt','hash':self.digest(b'new')})
        self.assertEqual(target,self.allowed/'existing.txt')

    @unittest.skipUnless(hasattr(os,'link'),'hardlinks required')
    def test_preflight_denies_existing_hardlink_before_dispatch(self):
        (self.base/'external').write_bytes(b'external')
        os.link(self.base/'external',self.allowed/'target')
        with self.assertRaisesRegex(ValueError,'postcondition_file_hardlinked'):
            self.verifier.preflight({'path':'target','hash':self.digest(b'new')})

    @unittest.skipUnless(hasattr(os,'mkfifo'),'FIFO creation requires POSIX')
    def test_preflight_denies_special_file_before_dispatch(self):
        os.mkfifo(self.allowed/'target')
        with self.assertRaisesRegex(ValueError,'postcondition_target_not_regular'):
            self.verifier.preflight({'path':'target','hash':self.digest(b'new')})

    def test_bad_expected_hash_denied(self):
        (self.allowed/'report.txt').write_bytes(b'hello')
        for bad in ['','A'*64,'zz'*32,42,False,None]:
            with self.subTest(value=bad),self.assertRaises(ValueError):
                self.verifier.verify({'path':'report.txt','hash':bad})

    def test_symlink_target_denied(self):
        (self.allowed/'record.txt').symlink_to(self.base/'secret.txt')
        with self.assertRaises(ValueError):
            self.call('record.txt',b'anything')

    def test_same_size_mutation_during_read_denied(self):
        target=self.allowed/'report.txt'; target.write_bytes(b'initial')
        raw_read=mod.os.read
        fired=[False]
        def attacking_read(fd,n):
            out=raw_read(fd,n)
            if out and not fired[0]:
                fired[0]=True
                target.write_bytes(b'changed')
            return out
        with patch.object(mod.os,'read',side_effect=attacking_read):
            with self.assertRaisesRegex(ValueError,'postcondition_file_changed_during_read'):
                self.call('report.txt',b'initial')
        self.assertTrue(fired[0])

    @unittest.skipUnless(os.name == 'posix', 'directory descriptor race test requires POSIX')
    def test_parent_directory_replaced_during_read_denied(self):
        parent=self.allowed/'sub'; parent.mkdir()
        (parent/'report.txt').write_bytes(b'initial')
        raw_read=mod.os.read
        fired=[False]
        def attacking_read(fd,n):
            out=raw_read(fd,n)
            if out and not fired[0]:
                fired[0]=True
                parent.rename(self.allowed/'old-sub')
                parent.mkdir()
                (parent/'report.txt').write_bytes(b'initial')
            return out
        with patch.object(mod.os,'read',side_effect=attacking_read):
            with self.assertRaisesRegex(ValueError,'postcondition_parent_replaced_during_read'):
                self.call('sub/report.txt',b'initial')
        self.assertTrue(fired[0])

    def test_replace_with_same_content_during_read_denied(self):
        target=self.allowed/'report.txt'; target.write_bytes(b'initial')
        raw_read=mod.os.read
        fired=[False]
        def attacking_read(fd,n):
            out=raw_read(fd,n)
            if out and not fired[0]:
                fired[0]=True
                (self.allowed/'replacement.txt').write_bytes(b'initial')
                os.replace(self.allowed/'replacement.txt',target)
            return out
        with patch.object(mod.os,'read',side_effect=attacking_read):
            with self.assertRaisesRegex(ValueError,'postcondition_file_replaced_during_read'):
                self.call('report.txt',b'initial')
        self.assertTrue(fired[0])

if __name__=='__main__':unittest.main()
