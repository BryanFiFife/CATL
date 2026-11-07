from __future__ import annotations
import os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'src'))
from catl.operator_auth import _require_keyfile, generate_test_software_keypair, SoftwareOperatorSigner

@unittest.skipUnless(os.name=='posix', 'POSIX hardening only')
class TestOperatorKeyPlatformNative(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='catl-op-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.private=self.root/'operator-priv.pem'
        self.public=self.root/'operator-pub.hex'

    def test_key_generation_readback_and_signature(self):
        generate_test_software_keypair(self.private,self.public)
        signer=SoftwareOperatorSigner(self.private)
        sig=bytes.fromhex(signer.sign_hex('616263'))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public.read_text().strip())).verify(sig,b'abc')
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode),0o600)

    def test_win32_private_key_load_is_denied(self):
        generate_test_software_keypair(self.private,self.public)
        with patch('catl.operator_auth.os.name','nt'):
            with self.assertRaisesRegex(PermissionError,'requires_reviewed_posix'):
                SoftwareOperatorSigner(self.private)

    def test_win32_private_key_generation_is_denied_without_files(self):
        with patch('catl.operator_auth.os.name','nt'):
            with self.assertRaisesRegex(PermissionError,'requires_reviewed_posix'):
                generate_test_software_keypair(self.private,self.public)
        self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())

    def test_world_writable_provisioning_parent_refused(self):
        self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(PermissionError,'parent_untrusted'):
                generate_test_software_keypair(self.private,self.public)
            self.assertFalse(self.private.exists())
        finally:self.root.chmod(0o700)

    def test_group_writable_provisioning_parent_refused(self):
        self.root.chmod(0o770)
        try:
            with self.assertRaisesRegex(PermissionError,'parent_untrusted'):
                generate_test_software_keypair(self.private,self.public)
        finally:self.root.chmod(0o700)

    def test_symlink_provisioning_parent_refused(self):
        alias=self.root.parent/(self.root.name+'-alias')
        alias.symlink_to(self.root,target_is_directory=True)
        self.addCleanup(lambda:alias.unlink(missing_ok=True))
        with self.assertRaisesRegex(PermissionError,'parent_invalid'):
            generate_test_software_keypair(alias/'key.pem',alias/'key.hex')

    def test_private_key_hardlink_refused(self):
        generate_test_software_keypair(self.private,self.public)
        second=self.root/'second-private.pem';os.link(self.private,second)
        with self.assertRaisesRegex(PermissionError,'hardlink_refused'):
            SoftwareOperatorSigner(self.private)

    def test_private_key_symlink_refused(self):
        generate_test_software_keypair(self.private,self.public)
        link=self.root/'private-link';link.symlink_to(self.private)
        with self.assertRaisesRegex(PermissionError,'symlink_refused'):
            SoftwareOperatorSigner(link)

    def test_private_key_wider_permissions_refused(self):
        generate_test_software_keypair(self.private,self.public)
        self.private.chmod(0o640)
        with self.assertRaisesRegex(PermissionError,'permissions_invalid'):
            SoftwareOperatorSigner(self.private)

    def test_no_overwrite_of_existing_key(self):
        generate_test_software_keypair(self.private,self.public)
        with self.assertRaises(FileExistsError):
            generate_test_software_keypair(self.private,self.public)

    def test_public_key_access_retained(self):
        generate_test_software_keypair(self.private,self.public)
        self.assertEqual(_require_keyfile(self.public,private=False).strip(),self.public.read_bytes().strip())



@unittest.skipUnless(os.name == 'nt', 'Requires native Windows to verify private key fail-closed policy')
class TestWindowsOperatorSignerNative(unittest.TestCase):
    def test_windows_key_generation_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / 'private.pem'
            public = Path(tmp) / 'public.hex'
            with self.assertRaisesRegex(PermissionError, 'requires_reviewed_posix_permissions'):
                generate_test_software_keypair(private, public)
            self.assertFalse(private.exists())
            self.assertFalse(public.exists())

    def test_windows_private_key_loading_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / 'private.pem'
            private.write_bytes(b'not a private key')
            with self.assertRaisesRegex(PermissionError, 'requires_reviewed_posix_permissions'):
                SoftwareOperatorSigner(private)

if __name__ == '__main__':
    unittest.main()
