"""Offline release-attestation attacks against disposable archives and keys."""
from __future__ import annotations
import hashlib,json,os,pathlib,stat,sys,tempfile,unittest,warnings,zipfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from release_attest import keygen,sign,verify,validate_release_zip,_read_unique_json

COMMIT='a'*40
VERSION='0.11.0rc1'

@unittest.skipIf(os.name=='nt', 'Windows private-key ACL enforcement not implemented; verify-only is supported')
class SigningTests(unittest.TestCase):
    def setUp(self):
        # Secret-file parent trust correctly rejects group-writable /tmp.
        self.t=tempfile.TemporaryDirectory(prefix='catl-attest-',dir='/root' if os.geteuid()==0 else str(pathlib.Path.home()))
        self.addCleanup(self.t.cleanup)
        self.root=pathlib.Path(self.t.name)
        self.private=self.root/'private.pem';self.public=self.root/'public.hex'
        self.fingerprint=keygen(self.private,self.public)['public_key_fingerprint_sha256']
        self.zip=self.root/'release.zip';self.att=self.root/'attest.json'
        self.make_zip()
    def make_zip(self,*,body=b'abc',members=None):
        payload=members or {'README.md':body,'src/catl/test.py':b'print("test")\n'}
        manifest={'algorithm':'sha256','version':VERSION,'files':{k:hashlib.sha256(v).hexdigest() for k,v in payload.items()}}
        sums=''.join(f'{h}  {k}\n' for k,h in sorted(manifest['files'].items())).encode()
        allitems={**payload,'RELEASE_MANIFEST.json':json.dumps(manifest,sort_keys=True).encode(),'SHA256SUMS.txt':sums}
        with zipfile.ZipFile(self.zip,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for k,v in allitems.items():z.writestr(k,v)
    def signing(self):return sign(self.zip,self.private,self.att,source_commit=COMMIT,version=VERSION)
    def checking(self,**kw):
        opts={'expected_public_key_fingerprint':self.fingerprint,'expected_commit':COMMIT,'expected_version':VERSION}
        opts.update(kw)
        return verify(self.zip,self.att,self.public,**opts)
    def test_sign_then_verify_correct_attestation(self):
        self.signing();r=self.checking();self.assertTrue(r['passed']);self.assertEqual(r['members'],4)
        self.assertEqual(self.private.stat().st_mode & 0o777,0o600)
    def test_signing_key_is_never_recreated_or_overwritten(self):
        with self.assertRaises(FileExistsError):keygen(self.private,self.public)
        self.signing()
        with self.assertRaises(FileExistsError):self.signing()
    def test_signer_requires_correct_commit_and_version(self):
        for commit,version in (('a','0.11.0rc1'),(COMMIT,'bad version'),(COMMIT,'1.0.0')):
            with self.subTest(commit=commit,version=version):
                with self.assertRaises(ValueError):sign(self.zip,self.private,self.att,source_commit=commit,version=version)
    def test_wrong_trust_pin_commit_and_version(self):
        self.signing()
        for params in ({'expected_public_key_fingerprint':'b'*64},
                       {'expected_commit':'b'*40}, {'expected_version':'0.11.0rc2'},
                       {'expected_public_key_fingerprint':''}):
            with self.subTest(params=params):
                with self.assertRaises(ValueError):self.checking(**params)
    def test_tampered_signature_and_signed_metadata(self):
        self.signing();good=self.att.read_bytes()
        data=json.loads(good);data['signature_hex']='0'*128
        self.att.write_text(json.dumps(data))
        with self.assertRaises(ValueError):self.checking()
        data=json.loads(good);data['payload']['zip_sha256']='f'*64
        self.att.write_text(json.dumps(data))
        with self.assertRaises(ValueError):self.checking()
        self.att.write_bytes(good)
        self.assertTrue(self.checking()['passed'])
    def test_tampered_archive_fails_verification(self):
        self.signing();self.make_zip(body=b'evil')
        with self.assertRaises(ValueError):self.checking()
    def test_archive_and_checksum_must_match(self):
        self.make_zip(body=b'changed')
        self.assertEqual(validate_release_zip(self.zip)['verified_members'],4)
        with zipfile.ZipFile(self.zip,'a') as z:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                z.writestr('README.md',b'altered')
        with self.assertRaises(ValueError):validate_release_zip(self.zip)
    def test_zip_traversal_and_symlink_rejected(self):
        for evil in ('../outside','/absolute','folder/../outside','folder\\windows','A//B','./first'):
            with self.subTest(evil=evil):
                self.make_zip(members={evil:b'x'})
                with self.assertRaises(ValueError):validate_release_zip(self.zip)
        self.make_zip()
        with zipfile.ZipFile(self.zip,'a') as z:
            link=zipfile.ZipInfo('evil-link')
            link.create_system=3
            link.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(link,'/etc/passwd')
        with self.assertRaises(ValueError):validate_release_zip(self.zip)
    def test_zip_bomb_ratio_rejected(self):
        self.make_zip(body=b'\0'*2_000_000)
        with self.assertRaises(ValueError):validate_release_zip(self.zip)
    def test_bad_private_key_permissions_and_symlink_rejected(self):
        self.private.chmod(0o644)
        with self.assertRaises(PermissionError):self.signing()
        self.private.chmod(0o600)
        real=self.root/'saved.pem';self.private.rename(real)
        self.private.symlink_to(real)
        with self.assertRaises(OSError):self.signing()
    def test_public_key_substitution_detected_by_independent_fingerprint(self):
        self.signing()
        other=self.root/'other.pem';otherpub=self.root/'other.hex';keygen(other,otherpub)
        with self.assertRaises(ValueError):verify(self.zip,self.att,otherpub,expected_public_key_fingerprint=self.fingerprint,
                                                   expected_commit=COMMIT,expected_version=VERSION)
    def test_malformed_duplicate_attestation_fields_rejected(self):
        self.signing()
        self.att.write_text('{"payload":{},"payload":{},"signature_scheme":"Ed25519","signature_hex":"0"}')
        with self.assertRaises(ValueError):self.checking()
    def test_missing_manifest_is_not_accepted(self):
        with zipfile.ZipFile(self.zip,'w') as z:z.writestr('README.md','content')
        with self.assertRaises(ValueError):self.signing()
    def test_private_key_parent_must_not_be_shared_writable(self):
        if os.name!='posix':self.skipTest('POSIX')
        parent=self.root/'untrusted';parent.mkdir(mode=0o777);parent.chmod(0o777)
        with self.assertRaises(PermissionError):keygen(parent/'private.pem',parent/'public.hex')
    def test_signed_nested_integration_bundle(self):
        version='1.3.0-runtime-attestation-lab'
        source={'CATL_Hermes_Integration/README_START_HERE.md':b'lab-only',
                'CATL_Hermes_Integration/BUILD_INFO.json':json.dumps({'bundle_version':version}).encode()}
        listing=''.join(f'{hashlib.sha256(value).hexdigest()}  {path.split("/",1)[1]}\n' for path,value in sorted(source.items()))
        source['CATL_Hermes_Integration/MANIFEST_SHA256.txt']=listing.encode()
        with zipfile.ZipFile(self.zip,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for path,data in source.items():z.writestr(path,data)
        self.assertEqual(validate_release_zip(self.zip)['version'],version)
        sign(self.zip,self.private,self.att,source_commit=COMMIT,version=version)
        self.assertTrue(self.checking(expected_version=version)['passed'])
        with zipfile.ZipFile(self.zip,'a') as z:z.writestr('CATL_Hermes_Integration/unauthorised.txt','invalid')
        with self.assertRaises(ValueError):self.checking(expected_version=version)

    def test_unsigned_hash_list_does_not_claim_signed_trust(self):
        self.signing()
        a=json.loads(self.att.read_text())
        self.assertEqual(a['signature_scheme'],'Ed25519')
        self.assertEqual(a['payload']['schema'],'CATL/RELEASE-ATTEST/v1')
        self.assertIn('source_commit',a['payload'])

if __name__=='__main__':unittest.main()
