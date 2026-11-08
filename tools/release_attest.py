#!/usr/bin/env python3
"""Detached Ed25519 attestations for CATL ZIP releases (software-key evaluation).

No implicit key generation, no embedded trust anchor, no automatic publication.
A verifier MUST obtain and pin the public key's SHA-256 fingerprint independently.
This is software-key signing, NOT HSM/FIDO2 verified physical human presence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

DOMAIN=b'CATL/RELEASE-ATTEST/v1\0'
MAX_ATTEST_BYTES=16*1024
MAX_INTERNAL_MANIFEST_BYTES=2*1024*1024
MAX_MEMBERS=2000
MAX_MEMBER_BYTES=64*1024*1024
MAX_TOTAL_BYTES=512*1024*1024
MAX_RATIO=500
COMMIT_RE=re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
VERSION_RE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$')


def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=True,allow_nan=False).encode('ascii')


def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def _read_unique_json(data: bytes, *, max_bytes: int = MAX_ATTEST_BYTES) -> dict:
    if len(data)>max_bytes:
        raise ValueError('attestation_oversized')
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('duplicate_json_field')
            out[k]=v
        return out
    value=json.loads(data.decode('utf-8'),object_pairs_hook=unique)
    if not isinstance(value,dict):raise ValueError('attestation_must_be_object')
    return value


def _bounded_member(z: zipfile.ZipFile, name: str, maximum: int) -> bytes:
    """Read only a bounded amount even if central-directory metadata lies."""
    info=z.getinfo(name)
    if info.file_size>maximum:
        raise ValueError('internal_release_metadata_oversized:' + name)
    with z.open(info) as source:
        data=source.read(maximum+1)
    if len(data)>maximum:
        raise ValueError('internal_release_metadata_oversized:' + name)
    return data


def validate_release_zip(path: Path) -> dict:
    """No extraction. Stream hash every member and verify internal tracked manifest."""
    with zipfile.ZipFile(path,'r') as z:
        members=z.infolist()
        if not members or len(members)>MAX_MEMBERS:
            raise ValueError('archive_member_limit')
        names=set();total=0;digests={}
        for m in members:
            name=m.filename
            parts=name.split('/')
            if (name in names or not name or name.startswith('/') or '\\' in name
                    or any(p in ('.','..','') for p in parts) or ':' in parts[0]
                    or m.is_dir() or stat.S_ISLNK(m.external_attr>>16)
                    or m.file_size>MAX_MEMBER_BYTES or m.file_size<0
                    or (m.file_size/max(m.compress_size,1))>MAX_RATIO):
                raise ValueError('unsafe_archive_member:'+name[:100])
            names.add(name)
            total+=m.file_size
            if total>MAX_TOTAL_BYTES:raise ValueError('archive_uncompressed_size_limit')
            digest=hashlib.sha256()
            with z.open(m) as source:
                while True:
                    part=source.read(1024*1024)
                    if not part:break
                    digest.update(part)
            digests[name]=digest.hexdigest()
        source_commit=None
        if 'RELEASE_MANIFEST.json' in names and 'SHA256SUMS.txt' in names:
            manifest_name='RELEASE_MANIFEST.json'
            manifest=_read_unique_json(_bounded_member(z,manifest_name,MAX_INTERNAL_MANIFEST_BYTES),
                                       max_bytes=MAX_INTERNAL_MANIFEST_BYTES)
            source_commit=manifest.get('source_commit')
            if source_commit is not None and (not isinstance(source_commit,str) or not COMMIT_RE.fullmatch(source_commit)):
                raise ValueError('invalid_embedded_source_commit')
            expected=manifest.get('files')
            if not isinstance(expected,dict) or manifest.get('algorithm')!='sha256':
                raise ValueError('invalid_internal_release_manifest')
            tracked=names-{'RELEASE_MANIFEST.json','SHA256SUMS.txt'}
            # The standalone release builder rejects secret/key file names;
            # the signer must enforce the same boundary even for a ZIP with
            # recomputed, internally consistent checksums.
            sensitive_parts={'.env','.envrc','.npmrc','.pypirc','id_rsa','id_ed25519',
                             'credentials.json','secrets.toml'}
            sensitive_suffixes=('.pem','.key','.p8','.p12','.pfx','.sqlite','.sqlite3','.db','.kdbx')
            for member in tracked:
                parts=member.lower().split('/')
                if (any(part in sensitive_parts or part.startswith('.env.') for part in parts)
                        or member.lower().endswith(sensitive_suffixes)):
                    raise ValueError('release_contains_sensitive_member:' + member)
            if set(expected)!=tracked or any(not isinstance(h,str) or not re.fullmatch(r'[0-9a-f]{64}',h)
                                              or h!=digests[p] for p,h in expected.items()):
                raise ValueError('internal_manifest_hash_or_set_mismatch')
            sums={}
            for line in _bounded_member(z,'SHA256SUMS.txt',MAX_INTERNAL_MANIFEST_BYTES).decode('utf-8').splitlines():
                matched=re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)',line)
                if not matched or matched[2] in sums:raise ValueError('invalid_internal_sha256sums')
                sums[matched[2]]=matched[1]
            if sums!=expected:raise ValueError('internal_sha256sums_mismatch')
            version=manifest.get('version')
        else:
            # The standalone Hermes integration ZIP uses a single containing
            # folder and MANIFEST_SHA256.txt listing paths relative to it.
            matches=[n for n in names if n.endswith('/MANIFEST_SHA256.txt')]
            if len(matches)!=1:raise ValueError('expected_internal_release_manifest_missing')
            manifest_name=matches[0]
            prefix=manifest_name[:-len('MANIFEST_SHA256.txt')]
            expected={}
            for line in _bounded_member(z,manifest_name,MAX_INTERNAL_MANIFEST_BYTES).decode('utf-8').splitlines():
                matched=re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)',line)
                if not matched:raise ValueError('invalid_internal_bundle_manifest')
                rel=matched[2]
                if not rel or '\\' in rel or any(p in ('','.','..') for p in rel.split('/')):
                    raise ValueError('unsafe_internal_manifest_path')
                name=prefix+rel
                if name in expected:raise ValueError('duplicate_internal_bundle_hash')
                expected[name]=matched[1]
            tracked=names-{manifest_name}
            if set(expected)!=tracked or any(expected[p]!=digests[p] for p in tracked):
                raise ValueError('internal_bundle_manifest_hash_or_set_mismatch')
            info_name=prefix+'BUILD_INFO.json'
            if info_name not in names:raise ValueError('bundle_version_evidence_missing')
            build=_read_unique_json(z.read(info_name))
            version=build.get('bundle_version')
        if not isinstance(version,str) or not VERSION_RE.fullmatch(version):
            raise ValueError('archive_version_invalid')
        return {'verified_members':len(names),'verified_source_members':len(tracked),
                'version':version,'manifest_sha256':digests[manifest_name],
                'source_commit':source_commit}



def _parent_safe(path: Path, *, for_private: bool) -> None:
    if not path.is_absolute():raise ValueError('key_path_not_absolute')
    if os.name == 'nt' and for_private:
        raise PermissionError('private_signing_requires_a_reviewed_posix_permission_boundary; Windows ACL support pending')
    p=path.parent
    while True:
        s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode):
            raise PermissionError('untrusted_key_parent')
        if os.name == 'posix' and s.st_mode & 0o022:
            raise PermissionError('writable_key_parent')
        if os.name == 'posix' and for_private and s.st_uid not in (os.geteuid(),0):
            raise PermissionError('key_parent_wrong_owner')
        if p==p.parent:break
        p=p.parent


def _read_key(path: Path, *, private: bool) -> bytes:
    _parent_safe(path,for_private=private)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size>4096 or s.st_size<1:
            raise PermissionError('key_not_regular_or_oversized')
        if os.name == 'posix' and private and (s.st_uid!=os.geteuid() or s.st_mode & 0o077):
            raise PermissionError('private_key_wrong_owner_or_permissions')
        if os.name == 'posix' and not private and s.st_mode & 0o022:
            raise PermissionError('public_key_writable_by_untrusted_party')
        return os.read(fd,4097)
    finally:os.close(fd)


def keygen(private_path: Path, public_path: Path) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if private_path==public_path or private_path.exists() or private_path.is_symlink() or public_path.exists() or public_path.is_symlink():
        raise FileExistsError('key_targets_must_not_exist')
    for path in (private_path,public_path):_parent_safe(path,for_private=True)
    key=Ed25519PrivateKey.generate()
    secret=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    made=[]
    try:
        for path,data,mode in ((private_path,secret,0o600),(public_path,public.hex().encode()+b'\n',0o644)):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
            made.append(path)
            with os.fdopen(fd,'wb') as out:
                os.fchmod(out.fileno(),mode)
                out.write(data)
                out.flush();os.fsync(out.fileno())
    except BaseException:
        for p in made:p.unlink(missing_ok=True)
        raise
    return {'public_key_fingerprint_sha256':hashlib.sha256(public).hexdigest()}


def _public_key(path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    data=_read_key(path,private=False).strip()
    if not re.fullmatch(rb'[0-9a-f]{64}',data):raise ValueError('malformed_public_key')
    raw=bytes.fromhex(data.decode('ascii'))
    return Ed25519PublicKey.from_public_bytes(raw),hashlib.sha256(raw).hexdigest()


def _payload(zip_path: Path, source_commit: str, version: str) -> dict:
    if not COMMIT_RE.fullmatch(source_commit) or not VERSION_RE.fullmatch(version):
        raise ValueError('invalid_source_commit_or_version')
    state=validate_release_zip(zip_path)
    if state['version']!=version:raise ValueError('version_does_not_match_embedded_release_manifest')
    if state['source_commit'] is not None and state['source_commit']!=source_commit:
        raise ValueError('claimed_commit_mismatches_embedded_source_commit')
    return {'schema':'CATL/RELEASE-ATTEST/v1','source_commit':source_commit,
            'version':version,'zip_sha256':sha256_file(zip_path),
            'internal_manifest_sha256':state['manifest_sha256'], 'files_verified':state['verified_members']}


def sign(zip_path: Path, private_key: Path, output: Path, *, source_commit: str,version: str) -> dict:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if output.exists() or output.is_symlink():raise FileExistsError('attestation_already_exists')
    payload=_payload(zip_path,source_commit,version)
    private=load_pem_private_key(_read_key(private_key,private=True),password=None)
    if not isinstance(private,Ed25519PrivateKey):raise ValueError('signer_must_be_ed25519')
    signature=private.sign(DOMAIN+canonical(payload)).hex()
    doc={'payload':payload,'signature_scheme':'Ed25519','signature_hex':signature}
    fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(canonical(doc)+b'\n');out.flush();os.fsync(out.fileno())
    return {'attestation':str(output),'source_commit':source_commit,'zip_sha256':payload['zip_sha256']}


def verify(zip_path: Path, attestation: Path, public_key: Path, *,
           expected_public_key_fingerprint: str,expected_commit: str,expected_version: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    if not re.fullmatch(r'[0-9a-f]{64}',expected_public_key_fingerprint):
        raise ValueError('missing_or_malformed_independent_public_key_pin')
    if attestation.is_symlink() or attestation.stat().st_size>MAX_ATTEST_BYTES:
        raise ValueError('unsafe_attestation_file')
    doc=_read_unique_json(attestation.read_bytes())
    if set(doc)!={'payload','signature_scheme','signature_hex'} or doc['signature_scheme']!='Ed25519':
        raise ValueError('invalid_attestation_envelope')
    if not isinstance(doc['payload'],dict) or set(doc['payload'])!={'schema','source_commit','version','zip_sha256','internal_manifest_sha256','files_verified'}:
        raise ValueError('invalid_attestation_payload')
    payload=doc['payload']
    if payload['schema']!='CATL/RELEASE-ATTEST/v1' or payload['source_commit']!=expected_commit or payload['version']!=expected_version:
        raise ValueError('attestation_provenance_mismatch')
    if not isinstance(doc['signature_hex'],str) or not re.fullmatch('[0-9a-f]{128}',doc['signature_hex']):
        raise ValueError('attestation_signature_format')
    key,fingerprint=_public_key(public_key)
    if fingerprint!=expected_public_key_fingerprint:raise ValueError('untrusted_signing_key')
    try:key.verify(bytes.fromhex(doc['signature_hex']),DOMAIN+canonical(payload))
    except InvalidSignature as e:raise ValueError('signature_invalid') from e
    expected=_payload(zip_path,expected_commit,expected_version)
    if payload!=expected:raise ValueError('signed_zip_hash_or_contents_mismatch')
    return {'passed':True,'source_commit':expected_commit,'version':expected_version,
            'zip_sha256':payload['zip_sha256'],'key_fingerprint_sha256':fingerprint,
            'members':payload['files_verified'],
            'limitations':'Software-key signature; signer identity and source commitment are external trust assertions, not independent host/CI provenance'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    k=sub.add_parser('keygen');k.add_argument('--private',type=Path,required=True);k.add_argument('--public',type=Path,required=True)
    s=sub.add_parser('sign');s.add_argument('--zip',type=Path,required=True);s.add_argument('--private',type=Path,required=True);s.add_argument('--output',type=Path,required=True);s.add_argument('--source-commit',required=True);s.add_argument('--version',required=True)
    v=sub.add_parser('verify');v.add_argument('--zip',type=Path,required=True);v.add_argument('--attestation',type=Path,required=True);v.add_argument('--public',type=Path,required=True);v.add_argument('--expected-key-sha256',required=True);v.add_argument('--expected-commit',required=True);v.add_argument('--expected-version',required=True)
    a=p.parse_args(argv)
    try:
        if a.action=='keygen':result=keygen(a.private,a.public)
        elif a.action=='sign':raise PermissionError('direct_signing_disabled_use_release_sealed')
        else:result=verify(a.zip,a.attestation,a.public,expected_public_key_fingerprint=a.expected_key_sha256,expected_commit=a.expected_commit,expected_version=a.expected_version)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except Exception as e:
        print(json.dumps({'passed':False,'error':type(e).__name__+':'+str(e)[:180]},indent=2),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
