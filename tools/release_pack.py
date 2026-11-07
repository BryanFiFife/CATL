"""Deterministic release ZIP + strict per-file SHA-256 integrity verification.

Manifests are *not signed*; users must obtain the ZIP/hash from a trusted source.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import stat
import zipfile
import tomllib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION=tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
STAMP=(2026,11,7,0,0,0)
SKIP_DIRS={'.git','.pytest_cache','.mypy_cache','.ruff_cache','__pycache__','build','dist'}
SKIP_SUFFIXES=('.pyc','.pyo','.whl')
SKIP_NAMES={'RELEASE_MANIFEST.json','SHA256SUMS.txt'}


def release_files():
    for p in sorted(ROOT.rglob('*')):
        if any(part in SKIP_DIRS or part.endswith('.egg-info') for part in p.relative_to(ROOT).parts):
            continue
        if p.is_symlink():
            raise ValueError(f'release_symlink_refused:{p}')
        if not p.is_file() or p.name in SKIP_NAMES or p.name.endswith(SKIP_SUFFIXES):
            continue
        rel=p.relative_to(ROOT).as_posix()
        if rel.startswith('/') or '..' in Path(rel).parts:
            raise ValueError('unsafe_release_member')
        yield rel,p.read_bytes()


def manifest(entries):
    return {'name':'caledapt-agent-trust','version':VERSION,
        'release_type':'private-linux-hardening-release-candidate',
        'algorithm':'sha256','signed':False,
        'files':{name:hashlib.sha256(data).hexdigest() for name,data in entries}}


def make(path:Path):
    entries=list(release_files())
    m=manifest(entries)
    mdata=(json.dumps(m,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
    sums=''.join(f'{digest}  {name}\n' for name,digest in sorted(m['files'].items())).encode()
    (ROOT/'RELEASE_MANIFEST.json').write_bytes(mdata)
    (ROOT/'SHA256SUMS.txt').write_bytes(sums)
    contents=sorted(entries+[("RELEASE_MANIFEST.json",mdata),("SHA256SUMS.txt",sums)])
    path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9,strict_timestamps=True) as z:
        for name,data in contents:
            zi=zipfile.ZipInfo(name,STAMP)
            zi.compress_type=zipfile.ZIP_DEFLATED
            zi.external_attr=(stat.S_IFREG|0o644)<<16
            z.writestr(zi,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    return {'files':len(contents),'zip_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'zip_bytes':path.stat().st_size}


def verify(path:Path):
    with zipfile.ZipFile(path) as z:
        members=z.infolist()
        names=[x.filename for x in members]
        if len(names)!=len(set(names)):
            raise ValueError('duplicate_zip_member')
        if any(n.startswith('/') or '..' in Path(n).parts or '\\' in n or n.endswith('/') for n in names):
            raise ValueError('unsafe_zip_member')
        if any(stat.S_ISLNK((x.external_attr>>16)&0xffff) for x in members):
            raise ValueError('symlink_zip_member')
        m=json.loads(z.read('RELEASE_MANIFEST.json'))
        expected=set(m['files'])|{'RELEASE_MANIFEST.json','SHA256SUMS.txt'}
        if set(names)!=expected or m.get('version')!=VERSION:
            raise ValueError('release_file_set_mismatch')
        for name,digest in m['files'].items():
            if hashlib.sha256(z.read(name)).hexdigest()!=digest:
                raise ValueError(f'file_hash_mismatch:{name}')
        checks=z.read('SHA256SUMS.txt').decode().splitlines()
        listed={}
        for line in checks:
            if not re.match(r'^[0-9a-f]{64}  \S+',line):
                raise ValueError('checksum_format_invalid')
            value,name=line.split('  ',1)
            if name in listed: raise ValueError('duplicate_checksum_entry')
            listed[name]=value
        if listed!=m['files']:
            raise ValueError('checksum_manifest_mismatch')
    return len(names)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--output',type=Path)
    group.add_argument('--verify',type=Path)
    opts=p.parse_args()
    if opts.output:
        result=make(opts.output)
        assert verify(opts.output)==result['files']
        print(json.dumps(result,sort_keys=True))
    else:
        print(f'PASS {verify(opts.verify)} verified archive files')
