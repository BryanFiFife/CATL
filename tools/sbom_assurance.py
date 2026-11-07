#!/usr/bin/env python3
"""Offline deterministic manifest/SBOM integrity check (NOT a vulnerability scan)."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

class AssuranceRejected(ValueError):
    pass

def _unique_pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise AssuranceRejected('duplicate_json_field')
        out[k]=v
    return out

def verify_source_manifest(root:Path)->dict:
    root=Path(root).resolve()
    if not root.is_dir():raise AssuranceRejected('root_missing')
    manifest=json.loads((root/'RELEASE_MANIFEST.json').read_text(),object_pairs_hook=_unique_pairs)
    files=manifest.get('files')
    if manifest.get('algorithm')!='sha256' or not isinstance(files,dict) or not files:
        raise AssuranceRejected('manifest_invalid')
    sums=(root/'SHA256SUMS.txt').read_text().splitlines()
    indexed={}
    for row in sums:
        match=re.fullmatch(r'([0-9a-f]{64})  (.+)',row)
        if not match or match.group(2) in indexed:raise AssuranceRejected('checksum_index_invalid')
        indexed[match.group(2)]=match.group(1)
    if indexed!=files:raise AssuranceRejected('checksum_index_mismatch')
    for path,expected in files.items():
        if (not isinstance(path,str) or not re.fullmatch(r'[a-zA-Z0-9_./+\-]{1,255}',path)
                or path.startswith('/') or any(s in ('','.','..') for s in path.split('/'))
                or not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected)):
            raise AssuranceRejected('path_or_digest_invalid')
        target=root/path
        current=root
        for segment in path.split('/'):
            current=current/segment
            if stat.S_ISLNK(os.lstat(current).st_mode):raise AssuranceRejected('symlink_in_source')
        if not stat.S_ISREG(os.lstat(target).st_mode):raise AssuranceRejected('nonfile_source')
        hasher=hashlib.sha256()
        with target.open('rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''):hasher.update(block)
        if hasher.hexdigest()!=expected:raise AssuranceRejected('source_digest_mismatch')
    return {'files':len(files),'source_manifest_digest':hashlib.sha256(
        (root/'RELEASE_MANIFEST.json').read_bytes()).hexdigest()}


def validate_cyclonedx(bom:dict)->dict:
    if not isinstance(bom,dict) or bom.get('bomFormat')!='CycloneDX' or bom.get('specVersion') not in ('1.5','1.6'):
        raise AssuranceRejected('bom_format_invalid')
    components=bom.get('components')
    if not isinstance(components,list) or not components:raise AssuranceRejected('bom_components_missing')
    refs=set()
    for entry in components:
        if not isinstance(entry,dict):raise AssuranceRejected('bom_entry_invalid')
        ref,name,version=entry.get('bom-ref'),entry.get('name'),entry.get('version')
        if (not isinstance(ref,str) or not ref or ref in refs or
                not isinstance(name,str) or not name or
                not isinstance(version,str) or not version or version in ('*','latest','unknown')):
            raise AssuranceRejected('bom_unpinned_or_duplicate_component')
        refs.add(ref)
    return {'component_count':len(components),'bom_sha256':hashlib.sha256(
        json.dumps(bom,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--bom',type=Path,required=True)
    args=p.parse_args()
    try:
        out={'manifest':verify_source_manifest(args.repo),'bom':validate_cyclonedx(
            json.loads(args.bom.read_text(),object_pairs_hook=_unique_pairs))}
    except (AssuranceRejected,OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'REJECTED','reason':str(exc)}));raise SystemExit(2)
    print(json.dumps({'status':'OFFLINE_FORMAT_AND_HASHES_ONLY','evidence':out},sort_keys=True))

if __name__=='__main__':main()
