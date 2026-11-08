#!/usr/bin/env python3
"""Offline CATL release ZIP vs immutable Git commit proof.

A detached signature authenticates ZIP bytes only; this tool additionally
checks that each archived payload equals the Git object recorded at the exact
reviewed commit. It makes no claim about remote repository trust, operator
identity, hardware-backed signing or independent build-environment provenance.
No network, worktree modification, extraction, automatic push or GitHub Actions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from release_pack import (_excluded_source_path, _portable_names, _safe_name,
                          _sensitive_name, verify as verify_release_zip)

MAX_GIT_FILE = 16 * 1024 * 1024
MAX_FILES = 4096


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(['git', '--no-replace-objects', '-C', str(root), *args],
                              check=True, capture_output=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('source_git_checkout_or_object_unavailable') from exc


def verify_source_artifact(archive: Path, checkout: Path, reviewed_commit: str) -> dict:
    """Compare the canonical release archive with the exact Git tree and blobs."""
    archive = Path(archive)
    checkout = Path(checkout).resolve(strict=True)
    if not isinstance(reviewed_commit, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', reviewed_commit):
        raise ValueError('source_reviewed_commit_required')
    top = Path(_git(checkout, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    observed = _git(checkout, 'rev-parse', 'HEAD').decode().strip()
    if top != checkout or observed != reviewed_commit:
        raise ValueError('source_reviewed_checkout_head_mismatch')
    algorithm = _git(checkout, 'rev-parse', '--show-object-format').decode().strip()
    if algorithm not in ('sha1', 'sha256') or len(reviewed_commit) != (40 if algorithm == 'sha1' else 64):
        raise ValueError('source_object_format_mismatch')
    tree = _git(checkout, 'ls-tree', '-r', '-z', '--full-tree', reviewed_commit)
    expected = {}
    for entry in tree.split(b'\0'):
        if not entry:
            continue
        try:
            metadata, raw_name = entry.split(b'\t', 1)
            mode, kind, oid = metadata.split(b' ')
            name = raw_name.decode('utf-8', 'strict')
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('source_git_tree_entry_invalid') from exc
        _safe_name(name)
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise ValueError('source_nonregular_git_member:' + name)
        if _excluded_source_path(name):
            continue
        if _sensitive_name(name):
            raise ValueError('source_sensitive_git_path:' + name)
        if len(oid) != len(reviewed_commit) or not re.fullmatch(rb'[0-9a-f]+', oid):
            raise ValueError('source_git_object_id_invalid')
        expected[name] = (oid.decode('ascii'), 0o755 if mode == b'100755' else 0o644)
    if not expected or len(expected) > MAX_FILES:
        raise ValueError('source_tracked_file_count_invalid')
    _portable_names(expected)
    # verify_release_zip checks the physical ZIP envelope, DEFLATE stream
    # exhaustion, in-archive checksums, portable filenames, version and modes.
    zip_members = verify_release_zip(archive)
    with zipfile.ZipFile(archive, 'r') as z:
        manifest = json.loads(z.read('RELEASE_MANIFEST.json'))
        if manifest.get('source_commit') != reviewed_commit:
            raise ValueError('source_manifest_claim_mismatch')
        entries = {info.filename: info for info in z.infolist()
                   if info.filename not in ('RELEASE_MANIFEST.json', 'SHA256SUMS.txt')}
        if set(entries) != set(expected):
            raise ValueError('source_git_tree_file_set_mismatch')
        total = 0
        for name, (oid, mode) in expected.items():
            info = entries[name]
            if stat.S_IMODE(info.external_attr >> 16) != mode:
                raise ValueError('source_git_file_mode_mismatch:' + name)
            payload = z.read(info)
            if len(payload) > MAX_GIT_FILE:
                raise ValueError('source_git_blob_oversized:' + name)
            try:
                object_bytes = int(_git(checkout, 'cat-file', '-s', oid).decode('ascii').strip())
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError('source_git_object_size_invalid:' + name) from exc
            if object_bytes > MAX_GIT_FILE:
                raise ValueError('source_git_blob_oversized:' + name)
            if object_bytes != len(payload):
                raise ValueError('source_git_blob_mismatch:' + name)
            committed = _git(checkout, 'cat-file', 'blob', oid)
            if payload != committed:
                raise ValueError('source_git_blob_mismatch:' + name)
            total += len(payload)
    if _git(checkout, 'rev-parse', 'HEAD').decode().strip() != reviewed_commit:
        raise ValueError('source_git_checkout_changed_during_verification')
    return {'verified': True,
            'source_commit': reviewed_commit, 'git_object_format': algorithm,
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'tracked_files': len(expected), 'archive_members': zip_members,
            'source_bytes': total,
            'limitations': 'Local exact Git object equivalence only; external trust, signed provenance and deployment gates still open.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_source_artifact(args.archive, args.checkout, args.commit)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (ValueError, OSError, KeyError, RuntimeError, zipfile.BadZipFile) as exc:
        print(json.dumps({'verified': False, 'error': type(exc).__name__ + ':' + str(exc)[:180]}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
