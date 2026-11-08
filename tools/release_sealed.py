#!/usr/bin/env python3
"""CATL reviewed-commit-to-Ed25519 offline source release gate.

This is an *additional release gate*, not a declaration of production approval.
No source checkout mutation, key creation, GitHub request, CI, or publication.
The reviewed commit and public-key fingerprint MUST be obtained out-of-band.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

from verify_source_artifact import verify_source_artifact

PIN_RE = re.compile(r'^[0-9a-f]{64}$')
COMMIT_RE = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')


class ReleaseGateDenied(PermissionError):
    pass


def _file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_existing_file(path: Path) -> None:
    if not path.is_absolute():
        raise ReleaseGateDenied('release_path_must_be_absolute')
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ReleaseGateDenied('release_file_type_or_link_invalid')


def _private_parent(path: Path, checkout: Path, *, purpose: str) -> None:
    if not path.is_absolute() or path.parent != path.parent.resolve(strict=True):
        raise ReleaseGateDenied(purpose + '_absolute_canonical_path_required')
    parent = path.parent
    checkout = checkout.resolve(strict=True)
    if parent == checkout or checkout in parent.parents:
        raise ReleaseGateDenied(purpose + '_inside_source_checkout')
    if os.name != 'posix':
        raise ReleaseGateDenied('protected_signing_requires_posix_host')
    s = parent.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
        raise ReleaseGateDenied(purpose + '_parent_untrusted')
    # No mutable or symlinked ancestors, including the parent's parent.
    item = parent
    while item != item.parent:
        si = item.lstat()
        if stat.S_ISLNK(si.st_mode) or not stat.S_ISDIR(si.st_mode) or si.st_mode & 0o022:
            raise ReleaseGateDenied(purpose + '_ancestor_untrusted')
        item = item.parent


def _safe_private_output(path: Path, checkout: Path) -> None:
    """Sign only into an operator-owned private directory outside source."""
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ReleaseGateDenied('attestation_output_must_be_new_absolute_file')
    _private_parent(path, checkout, purpose='attestation_output')


def _safe_signing_inputs(archive: Path, private_key: Path, checkout: Path) -> None:
    """Refuse a release ZIP or private signer key in mutable public directories."""
    for path, label in ((archive, 'source_archive'), (private_key, 'signer_private_key')):
        _safe_existing_file(path)
        _private_parent(path, checkout, purpose=label)

def _check_trust_pin(public_key: Path, expected_fingerprint: str) -> str:
    if not PIN_RE.fullmatch(expected_fingerprint):
        raise ReleaseGateDenied('independent_public_key_pin_required')
    _safe_existing_file(public_key)
    # Delegates key format/permissions and hash derivation to CATL's
    # existing release-attestation implementation.
    from release_attest import _public_key
    _key, observed = _public_key(public_key)
    if observed != expected_fingerprint:
        raise ReleaseGateDenied('release_signing_public_key_not_independently_pinned')
    return observed


def _verified_signing_toolchain(checkout: Path, reviewed_commit: str) -> None:
    """Reject dirty/hidden substitutions of CATL source signing code.

    The trusted operator still must independently review the commit and its
    dependencies; this compares the *local executing Python source files* to
    the Git tree rather than accepting a clean-looking git status result.
    """
    if not COMMIT_RE.fullmatch(reviewed_commit):
        raise ReleaseGateDenied('independently_reviewed_commit_required')
    checkout = checkout.resolve(strict=True)
    try:
        algorithm = subprocess.run(['git', '-C', str(checkout), 'rev-parse', '--show-object-format'],
                                   check=True, capture_output=True, timeout=15).stdout.decode().strip()
        if algorithm not in ('sha1', 'sha256'):
            raise ReleaseGateDenied('signing_git_object_format_invalid')
        for rel in ('tools/release_pack.py', 'tools/verify_source_artifact.py',
                    'tools/release_attest.py', 'tools/release_sealed.py'):
            path = checkout / rel
            parent = path.parent
            if parent.resolve(strict=True) != parent or not parent.is_dir():
                raise ReleaseGateDenied('signing_tool_parent_untrusted:' + rel)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
                raise ReleaseGateDenied('signing_tool_file_untrusted:' + rel)
            actual = path.read_bytes()
            if len(actual) != info.st_size:
                raise ReleaseGateDenied('signing_tool_read_race:' + rel)
            expected = subprocess.run(['git', '-C', str(checkout), 'rev-parse',
                                       reviewed_commit + ':' + rel],
                                      check=True, capture_output=True, timeout=15).stdout.decode().strip()
            digest = hashlib.new(algorithm, b'blob ' + str(len(actual)).encode() + b'\0' + actual).hexdigest()
            if expected != digest:
                raise ReleaseGateDenied('signing_tool_source_modified:' + rel)
    except ReleaseGateDenied:
        raise
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        raise ReleaseGateDenied('signing_toolchain_source_unavailable') from exc


def _source_proof(archive: Path, checkout: Path, reviewed_commit: str,
                  expected_version: str) -> dict:
    if not COMMIT_RE.fullmatch(reviewed_commit):
        raise ReleaseGateDenied('independently_reviewed_commit_required')
    if not isinstance(expected_version, str) or not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9._+-]{0,63}', expected_version):
        raise ReleaseGateDenied('expected_release_version_required')
    _safe_existing_file(archive)
    proof = verify_source_artifact(archive, checkout, reviewed_commit)
    # A signature is a public assertion of an exact software version. The
    # source-equivalence verifier already checks archive manifest/pyproject
    # parity; additionally bind the operator-supplied version to that archive.
    with zipfile.ZipFile(archive) as z:
        packaged_version = json.loads(z.read('RELEASE_MANIFEST.json'))['version']
    if packaged_version != expected_version:
        raise ReleaseGateDenied('release_attestation_version_mismatch')
    return proof


def sign_checked(*, archive: Path, checkout: Path, reviewed_commit: str,
                 private_key: Path, public_key: Path, expected_key_fingerprint: str,
                 output: Path, version: str) -> dict:
    """Fail closed if a signed ZIP differs from the independently pinned Git tree."""
    archive, checkout = Path(archive), Path(checkout)
    private_key, public_key, output = Path(private_key), Path(public_key), Path(output)
    if not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,63}', version):
        raise ReleaseGateDenied('expected_release_version_required')
    _safe_private_output(output, checkout)
    _safe_signing_inputs(archive, private_key, checkout)
    _check_trust_pin(public_key, expected_key_fingerprint)
    _verified_signing_toolchain(checkout, reviewed_commit)
    before = _source_proof(archive, checkout, reviewed_commit, version)
    # Keep the complete original signer and verifier as the cryptographic
    # authority. This wrapper adds an external Git-blob equivalence boundary.
    from release_attest import sign, verify
    try:
        sign(archive, private_key, output, source_commit=reviewed_commit, version=version)
        info = output.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 16384):
            raise ReleaseGateDenied('signed_attestation_output_untrusted')
        checked = verify(archive, output, public_key,
                         expected_public_key_fingerprint=expected_key_fingerprint,
                         expected_commit=reviewed_commit, expected_version=version)
        after = _source_proof(archive, checkout, reviewed_commit, version)
        _verified_signing_toolchain(checkout, reviewed_commit)
        if (after['archive_sha256'] != before['archive_sha256'] or
                checked['zip_sha256'] != before['archive_sha256'] or
                checked['source_commit'] != reviewed_commit or
                checked['version'] != version):
            raise ReleaseGateDenied('source_or_archive_changed_during_signing')
        return {'passed': True, 'action': 'sign_checked', 'commit': reviewed_commit,
                'zip_sha256': before['archive_sha256'], 'key_fingerprint': expected_key_fingerprint,
                'files_verified': after['tracked_files'],
                'limitations': 'Release source-equivalence/signature only; external deployment/assurance gates remain open.'}
    except BaseException:
        # Never leave an apparently releasable signature from an incomplete
        # combined source/signature acceptance operation.
        if output.is_file() and not output.is_symlink():
            output.unlink()
        raise


def verify_checked(*, archive: Path, checkout: Path, reviewed_commit: str,
                   public_key: Path, expected_key_fingerprint: str,
                   attestation: Path, version: str) -> dict:
    archive, checkout, public_key, attestation = map(Path, (archive, checkout, public_key, attestation))
    _safe_existing_file(attestation)
    _check_trust_pin(public_key, expected_key_fingerprint)
    _verified_signing_toolchain(checkout, reviewed_commit)
    before = _source_proof(archive, checkout, reviewed_commit, version)
    from release_attest import verify
    result = verify(archive, attestation, public_key,
                    expected_public_key_fingerprint=expected_key_fingerprint,
                    expected_commit=reviewed_commit, expected_version=version)
    after = _source_proof(archive, checkout, reviewed_commit, version)
    _verified_signing_toolchain(checkout, reviewed_commit)
    if (before['archive_sha256'] != after['archive_sha256'] or
            result['zip_sha256'] != before['archive_sha256'] or
            result['source_commit'] != reviewed_commit or result['version'] != version):
        raise ReleaseGateDenied('source_or_archive_changed_during_verification')
    return {'passed': True, 'action': 'verify_checked', 'commit': reviewed_commit,
            'zip_sha256': before['archive_sha256'], 'key_fingerprint': expected_key_fingerprint,
            'files_verified': after['tracked_files']}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('sign', 'verify'))
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--reviewed-commit', required=True)
    parser.add_argument('--public-key', required=True, type=Path)
    parser.add_argument('--expected-key-sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--private-key', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--attestation', type=Path)
    options = parser.parse_args(argv)
    common = dict(archive=options.archive, checkout=options.checkout,
                  reviewed_commit=options.reviewed_commit, public_key=options.public_key,
                  expected_key_fingerprint=options.expected_key_sha256, version=options.version)
    try:
        if options.action == 'sign':
            if options.private_key is None or options.output is None or options.attestation is not None:
                raise ReleaseGateDenied('sign_arguments_invalid')
            result = sign_checked(**common, private_key=options.private_key, output=options.output)
        else:
            if options.attestation is None or options.output is not None or options.private_key is not None:
                raise ReleaseGateDenied('verify_arguments_invalid')
            result = verify_checked(**common, attestation=options.attestation)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, PermissionError, RuntimeError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({'passed': False, 'error': type(exc).__name__ + ':' + str(exc)[:160]}),file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
