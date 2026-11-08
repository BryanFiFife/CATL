"""Deterministic, source-controlled CATL release ZIP with bounded verification.

Builds require a clean Git checkout. Only Git-tracked, regular source files are
eligible; ignored local secrets and arbitrary untracked files are never copied.
A manifest is NOT a signature: obtain released hashes via a trusted channel.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import stat
import subprocess
import tempfile
import tomllib
import unicodedata
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
STAMP = (2026, 11, 7, 0, 0, 0)
ZIP_DOS_TIME = (STAMP[3] << 11) | (STAMP[4] << 5) | (STAMP[5] // 2)
ZIP_DOS_DATE = ((STAMP[0] - 1980) << 9) | (STAMP[1] << 5) | STAMP[2]
SKIP_DIRS = {'.git', '.pytest_cache', '.mypy_cache', '.ruff_cache', '__pycache__', 'build', 'dist'}
SKIP_SUFFIXES = ('.pyc', '.pyo', '.whl')
SKIP_NAMES = {'RELEASE_MANIFEST.json', 'SHA256SUMS.txt'}
MAX_FILES = 4096
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 500
SENSITIVE_NAMES = {'.env', '.envrc', '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519', 'credentials.json', 'secrets.toml'}
SENSITIVE_SUFFIXES = ('.pem', '.key', '.p8', '.p12', '.pfx', '.sqlite', '.sqlite3', '.db', '.kdbx')
WINDOWS_DEVICE_NAMES = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} | {f'{kind}{n}' for kind in ('COM', 'LPT') for n in [*map(str, range(1, 10)), '¹', '²', '³']}


def _safe_name(name: str) -> str:
    if (not isinstance(name, str) or not name or name.startswith('/')
            or '\\' in name or '\x00' in name or '//' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError('release_unsafe_path')
    parts = name.split('/')
    if any(part in ('', '.', '..') or part.endswith(('.', ' ')) or
           any(c in '<>:"|?*' for c in part) or
           part.split('.', 1)[0].rstrip(' ').upper() in WINDOWS_DEVICE_NAMES
           for part in parts) or len(name) > 512:
        raise ValueError('release_unsafe_path')
    return name


def _portable_names(names) -> None:
    # Different Git names must not alias on case-insensitive or Unicode-
    # normalising filesystems during installation/extraction.
    canonical = set()
    for name in names:
        folded = unicodedata.normalize('NFC', _safe_name(name)).casefold()
        if folded in canonical:
            raise ValueError('release_cross_platform_filename_collision:' + name)
        canonical.add(folded)
    for folded in canonical:
        parts = folded.split('/')
        for i in range(1, len(parts)):
            if '/'.join(parts[:i]) in canonical:
                raise ValueError('release_cross_platform_file_directory_collision:' + folded)


def _excluded_source_path(name: str) -> bool:
    """Builder and offline verifier must agree about non-distributable paths."""
    parts = name.split('/')
    return (name in SKIP_NAMES or
            any(part in SKIP_DIRS or part.endswith('.egg-info') for part in parts) or
            name.endswith(SKIP_SUFFIXES))


def _sensitive_name(name: str) -> bool:
    parts = [part.lower() for part in name.split('/')]
    return (any(part in SENSITIVE_NAMES or part.startswith('.env.') for part in parts)
            or name.lower().endswith(SENSITIVE_SUFFIXES))


def _git(*args: str) -> bytes:
    try:
        return subprocess.run(['git', '--no-replace-objects', *args], cwd=ROOT, capture_output=True,
                              check=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('release_git_checkout_required') from exc


def _tracked_files(*, expected_commit: str | None = None) -> tuple[list[tuple[str, str, int]], str]:
    top = Path(os.fsdecode(_git('rev-parse', '--show-toplevel')).strip()).resolve()
    if top != ROOT.resolve():
        raise ValueError('release_git_root_mismatch')
    # Generated metadata is excluded from this cleanliness check because this
    # command regenerates it. ALL other tracked changes must be committed.
    dirty = _git('diff', '--name-only', '-z', 'HEAD', '--')
    for raw in dirty.split(b'\0'):
        if not raw:
            continue
        if os.fsdecode(raw) not in SKIP_NAMES:
            raise ValueError('release_tracked_source_dirty')
    # HEAD's immutable Git tree is authoritative. `git diff` and `git ls-files`
    # can hide modified working files marked skip-worktree/assume-unchanged.
    algorithm = _git('rev-parse', '--show-object-format').decode('ascii').strip()
    if algorithm not in ('sha1', 'sha256'):
        raise ValueError('release_git_object_format_unsupported')
    observed_commit = _git('rev-parse', 'HEAD').decode('ascii').strip()
    if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', observed_commit) or (
            expected_commit is not None and observed_commit != expected_commit):
        raise ValueError('release_unexpected_head_commit')
    raw_files = _git('ls-tree', '-r', '-z', '--full-tree', observed_commit)
    entries = []
    for row in raw_files.split(b'\0'):
        if not row:
            continue
        try:
            meta, raw = row.split(b'\t', 1)
            mode, kind, digest = meta.split(b' ')
            name = raw.decode('utf-8', 'strict')
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('release_git_tree_invalid') from exc
        _safe_name(name)
        if (mode not in (b'100644', b'100755') or kind != b'blob'
                or not re.fullmatch(b'[0-9a-f]{40}' if algorithm == 'sha1' else b'[0-9a-f]{64}', digest)):
            raise ValueError('release_unsafe_git_tree_entry:' + name)
        if _excluded_source_path(name):
            continue
        if _sensitive_name(name):
            raise ValueError('release_sensitive_tracked_path:' + name)
        entries.append((name, digest.decode('ascii'), 0o755 if mode == b'100755' else 0o644))
    if not entries or len(entries) > MAX_FILES or len(entries) != len(set(x[0] for x in entries)):
        raise ValueError('release_invalid_tracked_file_set')
    _portable_names(name for name, _digest, _mode in entries)
    return sorted(entries), algorithm


def _read_regular_source(name: str) -> bytes:
    path = ROOT
    for component in name.split('/')[:-1]:
        path = path / component
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError('release_untrusted_source_directory:' + name)
    path = ROOT.joinpath(*name.split('/'))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        raise ValueError('release_source_open_failed:' + name) from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > MAX_FILE_BYTES):
            raise ValueError('release_unsafe_source_file:' + name)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES or len(data) != info.st_size:
            raise ValueError('release_source_size_changed:' + name)
        return data
    finally:
        os.close(fd)


def release_files(*, expected_commit: str | None = None):
    total = 0
    entries, algorithm = _tracked_files(expected_commit=expected_commit)
    for name, committed_object_id, mode in entries:
        data = _read_regular_source(name)
        # Compare the actual bytes placed in the ZIP to the immutable HEAD
        # blob, not to an index that can suppress skip-worktree changes.
        git_object = b'blob ' + str(len(data)).encode('ascii') + b'\0' + data
        actual_oid = hashlib.new(algorithm, git_object).hexdigest()
        if actual_oid != committed_object_id:
            raise ValueError('release_tracked_blob_mismatch:' + name)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('release_source_total_oversized')
        yield name, data, mode


def manifest(entries):
    return {'name': 'caledapt-agent-trust', 'version': VERSION,
            'release_type': 'private-linux-hardening-release-candidate',
            'algorithm': 'sha256', 'signed': False,
            'files': {name: hashlib.sha256(data).hexdigest() for name, data, _mode in entries}}


def _write_zip(z: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    zi = zipfile.ZipInfo(name, STAMP)
    # Always encode Unix permissions, even when invoked on Windows. Without
    # this, byte-for-byte release determinism depends on the build host OS.
    zi.create_system = 3
    zi.create_version = 20
    zi.extract_version = 20
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = (stat.S_IFREG | mode) << 16
    z.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _metadata_targets_safe() -> None:
    # Never follow release-metadata symlinks into secrets or arbitrary files.
    for name in SKIP_NAMES:
        target = ROOT / name
        try:
            st = target.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or (os.name == 'posix' and st.st_uid != os.geteuid())):
            raise ValueError('release_metadata_target_untrusted:' + name)


def _atomic_metadata(target: Path, data: bytes) -> None:
    fd, tmpname = tempfile.mkstemp(prefix='.catl-meta-', dir=ROOT)
    tmp = Path(tmpname)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # The targets were checked before build. Never update a symlink, even
        # if a local process replaced the entry during the build.
        _metadata_targets_safe()
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def make(path: Path):
    path = Path(path).resolve(strict=False)
    if path == ROOT.resolve() or ROOT.resolve() in path.parents:
        raise ValueError('release_output_must_be_outside_source')
    _metadata_targets_safe()
    source_commit = _git('rev-parse', 'HEAD').decode('ascii').strip()
    if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', source_commit):
        raise ValueError('release_invalid_source_commit')
    entries = list(release_files(expected_commit=source_commit))
    if _git('rev-parse', 'HEAD').decode('ascii').strip() != source_commit:
        raise ValueError('release_head_changed_during_build')
    m = manifest(entries)
    m['source_commit'] = source_commit
    mdata = (json.dumps(m, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()
    sums = ''.join(f'{digest}  {name}\n' for name, digest in sorted(m['files'].items())).encode()
    if len(mdata) > MAX_METADATA_BYTES or len(sums) > MAX_METADATA_BYTES:
        raise ValueError('release_metadata_oversized')
    contents = sorted(entries + [('RELEASE_MANIFEST.json', mdata, 0o644), ('SHA256SUMS.txt', sums, 0o644)])
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unpredictable O_EXCL temporary prevents symlink pre-creation in /tmp.
    fd, tmpname = tempfile.mkstemp(prefix='.catl-archive-', suffix='.tmp', dir=path.parent)
    candidate = Path(tmpname)
    try:
        with os.fdopen(fd, 'w+b') as tmpstream:
            with zipfile.ZipFile(tmpstream, 'w', compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9, strict_timestamps=True) as z:
                for name, data, mode in contents:
                    _write_zip(z, name, data, mode)
            tmpstream.flush()
            os.fsync(tmpstream.fileno())
        if verify(candidate) != len(contents):
            raise ValueError('release_candidate_verification_failed')
        # Manifest and ZIP both derive from the same validated HEAD content.
        _metadata_targets_safe()
        os.replace(candidate, path)
    finally:
        candidate.unlink(missing_ok=True)
    # Local indexes are not signing evidence; write safely without opening the
    # destination symlink or partially writing the existing regular file.
    _atomic_metadata(ROOT / 'RELEASE_MANIFEST.json', mdata)
    _atomic_metadata(ROOT / 'SHA256SUMS.txt', sums)
    return {'files': len(contents), 'zip_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'zip_bytes': path.stat().st_size}


def _no_duplicate_keys(pairs):
    data = {}
    for k, v in pairs:
        if k in data:
            raise ValueError('release_duplicate_manifest_key')
        data[k] = v
    return data


def _bounded_read(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.file_size > limit:
        raise ValueError('release_zip_member_oversized:' + info.filename)
    with z.open(info, 'r') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('release_zip_member_oversized:' + info.filename)
    return data


def _validate_deflate_stream(f, item: zipfile.ZipInfo, start: int) -> None:
    """Consume every compressed byte. ZIP extraction can ignore hidden suffixes.

    Bounded decompression checks the entire raw DEFLATE stream before any
    contained source file can be approved. This also refuses trailing zlib
    members and truncated streams despite otherwise valid ZIP CRC/hash fields.
    """
    if item.compress_size < 1 or item.file_size / item.compress_size > MAX_COMPRESSION_RATIO:
        raise ValueError('release_zip_compression_ratio_invalid')
    decoder = zlib.decompressobj(-15)
    f.seek(start)
    remaining = item.compress_size
    produced = 0
    checksum = 0
    while remaining:
        chunk = f.read(min(65536, remaining))
        if not chunk or decoder.eof:
            raise ValueError('release_zip_deflate_stream_invalid')
        remaining -= len(chunk)
        try:
            uncompressed = decoder.decompress(chunk, item.file_size - produced + 1)
        except zlib.error as exc:
            raise ValueError('release_zip_deflate_stream_invalid') from exc
        produced += len(uncompressed)
        checksum = zlib.crc32(uncompressed, checksum)
        if (produced > item.file_size or decoder.unconsumed_tail or decoder.unused_data):
            raise ValueError('release_zip_hidden_compressed_payload')
    if not decoder.eof or produced != item.file_size or checksum != item.CRC:
        raise ValueError('release_zip_deflate_stream_incomplete_or_corrupt')


def _validate_zip_envelope(z: zipfile.ZipFile, members: list[zipfile.ZipInfo]) -> None:
    """Refuse ZIP polyglots, hidden local records, comments and noncanonical fields.

    Python's zipfile intentionally accepts prepended scripts and data following
    the last directory record. They have no name in RELEASE_MANIFEST and could
    otherwise be approved and signed. Public CATL archives have no such data.
    No extraction, unbounded allocation or private zipfile internals required.
    """
    f = z.fp
    if f is None:
        raise ValueError('release_zip_missing_stream')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size < 22:
        raise ValueError('release_zip_eocd_invalid')
    f.seek(size - 22)
    raw_eocd = f.read(22)
    if len(raw_eocd) != 22:
        raise ValueError('release_zip_eocd_invalid')
    signature, disk, cd_disk, disk_count, total_count, directory_size, directory_start, comment_len = (
        struct.unpack('<IHHHHIIH', raw_eocd))
    if (signature != 0x06054b50 or disk or cd_disk or comment_len or
            disk_count != total_count or total_count != len(members) or
            directory_start + directory_size != size - 22 or
            z.start_dir != directory_start or z.comment):
        raise ValueError('release_zip_noncanonical_container')
    offset = 0
    for item in sorted(members, key=lambda i: i.header_offset):
        if (item.header_offset != offset or item.flag_bits not in (0, 0x800)
                or (not item.filename.isascii() and item.flag_bits != 0x800)):
            raise ValueError('release_zip_hidden_local_entry_or_flags')
        if item.extra or item.comment:
            raise ValueError('release_zip_member_extra_or_comment')
        f.seek(offset)
        header = f.read(30)
        if len(header) != 30:
            raise ValueError('release_zip_local_header_truncated')
        (local_sig, version, flags, method, mod_time, mod_date, checksum,
         comp_size, file_size, name_size, extra_size) = struct.unpack('<IHHHHHIIIHH', header)
        if (local_sig != 0x04034b50 or version != 20 or flags != item.flag_bits or
                method != item.compress_type or mod_time != ZIP_DOS_TIME or
                mod_date != ZIP_DOS_DATE or checksum != item.CRC or
                comp_size != item.compress_size or file_size != item.file_size or
                extra_size or name_size < 1 or name_size > 512):
            raise ValueError('release_zip_local_header_mismatch')
        codec = 'utf-8' if flags & 0x800 else 'cp437'
        if f.read(name_size) != item.filename.encode(codec):
            raise ValueError('release_zip_local_filename_mismatch')
        if item.compress_type != zipfile.ZIP_DEFLATED:
            raise ValueError('release_zip_compression_method_invalid')
        _validate_deflate_stream(f, item, offset + 30 + name_size)
        offset += 30 + name_size + item.compress_size
    if offset != directory_start:
        raise ValueError('release_zip_unindexed_bytes_before_directory')
    f.seek(directory_start)
    for item in members:
        header = f.read(46)
        if len(header) != 46:
            raise ValueError('release_zip_central_header_truncated')
        (sig, made, required, flags, method, mtime, mdate, crc,
         compressed, uncompressed, name_size, extra_size, comment_size,
         disk_start, internal, external, local_offset) = struct.unpack('<IHHHHHHIIIHHHHHII', header)
        if (sig != 0x02014b50 or made != (3 << 8 | 20) or required != 20 or
                flags != item.flag_bits or mtime != ZIP_DOS_TIME or
                mdate != ZIP_DOS_DATE or extra_size or comment_size or disk_start or
                internal != 0 or (external & 0xffff) != 0 or item.date_time != STAMP or
                local_offset != item.header_offset or
                method != item.compress_type or crc != item.CRC or
                compressed != item.compress_size or uncompressed != item.file_size or
                external != item.external_attr or name_size < 1 or name_size > 512):
            raise ValueError('release_zip_central_header_mismatch')
        codec = 'utf-8' if flags & 0x800 else 'cp437'
        if f.read(name_size) != item.filename.encode(codec):
            raise ValueError('release_zip_central_filename_mismatch')
    if f.tell() != size - 22:
        raise ValueError('release_zip_unindexed_central_directory_bytes')


def verify(path: Path):
    with zipfile.ZipFile(path) as z:
        members = z.infolist()
        if len(members) < 3 or len(members) > MAX_FILES + 2:
            raise ValueError('release_zip_file_count_invalid')
        names = [item.filename for item in members]
        if len(names) != len(set(names)):
            raise ValueError('duplicate_zip_member')
        # Reject declared oversized payloads before spending CPU or memory
        # on DEFLATE decompression. Preserve the established refusal reason.
        declared_total = 0
        for member in members:
            limit = MAX_METADATA_BYTES if member.filename in SKIP_NAMES else MAX_FILE_BYTES
            if member.file_size > limit or member.file_size < 0:
                raise ValueError('release_zip_member_oversized:' + member.filename)
            declared_total += member.file_size
            if declared_total > MAX_TOTAL_BYTES + 2 * MAX_METADATA_BYTES:
                raise ValueError('release_zip_total_oversized')
        _validate_zip_envelope(z, members)
        _portable_names(names)
        total = 0
        for item in members:
            _safe_name(item.filename)
            if item.filename not in SKIP_NAMES and _excluded_source_path(item.filename):
                raise ValueError('release_zip_excluded_source_member:' + item.filename)
            if _sensitive_name(item.filename):
                raise ValueError('release_zip_sensitive_member:' + item.filename)
            mode = (item.external_attr >> 16) & 0xffff
            if (not stat.S_ISREG(mode) or stat.S_IMODE(mode) not in (0o644, 0o755) or item.flag_bits & 1
                    or item.compress_type != zipfile.ZIP_DEFLATED):
                raise ValueError('release_zip_member_type_invalid')
            limit = MAX_METADATA_BYTES if item.filename in SKIP_NAMES else MAX_FILE_BYTES
            if item.file_size > limit:
                raise ValueError('release_zip_member_oversized:' + item.filename)
            total += item.file_size
            if total > MAX_TOTAL_BYTES + 2 * MAX_METADATA_BYTES:
                raise ValueError('release_zip_total_oversized')
        lookup = {item.filename: item for item in members}
        if not SKIP_NAMES.issubset(lookup):
            raise ValueError('release_zip_metadata_missing')
        m = json.loads(_bounded_read(z, lookup['RELEASE_MANIFEST.json'], MAX_METADATA_BYTES),
                       object_pairs_hook=_no_duplicate_keys)
        if (not isinstance(m, dict) or m.get('algorithm') != 'sha256'
                or m.get('name') != 'caledapt-agent-trust'
                or m.get('version') != VERSION or m.get('signed') is not False
                or not isinstance(m.get('source_commit'), str)
                or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', m['source_commit'])
                or m.get('release_type') != 'private-linux-hardening-release-candidate'
                or not isinstance(m.get('files'), dict)):
            raise ValueError('release_manifest_schema_invalid')
        files = m['files']
        if not 1 <= len(files) <= MAX_FILES or set(names) != set(files) | SKIP_NAMES:
            raise ValueError('release_file_set_mismatch')
        if 'pyproject.toml' not in files:
            raise ValueError('release_project_metadata_missing')
        for name, digest in files.items():
            _safe_name(name)
            if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
                raise ValueError('release_manifest_digest_invalid')
            h = hashlib.sha256()
            with z.open(lookup[name], 'r') as stream:
                while chunk := stream.read(1024 * 1024):
                    h.update(chunk)
            if h.hexdigest() != digest:
                raise ValueError('file_hash_mismatch:' + name)
        # The manifest version MUST match the installable project's own
        # metadata. Self-consistent hashes alone do not ensure version parity.
        try:
            project = tomllib.loads(_bounded_read(z, lookup['pyproject.toml'], MAX_FILE_BYTES).decode('utf-8'))
            packaged_version = project['project']['version']
            packaged_name = project['project']['name']
        except (ValueError, UnicodeError, KeyError, TypeError) as exc:
            raise ValueError('release_project_metadata_invalid') from exc
        if packaged_version != m['version'] or packaged_name != m['name']:
            raise ValueError('release_packaged_identity_mismatch')
        checksum_data = _bounded_read(z, lookup['SHA256SUMS.txt'], MAX_METADATA_BYTES)
        try:
            checks = checksum_data.decode('utf-8', 'strict').splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError('release_checksum_utf8_invalid') from exc
        listed = {}
        for line in checks:
            match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            if match is None:
                raise ValueError('checksum_format_invalid')
            name = _safe_name(match[2])
            if name in listed:
                raise ValueError('duplicate_checksum_entry')
            listed[name] = match[1]
        if listed != files:
            raise ValueError('checksum_manifest_mismatch')
    return len(names)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--output', type=Path)
    group.add_argument('--verify', type=Path)
    opts = p.parse_args()
    if opts.output:
        result = make(opts.output)
        assert verify(opts.output) == result['files']
        print(json.dumps(result, sort_keys=True))
    else:
        print(f'PASS {verify(opts.verify)} verified archive files')
