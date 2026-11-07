"""Deterministic canonicalisation, bounded serialisation and local HMAC key handling."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any

MAX_WIRE_BYTES = 1024 * 1024


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hmac_hex(key: bytes, value: Any) -> str:
    return hmac.new(key, canonical(value), hashlib.sha256).hexdigest()


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def strict_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_constant")))


def parse_json(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_WIRE_BYTES:
        raise ValueError("message_too_large")
    value = strict_loads(line.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected_object")
    return value


def get_or_create_key(path: Path) -> bytes:
    """Create key exclusively with 0600 on POSIX. Never follow key-file symlinks."""
    if path.parent.is_symlink():
        raise PermissionError("key_directory_symlink_refused")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        parent_info = path.parent.stat()
        if parent_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError("key_directory_permissions_too_open")
        if parent_info.st_uid != os.geteuid():
            raise PermissionError("key_directory_wrong_owner")
    if path.is_symlink():
        raise PermissionError("refusing_symlink_key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        pass
    else:
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    if path.is_symlink():
        raise PermissionError("refusing_symlink_key")
    s = path.stat()
    if not stat.S_ISREG(s.st_mode):
        raise PermissionError("key_not_regular_file")
    if os.name == "posix":
        if s.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError("key_permissions_too_open")
        if s.st_uid != os.geteuid():
            raise PermissionError("key_file_wrong_owner")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (os.name == "posix" and actual.st_uid != os.geteuid()):
            raise PermissionError("key_replaced_or_wrong_owner")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            key = handle.read(33)
    finally:
        os.close(fd)
    if len(key) != 32:
        raise ValueError("bad_key_length")
    return key
