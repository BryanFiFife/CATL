"""Separate keyed rollback checkpoint for CATL's receipt stream.

Not a TPM/remote/notarised witness. Keeping this file under a different
protected directory from audit.sqlite3 detects a database-only rollback.
There is deliberately no automatic reconciliation after a crash: differences
fail closed until investigated by a trusted administrator.
"""
from __future__ import annotations

import contextlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Iterator

from .crypto import hmac_hex, strict_loads


class AnchorGuard:
    def __init__(self, path: Path, key: bytes):
        self.path = Path(path)
        self.key = key
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise PermissionError("anchor_parent_untrusted")
        if os.name == "posix":
            parent = self.path.parent.stat()
            if parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise PermissionError("anchor_parent_writable_by_others")
            if parent.st_uid != os.geteuid():
                raise PermissionError("anchor_parent_wrong_owner")

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        if os.name != "posix":
            raise PermissionError("anchor_lock_supported_on_posix_only")
        import fcntl
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise PermissionError("anchor_lock_permissions_invalid")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _document(self, count: int, head_mac: str) -> dict:
        if type(count) is not int or count < 0 or not isinstance(head_mac, str):
            raise ValueError("anchor_head_invalid")
        return {"version": 1, "receipt_count": count, "receipt_head_mac": head_mac}

    def _sealed(self, doc: dict) -> bytes:
        body = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        sig = hmac_hex(self.key, {"domain": "CATL/ANCHOR/v1", "body": body})
        return (json.dumps({"body": doc, "mac": sig}, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    def read(self) -> dict:
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                raise PermissionError("anchor_file_invalid")
            if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise PermissionError("anchor_file_permissions_invalid")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(4097)
        finally:
            os.close(fd)
        try:
            value = strict_loads(raw.decode("utf-8"))
            doc = value["body"]
            if not isinstance(doc, dict) or set(doc) != {"version", "receipt_count", "receipt_head_mac"}:
                raise ValueError("anchor_schema_invalid")
            if doc["version"] != 1 or type(doc["receipt_count"]) is not int or doc["receipt_count"] < 0:
                raise ValueError("anchor_schema_invalid")
            if not isinstance(doc["receipt_head_mac"], str) or len(doc["receipt_head_mac"]) > 128:
                raise ValueError("anchor_schema_invalid")
            # Verify over the exact canonical body, not a caller-provided string.
            parsed = strict_loads(self._sealed(doc).decode("utf-8"))
            if not isinstance(value["mac"], str) or not hmac.compare_digest(value["mac"], parsed["mac"]):
                raise ValueError("anchor_signature_invalid")
        except (UnicodeError, ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as exc:
            raise PermissionError("anchor_integrity_invalid") from exc
        return doc

    def assert_head(self, count: int, head_mac: str) -> None:
        doc = self.read()  # missing or corrupt anchor must fail closed
        if doc["receipt_count"] != count or not hmac.compare_digest(doc["receipt_head_mac"], head_mac):
            raise PermissionError("audit_rollback_or_unanchored_commit")

    def _atomic_write(self, count: int, head_mac: str, *, exclusive: bool = False) -> None:
        payload = self._sealed(self._document(count, head_mac))
        if exclusive and self.path.exists():
            raise FileExistsError("anchor_already_exists")
        fd, tmp = tempfile.mkstemp(prefix=".catl-anchor-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            # Strict bootstrap: cannot silently replace an existing checkpoint.
            if exclusive:
                os.link(tmp, self.path, follow_symlinks=False)
                os.unlink(tmp)
            else:
                if self.path.is_symlink():
                    raise PermissionError("anchor_symlink_refused")
                os.replace(tmp, self.path)
            dirfd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def bootstrap(self, count: int, head_mac: str) -> None:
        with self.locked():
            self._atomic_write(count, head_mac, exclusive=True)

    def advance(self, count: int, head_mac: str) -> None:
        # Caller MUST already hold the exclusive anchor lock.
        self._atomic_write(count, head_mac)
