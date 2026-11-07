"""Narrow, local, independently observed file SHA-256 postconditions.

The operator configures trusted roots and exact tool bindings. This does not
prove a remote side effect, and cannot make a writable filesystem immutable.
"""
from __future__ import annotations
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_VERIFIABLE_BYTES = 32 * 1024 * 1024


def pointer_value(value: dict[str, Any], pointer: str) -> Any:
    node: Any = value
    if not pointer.startswith("/"):
        raise ValueError("postcondition_invalid_pointer")
    for component in pointer[1:].split("/"):
        key = component.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            raise ValueError("postcondition_missing_argument")
    return node


@dataclass(frozen=True)
class FileDigestVerifier:
    root: Path
    path_pointer: str
    digest_pointer: str
    root_identity: tuple[int, int] | None = None

    @classmethod
    def from_dict(cls, info: dict[str, Any]) -> "FileDigestVerifier":
        if not isinstance(info, dict) or set(info) != {"kind", "root", "path_pointer", "digest_pointer"}:
            raise ValueError("postcondition_fields_invalid")
        if info["kind"] != "file_sha256" or not all(isinstance(info[k], str) for k in ("root", "path_pointer", "digest_pointer")):
            raise ValueError("postcondition_value_invalid")
        root = Path(info["root"])
        if not root.is_absolute() or not root.exists() or root.is_symlink() or not root.is_dir():
            raise ValueError("postcondition_root_invalid")
        if not info["path_pointer"].startswith("/") or not info["digest_pointer"].startswith("/"):
            raise ValueError("postcondition_pointer_invalid")
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            identity = (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino)
        finally:
            os.close(root_fd)
        return cls(root.resolve(strict=True), info["path_pointer"], info["digest_pointer"], identity)

    def preflight(self, args: dict[str, Any]) -> tuple[Path, str]:
        """Reject unsafe postcondition inputs before an external effect can occur."""
        raw = pointer_value(args, self.path_pointer)
        expected = pointer_value(args, self.digest_pointer)
        if not isinstance(raw, str) or not raw or not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
            raise ValueError("postcondition_argument_invalid")
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or any(p in ('', '.') for p in relative.parts):
            raise ValueError("postcondition_path_unsafe")
        target = self.root / relative
        current = self.root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("postcondition_symlink_denied")
            # Existing components must remain inside the trusted root.
            if current.exists() and not current.resolve(strict=True).is_relative_to(self.root):
                raise ValueError("postcondition_escaped_root")
        return target, expected

    def verify(self, args: dict[str, Any]) -> dict[str, Any]:
        """Inspect only a relative regular file under the trusted root; never follow symlinks."""
        target, expected = self.preflight(args)
        if not target.resolve(strict=True).is_relative_to(self.root):
            raise ValueError("postcondition_escaped_root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        # POSIX: independently traverse every parent using no-follow directory
        # descriptors, so replacing a parent with a symlink cannot redirect
        # the verifier to a separate path between preflight and read.
        if os.name == "posix" and hasattr(os, "O_DIRECTORY"):
            raw = pointer_value(args, self.path_pointer)
            components = Path(raw).parts
            parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent_fd)
                if self.root_identity and (info.st_dev, info.st_ino) != self.root_identity:
                    raise ValueError("postcondition_root_replaced")
                for item in components[:-1]:
                    next_fd = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = next_fd
                fd = os.open(components[-1], flags, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        else:
            # Windows: this does not eliminate NTFS reparse-point races.
            fd = os.open(target, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_VERIFIABLE_BYTES:
                raise ValueError("postcondition_file_invalid")
            sha = hashlib.sha256()
            seen = 0
            while True:
                part = os.read(fd, min(65536, MAX_VERIFIABLE_BYTES + 1 - seen))
                if not part:
                    break
                seen += len(part)
                if seen > MAX_VERIFIABLE_BYTES:
                    raise ValueError("postcondition_file_too_large")
                sha.update(part)
        finally:
            os.close(fd)
        observed = sha.hexdigest()
        return {"verified": observed == expected, "kind": "file_sha256", "sha256": observed, "bytes": seen}
