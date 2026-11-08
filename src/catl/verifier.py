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


def _check_writers(st: os.stat_result) -> None:
    """Evidence writable by unrelated local identities is not independent proof.

    Owner-writable outputs remain supported. Group/world-writable directories
    and final files are deliberately refused for protected postconditions.
    This check is also repeated on pinned descriptors to catch chmod races.
    """
    if os.name == "posix" and st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("postcondition_evidence_writable_by_untrusted")


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
            root_info = os.fstat(root_fd)
            _check_writers(root_info)
            identity = (root_info.st_dev, root_info.st_ino)
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
        root_now = self.root.stat()
        _check_writers(root_now)
        if self.root_identity and (root_now.st_dev, root_now.st_ino) != self.root_identity:
            raise ValueError("postcondition_root_replaced_before_dispatch")
        current = self.root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("postcondition_symlink_denied")
            # Existing components must remain inside the trusted root.
            if current.exists():
                if not current.resolve(strict=True).is_relative_to(self.root):
                    raise ValueError("postcondition_escaped_root")
                # Fail before dispatch when an existing output is an alias
                # outside the trusted root or a special file. Post-dispatch
                # validation would be too late to prevent that side effect.
                mode = current.lstat()
                _check_writers(mode)
                if current == target:
                    if not stat.S_ISREG(mode.st_mode):
                        raise ValueError("postcondition_target_not_regular")
                    if mode.st_nlink != 1:
                        raise ValueError("postcondition_file_hardlinked")
                elif not stat.S_ISDIR(mode.st_mode):
                    raise ValueError("postcondition_parent_not_directory")
        return target, expected

    def verify(self, args: dict[str, Any]) -> dict[str, Any]:
        """Inspect only a relative regular file under the trusted root; never follow symlinks."""
        target, expected = self.preflight(args)
        if not target.resolve(strict=True).is_relative_to(self.root):
            raise ValueError("postcondition_escaped_root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        # Keep the opened directory descriptor until verification is complete.
        # That lets us verify the path still names the *same* inode without
        # following mutable parent paths or a substituted symlink.
        parent_fd: int | None = None
        fd: int | None = None
        try:
            if os.name == "posix" and hasattr(os, "O_DIRECTORY"):
                raw = pointer_value(args, self.path_pointer)
                components = Path(raw).parts
                parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                info = os.fstat(parent_fd)
                _check_writers(info)
                if self.root_identity and (info.st_dev, info.st_ino) != self.root_identity:
                    raise ValueError("postcondition_root_replaced")
                for item in components[:-1]:
                    next_fd = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=parent_fd)
                    try:
                        _check_writers(os.fstat(next_fd))
                    except BaseException:
                        os.close(next_fd)
                        raise
                    os.close(parent_fd)
                    parent_fd = next_fd
                fd = os.open(components[-1], flags, dir_fd=parent_fd)
            else:
                # Windows: this does not eliminate NTFS reparse-point races.
                fd = os.open(target, flags)

            before = os.fstat(fd)
            _check_writers(before)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_VERIFIABLE_BYTES:
                raise ValueError("postcondition_file_invalid")
            # A hardlink can alias a file *outside* the configured root. Such a
            # file cannot serve as scoped independent postcondition evidence.
            if before.st_nlink != 1:
                raise ValueError("postcondition_file_hardlinked")
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

            after = os.fstat(fd)
            pinned = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                                 st.st_ctime_ns, st.st_nlink, stat.S_IMODE(st.st_mode))
            if parent_fd is not None:
                # A directory can be renamed/replaced after the first open;
                # the pinned descriptor would then verify an orphaned path.
                # Walk afresh from the pinned root without following symlinks
                # and confirm the parent is still the same directory.
                check_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    root_now = os.fstat(check_fd)
                    _check_writers(root_now)
                    if self.root_identity and (root_now.st_dev, root_now.st_ino) != self.root_identity:
                        raise ValueError("postcondition_parent_replaced_during_read")
                    for component in components[:-1]:
                        next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                          os.O_NOFOLLOW, dir_fd=check_fd)
                        try:
                            _check_writers(os.fstat(next_fd))
                        except BaseException:
                            os.close(next_fd)
                            raise
                        os.close(check_fd)
                        check_fd = next_fd
                    parent_now = os.fstat(check_fd)
                    parent_before = os.fstat(parent_fd)
                    _check_writers(parent_before)
                    _check_writers(parent_now)
                    if ((parent_now.st_dev, parent_now.st_ino) !=
                            (parent_before.st_dev, parent_before.st_ino)):
                        raise ValueError("postcondition_parent_replaced_during_read")
                    current = os.stat(components[-1], dir_fd=check_fd,
                                      follow_symlinks=False)
                finally:
                    os.close(check_fd)
            else:
                current = os.lstat(target)
            if (not stat.S_ISREG(current.st_mode) or
                    (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)):
                raise ValueError("postcondition_file_replaced_during_read")
            _check_writers(after)
            _check_writers(current)
            if pinned(before) != pinned(after) or pinned(after) != pinned(current) or seen != after.st_size:
                raise ValueError("postcondition_file_changed_during_read")
        finally:
            if fd is not None:
                os.close(fd)
            if parent_fd is not None:
                os.close(parent_fd)
        observed = sha.hexdigest()
        return {"verified": observed == expected, "kind": "file_sha256", "sha256": observed, "bytes": seen}
