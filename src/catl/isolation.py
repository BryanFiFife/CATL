"""Portable subprocess identity guard. Separate UID != full OS sandbox."""
from __future__ import annotations
import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Isolation:
    user: int | None = None
    group: int | None = None
    extra_groups: tuple[int, ...] | None = None
    sandbox_user: str | None = None
    unsandboxed: bool = False


def isolation_for(backend_user: str | None, allow_unsandboxed: bool) -> Isolation:
    """Require an explicit safer identity; never silently run a privileged child."""
    if backend_user:
        if os.name != "posix":
            raise RuntimeError("backend_user_supported_on_posix_only")
        import pwd
        try:
            entry = pwd.getpwnam(backend_user)
        except KeyError as exc:
            raise ValueError("backend_user_unknown") from exc
        if entry.pw_uid == 0 or entry.pw_uid == os.geteuid():
            raise PermissionError("backend_must_have_distinct_unprivileged_uid")
        if os.geteuid() != 0:
            raise PermissionError("backend_user_requires_root_or_external_supervisor")
        return Isolation(user=entry.pw_uid, group=entry.pw_gid, extra_groups=(), sandbox_user=entry.pw_name)
    if not allow_unsandboxed:
        raise PermissionError("isolation_required: specify --backend-user on POSIX or --allow-unsandboxed for a demo")
    return Isolation(unsandboxed=True)


SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR")


def child_environment(*, pass_env: tuple[str, ...] = (), sandbox_home: str | None = None) -> dict[str, str]:
    """No inherited cloud tokens or agent-side secrets by default."""
    import re
    requested = tuple(pass_env)
    if any(not re.fullmatch(r"[A-Z_][A-Z0-9_]*", x) for x in requested):
        raise ValueError("invalid_pass_env_name")
    env = {name: os.environ[name] for name in SAFE_ENV_KEYS if name in os.environ}
    env.update({name: os.environ[name] for name in requested if name in os.environ})
    if sandbox_home:
        env["HOME"] = sandbox_home
    elif "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    if sys.platform == "win32":
        for key in ("USERPROFILE", "HOMEDRIVE", "HOMEPATH"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def validate_workdir(workdir: Path | None) -> str | None:
    if workdir is None:
        return None
    root = workdir.resolve(strict=True)
    if not root.is_dir() or workdir.is_symlink():
        raise ValueError("backend_workdir_invalid")
    return str(root)
