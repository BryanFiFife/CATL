#!/usr/bin/env python3
"""CATL Linux installer and verifier.

Security principles:
- verify the release manifest before privileged changes;
- preserve existing state/anchors and refuse ambiguous recovery;
- use dedicated non-root service identities;
- render only the reviewed systemd templates shipped with CATL;
- make every mandatory subprocess fail closed;
- support a static/no-activation mode for containers and offline acceptance.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import NamedTuple
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
CATL_VENV = Path("/opt/catl/venv")
CATL_STATE = Path("/var/lib/catl/state")
CATL_ANCHOR = Path("/var/lib/catl-anchor")
CATL_WORK = Path("/var/lib/catl-tools/work")
CATL_POLICY = Path("/etc/catl/policy.json")
CATL_OPERATOR_PUBLIC = Path("/etc/catl/operator-public.hex")
CATL_TOOL_SERVER = Path("/opt/catl/tool-server.py")
CATL_SYSTEMD = Path("/etc/systemd/system")
CATL_TMPFILES = Path("/etc/tmpfiles.d/catl.conf")

SERVICE_USERS = ("catl-broker", "catl-agent", "catl-tools")
SERVICE_GROUPS = (
    "catl-broker", "catl-agent", "catl-tools",
    "catl-agent-ipc", "catl-operator-ipc", "catl-backend-ipc",
)
SUPPLEMENTARY = {
    "catl-broker": ("catl-agent-ipc", "catl-operator-ipc", "catl-backend-ipc"),
    "catl-agent": ("catl-agent-ipc",),
    "catl-tools": ("catl-backend-ipc",),
}
UNIT_FILES = {
    "broker": "catl-broker.service.example",
    "backend": "catl-backend.service.example",
}
IDENTITY_TOKENS = {
    "broker": ("AGENT_UID", "OPERATOR_UID", "AGENT_GID", "OPERATOR_GID", "TOOLS_UID"),
    "backend": ("BROKER_UID", "BACKEND_IPC_GID"),
}
COMMON_HARDENING = (
    "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true",
    "PrivateNetwork=yes", "IPAddressDeny=any", "RestrictAddressFamilies=AF_UNIX",
    "CapabilityBoundingSet=", "AmbientCapabilities=",
)


class InstallerFailure(RuntimeError):
    """Fail-closed installation or verification error."""


class IdentitySet(NamedTuple):
    broker_uid: int
    agent_uid: int
    operator_uid: int
    tools_uid: int
    agent_gid: int
    operator_gid: int
    backend_gid: int

    def unit_values(self, kind: str) -> dict[str, int]:
        if kind == "broker":
            return {
                "AGENT_UID": self.agent_uid,
                "OPERATOR_UID": self.operator_uid,
                "AGENT_GID": self.agent_gid,
                "OPERATOR_GID": self.operator_gid,
                "TOOLS_UID": self.tools_uid,
            }
        if kind == "backend":
            return {"BROKER_UID": self.broker_uid, "BACKEND_IPC_GID": self.backend_gid}
        raise InstallerFailure("unknown service kind: %s" % kind)


def _run(command, *, timeout=300, capture_output=False, text=False, cwd=None):
    if not isinstance(command, (list, tuple)) or not command:
        raise InstallerFailure("invalid subprocess argv")
    try:
        return subprocess.run(list(command), check=True, timeout=timeout,
                              capture_output=capture_output, text=text, cwd=cwd)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise InstallerFailure("command failed: %s" % " ".join(map(str, command))) from exc


def run_or_fail(command, *, timeout=300):
    return _run(command, timeout=timeout)


def verify_manifest(root: Path) -> int:
    root = Path(root).resolve(strict=True)
    manifest = root / "RELEASE_MANIFEST.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise InstallerFailure("missing or unsafe release manifest")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallerFailure("unreadable release manifest") from exc
    files = data.get("files") if isinstance(data, dict) else None
    if data.get("algorithm") != "sha256" or not isinstance(files, dict) or not files:
        raise InstallerFailure("invalid manifest schema or empty manifest")
    for rel, expected in files.items():
        if not isinstance(rel, str) or not rel or "\\" in rel:
            raise InstallerFailure("invalid manifest path")
        pure = PurePosixPath(rel)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in rel.split("/")):
            raise InstallerFailure("unsafe manifest path: %s" % rel)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise InstallerFailure("invalid digest for: %s" % rel)
        target = root.joinpath(*pure.parts)
        parent = root
        for component in pure.parts[:-1]:
            parent = parent / component
            if parent.is_symlink():
                raise InstallerFailure("symlink in manifest path: %s" % rel)
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
            raise InstallerFailure("missing or unsafe manifest entry: %s" % rel)
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise InstallerFailure("hash mismatch: %s" % rel)
    return len(files)


def detect_root(custom=None) -> Path:
    root = Path(custom).resolve() if custom else REPO_ROOT
    if not root.is_dir():
        raise InstallerFailure("source root missing: %s" % root)
    return root


def find_python(specified=None) -> str:
    candidate = specified or sys.executable or "python3"
    resolved = shutil.which(candidate)
    if not resolved or not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
        raise InstallerFailure("no executable Python interpreter: %s" % candidate)
    _run([resolved, "-c", "import sys; raise SystemExit(sys.version_info < (3,11))"],
         timeout=15, capture_output=True)
    return resolved


def _review_template(text: str, kind: str) -> None:
    lines = set(text.splitlines())
    for item in COMMON_HARDENING:
        if item not in lines:
            raise InstallerFailure("reviewed %s unit missing safeguard: %s" % (kind, item))
    required_user = "User=catl-broker" if kind == "broker" else "User=catl-tools"
    required_cli = "ExecStart=/usr/local/bin/catl broker" if kind == "broker" else "ExecStart=/usr/local/bin/catl backend-service"
    if required_user not in lines or not any(row.startswith(required_cli) for row in lines):
        raise InstallerFailure("unexpected %s unit identity or entrypoint" % kind)
    if "AmbientCapabilities=CAP_NET_BIND_SERVICE" in text or "python -m catl." in text:
        raise InstallerFailure("unreviewed capability or module entrypoint in %s unit" % kind)


def _template(root: Path, kind: str) -> str:
    if kind not in UNIT_FILES:
        raise InstallerFailure("unknown CATL service: %s" % kind)
    path = root / "packaging" / "systemd" / UNIT_FILES[kind]
    if path.is_symlink() or not path.is_file():
        raise InstallerFailure("reviewed unit template missing or unsafe: %s" % path)
    text = path.read_text(encoding="utf-8")
    _review_template(text, kind)
    return text


def render_unit_template(kind: str, identities: IdentitySet, *, root=None) -> str:
    source = detect_root(root)
    text = _template(source, kind)
    values = identities.unit_values(kind)
    required = set(IDENTITY_TOKENS[kind])
    if set(values) != required:
        raise InstallerFailure("identity substitution mismatch")
    for token, number in values.items():
        if type(number) is not int or number < 1:
            raise InstallerFailure("invalid non-root UID/GID: %s" % token)
        if not re.search(r"\b" + re.escape(token) + r"\b", text):
            raise InstallerFailure("expected placeholder missing: %s" % token)
        text = re.sub(r"\b" + re.escape(token) + r"\b", str(number), text)
    text = text.replace("/usr/local/bin/catl ", str(CATL_VENV / "bin/catl") + " ")
    if kind == "backend":
        text = text.replace("/usr/local/bin/python3 /opt/catl/tool-server.py",
                            str(CATL_VENV / "bin/python") + " " + str(CATL_TOOL_SERVER))
    if any(re.search(r"\b" + re.escape(token) + r"\b", text) for token in required):
        raise InstallerFailure("unresolved identity placeholder in %s unit" % kind)
    lines = set(text.splitlines())
    if not set(COMMON_HARDENING).issubset(lines):
        raise InstallerFailure("rendered unit weakened reviewed hardening")
    if not any(row.startswith("ExecStart=" + str(CATL_VENV / "bin/catl") + " ") for row in lines):
        raise InstallerFailure("rendered unit lacks CATL CLI entrypoint")
    return text


def _safe_regular(path: Path, *, max_bytes=1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise InstallerFailure("required regular file missing or unsafe: %s" % path)
    st = path.stat()
    if st.st_size > max_bytes or (st.st_mode & 0o022):
        raise InstallerFailure("unsafe writable/oversized input: %s" % path)
    return path.read_bytes()


def _validate_public_key(path: Path) -> bytes:
    raw = _safe_regular(path, max_bytes=4096).strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", raw):
        raise InstallerFailure("operator public key must be exactly 32-byte Ed25519 hex")
    return raw.lower() + b"\n"


def _require_linux_root() -> None:
    if sys.platform != "linux":
        raise InstallerFailure("automatic installation is supported only on Linux")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise InstallerFailure("--install requires root")


def _lookup_user(name: str):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def _lookup_group(name: str):
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def _ensure_group(name: str):
    found = _lookup_group(name)
    if found is None:
        _run(["groupadd", "--system", name])
        found = _lookup_group(name)
    if found is None or found.gr_gid == 0:
        raise InstallerFailure("failed to provision non-root group: %s" % name)
    return found


def _ensure_user(name: str):
    found = _lookup_user(name)
    if found is None:
        _ensure_group(name)
        shell = shutil.which("nologin") or "/usr/sbin/nologin"
        _run(["useradd", "--system", "--no-create-home", "--gid", name, "--shell", shell, name])
        found = _lookup_user(name)
    if found is None or found.pw_uid == 0:
        raise InstallerFailure("failed to provision non-root user: %s" % name)
    return found


def _ensure_membership(user: str, group: str) -> None:
    g = _ensure_group(group)
    u = _lookup_user(user)
    if u is None:
        raise InstallerFailure("user missing for group membership: %s" % user)
    if u.pw_gid != g.gr_gid and user not in g.gr_mem:
        _run(["usermod", "-a", "-G", group, user])
        g = _lookup_group(group)
        if g is None or user not in g.gr_mem:
            raise InstallerFailure("group membership did not persist: %s -> %s" % (user, group))


def _validate_operator_user(operator_user: str):
    if not operator_user:
        raise InstallerFailure("--operator-user is required")
    operator = _lookup_user(operator_user)
    if operator is None or operator.pw_uid == 0:
        raise InstallerFailure("operator user must already exist and be non-root")
    if operator_user in SERVICE_USERS:
        raise InstallerFailure("operator user must be distinct from CATL service users")
    return operator


def _require_command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved or not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
        raise InstallerFailure("required host command missing: %s" % name)
    return resolved


def _preflight_host_tools(*, activation: bool) -> None:
    for name in ("groupadd", "useradd", "usermod", "runuser", "systemd-analyze"):
        _require_command(name)
    if activation:
        _require_command("systemctl")


def _assert_secure_ancestor(path: Path) -> None:
    """Reject symlinked or writable privileged installation ancestors."""
    candidate = Path(path)
    parent = candidate.parent
    while not parent.exists():
        if parent == parent.parent:
            break
        parent = parent.parent
    current = parent
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise InstallerFailure("cannot inspect installation ancestor: %s" % current) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise InstallerFailure("unsafe installation ancestor: %s" % current)
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise InstallerFailure("untrusted writable installation ancestor: %s" % current)
        if current == Path("/"):
            break
        current = current.parent


def provision_identities(operator_user: str) -> IdentitySet:
    operator = _validate_operator_user(operator_user)
    for group in SERVICE_GROUPS:
        _ensure_group(group)
    for user in SERVICE_USERS:
        _ensure_user(user)
    for user, groups in SUPPLEMENTARY.items():
        for group in groups:
            _ensure_membership(user, group)
    _ensure_membership(operator_user, "catl-operator-ipc")
    broker = _lookup_user("catl-broker")
    agent = _lookup_user("catl-agent")
    tools = _lookup_user("catl-tools")
    ids = IdentitySet(
        broker.pw_uid, agent.pw_uid, operator.pw_uid, tools.pw_uid,
        _lookup_group("catl-agent-ipc").gr_gid,
        _lookup_group("catl-operator-ipc").gr_gid,
        _lookup_group("catl-backend-ipc").gr_gid,
    )
    if len({ids.broker_uid, ids.agent_uid, ids.operator_uid, ids.tools_uid}) != 4:
        raise InstallerFailure("CATL service/operator UIDs must be distinct")
    return ids


def _ensure_dir(path: Path, uid: int, gid: int, mode: int, *, preserve_existing=True) -> None:
    _assert_secure_ancestor(path)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise InstallerFailure("unsafe installation path: %s" % path)
        st = path.stat()
        actual_mode = stat.S_IMODE(st.st_mode)
        if preserve_existing and (st.st_uid != uid or st.st_gid != gid or actual_mode != mode):
            raise InstallerFailure("existing path ownership/mode mismatch: %s" % path)
        if not preserve_existing:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        return
    path.mkdir(parents=True, mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _atomic_write(path: Path, data: bytes, *, uid=0, gid=0, mode=0o644, preserve_equal=True) -> None:
    _assert_secure_ancestor(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise InstallerFailure("unsafe file target: %s" % path)
        current = path.read_bytes()
        if preserve_equal and current == data:
            return
    fd, temp_name = tempfile.mkstemp(prefix=".catl-install-", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        if path.is_symlink():
            raise InstallerFailure("target changed to symlink during write: %s" % path)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _state_anchor_precondition() -> str:
    for directory in (CATL_STATE, CATL_ANCHOR):
        if directory.is_symlink():
            raise InstallerFailure("unsafe symlinked protected directory: %s" % directory)
        if directory.exists() and not directory.is_dir():
            raise InstallerFailure("protected path is not a directory: %s" % directory)
    state_entries = list(CATL_STATE.iterdir()) if CATL_STATE.exists() else []
    anchor = CATL_ANCHOR / "head.json"
    if anchor.is_symlink():
        raise InstallerFailure("unsafe symlinked anchor")
    if anchor.exists() and not anchor.is_file():
        raise InstallerFailure("anchor is not a regular file")
    if anchor.exists() and not state_entries:
        raise InstallerFailure("anchor exists but state is empty; manual recovery required")
    if state_entries and not anchor.exists():
        raise InstallerFailure("existing state has no anchor; automatic recovery refused")
    return "existing" if anchor.exists() else "fresh"


def _install_venv(root: Path, python: str, wheelhouse: str | None, package_wheel: str | None = None) -> None:
    _assert_secure_ancestor(CATL_VENV)
    if CATL_VENV.exists() and (CATL_VENV.is_symlink() or not CATL_VENV.is_dir()):
        raise InstallerFailure("unsafe CATL venv target")
    if not CATL_VENV.exists():
        CATL_VENV.parent.mkdir(parents=True, exist_ok=True)
        _run([python, "-m", "venv", str(CATL_VENV)], timeout=180)
    vpython = CATL_VENV / "bin" / "python"
    if not vpython.is_file():
        raise InstallerFailure("CATL venv Python missing")
    pip = [str(vpython), "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]
    if wheelhouse:
        wheel = Path(wheelhouse).resolve(strict=True)
        if not wheel.is_dir():
            raise InstallerFailure("wheelhouse is not a directory")
        pip += ["--no-index", "--find-links", str(wheel)]
    target = str(root)
    if package_wheel:
        package = Path(package_wheel).resolve(strict=True)
        if package.is_symlink() or not package.is_file() or package.suffix != ".whl":
            raise InstallerFailure("--package-wheel must reference a regular wheel file")
        target = str(package)
    _run(pip + ["--upgrade", target], timeout=600)
    _run([str(CATL_VENV / "bin" / "catl"), "--help"], timeout=30, capture_output=True)


def _install_payload(root: Path, ids: IdentitySet, public_key: bytes) -> None:
    broker_gid = _lookup_group("catl-broker").gr_gid
    tools_gid = _lookup_group("catl-tools").gr_gid
    _ensure_dir(CATL_STATE, ids.broker_uid, broker_gid, 0o700)
    _ensure_dir(CATL_ANCHOR, ids.broker_uid, broker_gid, 0o700)
    _ensure_dir(CATL_WORK, ids.tools_uid, tools_gid, 0o700)
    _ensure_dir(Path("/run/catl-agent"), ids.broker_uid, ids.agent_gid, 0o710, preserve_existing=False)
    _ensure_dir(Path("/run/catl-operator"), ids.broker_uid, ids.operator_gid, 0o710, preserve_existing=False)
    _ensure_dir(Path("/run/catl-tools"), ids.tools_uid, ids.backend_gid, 0o710, preserve_existing=False)
    _ensure_dir(Path("/etc/catl"), 0, broker_gid, 0o750)
    _ensure_dir(Path("/opt/catl"), 0, 0, 0o755)

    policy = (root / "examples" / "policy.json")
    tool_server = (root / "examples" / "mock_server.py")
    tmpfiles = (root / "packaging" / "tmpfiles.d" / "catl.conf.example")
    policy_bytes = _safe_regular(policy)
    tool_bytes = _safe_regular(tool_server)
    tmpfiles_bytes = _safe_regular(tmpfiles)
    if CATL_POLICY.exists():
        if CATL_POLICY.is_symlink() or not CATL_POLICY.is_file():
            raise InstallerFailure("unsafe existing policy")
        # Existing policy is operator-controlled state: preserve exactly.
    else:
        _atomic_write(CATL_POLICY, policy_bytes, uid=0, gid=broker_gid, mode=0o640)
    if CATL_OPERATOR_PUBLIC.exists():
        if CATL_OPERATOR_PUBLIC.read_bytes() != public_key:
            raise InstallerFailure("existing operator public key differs; explicit rotation required")
    else:
        _atomic_write(CATL_OPERATOR_PUBLIC, public_key, uid=0, gid=broker_gid, mode=0o640)
    _atomic_write(CATL_TOOL_SERVER, tool_bytes, uid=0, gid=0, mode=0o755)
    _atomic_write(CATL_TMPFILES, tmpfiles_bytes, uid=0, gid=0, mode=0o644)
    for kind, destination in (("backend", CATL_SYSTEMD / "catl-backend.service"),
                              ("broker", CATL_SYSTEMD / "catl-broker.service")):
        rendered = render_unit_template(kind, ids, root=root).encode("utf-8")
        _atomic_write(destination, rendered, uid=0, gid=0, mode=0o644)


def _bootstrap_anchor_if_fresh(state_kind: str) -> None:
    if state_kind != "fresh":
        return
    _run(["runuser", "-u", "catl-broker", "--",
          str(CATL_VENV / "bin/catl"), "anchor-init",
          "--state-dir", str(CATL_STATE), "--anchor-path", str(CATL_ANCHOR / "head.json"),
          "--accept-current-verified-head"], timeout=120)


def _static_verify(ids: IdentitySet) -> None:
    broker_group = _lookup_group("catl-broker")
    tools_group = _lookup_group("catl-tools")
    if broker_group is None or tools_group is None:
        raise InstallerFailure("CATL service groups are incomplete")
    checks = (
        (CATL_STATE, ids.broker_uid, broker_group.gr_gid, 0o700),
        (CATL_ANCHOR, ids.broker_uid, broker_group.gr_gid, 0o700),
        (CATL_WORK, ids.tools_uid, tools_group.gr_gid, 0o700),
    )
    for path, uid, gid, mode in checks:
        if path.is_symlink() or not path.is_dir():
            raise InstallerFailure("required directory missing/unsafe: %s" % path)
        st = path.stat()
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
            raise InstallerFailure("ownership/mode verification failed: %s" % path)
    required = [CATL_POLICY, CATL_OPERATOR_PUBLIC, CATL_TOOL_SERVER,
                CATL_SYSTEMD / "catl-broker.service", CATL_SYSTEMD / "catl-backend.service"]
    for path in required:
        if path.is_symlink() or not path.is_file():
            raise InstallerFailure("required installed file missing/unsafe: %s" % path)
    _run([str(CATL_VENV / "bin/catl"), "--help"], timeout=30, capture_output=True)
    _run(["systemd-analyze", "verify", str(CATL_SYSTEMD / "catl-backend.service"),
          str(CATL_SYSTEMD / "catl-broker.service")], timeout=60, capture_output=True)


def _doctor(ids: IdentitySet, *, strict=False) -> None:
    command = ["runuser", "-u", "catl-broker", "--", str(CATL_VENV / "bin/catl"), "doctor",
               "--config", str(CATL_POLICY), "--state-dir", str(CATL_STATE),
               "--anchor-path", str(CATL_ANCHOR / "head.json"), "--agent-uid", str(ids.agent_uid),
               "--operator-uid", str(ids.operator_uid), "--backend-uid", str(ids.tools_uid)]
    if strict:
        command.append("--strict")
    _run(command, timeout=60)


def _host_audit() -> None:
    _run([str(CATL_VENV / "bin/catl"), "host-audit",
          "--broker-unit", "catl-broker.service",
          "--backend-unit", "catl-backend.service",
          "--broker-user", "catl-broker",
          "--backend-user", "catl-tools"], timeout=60)


def _activate_systemd() -> None:
    _run(["systemctl", "daemon-reload"], timeout=60)
    _run(["systemctl", "enable", "catl-backend.service", "catl-broker.service"], timeout=60)
    _run(["systemctl", "restart", "catl-backend.service"], timeout=60)
    _run(["systemctl", "restart", "catl-broker.service"], timeout=60)
    _run(["systemctl", "is-active", "--quiet", "catl-backend.service"], timeout=30)
    _run(["systemctl", "is-active", "--quiet", "catl-broker.service"], timeout=30)


def _identities_from_existing(operator_user: str) -> IdentitySet:
    operator = _lookup_user(operator_user) if operator_user else None
    broker = _lookup_user("catl-broker")
    agent = _lookup_user("catl-agent")
    tools = _lookup_user("catl-tools")
    ga = _lookup_group("catl-agent-ipc")
    go = _lookup_group("catl-operator-ipc")
    gb = _lookup_group("catl-backend-ipc")
    if not all((operator, broker, agent, tools, ga, go, gb)):
        raise InstallerFailure("CATL identities are incomplete")
    ids = IdentitySet(broker.pw_uid, agent.pw_uid, operator.pw_uid, tools.pw_uid,
                      ga.gr_gid, go.gr_gid, gb.gr_gid)
    if 0 in (ids.broker_uid, ids.agent_uid, ids.operator_uid, ids.tools_uid):
        raise InstallerFailure("root identity detected in CATL service/operator set")
    if len({ids.broker_uid, ids.agent_uid, ids.operator_uid, ids.tools_uid}) != 4:
        raise InstallerFailure("CATL service/operator UIDs are not distinct")
    return ids


def preparation_phase(root: Path, operator_public_key: Path | None = None) -> dict:
    count = verify_manifest(root)
    for directory in ("src", "tools", "examples", "packaging/systemd", "packaging/tmpfiles.d"):
        if not (root / directory).is_dir():
            raise InstallerFailure("required source directory missing: %s" % directory)
    for kind in UNIT_FILES:
        _template(root, kind)
    if operator_public_key is not None:
        _validate_public_key(operator_public_key)
    return {"verified_manifest_entries": count, "reviewed_units": sorted(UNIT_FILES)}


def preflight(args) -> None:
    root = detect_root(args.source_root)
    result = preparation_phase(root, Path(args.operator_public_key) if args.operator_public_key else None)
    python = find_python(args.python)
    print("[OK] manifest entries:", result["verified_manifest_entries"])
    print("[OK] reviewed units:", ", ".join(result["reviewed_units"]))
    print("[OK] Python:", python)
    if not args.operator_user:
        print("[WARN] --operator-user is required for installation")
    if not args.operator_public_key:
        print("[WARN] --operator-public-key is required for installation")


def install(args) -> None:
    _require_linux_root()
    root = detect_root(args.source_root)
    if not args.operator_public_key:
        raise InstallerFailure("--operator-public-key is required")
    key_path = Path(args.operator_public_key).resolve(strict=True)
    preparation_phase(root, key_path)
    python = find_python(args.python)
    public_key = _validate_public_key(key_path)

    # Read-only host checks happen before any privileged filesystem/account mutation.
    _validate_operator_user(args.operator_user)
    _preflight_host_tools(activation=not args.no_systemd_activate)
    state_kind = _state_anchor_precondition()
    for target in (CATL_VENV, CATL_STATE, CATL_ANCHOR, CATL_WORK, CATL_POLICY,
                   CATL_OPERATOR_PUBLIC, CATL_TOOL_SERVER, CATL_SYSTEMD, CATL_TMPFILES):
        _assert_secure_ancestor(target)

    # Install/test the package first. A dependency/build failure must not create
    # service users, protected state or systemd units.
    _install_venv(root, python, args.wheelhouse, args.package_wheel)

    ids = provision_identities(args.operator_user)
    _install_payload(root, ids, public_key)
    _bootstrap_anchor_if_fresh(state_kind)
    _static_verify(ids)
    _doctor(ids, strict=False)
    if not args.no_systemd_activate:
        _activate_systemd()
        _host_audit()
    print("[OK] CATL installation verified" + (" (static/no activation)" if args.no_systemd_activate else ""))

def verify_installed(args) -> None:
    _require_linux_root()
    _preflight_host_tools(activation=not args.no_systemd_activate)
    ids = _identities_from_existing(args.operator_user)
    _state_anchor_precondition()
    _static_verify(ids)
    _doctor(ids, strict=False)
    if not args.no_systemd_activate:
        _run(["systemctl", "is-active", "--quiet", "catl-backend.service"], timeout=30)
        _run(["systemctl", "is-active", "--quiet", "catl-broker.service"], timeout=30)
        _host_audit()
    print("[OK] installed CATL verified")

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CATL Linux installer and deployment verifier")
    parser.add_argument("--source-root")
    parser.add_argument("--python", default=None)
    parser.add_argument("--operator-user")
    parser.add_argument("--operator-public-key")
    parser.add_argument("--wheelhouse")
    parser.add_argument("--package-wheel", help="install a prebuilt CATL wheel instead of building the source tree")
    parser.add_argument("--no-systemd-activate", action="store_true",
                        help="install/verify static deployment but do not daemon-reload, enable or start services")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--install", action="store_true")
    modes.add_argument("--verify-installed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.install:
            install(args)
        elif args.verify_installed:
            if not args.operator_user:
                raise InstallerFailure("--operator-user is required for installed verification")
            verify_installed(args)
        else:
            preflight(args)
        return 0
    except InstallerFailure as exc:
        parser.exit(1, "[FAIL] %s\n" % exc)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
