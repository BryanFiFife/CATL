#!/usr/bin/env python3
"""CATL Linux deployment preflight and reviewed-unit renderer.

The privileged installer is intentionally disabled until real Linux acceptance
and anchored-key recovery procedures exist. Nothing here provisions host state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
CATL_VENV = Path("/opt/catl/venv")
CATL_STATE = Path("/var/lib/catl/state")
CATL_ANCHOR = Path("/var/lib/catl-anchor")
CATL_WORK = Path("/var/lib/catl-tools/work")
CATL_SYSTEMD = Path("/etc/systemd/system")
CATL_POLICY = Path("/etc/catl/policy.json")

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
    """Expected, fail-closed installer or preflight rejection."""


def verify_manifest(root: Path) -> int:
    """Verify existing release files without changing any file or following symlinks."""
    root = Path(root).resolve(strict=True)
    manifest = root / "RELEASE_MANIFEST.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise InstallerFailure("missing or unsafe release manifest")
    try:
        obj = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallerFailure("unreadable release manifest") from exc
    files = obj.get("files") if isinstance(obj, dict) else None
    if not isinstance(obj, dict) or obj.get("algorithm") != "sha256" or not isinstance(files, dict) or not files:
        raise InstallerFailure("invalid manifest schema or empty manifest")
    for rel, expected in files.items():
        if not isinstance(rel, str) or not rel or "\\" in rel:
            raise InstallerFailure("invalid manifest path")
        parts = PurePosixPath(rel)
        if parts.is_absolute() or any(x in (".", "..") for x in rel.split("/")):
            raise InstallerFailure("unsafe manifest path: %s" % rel)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise InstallerFailure("invalid digest for: %s" % rel)
        target = root.joinpath(*parts.parts)
        if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(root):
            raise InstallerFailure("missing or unsafe manifest entry: %s" % rel)
        # Reject a symlink in any path component, not merely the leaf.
        parent = root
        for component in parts.parts[:-1]:
            parent = parent / component
            if parent.is_symlink():
                raise InstallerFailure("symlink in manifest path: %s" % rel)
        sha = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                sha.update(chunk)
        if sha.hexdigest() != expected:
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
    check = [resolved, "-c", "import sys; raise SystemExit(sys.version_info < (3, 11))"]
    try:
        subprocess.run(check, check=True, timeout=15, capture_output=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise InstallerFailure("Python 3.11+ interpreter validation failed") from exc
    return resolved


def run_or_fail(command, *, timeout=300):
    """Run a fixed argv without a shell; propagate errors and timeouts."""
    if not isinstance(command, (list, tuple)) or not command:
        raise InstallerFailure("missing subprocess argv")
    return subprocess.run(list(command), check=True, timeout=timeout)


def _check_unit_hardening(text: str, kind: str) -> None:
    lines = set(text.splitlines())
    for directive in COMMON_HARDENING:
        if directive not in lines:
            raise InstallerFailure("reviewed %s unit missing safeguard: %s" % (kind, directive))
    required = (
        ("User=catl-broker", "ExecStart=/usr/local/bin/catl broker")
        if kind == "broker" else
        ("User=catl-tools", "ExecStart=/usr/local/bin/catl backend-service")
    )
    if required[0] not in lines or not any(row.startswith(required[1]) for row in lines):
        raise InstallerFailure("unexpected %s unit identity or CLI entrypoint" % kind)
    if "AmbientCapabilities=CAP_NET_BIND_SERVICE" in text or "python -m catl." in text:
        raise InstallerFailure("unreviewed capability or module entrypoint in %s unit" % kind)


def render_unit_template(kind: str, *, root=None, identities=None) -> str:
    """Read reviewed templates; optionally resolve strictly numeric UID/GID fields.

    This only returns text. It never installs or enables a service.
    """
    if kind not in UNIT_FILES:
        raise InstallerFailure("unknown CATL service: %s" % kind)
    source = detect_root(root) / "packaging" / "systemd" / UNIT_FILES[kind]
    if source.is_symlink() or not source.is_file():
        raise InstallerFailure("reviewed unit template missing or unsafe: %s" % source)
    text = source.read_text(encoding="utf-8")
    _check_unit_hardening(text, kind)
    if identities is None:
        return text
    required = set(IDENTITY_TOKENS[kind])
    if not isinstance(identities, dict) or set(identities) != required:
        raise InstallerFailure("missing/extra UID/GID substitutions")
    for name in sorted(required):
        number = identities[name]
        if type(number) is not int or number < 1:
            raise InstallerFailure("invalid non-root UID/GID: %s" % name)
        if not re.search(r"\b" + name + r"\b", text):
            raise InstallerFailure("expected template placeholder missing: %s" % name)
        text = re.sub(r"\b" + name + r"\b", str(number), text)
    # Render only the package CLI path, not an invented Python module entrypoint.
    text = text.replace("/usr/local/bin/catl ", str(CATL_VENV / "bin/catl") + " ")
    _check_rendered_unit(text, kind)
    return text


def _check_rendered_unit(text: str, kind: str) -> None:
    lines = set(text.splitlines())
    if not set(COMMON_HARDENING).issubset(lines):
        raise InstallerFailure("rendered unit weakened security restrictions")
    if not any(line.startswith("ExecStart=" + str(CATL_VENV / "bin/catl") + " ") for line in lines):
        raise InstallerFailure("rendered unit lacks package CLI")
    if any(re.search(r"\b" + p + r"\b", text) for p in IDENTITY_TOKENS[kind]):
        raise InstallerFailure("unresolved UID/GID placeholder")


def preparation_phase(root: Path) -> dict:
    count = verify_manifest(root)
    for directory in ("src", "tools", "examples", "packaging/systemd"):
        if not (root / directory).is_dir():
            raise InstallerFailure("required source directory missing: %s" % directory)
    for kind in UNIT_FILES:
        render_unit_template(kind, root=root)
    return {"verified_manifest_entries": count, "reviewed_units": list(UNIT_FILES),
            "installation_enabled": False}


def preflight(args):
    root = detect_root(args.source_root)
    plan = preparation_phase(root)
    executable = find_python(args.python)
    print("[OK] verified %s release files; reviewed service templates: %s" %
          (plan["verified_manifest_entries"], ", ".join(plan["reviewed_units"])))
    print("[OK] interpreter:", executable)
    print("[BLOCKED] automated installation is disabled pending live Linux acceptance")


def install(args):
    # Deliberately no mkdir, chown, account provisioning, venv or service changes.
    # No privileged operation should occur until the entire transaction is vetted.
    raise InstallerFailure("automated installation disabled: isolated Linux acceptance and key/anchor recovery unverified")


def verify_installed(args):
    # A file-existence check is insufficient evidence of a working trust boundary.
    raise InstallerFailure("installed-state verification not implemented; refusing a false positive")


def main(argv=None):
    parser = argparse.ArgumentParser(description="CATL read-only deployment preflight (install disabled)")
    parser.add_argument("--source-root")
    parser.add_argument("--python", default=None)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--install", action="store_true")
    modes.add_argument("--verify-installed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.install:
            install(args)
        elif args.verify_installed:
            verify_installed(args)
        else:
            preflight(args)
    except (InstallerFailure, OSError) as exc:
        parser.exit(1, "[FAIL] %s\n" % exc)


if __name__ == "__main__":
    main()
