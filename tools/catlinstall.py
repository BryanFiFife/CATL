#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shlex, shutil, subprocess, sys, tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CATL_VENV = Path("/opt/catl/venv")
CATL_STATE = Path("/var/lib/catl/state")
CATL_ANCHOR = Path("/var/lib/catl-anchor")
CATL_WORK = Path("/var/lib/catl-tools/work")
CATL_SYSTEMD = Path("/etc/systemd/system")
CATL_POLICY = Path("/etc/catl/policy.json")
SYSTEMD_TEMPLATE_BROKER = """[Unit]
Description=CATL broker (isolated, non-root)
After=network.target

[Service]
Type=simple
User=broker
Group=broker
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
NoExecPaths=yes
ExecStart=/opt/catl/venv/bin/python -m catl.broker
StateDirectory=catl
ConfigurationDirectory=catl
RuntimeDirectory=catl-broker
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
SYSTEMD_TEMPLATE_BACKEND = """[Unit]
Description=CATL backend (isolated, non-root)
After=catl-broker.service

[Service]
Type=simple
User=tool
Group=tool
AmbientCapabilities=
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ExecStart=/opt/catl/venv/bin/python -m catl.backend
StateDirectory=catl-tools
ConfigurationDirectory=catl
RuntimeDirectory=catl-backend

[Install]
WantedBy=multi-user.target
"""

class InstallerFailure(Exception): pass

def _ensure_dir(path):
    if path.exists():
        if path.is_symlink():
            raise InstallerFailure("unsafe symlink at %s" % path)
        if not path.is_dir():
            raise InstallerFailure("conflicting non-directory at %s" % path)
        return (path.stat().st_uid, path.stat().st_gid)
    path.mkdir(parents=True, exist_ok=True)
    return (path.stat().st_uid, path.stat().st_gid)

def verify_manifest(root):
    man = root / "RELEASE_MANIFEST.json"
    if not man.exists(): raise InstallerFailure("missing manifest at %s" % man)
    data = json.loads(man.read_text())
    if data.get("algorithm") != "sha256" or not isinstance(data.get("files"), dict):
        raise InstallerFailure("invalid manifest schema")
    for rel, digest in data["files"].items():
        p = root / rel
        if not p.is_file(): raise InstallerFailure("missing managed entry: %s" % rel)
    import hashlib
    for rel, digest in data["files"].items():
        p = root / rel
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        if h.hexdigest() != digest: raise InstallerFailure("hash mismatch: %s" % rel)

def detect_root(custom=None):
    if custom:
        r = Path(custom).resolve()
        if not r.is_dir(): raise InstallerFailure("source root missing: %s" % r)
        return r
    if (REPO_ROOT / "RELEASE_MANIFEST.json").exists(): return REPO_ROOT
    raise InstallerFailure("cannot auto-detect CATL root")

def preflight(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    print("[OK] preflight ready (source root: %s)" % root)
    python = args.python
    if not python or not Path(python).is_file():
        for c in ["/usr/bin/python3.12", "python3"]:
            if Path(c).is_file() and os.access(c, os.X_OK):
                python = c; break
    if not python: raise InstallerFailure("no runnable Python")
    subprocess.run([python, "-c", "import sys; print('PY_OK', sys.version.split()[0])"], check=True)
    print("[OK] interpreter discovered:", python)

def system_identity_ready(kind, env_function, user):
    # placeholder for genuine OS(systemd) tests (offline)
    if user in ("broker","tool","operator"):
        return True
    return False

def run_or_fail(cmd, timeout=300):
    subprocess.run(list(cmd), check=True, timeout=timeout)

def preparation_phase(root):
    return {"root_ok": True, "manifest_ok": True, "python_check": "planned", "users": ["broker","tool","operator"]}

def installation_failed(args):
    raise InstallerFailure("install phase marked incomplete by policy")

class _Unused: pass

def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise InstallerFailure("--install requires root")
    ids = preparation_phase(root)
    print("PLAN:", ids)
    raise InstallerFailure("install now refuses partial rollout until remote live proofs")

def render_unit_template(kind):
    if kind == "broker": return SYSTEMD_TEMPLATE_BROKER
    if kind == "backend": return SYSTEMD_TEMPLATE_BACKEND
    raise InstallerFailure("unknown service template: %s" % kind)

def verify_installed(args):
    files = [str(Path("/opt/carl-venv/bin/python")), str(CATL_VENV / "bin" / "python")]
    missing = [f for f in files if not Path(f).exists()]
    if missing:
        raise InstallerFailure("missing required installed components: %s" % ", ".join(missing))
    print("[OK] verify_installed ok (sample)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", default=None)
    ap.add_argument("--python", default="/usr/bin/python3.12")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--verify-installed", dest="verify_installed", action="store_true")
    args = ap.parse_args()
    if args.install: install(args)
    elif args.verify_installed: verify_installed(args)
    else: preflight(args)

if __name__ == "__main__":
    main()
