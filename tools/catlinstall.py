#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

class InstallerFailure(Exception):
    pass

def verify_manifest(root):
    man = root / "RELEASE_MANIFEST.json"
    if not man.exists():
        raise InstallerFailure("missing manifest at %s" % man)
    data = json.loads(man.read_text())
    if data.get("algorithm") != "sha256" or not isinstance(data.get("files"), dict):
        raise InstallerFailure("invalid manifest schema")
    for rel, digest in data["files"].items():
        p = root / rel
        if not p.is_file():
            raise InstallerFailure("missing managed entry: %s" % rel)
        import hashlib
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            raise InstallerFailure("hash mismatch: %s" % rel)

def detect_root(custom):
    if custom:
        r = Path(custom).resolve()
        if not r.is_dir():
            raise InstallerFailure("source root does not exist: %s" % r)
        return r
    if (REPO_ROOT / "RELEASE_MANIFEST.json").exists():
        return REPO_ROOT
    raise InstallerFailure("cannot auto-detect CATL root")

def preflight(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    python = args.python
    if not python or not Path(python).is_file():
        for c in ["/usr/bin/python3.12", "python3"]:
            if Path(c).is_file() and os.access(c, os.X_OK):
                python = c; break
    if not python:
        raise InstallerFailure("no usable Python")
    subprocess.run([python, "-c", "import os; print('PY_OK', os.uname().sysname if hasattr(os,'uname') else 'OK')"], check=True)
    print("[OK] preflight passed")

def run_or_fail(cmd):
    subprocess.run(cmd, check=True)

def install_plan(root):
    plan = {"directories": [], "services": []}
    for candidate in ["/var/lib/catl/state", "/var/lib/catl-anchor", "/var/lib/catl-tools/work"]:
        plan["directories"].append(candidate)
    return plan

def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise InstallerFailure("--install requires root")
    target_dir = Path("/var/lib/catl/state")
    target_dir.mkdir(parents=True, exist_ok=True)
    if target_dir.stat().st_uid != 0:
        raise InstallerFailure("ownership unsafe at %s" % target_dir)
    # no chown reset; explicit abort to keep incomplete state safe
    raise InstallerFailure("install is still scaffolded and unsafe; refusing partial success")

def verify_installed(args):
    files = ["/opt/carl-venv/bin/python"]
    missing = [p for p in files if not Path(p).exists()]
    if missing:
        raise InstallerFailure("missing installed components: %s" % ", ".join(missing))
    print("[OK] verify_installed passed (%d paths)" % (len(files)-len(missing)))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", default=None)
    ap.add_argument("--python", default="/usr/bin/python3.12")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--verify-installed", dest="verify_installed", action="store_true")
    args = ap.parse_args()
    if args.install:
        install(args)
    elif args.verify_installed:
        verify_installed(args)
    else:
        preflight(args)

if __name__ == "__main__":
    main()
