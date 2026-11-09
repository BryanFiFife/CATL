#!/usr/bin/env python3
"""CATL Linux installer: testable scaffolding with real check abstractions."""
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
    print("[OK] source root:", root)
    ex = args.python
    if not ex or not Path(ex).is_file():
        for cand in ["/usr/bin/python3.12", "python3"]:
            if Path(cand).is_file() and os.access(cand, os.X_OK):
                ex = cand
                break
    if not ex:
        raise InstallerFailure("missing usable Python interpreter")
    subprocess.run([ex, "-c", "import sys; print('PY_OK', sys.version.split()[0])"], check=True)
    print("[OK] Python interpreter:", ex)
    for d in ("tools", "examples", "src", "packaging"):
        if not (root / d).is_dir():
            raise InstallerFailure("missing required source directory: %s" % d)
    print("[OK] preflight: source shape valid")

def run_or_fail(argv):
    subprocess.run(list(argv), check=True)

def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise InstallerFailure("--install requires root")
    for target in [Path("/var/lib/catl/state"), Path("/var/lib/catl-anchor"),
                   Path("/var/lib/catl-tools/work")]:
        if target.exists() is False:
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, 0o700)
        elif os.stat(target).st_uid != 0 or (os.stat(target).st_mode & 0o007) != 0:
            raise InstallerFailure("unsafe/incorrect ownership at %s" % target)
    print("[OK] idempotent ownership check passed")
    # deliberate scaffolding safeguard
    raise InstallerFailure("install stage not yet production-ready; explicit abort for incomplete scaffold")

def verify_installed(args):
    print("=== installed verification ===")
    failures = []
    for p in ["/opt/carl-venv/bin/python", "/etc/carl/policy.json"]:
        if not Path(p).exists():
            failures.append(p)
            print("[FAIL] missing:", p)
        else:
            print("[OK  ]", p)
    if failures:
        raise InstallerFailure("installation incomplete; failing components: %s" % ", ".join(failures))
    print("[OK] verify_installed complete")

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
