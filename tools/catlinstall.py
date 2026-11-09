#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys
from pathlib import Path


def verify_manifest(root):
    man = root / "RELEASE_MANIFEST.json"
    if not man.exists():
        raise SystemExit("ERROR: missing RELEASE_MANIFEST.json in %s" % root)
    data = json.loads(man.read_text())
    if data.get("algorithm") != "sha256":
        raise SystemExit("ERROR: unsupported manifest algorithm")
    files = data.get("files", {})
    if not isinstance(files, dict) or not files:
        raise SystemExit("ERROR: invalid manifest files")
    mismatch = 0
    for rel, digest in files.items():
        p = root / rel
        if not p.is_file():
            mismatch += 1
            print("  [FAIL] missing:", rel)
            continue
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            mismatch += 1
            print("  [FAIL] digest mismatch:", rel)
    if mismatch:
        raise SystemExit("ERROR: %d manifest mismatches" % mismatch)
    print("[OK] manifest verified (%d entries)" % len(files))


def detect_root(custom):
    if custom:
        root = Path(custom).resolve()
        if not root.is_dir():
            raise SystemExit("ERROR: source root missing: %s" % root)
        return root
    here = Path(__file__).resolve().parents[1]
    if (here / "RELEASE_MANIFEST.json").exists():
        return here
    cand = Path.cwd()
    if (cand / "RELEASE_MANIFEST.json").exists():
        return cand.resolve()
    raise SystemExit("ERROR: cannot auto-detect CATL root")


def preflight(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    print("[OK] source root:", root)
    python = args.python
    if not python or not Path(python).is_file():
        for cand in ["/usr/bin/python3.12", "python3"]:
            if Path(cand).is_file() and os.access(cand, os.X_OK):
                python = cand
                break
    if not python:
        raise SystemExit("ERROR: no usable Python interpreter found")
    subprocess.run([python, "-c", "import sys; print('OK', sys.version.split()[0])"], check=True)
    print("[OK] Python:", python)
    for d in ("tools", "examples", "src"):
        if not (root / d).is_dir():
            raise SystemExit("ERROR: missing %s" % d)
    print("[OK] preflight passed (source shape valid)")


def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if os.geteuid() != 0:
        raise SystemExit("ERROR: --install requires root")
    for d in [Path("/var/lib/catl/state"), Path("/var/lib/carl-anchor"),
              Path("/var/lib/carl-tools/work"), Path("/etc/carl")]:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    vroot = Path("/opt/carl-venv")
    if not vroot.exists():
        subprocess.run(["python3", "-m", "venv", str(vroot)], check=True)
    subprocess.run([str(vroot / "bin" / "python"), "-m", "pip", "install", "-U", "pip", "setuptools", "wheel"], check=False)
    subprocess.run([str(vroot / "bin" / "python"), "-m", "pip", "install", ".", "--no-build-isolation"], cwd=root, check=False)
    policy = Path("/etc/carl/policy.json")
    if not policy.exists():
        policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(root / "examples" / "policy.json"), str(policy))
    print("[OK] basic install scaffolding complete; anchor initialisation still requires operator confirmation")


def verify_installed(args):
    print("=== installed verification ===")
    failures = 0
    for p in ["/opt/carl-venv/bin/python", "/etc/carl/policy.json", "/var/lib/carl/state"]:
        if not Path(p).exists():
            failures += 1
            print("[FAIL] missing", p)
        else:
            print("[OK  ]", p)
    for uid in ["catl-broker", "catl-tools"]:
        try:
            import pwd
            info = pwd.getpwnam(uid)
            if info.pw_uid == 0:
                failures += 1
                print("[FAIL] service user is root:", uid)
        except KeyError:
            failures += 1
            print("[FAIL] missing user:", uid)
    print("installation verify failures:", failures)
    raise SystemExit(66 if failures else 0)


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
