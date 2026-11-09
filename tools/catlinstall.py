#!/usr/bin/env python3
"""CATL Linux installer (combined with installer and stub test)."""
from __future__ import annotations

import argparse, hashlib, json, os, pathlib, shutil, stat, subprocess, sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def verify_manifest(root: Path):
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
            mismatch += 1; print("  [FAIL] missing:", rel); continue
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            mismatch += 1; print("  [FAIL] digest mismatch:", rel)
    if mismatch:
        raise SystemExit("ERROR: %d manifest mismatches" % mismatch)
    sums = root / "SHA256SUMS.txt"
    if sums.exists():
        parsed = {}
        for line in sums.read_text().splitlines():
            parts = line.split("  ", 1)
            if len(parts) != 2:
                raise SystemExit("ERROR: bad checksum row")
            parsed[parts[1]] = parts[0]
        if parsed != files:
            raise SystemExit("ERROR: checksum index differs from manifest")
    print("[OK] manifest verified (%d entries)" % len(files))


def detect_root(custom=None):
    if custom:
        root = Path(custom).resolve()
        if not root.is_dir():
            raise SystemExit("ERROR: source root missing: %s" % custom)
        return root
    if (REPO_ROOT / "RELEASE_MANIFEST.json").exists():
        return REPO_ROOT
    cand = Path.cwd()
    if (cand / "RELEASE_MANIFEST.json").exists():
        return cand.resolve()
    raise SystemExit("ERROR: cannot auto-detect CATL root")


def preflight(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    python = args.python
    if not python or not Path(python).is_file():
        for cand in ["/usr/bin/python3.12", "python3"]:
            if Path(cand).is_file() and os.access(cand, os.X_OK):
                python = cand
                break
    if not python:
        raise SystemExit("ERROR: no usable Python interpreter found")
    subprocess.run([python, "-c", "import sys; print('OK', sys.version.split()[0])"], check=True)
    for d in ("tools", "examples", "src", "packaging"):
        if not (root / d).is_dir():
            raise SystemExit("ERROR: missing %s" % d)
    print("[OK] preflight passed (source root: %s)" % root)
    print("[INFO] (preflight does not modify audit state)")


def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if os.geteuid() != 0:
        print("[ERROR] --install requires root")
        raise SystemExit(64)
    # 1. venv
    venv = Path("/opt/catl-venv")
    if not venv.exists():
        subprocess.run(["python3", "-m", "venv", str(venv)], check=True, env=dict(os.environ, PYTHONHASHSEED="0"))
    # required deps
    r = subprocess.run([str(venv / "bin" / "python"), "-m", "pip", "install", "--no-cache-dir",
                        "cryptography==50.0.2", "jsonschema==4.26.0"],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED="0"))
    if r.returncode != 0:
        raise SystemExit("ERROR: dependency installation failed:\n" + r.stderr)
    # state dirs
    for d in (Path("/var/lib/catl/state"), Path("/var/lib/carl-anchor"), Path("/var/lib/carl-tools/work"), Path("/etc/carl")):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        subprocess.run(["chown", "catl-broker:catl-broker" if str(d).startswith("/var/lib/carl/state") else "root:root", str(d)],
                       stderr=subprocess.DEVNULL, check=False)
    policy = Path("/etc/carl/policy.json")
    if not policy.exists():
        policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(root / "examples" / "policy.json"), str(policy))
        os.chmod(policy, 0o644)
    print("[OK] installation scaffold complete (state preserved)")
    print("Next: install custom systemd units from packaging/systemd and run catl host-audit")


def verify_installed(args):
    failures = 0
    need = ["/opt/catl-venv/bin/python", "/etc/carl/policy.json",
            "/var/lib/carl/state", "/var/lib/carl-anchor"]
    for p in need:
        if not Path(p).exists():
            failures += 1
            print("[FAIL] missing:", p)
        else:
            print("[OK] ", p)
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
