#!/usr/bin/env python3
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
    python = args.python
    if not python or not Path(python).is_file():
        for cand in ["/usr/bin/python3.12", "python3"]:
            if Path(cand).is_file() and os.access(cand, os.X_OK):
                python = cand
                break
    if not python:
        raise SystemExit("ERROR: no usable Python interpreter found")
    subprocess.run([python, "-c", "import sys; print('OK', sys.version.split()[0])"], check=True)
    print("[OK] source root:", root)
    print("[OK] Python candidate:", python)
    for d in ("tools", "examples", "src"):
        if not (root / d).is_dir():
            raise SystemExit("ERROR: missing %s" % d)
    print("[OK] preflight passed")


def install(args):
    root = detect_root(args.source_root)
    verify_manifest(root)
    if os.geteuid() != 0:
        raise SystemExit("ERROR: --install can only succeed as root")
    print("scaffold only — runtime installation is still in progress")
    for d in ["/var/lib/carl/state", "/var/lib/carl-anchor", "/var/lib/carl-tools/work", "/etc/carl"]:
        Path(d).mkdir(parents=True, exist_ok=True)
        os.chmod(Path(d), 0o700)
    venv = Path("/opt/carl-venv")
    if not venv.exists():
        subprocess.run(["python3", "-m", "venv", str(venv)], check=True)
    # install dependencies
    subprocess.run([str(venv / "bin" / "python"), "-m", "pip", "install", "--no-cache-dir",
                    "cryptography==50.0.2", "jsonschema==4.26.0"], check=False)
    policy = Path("/etc/carl/policy.json")
    if not policy.exists():
        policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(root / "examples" / "policy.json"), str(policy))
    sysdir = Path("/etc/systemd/system")
    for name in ("carl-broker.service", "carl-backend.service"):
        target = sysdir / name
        if not target.exists():
            print("[INFO] service file not found; prepare from template/manual installation output")
    print("[OK] basic install scaffolding complete")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--verify-installed", dest="verify_installed", action="store_true")
    ap.add_argument("--python", default="/usr/bin/python3.12")
    args = ap.parse_args()
    if args.install:
        install(args)
    elif args.verify_installed:
        for p in ["/opt/carl-venv/bin/python", "/etc/carl/policy.json", "/var/lib/carl/state"]:
            if not Path(p).exists():
                print("[FAIL] missing", p)
                raise SystemExit(10)
        print("[OK] installed skeleton present")
    else:
        preflight(args)


if __name__ == "__main__":
    main()
PYEOF