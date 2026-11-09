"""Offline checks for the Linux installer scaffold."""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"


def test_installer_exists():
    assert INSTALLER.exists()


def test_help():
    r = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    for tok in ("--check", "--install", "--verify-installed"):
        assert tok in r.stdout


def test_preflight_accepts_this_repo():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(ROOT)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout
    assert "[OK] preflight passed" in r.stdout


def test_preflight_rejects_bad_source():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check",
                        "--source-root", "/totally/nonexistent/catlpredir"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "source root missing" in (r.stdout + r.stderr).lower()


def test_manifest_integrity():
    import json, hashlib
    root = ROOT
    man = root / "RELEASE_MANIFEST.json"
    data = json.loads(man.read_text())
    assert data.get("algorithm") == "sha256"
    files = data.get("files", {})
    assert isinstance(files, dict) and files
    for rel, digest in files.items():
        p = root / rel
        assert p.is_file(), "missing tracked file: %s" % rel
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() == digest
