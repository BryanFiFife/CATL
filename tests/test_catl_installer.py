"""Stdlib-based checks for the Linux installer."""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catl_installer.py"
MANIFEST = ROOT / "RELEASE_MANIFEST.json"


def test_installer_exists():
    assert INSTALLER.exists()


def test_help():
    r = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    for tok in ("--check", "--install", "--verify-installed"):
        assert tok in r.stdout


def test_preflight_rejects_bad_source():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root",
                        "/no/such/catlpredir"], capture_output=True, text=True)
    assert r.returncode != 0


def test_manifest_integrity():
    import json, hashlib
    data = json.loads(MANIFEST.read_text())
    assert data.get("algorithm") == "sha256"
    files = data.get("files", {})
    assert isinstance(files, dict) and files
    mismatch = [rel for rel, d in files.items()
                if not (ROOT / rel).exists()
                or hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() != d]
    assert not mismatch, mismatch[:3]
