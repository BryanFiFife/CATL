"""Offline checks for the Catl installer scaffold."""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"
MANIFEST = ROOT / "RELEASE_MANIFEST.json"


def test_installer_exists():
    assert INSTALLER.exists() and INSTALLER.stat().st_size > 400


def test_flags_parse():
    r = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    for token in ("--check", "--install", "--verify-installed"):
        assert token in r.stdout


def test_preflight_accepts_this_repo():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(ROOT)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout
    assert "preflight passed" in r.stdout.lower()


def test_preflight_rejects_missing_source():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check",
                        "--source-root", "/absolutely/nonexistent/catlpredir"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "source root missing" in (r.stdout + r.stderr).lower()


def test_manifest_consistent():
    data = json.loads(MANIFEST.read_text())
    assert data["algorithm"] == "sha256"
    files = data.get("files", {})
    assert isinstance(files, dict)
    mismatch = [rel for rel, digest in (files or {}).items() if not (ROOT / rel).exists()]
    assert not mismatch, mismatch[:3]
PYEOF