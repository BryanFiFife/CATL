"""Offline structural checks for the Linux installer scaffold."""
from pathlib import Path
import subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"


def test_installer_exists():
    assert INSTALLER.exists()


def test_installer_flags_parse_help():
    r = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    for token in ("--check", "--install", "--verify-installed"):
        assert token in r.stdout


def test_preflight_refuses_bad_source():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check",
                        "--source-root", "/non-existent/path/absolutely"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "source root missing" in (r.stdout + r.stderr).lower()


def test_preflight_accepts_this_repo():
    r = subprocess.run([sys.executable, str(INSTALLER), "--check",
                        "--source-root", str(ROOT)], capture_output=True, text=True)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "preflight passed" in r.stdout.lower()
