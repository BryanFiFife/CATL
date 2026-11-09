#!/usr/bin/env python3
import unittest, subprocess, sys, tempfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"


class TestCatlScaffold(unittest.TestCase):
    def test_help(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for tok in ("--check", "--install", "--verify-installed"):
            self.assertIn(tok, proc.stdout)

    def test_root_fails_obviously_wrong(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root",
                               "/this/does/not/exist"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_installer_file_non_empty(self):
        self.assertTrue(INSTALLER.is_file())
        self.assertGreater(INSTALLER.stat().st_size, 100)

    def test_run_or_fail_propagates_nonzero(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ci", str(INSTALLER))
        ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci)
        with self.assertRaises(subprocess.CalledProcessError):
            ci.run_or_fail(["python", "-c", "import sys; sys.exit(17)"])

    def test_run_or_fail_accepts_zero(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ci", str(INSTALLER))
        ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci)
        ci.run_or_fail(["python", "-c", "pass"])

    def test_verify_installed_missing_paths(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--verify-installed"],
                              capture_output=True, text=True, cwd="/")
        self.assertNotEqual(proc.returncode, 0)

    def test_preflight_rejects_low_shape(self):
        empty = ROOT / "empty_shape"
        if empty.exists():
            import shutil
            shutil.rmtree(empty)
        empty.mkdir()
        (empty / "RELEASE_MANIFEST.json").write_text('{"algorithm":"sha256","files":{}}')
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(empty)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_no_empty_success(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", "/bad"],
                              capture_output=True, text=True)
        # must never exit 0 under fail-closed contract
        self.assertNotEqual(proc.returncode, 0)

if __name__ == "__main__":
    unittest.main()
