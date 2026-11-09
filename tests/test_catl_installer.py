#!/usr/bin/env python3
import unittest, subprocess, sys, tempfile, os, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"

class TestInstallerSubstantial(unittest.TestCase):
    def test_help(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for t in ("--check", "--install", "--verify-installed"):
            self.assertIn(t, proc.stdout)

    def test_requires_root_for_install(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--install"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_run_or_fail_propagates(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with self.assertRaises(subprocess.CalledProcessError):
            mod.run_or_fail([sys.executable, "-c", "raise SystemExit(4)"])

    def test_run_or_fail_accepts_zero(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.run_or_fail([sys.executable, "-c", "pass"])

    def test_verify_installed_missing(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--verify-installed"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_non_root_path_rejected(self):
        d = Path(tempfile.mkdtemp(prefix="catl-bad-")) / "missing_src"
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(d)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_manifest_missing(self):
        d = Path(tempfile.mkdtemp(prefix="catl-noman-"))
        for nm in ("tools","examples","src","packaging"): (d/nm).mkdir()
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(d)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_render_backend_unit_text(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        unit = mod.render_unit_template("backend")
        self.assertIn("NoNewPrivileges", unit)
        self.assertIn("/opt/catl/venv/bin/python", unit)

    def test_render_broker_unit_text(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        unit = mod.render_unit_template("broker")
        self.assertIn("NoNewPrivileges", unit)
        self.assertIn("/opt/catl/venv/bin/python", unit)
        self.assertIn("broker", unit)

    def test_no_empty_success(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", "/bad"],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

if __name__ == "__main__":
    unittest.main()
