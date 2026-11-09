#!/usr/bin/env python3
import unittest, subprocess, sys, tempfile, os, pathlib
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
        # Allow either root failure 1 or success skeleton issue
        self.assertNotEqual(proc.returncode, 0)

    def test_run_or_fail_propagates(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with self.assertRaises(subprocess.CalledProcessError):
            mod.run_or_fail([sys.executable, "-c", "raise SystemExit(1)"])

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
        bogus = Path(tempfile.mkdtemp(prefix="catl-")) / "does_not_exist_src"
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(bogus)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_manifest_missing(self):
        d = pathlib.Path(tempfile.mkdtemp(prefix="catl-noman-"))
        (d / "tools").mkdir(); (d / "examples").mkdir(); (d / "src").mkdir(); (d / "packaging").mkdir()
        proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(d)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_install_plan_present(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inst", str(INSTALLER))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        plan = mod.install_plan(Path("."))
        self.assertTrue(isinstance(plan, dict))
        self.assertTrue("directories" in plan)


if __name__ == "__main__":
    unittest.main()
