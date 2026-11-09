import unittest
import subprocess, sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"
MANIFEST = ROOT / "RELEASE_MANIFEST.json"


class InstallerUnittests(unittest.TestCase):
    def test_help(self):
        proc = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        for tok in ("--check", "--install", "--verify-installed"):
            self.assertIn(tok, proc.stdout)

    def test_rejects_nonexistent_source(self):
        proc = subprocess.run(
            [sys.executable, str(INSTALLER), "--check", "--source-root", "/absolutely/missing/root"],
            capture_output=True, text=True)
        self.assertNotEqual(0, proc.returncode)

    def test_installer_file_is_nonempty(self):
        self.assertTrue(INSTALLER.is_file())
        self.assertGreater(INSTALLER.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
