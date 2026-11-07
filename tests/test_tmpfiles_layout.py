"""Keep the rootless IPC directory blueprint least-privileged."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TmpfilesLayoutTests(unittest.TestCase):
    def test_socket_directories_provisioned_without_world_access(self):
        lines = (ROOT / "packaging/tmpfiles.d/catl.conf.example").read_text().splitlines()
        actual = [line.split() for line in lines if line.strip() and not line.startswith("#")]
        expected = {
            "/run/catl-agent": ("0710", "catl-broker", "catl-agent-ipc"),
            "/run/catl-operator": ("0710", "catl-broker", "catl-operator-ipc"),
            "/run/catl-tools": ("0710", "catl-tools", "catl-backend-ipc"),
        }
        self.assertEqual(set(row[1] for row in actual), set(expected))
        for row in actual:
            self.assertEqual(row[0], "d")
            self.assertEqual(tuple(row[2:5]), expected[row[1]])
            self.assertEqual(row[5:], ["-"])


if __name__ == "__main__":
    unittest.main()
