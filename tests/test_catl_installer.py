"""No-root, standard-library regression tests for the CATL read-only installer."""
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"
spec = importlib.util.spec_from_file_location("catl_installer_under_test", INSTALLER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCatlInstaller(unittest.TestCase):
    def make_root(self):
        temp = tempfile.TemporaryDirectory(prefix="catl-installer-test-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for directory in ("src", "tools", "examples", "packaging/systemd"):
            (root / directory).mkdir(parents=True)
        for file in ("catl-broker.service.example", "catl-backend.service.example"):
            shutil.copyfile(ROOT / "packaging/systemd" / file, root / "packaging/systemd" / file)
        (root / "README.md").write_text("CATL synthetic test fixture\n", encoding="utf-8")
        digest = hashlib.sha256((root / "README.md").read_bytes()).hexdigest()
        (root / "RELEASE_MANIFEST.json").write_text(json.dumps({
            "algorithm": "sha256", "files": {"README.md": digest}
        }), encoding="utf-8")
        return root

    def test_help(self):
        completed = subprocess.run([sys.executable, str(INSTALLER), "--help"],
                                   capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for flag in ("--check", "--install", "--verify-installed"):
            self.assertIn(flag, completed.stdout)

    def test_preflight_synthetic_root_read_only(self):
        root = self.make_root()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            mod.preflight(SimpleNamespace(source_root=str(root), python=sys.executable))
        self.assertIn("[BLOCKED]", output.getvalue())
        self.assertFalse((root / "catl-installed").exists())

    def test_cli_rejects_missing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, str(INSTALLER), "--check", "--source-root", str(Path(tmp) / "missing")],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("source root missing", proc.stderr)

    def test_manifest_valid(self):
        root = self.make_root()
        self.assertEqual(mod.verify_manifest(root), 1)

    def test_manifest_hash_mismatch(self):
        root = self.make_root()
        (root / "README.md").write_text("tampered")
        with self.assertRaisesRegex(mod.InstallerFailure, "hash mismatch"):
            mod.verify_manifest(root)

    def test_manifest_rejects_empty_and_non_object(self):
        root = self.make_root()
        for bad in ('{"algorithm":"sha256","files":{}}', '[]', 'null', '{'):
            (root / "RELEASE_MANIFEST.json").write_text(bad)
            with self.subTest(bad=bad), self.assertRaises(mod.InstallerFailure):
                mod.verify_manifest(root)

    def test_manifest_rejects_traversal(self):
        root = self.make_root()
        (root / "RELEASE_MANIFEST.json").write_text(json.dumps({
            "algorithm": "sha256", "files": {"../outside": "0" * 64}
        }))
        with self.assertRaisesRegex(mod.InstallerFailure, "unsafe manifest path"):
            mod.verify_manifest(root)

    def test_manifest_rejects_leaf_symlink(self):
        root = self.make_root()
        (root / "README.md").rename(root / "actual.txt")
        (root / "README.md").symlink_to(root / "actual.txt")
        with self.assertRaisesRegex(mod.InstallerFailure, "unsafe manifest entry"):
            mod.verify_manifest(root)

    def test_manifest_rejects_parent_symlink(self):
        root = self.make_root()
        (root / "original").mkdir()
        (root / "original" / "readme.txt").write_text("data")
        (root / "linked").symlink_to(root / "original", target_is_directory=True)
        digest = hashlib.sha256(b"data").hexdigest()
        (root / "RELEASE_MANIFEST.json").write_text(json.dumps({
            "algorithm": "sha256", "files": {"linked/readme.txt": digest}
        }))
        with self.assertRaisesRegex(mod.InstallerFailure, "symlink"):
            mod.verify_manifest(root)

    def test_python_discovery_works_with_executable_path(self):
        self.assertTrue(Path(mod.find_python(sys.executable)).is_file())

    def test_python_discovery_fails_when_missing(self):
        with self.assertRaisesRegex(mod.InstallerFailure, "no executable Python"):
            mod.find_python("/completely/nonexistent/python")

    def test_run_or_fail_accepts_success(self):
        mod.run_or_fail([sys.executable, "-c", "pass"])

    def test_run_or_fail_propagates_failure(self):
        with self.assertRaises(subprocess.CalledProcessError):
            mod.run_or_fail([sys.executable, "-c", "raise SystemExit(7)"])

    def test_install_is_fail_closed_without_any_mutation(self):
        with patch.object(Path, "mkdir", side_effect=AssertionError("host mutation")) as mkdir, \
             patch.object(mod.subprocess, "run", side_effect=AssertionError("host subprocess")) as run:
            with self.assertRaisesRegex(mod.InstallerFailure, "disabled"):
                mod.install(SimpleNamespace(source_root="/unused"))
            mkdir.assert_not_called()
            run.assert_not_called()

    def test_verify_installed_cannot_false_positive(self):
        with self.assertRaisesRegex(mod.InstallerFailure, "not implemented"):
            mod.verify_installed(SimpleNamespace())

    def test_reviewed_broker_template_used_unmodified(self):
        unit = mod.render_unit_template("broker")
        reference = (ROOT / "packaging/systemd/catl-broker.service.example").read_text()
        self.assertEqual(unit, reference)
        self.assertIn("User=catl-broker", unit)
        self.assertNotIn("CAP_NET_BIND_SERVICE", unit)

    def test_reviewed_backend_template_used_unmodified(self):
        unit = mod.render_unit_template("backend")
        reference = (ROOT / "packaging/systemd/catl-backend.service.example").read_text()
        self.assertEqual(unit, reference)
        self.assertIn("User=catl-tools", unit)
        self.assertNotIn("python -m catl.backend", unit)

    def test_unit_rejects_weakened_hardening(self):
        root = self.make_root()
        path = root / "packaging/systemd/catl-broker.service.example"
        path.write_text(path.read_text().replace("PrivateNetwork=yes", "PrivateNetwork=no"))
        with self.assertRaisesRegex(mod.InstallerFailure, "missing safeguard"):
            mod.render_unit_template("broker", root=root)

    def test_unit_rejects_wrong_entrypoint(self):
        root = self.make_root()
        path = root / "packaging/systemd/catl-broker.service.example"
        path.write_text(path.read_text().replace("/usr/local/bin/catl broker", "python -m catl.broker"))
        with self.assertRaisesRegex(mod.InstallerFailure, "CLI entrypoint"):
            mod.render_unit_template("broker", root=root)

    def test_render_rejects_missing_identity(self):
        with self.assertRaisesRegex(mod.InstallerFailure, "missing/extra"):
            mod.render_unit_template("broker", identities={"AGENT_UID": 1001})

    def test_render_rejects_root_uid(self):
        ids = {name: 1001 for name in mod.IDENTITY_TOKENS["broker"]}
        ids["AGENT_UID"] = 0
        with self.assertRaisesRegex(mod.InstallerFailure, "non-root"):
            mod.render_unit_template("broker", identities=ids)

    def test_render_replaces_identities_without_weakening_controls(self):
        ids = {name: 1000 + i for i, name in enumerate(mod.IDENTITY_TOKENS["broker"], 1)}
        result = mod.render_unit_template("broker", identities=ids)
        self.assertIn("ExecStart=/opt/catl/venv/bin/catl broker", result)
        self.assertIn("ProtectHome=true", result)
        self.assertIn("CapabilityBoundingSet=", result)
        for token in ids:
            self.assertNotIn(token, result)

    def test_rejects_unknown_unit_name(self):
        with self.assertRaisesRegex(mod.InstallerFailure, "unknown CATL service"):
            mod.render_unit_template("something-else")

    def test_plan_requires_real_manifest_and_templates(self):
        root = self.make_root()
        result = mod.preparation_phase(root)
        self.assertEqual(result["verified_manifest_entries"], 1)
        self.assertFalse(result["installation_enabled"])
        (root / "packaging/systemd/catl-backend.service.example").unlink()
        with self.assertRaisesRegex(mod.InstallerFailure, "missing or unsafe"):
            mod.preparation_phase(root)


if __name__ == "__main__":
    unittest.main()
