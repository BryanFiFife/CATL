import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, call

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "catlinstall.py"
spec = importlib.util.spec_from_file_location("catl_installer", INSTALLER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def write_manifest(root, paths):
    files = {}
    for rel in paths:
        files[rel] = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    (root / "RELEASE_MANIFEST.json").write_text(json.dumps({"algorithm": "sha256", "files": files}))


class InstallerTests(unittest.TestCase):
    def fixture(self):
        td = tempfile.TemporaryDirectory(prefix="catl-inst-")
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        for d in ("src", "tools", "examples", "packaging/systemd", "packaging/tmpfiles.d"):
            (root / d).mkdir(parents=True)
        for p in ("catl-broker.service.example", "catl-backend.service.example"):
            (root / "packaging/systemd" / p).write_bytes((ROOT / "packaging/systemd" / p).read_bytes())
        (root / "packaging/tmpfiles.d/catl.conf.example").write_bytes((ROOT / "packaging/tmpfiles.d/catl.conf.example").read_bytes())
        (root / "examples/policy.json").write_bytes((ROOT / "examples/policy.json").read_bytes())
        (root / "examples/mock_server.py").write_bytes((ROOT / "examples/mock_server.py").read_bytes())
        (root / "README.md").write_text("fixture\n")
        write_manifest(root, ["README.md", "examples/policy.json", "examples/mock_server.py",
                              "packaging/systemd/catl-broker.service.example",
                              "packaging/systemd/catl-backend.service.example",
                              "packaging/tmpfiles.d/catl.conf.example"])
        return root

    def identities(self):
        return mod.IdentitySet(26101, 26102, 26103, 26104, 26202, 26203, 26204)

    def test_cli_help(self):
        p = subprocess.run([sys.executable, str(INSTALLER), "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for flag in ("--install", "--verify-installed", "--operator-user", "--operator-public-key", "--no-systemd-activate"):
            self.assertIn(flag, p.stdout)

    def test_manifest_valid(self):
        root = self.fixture()
        self.assertEqual(mod.verify_manifest(root), 6)

    def test_manifest_tamper_fails(self):
        root = self.fixture(); (root / "README.md").write_text("tampered")
        with self.assertRaisesRegex(mod.InstallerFailure, "hash mismatch"):
            mod.verify_manifest(root)

    def test_manifest_traversal_fails(self):
        root = self.fixture()
        (root / "RELEASE_MANIFEST.json").write_text(json.dumps({"algorithm":"sha256","files":{"../x":"0"*64}}))
        with self.assertRaisesRegex(mod.InstallerFailure, "unsafe manifest path"):
            mod.verify_manifest(root)

    def test_manifest_leaf_symlink_fails(self):
        root = self.fixture(); (root / "README.md").rename(root / "real")
        (root / "README.md").symlink_to(root / "real")
        with self.assertRaises(mod.InstallerFailure): mod.verify_manifest(root)

    def test_find_python(self):
        self.assertTrue(Path(mod.find_python(sys.executable)).is_file())

    def test_find_python_missing(self):
        with self.assertRaises(mod.InstallerFailure): mod.find_python("/never/here/python")

    def test_run_or_fail_propagates(self):
        with self.assertRaises(mod.InstallerFailure): mod.run_or_fail([sys.executable,"-c","raise SystemExit(4)"])

    def test_validate_operator_key(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"pub";p.write_text("ab"*32+"\n");p.chmod(0o644)
            self.assertEqual(mod._validate_public_key(p), ("ab"*32+"\n").encode())

    def test_validate_operator_key_rejects_writable(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"pub";p.write_text("ab"*32);p.chmod(0o666)
            with self.assertRaises(mod.InstallerFailure): mod._validate_public_key(p)

    def test_render_broker_from_reviewed_template(self):
        root=self.fixture(); text=mod.render_unit_template("broker", self.identities(), root=root)
        self.assertIn("ExecStart=/opt/catl/venv/bin/catl broker", text)
        self.assertIn("--agent-uid 26102", text);self.assertIn("--backend-uid 26104", text)
        self.assertIn("ProtectHome=true", text);self.assertIn("CapabilityBoundingSet=",text)
        self.assertNotIn("AGENT_UID", text);self.assertNotIn("CAP_NET_BIND_SERVICE", text)

    def test_render_backend_uses_venv_python_and_cli(self):
        root=self.fixture(); text=mod.render_unit_template("backend", self.identities(), root=root)
        self.assertIn("ExecStart=/opt/catl/venv/bin/catl backend-service", text)
        self.assertIn("--broker-uid 26101",text);self.assertIn("--broker-gid 26204",text)
        self.assertIn("-- /opt/catl/venv/bin/python /opt/catl/tool-server.py", text)

    def test_render_rejects_weakened_template(self):
        root=self.fixture(); p=root/"packaging/systemd/catl-broker.service.example"
        p.write_text(p.read_text().replace("PrivateNetwork=yes","PrivateNetwork=no"))
        with self.assertRaisesRegex(mod.InstallerFailure,"missing safeguard"):
            mod.render_unit_template("broker",self.identities(),root=root)

    def test_render_rejects_root_identity(self):
        bad=mod.IdentitySet(26101,0,26103,26104,26202,26203,26204)
        with self.assertRaises(mod.InstallerFailure): mod.render_unit_template("broker",bad,root=self.fixture())

    def test_preparation_phase_verifies_templates_and_manifest(self):
        root=self.fixture(); result=mod.preparation_phase(root)
        self.assertEqual(result["verified_manifest_entries"],6)
        self.assertEqual(result["reviewed_units"],["backend","broker"])

    def test_preflight_read_only(self):
        root=self.fixture()
        args=SimpleNamespace(source_root=str(root),operator_public_key=None,python=sys.executable,operator_user=None)
        with patch.object(Path,"mkdir",side_effect=AssertionError("mutation")), contextlib.redirect_stdout(io.StringIO()):
            mod.preflight(args)

    def test_state_anchor_fresh(self):
        with patch.object(mod,"CATL_STATE",Path("/definitely/not-here-state")), patch.object(mod,"CATL_ANCHOR",Path("/definitely/not-here-anchor")):
            self.assertEqual(mod._state_anchor_precondition(),"fresh")

    def test_state_without_anchor_refused(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state";anchor=Path(td)/"anchor";state.mkdir();anchor.mkdir();(state/"audit.sqlite3").write_text("x")
            with patch.object(mod,"CATL_STATE",state),patch.object(mod,"CATL_ANCHOR",anchor):
                with self.assertRaisesRegex(mod.InstallerFailure,"no anchor"):
                    mod._state_anchor_precondition()

    def test_anchor_without_state_refused(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state";anchor=Path(td)/"anchor";state.mkdir();anchor.mkdir();(anchor/"head.json").write_text("x")
            with patch.object(mod,"CATL_STATE",state),patch.object(mod,"CATL_ANCHOR",anchor):
                with self.assertRaisesRegex(mod.InstallerFailure,"state is empty"):
                    mod._state_anchor_precondition()

    def test_existing_state_and_anchor_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state";anchor=Path(td)/"anchor";state.mkdir();anchor.mkdir();(state/"audit.sqlite3").write_text("x");(anchor/"head.json").write_text("x")
            with patch.object(mod,"CATL_STATE",state),patch.object(mod,"CATL_ANCHOR",anchor):
                self.assertEqual(mod._state_anchor_precondition(),"existing")

    def test_ensure_dir_refuses_wrong_existing_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x";p.mkdir();p.chmod(0o755)
            with patch.object(mod,"_assert_secure_ancestor"):
                with self.assertRaisesRegex(mod.InstallerFailure,"ownership/mode mismatch"):
                    mod._ensure_dir(p, os.getuid(), os.getgid(), 0o700)

    def test_atomic_write_preserves_equal(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"f";p.write_bytes(b"same")
            before=p.stat().st_mtime_ns
            with patch.object(mod,"_assert_secure_ancestor"):
                mod._atomic_write(p,b"same",uid=os.getuid(),gid=os.getgid(),mode=0o644)
            self.assertEqual(p.read_bytes(),b"same");self.assertEqual(p.stat().st_mtime_ns,before)

    def test_install_requires_public_key_before_mutation(self):
        args=SimpleNamespace(source_root=str(self.fixture()),operator_public_key=None,operator_user="x",python=sys.executable,wheelhouse=None,package_wheel=None,no_systemd_activate=True)
        with patch.object(mod,"_require_linux_root"), patch.object(mod,"provision_identities") as ids:
            with self.assertRaisesRegex(mod.InstallerFailure,"operator-public-key"):
                mod.install(args)
            ids.assert_not_called()

    def test_package_failure_happens_before_identity_mutation(self):
        root=self.fixture()
        with tempfile.TemporaryDirectory() as td:
            key=Path(td)/"pub";key.write_text("aa"*32);key.chmod(0o644)
            args=SimpleNamespace(source_root=str(root),operator_public_key=str(key),operator_user="operator",python=sys.executable,wheelhouse=None,package_wheel=None,no_systemd_activate=True)
            with patch.object(mod,"_require_linux_root"), \
                 patch.object(mod,"_validate_operator_user"), \
                 patch.object(mod,"_preflight_host_tools"), \
                 patch.object(mod,"_state_anchor_precondition",return_value="fresh"), \
                 patch.object(mod,"_assert_secure_ancestor"), \
                 patch.object(mod,"_install_venv",side_effect=mod.InstallerFailure("package failed")), \
                 patch.object(mod,"provision_identities") as identities:
                with self.assertRaisesRegex(mod.InstallerFailure,"package failed"):
                    mod.install(args)
                identities.assert_not_called()

    def test_install_pipeline_success_static(self):
        root=self.fixture()
        with tempfile.TemporaryDirectory() as td:
            key=Path(td)/"pub";key.write_text("aa"*32);key.chmod(0o644)
            args=SimpleNamespace(source_root=str(root),operator_public_key=str(key),operator_user="operator",python=sys.executable,wheelhouse=None,package_wheel=None,no_systemd_activate=True)
            ids=self.identities()
            with patch.object(mod,"_require_linux_root"),patch.object(mod,"_validate_operator_user"),patch.object(mod,"_preflight_host_tools"),patch.object(mod,"_assert_secure_ancestor"),patch.object(mod,"provision_identities",return_value=ids),patch.object(mod,"_state_anchor_precondition",return_value="fresh"),patch.object(mod,"_install_venv") as venv,patch.object(mod,"_install_payload") as payload,patch.object(mod,"_bootstrap_anchor_if_fresh") as anchor,patch.object(mod,"_static_verify") as verify,patch.object(mod,"_doctor") as doctor,patch.object(mod,"_activate_systemd") as activate,patch.object(mod,"_host_audit") as audit,contextlib.redirect_stdout(io.StringIO()):
                mod.install(args)
            venv.assert_called_once();payload.assert_called_once();anchor.assert_called_once_with("fresh");verify.assert_called_once_with(ids);doctor.assert_called_once_with(ids,strict=False);activate.assert_not_called();audit.assert_not_called()

    def test_install_pipeline_activation_runs_host_audit(self):
        root=self.fixture()
        with tempfile.TemporaryDirectory() as td:
            key=Path(td)/"pub";key.write_text("aa"*32);key.chmod(0o644)
            args=SimpleNamespace(source_root=str(root),operator_public_key=str(key),operator_user="operator",python=sys.executable,wheelhouse=None,package_wheel=None,no_systemd_activate=False)
            ids=self.identities()
            with patch.object(mod,"_require_linux_root"),patch.object(mod,"_validate_operator_user"),patch.object(mod,"_preflight_host_tools"),patch.object(mod,"_assert_secure_ancestor"),patch.object(mod,"provision_identities",return_value=ids),patch.object(mod,"_state_anchor_precondition",return_value="existing"),patch.object(mod,"_install_venv"),patch.object(mod,"_install_payload"),patch.object(mod,"_bootstrap_anchor_if_fresh"),patch.object(mod,"_static_verify"),patch.object(mod,"_doctor"),patch.object(mod,"_activate_systemd") as activate,patch.object(mod,"_host_audit") as audit,contextlib.redirect_stdout(io.StringIO()):
                mod.install(args)
            activate.assert_called_once();audit.assert_called_once()

    def test_secure_ancestor_rejects_world_writable_parent(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)/"open";parent.mkdir();parent.chmod(0o777)
            with self.assertRaises(mod.InstallerFailure):
                mod._assert_secure_ancestor(parent/"target")

    def test_host_audit_invokes_real_cli_command(self):
        with patch.object(mod,"_run") as run:
            mod._host_audit()
        argv=run.call_args.args[0]
        self.assertEqual(argv[1],"host-audit")
        self.assertIn("catl-broker.service",argv)
        self.assertIn("catl-backend.service",argv)

    def test_identity_tokens(self):
        ids=self.identities();self.assertEqual(ids.unit_values("backend"),{"BROKER_UID":26101,"BACKEND_IPC_GID":26204})

    def test_static_verify_rejects_missing(self):
        ids=self.identities()
        with patch.object(mod,"CATL_STATE",Path("/missing/catl/state")):
            with self.assertRaises(mod.InstallerFailure):mod._static_verify(ids)

    def test_unknown_unit_rejected(self):
        with self.assertRaises(mod.InstallerFailure):mod.render_unit_template("bad",self.identities(),root=self.fixture())


if __name__ == "__main__": unittest.main()
