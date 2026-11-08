"""The legacy release-attestation CLI must never bypass reviewed-source signing.

The in-process signer remains available to tools/release_sealed.py, which
requires an independent Git commit and pinned verification key.
"""
from __future__ import annotations
import importlib.util
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / 'tools' / 'release_attest.py'
SEALED = ROOT / 'tools' / 'release_sealed.py'


class DirectSigningGuardTests(unittest.TestCase):
    def test_legacy_cli_sign_refuses_unreviewed_source(self):
        result = subprocess.run(
            [sys.executable, str(SIGNER), 'sign',
             '--zip', '/nonexistent/unchecked.zip',
             '--private', '/nonexistent/operator-key',
             '--output', '/nonexistent/unchecked-attestation.json',
             '--source-commit', 'a' * 40,
             '--version', '0.11.0rc1'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('direct_signing_disabled_use_release_sealed', result.stderr)

    def test_legacy_module_still_exposes_internal_signer_for_sealed_gate(self):
        spec = importlib.util.spec_from_file_location('release_attest', SIGNER)
        self.assertIsNotNone(spec)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertTrue(callable(mod.sign))
        self.assertTrue(SEALED.is_file())


if __name__ == '__main__':
    unittest.main()
