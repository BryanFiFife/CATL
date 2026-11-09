"""Offline tests for release inventory truthfulness and determinism."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from build_release_sbom import InventoryError, build, render


class TestBuildReleaseSBOM(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'pyproject.toml').write_text(
            '[project]\nname = "caledapt-agent-trust"\nversion = "0.11.0rc1"\n'
            'dependencies = ["jsonschema==4.26.0", "cryptography==50.0.2"]\n')
        (self.root / 'requirements-security-audit.txt').write_text(
            '# Pinned snapshot, not a lock\njsonschema==4.26.0\n'
            'attrs==26.1.0\ncryptography==50.0.2\n')

    def test_deterministic_and_scoped(self):
        first = render(self.root)
        self.assertEqual(first, render(self.root))
        bom = json.loads(first)
        self.assertEqual(bom['metadata']['component']['version'], '0.11.0rc1')
        self.assertEqual(len(bom['components']), 3)
        self.assertEqual(bom['metadata']['properties'][0]['value'], 'PINNED_AUDIT_INVENTORY_ONLY')
        self.assertEqual(len(bom['dependencies'][0]['dependsOn']), 2)
        self.assertTrue(all(c['bom-ref'] == c['purl'] for c in bom['components']))

    def test_version_changes_identity(self):
        original = build(self.root)['serialNumber']
        file = self.root / 'pyproject.toml'
        file.write_text(file.read_text().replace('0.11.0rc1', '0.11.0rc2'))
        self.assertNotEqual(original, build(self.root)['serialNumber'])

    def test_reject_unpinned_inventory(self):
        file = self.root / 'requirements-security-audit.txt'
        file.write_text(file.read_text().replace('attrs==26.1.0', 'attrs>=26.1.0'))
        with self.assertRaisesRegex(InventoryError, 'not_an_exact_pin'):
            build(self.root)

    def test_reject_mismatched_direct_pin(self):
        file = self.root / 'requirements-security-audit.txt'
        file.write_text(file.read_text().replace('cryptography==50.0.2', 'cryptography==49.0.0'))
        with self.assertRaisesRegex(InventoryError, 'direct_dependency_missing_or_mismatch'):
            build(self.root)

    def test_reject_duplicated_normalized_package(self):
        file = self.root / 'requirements-security-audit.txt'
        file.write_text(file.read_text() + 'CryptoGraphy==50.0.2\n')
        with self.assertRaisesRegex(InventoryError, 'duplicate_package'):
            build(self.root)

    def test_reject_indirect_missing(self):
        file = self.root / 'requirements-security-audit.txt'
        file.write_text('attrs==26.1.0\n')
        with self.assertRaisesRegex(InventoryError, 'direct_dependency_missing_or_mismatch'):
            build(self.root)


if __name__ == '__main__':
    unittest.main()
