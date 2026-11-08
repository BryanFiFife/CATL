"""Version metadata consistency regression for offline release signing."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_release_sealed as fixture
from release_sealed import ReleaseGateDenied

class ReleaseVersionBindingTests(unittest.TestCase):
    setUp = fixture.SealedReleaseGateTests.setUp
    sign = fixture.SealedReleaseGateTests.sign
    verify = fixture.SealedReleaseGateTests.verify
    def test_mismatched_release_version_rejected_before_signing(self):
        with self.assertRaises(ReleaseGateDenied):
            self.sign(version='9.9.9')
        self.assertEqual(self.fake.events, [])
        self.assertFalse(self.signature.exists())

    def test_verify_rejects_mismatched_archive_version(self):
        # A forged but internally correctly signed attestation for a different
        # version must not bind to the committed source archive.
        self.sign()
        self.signature.unlink()
        self.fake.sign(self.archive, self.private, self.signature,
                       source_commit=self.commit, version='9.9.9')
        with self.assertRaises(ReleaseGateDenied):
            self.verify(version='9.9.9')

if __name__ == '__main__':unittest.main()
