"""Publisher safety regressions: no GitHub network or Actions consumption."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import publish_github_release as pub


class PublisherSafety(unittest.TestCase):
    COMMIT = "a" * 40
    URL = "https://github.com/BryanFiFife/CATL/releases/tag/v0.11.0rc1"

    def test_reject_non_commit_input(self):
        for wrong in ("a" * 39, "A" * 40, "../main", "main", ""):
            with self.subTest(wrong=wrong):
                with self.assertRaises(pub.PublishError):
                    pub.validate_head(wrong)

    def test_reject_wrong_checkout_sha(self):
        with patch.dict(sys.modules, {"release_pack": SimpleNamespace(
                _git=lambda *args: b"b" * 40 + b"\\n")}):
            with self.assertRaisesRegex(pub.PublishError, "wrong checkout"):
                pub.validate_head(self.COMMIT)

    def test_reject_output_inside_checkout(self):
        with patch.object(pub, "validate_head", return_value=self.COMMIT):
            with self.assertRaisesRegex(pub.PublishError, "outside the source"):
                pub.prepare(self.COMMIT, pub.ROOT / "dist", run_tests=False)

    def test_refuses_existing_tag(self):
        response = SimpleNamespace(returncode=0, stdout="{}", stderr="")
        with patch.object(pub.subprocess, "run", return_value=response):
            with self.assertRaisesRegex(pub.PublishError, "already exists"):
                pub.verify_tag_absent("gh")

    def test_refuses_non_404_lookup_error(self):
        response = SimpleNamespace(returncode=1, stdout="",
                                   stderr="gh: forbidden (HTTP 403)")
        with patch.object(pub.subprocess, "run", return_value=response):
            with self.assertRaisesRegex(pub.PublishError, "could not prove"):
                pub.verify_tag_absent("gh")

    def test_proven_absent_tag(self):
        response = SimpleNamespace(returncode=1, stdout="",
                                   stderr="gh: Not Found (HTTP 404)")
        with patch.object(pub.subprocess, "run", return_value=response):
            pub.verify_tag_absent("gh")

    def test_publish_exact_pinned_commit(self):
        def fake_checked(argv, **kwargs):
            if argv[1:3] == ["auth", "status"]:
                return ""
            if argv[1:3] == ["repo", "view"]:
                return pub.REPO
            if argv[1:3] == ["release", "create"]:
                self.assertIn(self.COMMIT, argv)
                self.assertIn("--draft", argv)
                self.assertIn("--prerelease", argv)
                self.assertNotIn("--publish", argv)
                return self.URL
            if argv[1] == "api":
                return json.dumps({"tag_name": pub.TAG, "target_commitish": self.COMMIT,
                                   "draft": True, "assets": [
                                       {"name": "a.zip", "size": 3},
                                       {"name": "sha.txt", "size": 4},
                                   ]})
            self.fail(f"unexpected command {argv}")
        with tempfile.TemporaryDirectory() as tmp:
            archive, checksum = Path(tmp) / "a.zip", Path(tmp) / "sha.txt"
            archive.write_bytes(b"zip")
            checksum.write_bytes(b"sums")
            with patch.object(pub, "checked", side_effect=fake_checked), patch.object(
                    pub, "verify_tag_absent", return_value=None):
                url = pub.publish("gh", self.COMMIT, archive, checksum,
                                  Path(tmp) / "notes.md")
        self.assertEqual(url, self.URL)

    def test_publish_rejects_draft_target_to_wrong_commit(self):
        calls = iter(["", pub.REPO, self.URL,
                      json.dumps({"tag_name": pub.TAG, "target_commitish": "b" * 40,
                                  "draft": True, "assets": []})])
        with patch.object(pub, "checked", side_effect=lambda *args, **kwargs: next(calls)), patch.object(
                pub, "verify_tag_absent", return_value=None):
            with self.assertRaisesRegex(pub.PublishError, "unexpected tag, commit"):
                pub.publish("gh", self.COMMIT, Path("/tmp/a.zip"),
                            Path("/tmp/sha.txt"), Path("/tmp/notes.md"))


if __name__ == "__main__":
    unittest.main()
