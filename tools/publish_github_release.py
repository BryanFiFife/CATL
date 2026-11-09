#!/usr/bin/env python3
"""Create a private CATL GitHub draft pre-release without GitHub Actions.

Runs local acceptance and the existing deterministic source packer first.
Requires operator-owned GitHub CLI authentication. No automatic pushing,
CI dispatch, repository visibility change, or signing-key generation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "BryanFiFife/CATL"
VERSION = "0.11.0rc1"
TAG = f"v{VERSION}"


class PublishError(RuntimeError):
    pass


def checked(argv: list[str], *, cwd: Path = ROOT, env: dict | None = None) -> str:
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               check=False)
    if completed.returncode:
        raise PublishError(f"command failed ({completed.returncode}): {argv[0]} "
                           + (completed.stderr or completed.stdout)[-1600:])
    return completed.stdout.strip()


def validate_head(expected: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise PublishError("expected commit must be exactly 40 lowercase hex characters")
    # The packer hardens Git execution against inherited config and hooks.
    sys.path.insert(0, str(ROOT / "tools"))
    from release_pack import _git
    head = _git("rev-parse", "HEAD").decode("ascii").strip()
    if head != expected:
        raise PublishError(f"wrong checkout: HEAD={head}, expected={expected}")
    return head


def verify_tag_absent(gh: str) -> None:
    # A missing Release and an existing tag are different states.
    # Never silently retarget or overwrite a tag.
    target = f"repos/{REPO}/git/ref/tags/{TAG}"
    response = subprocess.run([gh, "api", target], cwd=ROOT, capture_output=True,
                              text=True, check=False)
    if response.returncode == 0:
        raise PublishError(f"tag {TAG} already exists; refusing to reuse or move it")
    if "HTTP 404" not in response.stderr and "Not Found" not in response.stderr:
        raise PublishError("could not prove tag absent: " + response.stderr[-1000:])


def prepare(expected: str, output_dir: Path, *, run_tests: bool = True) -> tuple[Path, Path, Path]:
    validate_head(expected)
    output_dir = output_dir.resolve()
    root = ROOT.resolve()
    if output_dir == root or root in output_dir.parents:
        raise PublishError("release output directory must be outside the source tree")
    checked([sys.executable, "tools/build_release_sbom.py", "--check"])
    if run_tests:
        if not sys.platform.startswith("linux"):
            raise PublishError("the native release test gate requires Linux; use a trusted Linux/WSL host")
        xvfb = shutil.which("xvfb-run")
        if not xvfb:
            raise PublishError("xvfb-run is required for desktop tests; install xvfb")
        env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
        checked([xvfb, "-a", sys.executable, "-m", "unittest",
                 "discover", "-s", "tests", "-p", "test_*.py", "-v"], env=env)
        checked([sys.executable, "tools/security_sanity.py"])
        checked([sys.executable, "-m", "compileall", "-q",
                 "src", "tests", "integrations/hermes", "tools"])
    # Compilation may create __pycache__, but source packer includes only
    # immutable Git-tracked files and refuses dirty tracked source bytes.
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"CATL-{VERSION}-source.zip"
    checked([sys.executable, "tools/release_pack.py", "--output", str(archive)])
    checked([sys.executable, "tools/release_pack.py", "--verify", str(archive)])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = output_dir / f"CATL-{VERSION}-SHA256SUMS.txt"
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    notes = output_dir / f"CATL-{VERSION}-RELEASE-NOTES.md"
    base = (ROOT / "docs" / "RELEASE_NOTES_PUBLIC_V011.md").read_text(encoding="utf-8")
    notes.write_text(base + f"\n## Exact release artifact\n\n"
                     f"- Source commit: `{expected}`\n"
                     f"- SHA-256: `{digest}`\n"
                     "- Artifact is an **unsigned** source ZIP unless a separate "
                     "verified detached attestation is attached.\n"
                     "- The current LICENSE permits **private evaluation only**; "
                     "this draft is not open-source licensing or production GA.\n",
                     encoding="utf-8")
    return archive, checksum, notes


def publish(gh: str, expected: str, archive: Path, checksum: Path, notes: Path) -> str:
    checked([gh, "auth", "status"])
    actual = checked([gh, "repo", "view", REPO, "--json", "nameWithOwner",
                      "--jq", ".nameWithOwner"])
    if actual.casefold() != REPO.casefold():
        raise PublishError("authenticated GitHub repository mismatch")
    verify_tag_absent(gh)
    # This action creates the GitHub Release and tag; it does not push
    # commits, run CI or change repository visibility.
    url = checked([gh, "release", "create", TAG, str(archive), str(checksum),
                   "--repo", REPO, "--target", expected,
                   "--title", f"CATL {VERSION} — Linux evaluation pre-release",
                   "--notes-file", str(notes), "--draft", "--prerelease",
                   "--latest=false"])
    # GitHub drafts can have no backing Git tag until they are published.
    # Verify the draft's target_commitish and attached assets instead.
    payload = json.loads(checked([gh, "api", f"repos/{REPO}/releases/tags/{TAG}"]))
    if (payload.get("tag_name") != TAG or payload.get("target_commitish") != expected
            or payload.get("draft") is not True):
        raise PublishError("created draft has unexpected tag, commit or publication state")
    found = {asset.get("name"): asset for asset in payload.get("assets", [])}
    for path in (archive, checksum):
        asset = found.get(path.name)
        if not asset or asset.get("size") != path.stat().st_size:
            raise PublishError("created draft missing expected uploaded asset: " + path.name)
    return url


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True, help="reviewed 40-char Git commit SHA")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="directory outside the checkout")
    parser.add_argument("--create-draft", action="store_true",
                        help="explicitly create draft GitHub Release through authenticated gh")
    parser.add_argument("--ack-evaluation-license", action="store_true",
                        help="acknowledge existing private-evaluation-only licence")
    args = parser.parse_args()
    try:
        archive, checksum, notes = prepare(args.expected_commit, args.output_dir)
        print(json.dumps({"status": "LOCALLY_VERIFIED_ONLY", "archive": str(archive),
                          "sha256": checksum.read_text().split()[0],
                          "notes": str(notes)}, sort_keys=True))
        if args.create_draft:
            if not args.ack_evaluation_license:
                raise PublishError("--ack-evaluation-license required before creating a draft")
            gh = shutil.which("gh")
            if not gh:
                raise PublishError("GitHub CLI gh is required: https://cli.github.com/")
            print(publish(gh, args.expected_commit, archive, checksum, notes))
    except (PublishError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("RELEASE_BLOCKED: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
