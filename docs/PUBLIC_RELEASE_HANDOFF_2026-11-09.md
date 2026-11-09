# CATL v0.11.0rc1 — release handoff (9 November 2026)

**Owner decision:** prepare CATL for a no-charge GitHub release; do not change repository visibility.
**Classification:** Linux-focused PRE-RELEASE / evaluation only; not production-certified or GA.

## Source of truth

- Latest pre-preparation release source branch: release/v0.11.0rc1-source at a07394582395bf7f13c353fe233d62c9828eadba.
- Release-preparation branch: release/v0.11.0rc1-prep-20261109.
- Previous native Linux / four-UID engineering baseline: 6ccd65009cfb88dc5d4b4c164d9725a98b4cebe5.
- After any source changes, regenerate the release archive and obtain a NEW ZIP hash and attestation. Old hashes are not valid for a changed tree.
- GitHub Actions remain manual-only. Do not launch any workflow without explicit owner approval.

## Changes in this preparation branch

The new tools/build_release_sbom.py creates a deterministic CycloneDX 1.6 **pinned-audit-inventory-only** SBOM from pyproject.toml and requirements-security-audit.txt. The previously stale 0.5.0 document is replaced with a current v0.11.0rc1 six-component inventory. Six local unit tests cover pin enforcement, duplicates and determinism. The --check mode fails if the committed SBOM is stale.

**The six-component inventory is not a complete installed or cross-platform dependency tree, vulnerability scan, or licence audit.** A complete resolved environment and independent dependency review remain separate gates.

## Build on a trusted Linux checkout

From a clean checkout of the exact reviewed release-preparation commit, run:

    git status --porcelain
    git rev-parse HEAD
    python3 tools/build_release_sbom.py --check
    PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 tools/security_sanity.py
    python3 -m compileall -q src tests integrations/hermes tools
    python3 tools/release_pack.py --output /tmp/CATL-v0.11.0rc1-source.zip
    python3 tools/release_pack.py --verify /tmp/CATL-v0.11.0rc1-source.zip
    sha256sum /tmp/CATL-v0.11.0rc1-source.zip

The release packer rebuilds the manifest and checksum index from exact tracked HEAD bytes, and requires its output to be OUTSIDE the checkout. It is not a signer. Sign and verify the resulting ZIP with tools/release_attest.py per docs/RELEASE_ATTESTATIONS.md on a trusted operator machine, with the independently pinned public fingerprint. Private keys MUST NOT be committed.

Do not credit the final source tree with old tests. Re-run full native Linux tests and, where available, the real rootless/four-UID acceptance on the exact release commit before publishing claims about it.

## GitHub Release steps

1. Review the preparation branch and its exact immutable tested commit.
2. Decide on a PUBLIC-DISTRIBUTION LICENCE. The existing LICENSE allows private evaluation only; no automatic permission to redistribute, modify or deploy in production. Do not call the project open source under those terms.
3. In GitHub Releases, create a **draft** targeting the exact tested commit. Create tag v0.11.0rc1 only if unused. Mark the release **pre-release**, not GA.
4. Upload the locally verified ZIP, its SHA-256 checksum and detached release attestation. Use docs/RELEASE_NOTES_PUBLIC_V011.md, retaining every support limitation.
5. Independently verify the uploaded bytes. A GitHub-generated source download is not the independently signed package.
6. Publish the pre-release, and change visibility only when the owner elects to do so.

## Open security gates

Hardened production systemd/LSM/cgroup/firewall egress; real installed Hermes tool bypass; Windows/macOS protected runtimes; physical FIDO2; independently administered off-host audit witness and external pen-test; real provider-specific authoritative effect reconciliation; complete MCP SDK/transport conformance; complete SBOM and independent vulnerability/licence assessment; independently reviewed signed provenance.

Free availability is not proof of production readiness.
