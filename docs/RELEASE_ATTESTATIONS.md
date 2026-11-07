# 🔏 CATL software-signed release attestation (private evaluation)

**Status:** a software Ed25519 signature tool is implemented and tested. It is **not** a hardware-backed, independently attested or production-certified release-signing system. Off-host receipt witnessing, reproducible independent build attestation and external security review remain open.

`tools/release_attest.py` makes and verifies a **detached** signature binding a source ZIP's exact SHA-256, its internal `RELEASE_MANIFEST.json` and `SHA256SUMS.txt`, its declared version and the source commit claimed by the signing operator. It also supports the separate Hermes integration ZIP's `MANIFEST_SHA256.txt`. Verification fails closed for duplicate archive members, malicious paths, symlinks, file-set/hash mismatch, unbounded expansion and wrong keys/signatures/commits.

**Platform note:** Private-key generation/signing is currently restricted to POSIX hosts with reviewed file ownership and mode checks; Windows private-key ACL enforcement is **not** implemented. A Windows operator can verify an attestation using the independently pinned public-key fingerprint, but must sign on a protected Linux/macOS operator host.

## Key management (operator only)

Create a private, trusted directory owned by you, not accessible to the CATL agent or backend. Never generate the release key inside Hermes or the broker.

```bash
umask 077
mkdir -p "$HOME/.config/catl-release"
chmod 700 "$HOME/.config/catl-release"
python3 tools/release_attest.py keygen \
  --private "$HOME/.config/catl-release/release-private.pem" \
  --public "$HOME/.config/catl-release/release-public.hex"
```

This prints the SHA-256 fingerprint of the raw public key. Record the fingerprint **out of band**. The private key is mode `0600`, never overwritten, and must not be uploaded to GitHub. Do not grant the agent any key access. For high-assurance signing replace this software-key path with a reviewed HSM/user-presence design.

## Build, sign and verify

First review the source tree and pinned commit, run the native regression suite locally and regenerate/check its manifest using `tools/release_pack.py`. The signatures **do not prove** that the claimed source commit matches the actual artifact: the signer is making that assertion. A separate source-to-artifact reproducibility verification is required before GA.

```bash
# Build deterministic source ZIP (review generated manifests before distribution).
python3 tools/release_pack.py --output /tmp/catl-release-candidate.zip
python3 tools/release_pack.py --verify /tmp/catl-release-candidate.zip

# Create detached attestation; never commit the private key.
python3 tools/release_attest.py sign \
  --zip /tmp/catl-release-candidate.zip \
  --private "$HOME/.config/catl-release/release-private.pem" \
  --output /tmp/catl-release-candidate.attestation.json \
  --source-commit YOUR_REVIEWED_40_HEX_COMMIT \
  --version 0.11.0rc1

# Verify before installing, using the key fingerprint independently recorded.
python3 tools/release_attest.py verify \
  --zip /tmp/catl-release-candidate.zip \
  --attestation /tmp/catl-release-candidate.attestation.json \
  --public "$HOME/.config/catl-release/release-public.hex" \
  --expected-key-sha256 YOUR_INDEPENDENT_PUBLIC_KEY_FINGERPRINT \
  --expected-commit YOUR_REVIEWED_40_HEX_COMMIT \
  --expected-version 0.11.0rc1
```

**Do not treat a key published alongside an untrusted ZIP as independently trustworthy.** The signed payload is not a Sigstore provenance statement, signed Git tag, trusted CI attestation or reproducible-build proof. These remain independent release gates. The tool never contacts GitHub or uses GitHub Actions.
