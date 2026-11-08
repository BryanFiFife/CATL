# CATL v4: strict ZIP container and source-to-artifact provenance gate

**Status:** locally tested development hardening. **Not public GA.**

This work continues the v3 package-safety changes against exact baseline
`feature/six-roadmap-foundations-20261107` at
`c3ef3ad046a2b718c42053bd8e78cb4884cdbba4`.

## Attacks reproduced against the earlier release packager

1. A `#!/bin/sh` ZIP polyglot preamble was accepted even when it was not in
   `RELEASE_MANIFEST.json` or `SHA256SUMS.txt`.
2. Trailing arbitrary bytes and a ZIP archive comment were accepted.
3. An unindexed suffix inside a **compressed file member**, together with
   adjusted ZIP compressed-size and central-directory fields, was accepted.
   The Python ZIP reader returned the original file content with valid hashes.
4. Archive entries under `.git/hooks`, `build/`, `dist/`, and `__pycache__/`
   could be introduced with fully recomputed, self-consistent source hashes.
5. ZIP OS-ID fields, internal attributes and local-header timestamps could be
   modified while retaining successful archive verification.

## Code-level mitigations

* Reject extra archive data, comments, local/central filename disagreements,
  noncontiguous local records, member extra fields, and inconsistent EOCD.
* Stream the **entire raw DEFLATE input** for every member with bounded output,
  checking exact stream exhaustion, length and CRC. Compression-ratio gate is
  aligned to 500:1 with the existing CATL attestation verifier.
* Enforce the builder's excluded-source rules in the verifier, including
  `.git` and build/cache artifacts, not just private-key file extensions.
* Enforce fixed ZIP metadata, date, permissions and creator OS for portable,
  deterministic archives. The builder explicitly writes Unix permission
  metadata even on a Windows development host.
* Add `tools/verify_source_artifact.py`, which takes a **separately reviewed
  Git SHA** and compares every extracted ZIP member to the immutable bytes
  returned by `git cat-file blob`, including executable modes and file set.
  A forged archive that merely recomputes hashes no longer passes this check.
* Support Git SHA-1 and SHA-256 object formats without any network access.

## Local workflows

In a **clean complete checkout** with the v4 patch locally applied, run the
project's full native and deployment suites before committing. This gate
**cannot produce a valid release ZIP from uncommitted changes**, by design.

After the local changes pass review and are committed locally (no push needed):

```bash
# Do this only in the reviewed, committed checkout.
python3 tools/release_pack.py --output /absolute/trusted/release.zip
python3 tools/release_pack.py --verify /absolute/trusted/release.zip

# Pin this reviewed HEAD through an independent channel.
COMMIT="$(git rev-parse HEAD)"
python3 tools/verify_source_artifact.py \
  --checkout "$(pwd -P)" \
  --commit "$COMMIT" \
  --archive /absolute/trusted/release.zip
```

Only then request a release attestation using an independently verified
operator key. **Do not interpret a software Ed25519 signature as a hardware
presence proof or as independent CI/reproducible-build provenance.**

Do **not** run the historical `release_attest.py` signing CLI against untrusted
ZIP input without first passing the new exact-source verifier. The historical
signer remains independently callable, so enforcing this as an unavoidable
operator/signing policy is an additional release gate.

## Scope and outstanding acceptance

The v4 isolated tests cover only the rebuilt release packager, source-proof
helper and synthetic Git repositories. The complete live CATL checkout is not
mounted here. This work **does not** verify the 486 native tests on the amended
branch, installed Hermes bypass coverage, a production four-UID broker, Windows
AppContainer, macOS sandbox, FIDO2 authenticator, independent off-host witness,
provider readback, pinned `cryptography==50.0.2`, independent pen-test, or
public licensing and documentation readiness.

**Stop condition:** until those gates have actual target-host evidence, keep
CATL explicitly pre-release and private. No automatic Git push, Actions,
release or publication is performed by these tools.
