# CATL v5 — commit-bound signing gate

**Release status: NOT public GA.** This development addition closes an offline source-artifact-to-signature workflow gap, not host sandbox, key isolation, Hermes, FIDO2, witness independence, or independent penetration-testing gates.

The existing `tools/release_attest.py` signs ZIPs and validates the internal manifest. It does not independently prove the ZIP corresponds to the claimed Git commit. The v4 `tools/verify_source_artifact.py` proves the correspondence but was a separate optional manual step. `tools/release_sealed.py` chains both as a single, fail-closed operator operation:

1. Require that all patched source is committed locally to a reviewed Git commit before the release ZIP is built, and require a **separately reviewed exact Git commit hash**. The hash may not be inferred from the ZIP or caller's `HEAD` aliases.
2. Require an **independently recorded public-key fingerprint**. An adjacent untrusted key file is not a trust anchor.
3. Sign only on a protected POSIX operator host; the source ZIP, private signer key and output must reside in operator-owned, non-group/world-accessible directories, outside the source checkout. The private key must never be inside the CATL source tree.
4. Prove every packaged ZIP member equals the reviewed Git object (`verify_source_artifact`), including file names and modes.
5. Call the existing Ed25519 release attestation signer and verifier. Verify key fingerprint, claimed commit, version, ZIP and manifest hashes.
6. Compare all four local signing tool source files against their exact committed Git blobs, before and after signing, including hidden `skip-worktree` changes and SHA-256 format Git repositories.
7. Reject world-readable, linked, malformed or oversized newly signed attestation output. Repeat the source proof after signing; reject any archive drift and remove a newly created signature if a later check fails.

## Operator signing (only after independent acceptance)

Example commands, **not yet approved to run for public release**:

```sh
# Review the exact source commit independently; do not copy this value from
# an untrusted ZIP or use a broad Git ref like HEAD as the release trust pin.
REVIEWED_COMMIT='YOUR_REVIEWED_FULL_GIT_SHA'
PINNED_PUBLIC_KEY_SHA256='YOUR_INDEPENDENT_PIN'

# Build ZIP under a private operator-owned directory outside the source.
# Full native/regression/security acceptance must have passed first.
python3 tools/release_pack.py --output "$HOME/.config/catl-release/catl-0.11.0rc1.zip"
python3 tools/release_pack.py --verify "$HOME/.config/catl-release/catl-0.11.0rc1.zip"

python3 tools/release_sealed.py sign \
  --checkout "$PWD" \
  --archive "$HOME/.config/catl-release/catl-0.11.0rc1.zip" \
  --reviewed-commit "$REVIEWED_COMMIT" --version 0.11.0rc1 \
  --private-key "$HOME/.config/catl-release/release-private.pem" \
  --public-key "$HOME/.config/catl-release/release-public.hex" \
  --expected-key-sha256 "$PINNED_PUBLIC_KEY_SHA256" \
  --output "$HOME/.config/catl-release/catl-0.11.0rc1.attestation.json"

python3 tools/release_sealed.py verify \
  --checkout "$PWD" \
  --archive "$HOME/.config/catl-release/catl-0.11.0rc1.zip" \
  --reviewed-commit "$REVIEWED_COMMIT" --version 0.11.0rc1 \
  --public-key "$HOME/.config/catl-release/release-public.hex" \
  --expected-key-sha256 "$PINNED_PUBLIC_KEY_SHA256" \
  --attestation "$HOME/.config/catl-release/catl-0.11.0rc1.attestation.json"
```

The direct `tools/release_attest.py sign` path still exists for old private evaluation workflows and does **not** require this proof; it must not be used as the production release procedure. A truly mandatory public release must also restrict distribution credentials to the protected release coordinator, require separately authenticated test and review evidence, and keep the final release artifact immutable until publication.

## Executed local tests

`tests/test_release_sealed.py` exercises the gate against a real disposable Git repository, a v4 canonical source ZIP, and a **test double for `release_attest` that uses real Ed25519 primitives**. It is deliberately not evidence of the exact existing CATL signer being imported and integrated: that check still requires the complete private checkout and pinned dependencies. The tests cover good-path sign/verify, missing or mismatched source pins, untrusted signing paths, mutated archives, signature tampering, key substitution, dirty/hide-modified signing tools, post-sign archive drift, unsafe output permissions and partial-output cleanup.

## Still blocking public GA

- Full patched private checkout native suite and pinned dependency versions.
- Four-UID protected Linux process installation, LSM/cgroup and egress bypass attempts.
- Live installed Hermes effective tool-registry tests, direct-backend bypass tests and modern MCP conformance.
- Physical FIDO2 user-presence and independent, off-host witness acceptance.
- Real provider readback/idempotency, Windows/macOS protected launchers if those platforms are advertised.
- Independent external security audit and remediation retest.
- Public licence and distribution model decision (current `LICENSE` prohibits publication and redistribution).
- Public artifact signing process pinned to an independent build/attestation environment with reviewable retained evidence.

Never treat locally generated receipts, faked test fixtures or developer-authored reports as evidence that an independent assessor has approved production release.

## Protected CLI policy (8 November 2026)

The historical `python tools/release_attest.py sign ...` command now **fails closed** instead of issuing a signature without source-to-Git equivalence. Release operators must use `python tools/release_sealed.py sign ...` with an independently reviewed commit and pinned verification-key fingerprint. The internal `release_attest.sign()` API remains available to the guarded workflow; it is not a separately authorised public release command.

This change does not satisfy Linux deployment confinement, hardware approval, independent witnessing, real provider-effect reconciliation, or external penetration-testing gates.
