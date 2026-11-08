# CATL — targeted source hardening and release acceptance, 8 November 2026

**Verdict: NOT general-availability release ready.** This is a scoped, independently
repeated local regression of three authenticated source files plus the witness
protocol and test fixtures. It is not a 486-test native checkout rerun, real
Hermes deployment, independent pentest, or cross-OS acceptance certificate.

## Verified starting revision

- Repository: private `BryanFiFife/CATL`.
- Source branch: `feature/six-roadmap-foundations-20261107`.
- Required base HEAD: `c3ef3ad046a2b718c42053bd8e78cb4884cdbba4`.
- Exact Git blob hashes (all independently matched before patching):
  - `tools/release_pack.py`: `ce34f13f2f44bd7c263fe72843f1987043dfc9ba`
  - `tools/release_attest.py`: `34f1e03fccca341a0e4a084d62a8579cc8f714a2`
  - `tools/witness_service.py`: `87d9803d3d5c29713f285fed541dc486863379e9`
  - `src/catl/witness_protocol.py` (unchanged): `b28cbd8d7b2116b672664e568b484e8ac998cc3c`
- Existing upstream regression files for witness protocol, source-IP and release
  signing were also checked against Git blob hashes and executed against the
  patched tool implementation.

## Bugs reproduced before corrections

1. **Untracked secret packaging**: the original `tools/release_pack.py`
   recursively packaged `ROOT.rglob('*')`, including `.env` and arbitrary files.
2. **Hidden-index source substitution**: the first hardening patch trusted
   `git diff HEAD`; Git `skip-worktree` and `assume-unchanged` hid a modified
   tracked file, and the builder placed synthetic `PRIVATE_KEY_DO_NOT_PACKAGE`
   text into a purportedly clean ZIP. Fixed by checking every candidate's
   bytes against the immutable committed Git blob object ID.
3. **Predictable temporary ZIP clobber**: the first patch opened
   `<output>.tmp` with ordinary ZIP writing, allowing a precreated symlink
   to redirect writes. Now uses a random exclusive temporary file, fsync and
   atomic replacement. Metadata symlinks/hardlinks are also refused.
4. **Lost executable mode**: the earlier packer forced all ZIP entries to
   mode 0644, breaking executable tracked scripts. Committed 0755 source
   mode is preserved.
5. **Manifest/attestation incompatibility**: the exact upstream
   `tools/release_attest.py` rejected valid CATL source manifests >16 KiB
   with `attestation_oversized` (the checked source manifest is ~18 KiB).
   The internal release-manifest bound is now a separate 2 MiB, while the
   signed attestation document remains tightly limited to 16 KiB.
6. **Signer provenance mismatch**: signed release ZIPs now include the
   exact Git HEAD object ID in `RELEASE_MANIFEST.json`; signing refuses
   a different claimed source commit. SHA-1 and SHA-256 Git object formats
   are accepted. This is operator-supplied provenance metadata, **not**
   an independent reproducible-build proof.
7. **Signature policy bypass through recomputed hashes**: the old signer
   accepted a CATL ZIP containing a `.env` or private-key filename if the
   attacker also regenerated its internal manifest and SHA-256 sums. It now
   enforces the source-package sensitive-path denylist independently.
8. **Witness HTTP framing**: incomplete bodies and duplicate `Content-Type`
   headers previously could reach the signed witness ledger. They are now
   rejected before mutation.

## Local execution evidence (repeated final source state)

- `python -m unittest discover -s tests -v`: **88 tests passed; 0 failures**.
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests`: **88 tests plus
  140 subtests passed; 0 failures**, ~40.29s.
- Included 8 real local TLS 1.3 witness tests on the exact witness service,
  running as a separate nonroot UID; restart and certificate pin tests passed.
- The combined patch cleanly applied to copies matching the three verified
  GitHub source blob hashes; resulting production files matched byte-for-byte.
- `verify_checkout_source.py` passed an exact Git tree check and rejected a
  synthetic `skip-worktree`-concealed modified file.
- All tests used synthetic repositories/certificates. **These 88 cases are a
  reconstructed targeted test slice, not the full 486-case CATL native suite.**

## Tests and limits

- Packaging synthetic Git fixtures: untracked/ignored secrets, tracked secret
  extensions, modifications hidden by Git index bits, staged/dirty sources,
  symlinks, hardlinks, temp ZIP clobber, metadata clobber, executable modes,
  duplicate/oversized/tampered ZIPs, deterministic rebuilds, archive bounds.
- End-to-end: 180+ file Git checkout → source ZIP → internal manifest and
  checksums → ephemeral Ed25519 signature → independent public-key-fingerprint
  verification; tampering, wrong commit, wrong signer, oversized manifest,
  wrong checksums, SHA-256 Git repository variant tested.
- Witness: actual source and protocol, synthetic framing attacks plus a
  **real local TLS 1.3 separate-UID server** with client cert pinning,
  wrong-but-CA-valid certificate, wrong hostname, no certificate, rollback,
  restart, duplicate-header and allowed-source controls.
- All witness keys, CA material and idempotency fixtures are synthetic and
  short-lived. No production CATL, Hermes, customer data, external payment,
  network destination, CI or Git remote was changed.
- Test environment: Linux, Python 3.13.5, cryptography 46.0.4,
  jsonschema 4.26.0. **Pinned cryptography==50.0.2 is untested here**.

**Release gates remaining:** current full CATL 486-test suite from a clean
patched checkout; real four-UID CATL broker and live Hermes tool-bypass tests;
production-equivalent systemd/LSM/cgroups/egress; independently administered
off-host witness; hardware-backed operator human-presence; real provider-side
idempotency/readback; Windows protected broker and macOS sandbox; signed and
independently reproducible dependency provenance; independent security review
and retest. Existing Linux test history on the unpatched branch cannot be
promoted into acceptance evidence for this patch.

## How to apply without invoking GitHub Actions

From a **clean, trusted** checkout pinned to the SHA above, run the provided
`apply_and_test.sh /absolute/path/to/CATL` script. It fails on SHA drift,
dirty tracked files or a mismatch in the three original Git blob identities.
It applies the patch locally, runs focused tests and the repository static
sanity scanner. It does **not** push, commit, merge or schedule CI.

Then, on a disposable Linux VM with the full native source and reviewed OS
UID setup, run the full unittest and pytest suites under Xvfb, separate-UID
integration, Hermes tests, incident/rollback, build and signing tests. Review
failures before authorising any Git push. Production release and branch merge
remain **blocked**, regardless of passing targeted tests.
