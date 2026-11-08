# CATL v3 release-source portability and provenance hardening

**Status: local development patch; NOT production/general availability.**

This addition extends the 8 November witness/release-security patch. It closes
four proven release-packaging defects which could produce conflicting or unsafe
Windows/macOS installations, or allow forged internal release identity metadata.

## Failures reproduced against the previous local packager

- Linux Git trees could package Windows devices (`CON`, `AUX.txt`, `COM9`,
  `LPT1`), alternate-data-stream syntax (`name:stream`), illegal Windows
  characters (`?`, `|`), trailing spaces and trailing dots.
- Git trees could package `README.md` and `readme.md` simultaneously, a file `DOCS` with a
  `docs/` directory, or both
  NFC and NFD spellings of a name. They may overwrite/alias on target disks.
- A ZIP with fully recomputed manifest hashes could omit the source commit.
- A ZIP with fully recomputed manifest hashes could carry a `pyproject.toml`
  with a different version or package identity than its release manifest.

## Mitigations

- `_safe_name` rejects Windows device names, colon, forbidden path characters,
  trailing whitespace and dots; applied both to tracked Git paths and ZIPs.
- `_portable_names` rejects Unicode NFC + casefold filename collisions.
- `verify` now requires a well-formed source commit and declared release type.
- `verify` reads and validates packaged project name+version against manifest.
- All 22 original release-pack trust-boundary tests and 13 new tests pass in
  the reconstructed Python 3.13 Linux fixture; 14 added hostile subtests pass.

## Limitations

- This is source-package path safety, not a Windows AppContainer/macOS sandbox.
- An Ed25519 signature proves the signing key signed bytes, but provenance
  remains an operator assertion absent independent build verification.
- Live Hermes runtime, cross-OS host integration, external witness, FIDO2,
  provider readback, pinned-crypto retest and independent review remain open.
- No CI, push, commit, tag, branch, release or production deployment performed.

**Do not mark CATL GA.** The complete private checkout and deployment-level
release acceptance gates still require independently collected evidence.
