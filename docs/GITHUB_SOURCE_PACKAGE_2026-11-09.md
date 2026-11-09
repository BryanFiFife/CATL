# CATL v0.11.0rc2 — public source package

CATL is a public, open-source project licensed under the **Apache License 2.0**.

The canonical repository is:

https://github.com/BryanFiFife/CATL

A convenient GitHub-generated snapshot of the pinned rc2 release branch is available at:

https://github.com/BryanFiFife/CATL/archive/refs/heads/release/v0.11.0-rc2.zip

GitHub-generated source ZIP wrapper metadata is not treated as a reproducible build signature. The repository contains `RELEASE_MANIFEST.json` and `SHA256SUMS.txt` for individual tracked source files.

For a deterministic CATL source archive from a trusted checkout:

```bash
python tools/release_pack.py --output /tmp/CATL-0.11.0rc2-source.zip
python tools/release_pack.py --verify /tmp/CATL-0.11.0rc2-source.zip
sha256sum /tmp/CATL-0.11.0rc2-source.zip
```

The packer verifies tracked source bytes against Git, rejects unsafe paths and sensitive tracked files, produces a bounded deterministic ZIP, and embeds a manifest tied to the source commit.

## Release evidence

The rc2 installer acceptance records 31 passing installer regressions, a 1,000-case hostile-manifest sweep, disposable Linux install/verify/reinstall testing and static systemd validation. The core security baseline records 278 Linux regressions and a four-identity signed rootless E2E.

See:

- [rc2 release notes](RELEASE_NOTES_PUBLIC_V011_RC2.md)
- [installer acceptance](INSTALLER_ACCEPTANCE_2026-11-09.md)
- [security policy](../SECURITY.md)
- [release attestation tooling](RELEASE_ATTESTATIONS.md)

## Licence

Copyright © 2026 Caledapt.

CATL is distributed under the Apache License 2.0. See the repository [`LICENSE`](../LICENSE) and [`NOTICE`](../NOTICE) files.
