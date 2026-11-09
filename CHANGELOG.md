# Changelog

All notable public CATL release-candidate changes are summarised here.

## v0.11.0rc2 — 2026-11-09

### Added

- functional Linux installer with manifest verification, dedicated service identities, reviewed systemd rendering, state/anchor preservation and post-install verification;
- Apache License 2.0 open-source distribution;
- public `NOTICE`, contribution guidance, issue forms, PR template and citation metadata;
- public release/discovery metadata for AI-agent security, MCP security and human-in-the-loop tool control.

### Security / verification

- 31/31 installer regression tests recorded;
- 1,000/1,000 hostile manifest cases rejected;
- disposable Linux install → verify → reinstall smoke test recorded;
- rendered systemd units passed static verification with offline security score 1.3 / OK;
- prior core baseline records 278 passing Linux regressions and four-identity signed rootless E2E coverage.

### Scope

Protected operation remains Linux-focused. Windows/macOS protected runtimes, completed hardware-backed presence, independent penetration testing and independently administered off-host witnessing are not claimed by rc2.

See [rc2 release notes](docs/RELEASE_NOTES_PUBLIC_V011_RC2.md) and [security policy](SECURITY.md).

## v0.11.0rc1

Initial public Linux-focused evaluation pre-release, including the protected broker, signed operator decisions, rootless identity separation, audit anchoring, uncertainty handling and MCP integration foundations.

Historical evidence remains in the repository under `docs/` and `reports/`.
