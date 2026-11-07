# 🛡️ CATL v0.7.0rc1 — private Linux hardening candidate

**Release scope:** Local-first MCP tool gateway on Linux with separate agent, operator, broker and backend UIDs. No production/enterprise certification or supported protected broker on Windows/macOS.

### Improvements

- Trusted policy owner/parent validation with no-follow FD loading and bounded size.
- Turning off a safety feature or tool revokes pending and approved actions, with replay-proof signed revocation evidence.
- Untrusted tool-output structure/size validation and metadata stripping; uncertain outcomes recorded explicitly.
- Current 2026-07-28 MCP `_meta` fields required for the supported tool-only subset.
- Read-only `catl host-audit` command checks systemd unit restrictions and fails closed if it cannot inspect services.
- Hardened example service settings and a static systemd syntax check in Linux CI.
- Isolated database rollback drill and test; `catl doctor` warns about permitted tools without independent outcome verification.
- Deterministic release packager now reads version from `pyproject.toml`, avoiding stale hardcoded manifest versions.

### Still blocked

Public/production security claims depend on live Linux host attestation and independently reviewed isolation, external pentest, independently verifiable release provenance, and safe treatment of external side effects. Full MCP interoperability and non-Linux protected execution are not delivered.
