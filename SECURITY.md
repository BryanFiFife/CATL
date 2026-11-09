# 🔒 CATL security policy

**Current public release candidate: v0.11.0rc2**

CATL is open source under the Apache License 2.0 and is designed as a defensive trust layer for AI-agent and MCP tool execution. It is developer-tested security software, not an independent security certification.

## Supported security scope

The protected runtime currently supported by the release candidate is Linux. The intended deployment separates broker, agent, human operator and tool-backend authority across distinct identities and authenticated Unix-socket channels.

Use the protected broker path for consequential testing:

- `catl broker`
- `catl backend-service`
- `catl shim`
- `catl overlay --operator-socket ...`

The deliberately unsafe demonstration paths, including `catl run --allow-unsandboxed` and `overlay --unsafe-direct-state`, are for disposable evaluation only.

## Security principles

- **Default deny:** unknown or unauthorised tool actions do not silently pass.
- **No silent trust reset:** anchored state must not be automatically reinitialised after integrity failure.
- **Separated authority:** broker policy/signing state must not be writable by the untrusted agent.
- **Exact approvals:** operator approvals are action-bound and replay-resistant.
- **No blind retry of uncertain effects:** externally ambiguous operations are quarantined for reconciliation.
- **Host controls still matter:** CATL cannot protect a capability the agent can reach through an unmediated shell, plugin, credential, network route or alternate tool registry.
- **No mandatory cloud control plane:** CATL does not require a listening public TCP API, automatic updater or external account for local trust decisions.

## Reporting a vulnerability

Please **do not open a public issue containing exploit details, secrets, customer data or a working bypass**.

Preferred route: use GitHub's private security-advisory reporting flow for this repository:

https://github.com/BryanFiFife/CATL/security/advisories/new

If private advisory reporting is unavailable, contact Caledapt through its established business contact channel and clearly mark the message **CATL SECURITY**.

A useful report includes:

1. affected CATL version/commit;
2. platform and deployment mode;
3. minimal reproducer;
4. expected vs actual trust-boundary behaviour;
5. impact and realistic attacker prerequisites;
6. any proposed mitigation.

## Current evidence

For v0.11.0rc2, public evidence includes:

- 31/31 installer regression tests;
- 1,000/1,000 hostile-manifest cases rejected;
- disposable Linux install → verify → reinstall smoke testing;
- static `systemd-analyze verify` checks on rendered broker/backend units;
- offline systemd security analysis scoring 1.3 / OK for both reviewed service profiles;
- the prior core baseline recording 278 passing Linux regressions;
- a four-identity signed rootless E2E covering forgery denial, tool execution, approval/replay control, audit verification, channel isolation and broker-key denial.

See:

- [rc2 release notes](docs/RELEASE_NOTES_PUBLIC_V011_RC2.md)
- [installer acceptance](docs/INSTALLER_ACCEPTANCE_2026-11-09.md)
- [threat model](docs/THREAT_MODEL.md)
- [rootless Linux deployment](docs/DEPLOY_ROOTLESS_LINUX.md)
- [v0.11 red-team assessment](docs/RED_TEAM_ASSESSMENT_V011.md)
- [release attestations](docs/RELEASE_ATTESTATIONS.md)

## Known boundaries

CATL does not claim:

- protected Windows AppContainer or macOS sandbox operation end-to-end;
- completed hardware-backed FIDO2/WebAuthn presence assurance;
- independent penetration-test certification;
- an independently administered off-host witness;
- proof that an external provider actually settled an email/API/payment effect merely because a tool returned success;
- protection against a compromised host administrator/kernel or stolen operator authority.

Security changes should include a reproducer and regression test wherever practical.
