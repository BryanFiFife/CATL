# 🔒 CATL v0.7.0rc1 — security and disclosure

**Private evaluation. Not production certified and not guaranteed free of backdoors.** CATL does not eliminate the need for OS isolation, trusted update provenance, independent audit or a separately verified approval channel.

- **Use the rootless Linux broker** (`catl broker --backend-socket`, `catl backend-service`, `catl shim`, `catl overlay --operator-socket`) for isolation experiments. Distinct agent, operator, backend and broker OS identities are required. The existing `catl run --allow-unsandboxed` and `overlay --unsafe-direct-state` modes are demonstrations only.
- **Fail-closed database:** empty state starts disarmed. Anchored mode refuses removed or stale checkpoints and replayed control/approval rows. Do not auto-reinitialise or silently reset the anchor.
- **External checks required:** broker code and dependencies must be administrator-owned/read-only to the agent; restrict network and filesystem rights of every process; isolate the backend's credentials; avoid unreviewed installers and arbitrary tool servers.
- **Human identity:** the protected operator socket pins a Linux UID, but cannot independently distinguish a legitimate human from malware running as that user.
- **No remote updater/telemetry:** this project does not add a listening TCP API, automatic updater or mandatory external account.
- **Report vulnerabilities privately** through Caledapt's established contact channel. Do not post exploit details, credentials or customer data in public issues.

Read [v0.5 audit](docs/SECURITY_AUDIT_V05.md), [rootless Linux deployment](docs/DEPLOY_ROOTLESS_LINUX.md) and [architecture](docs/ARCHITECTURE.md).

## Current release evidence

The local engineering review is at [docs/SECURITY_AUDIT_V07.md](docs/SECURITY_AUDIT_V07.md), with explicit unresolved production gates in [docs/RELEASE_GATES_V07.md](docs/RELEASE_GATES_V07.md). No unaudited network service, key access from the agent, or automated trust recovery is included in the protected Linux broker.


## 🧨 v0.10 internal red-team findings

See [`docs/RED_TEAM_ASSESSMENT_V010.md`](docs/RED_TEAM_ASSESSMENT_V010.md) for reproducible Linux agent-socket exhaustion and backend message-flood findings, mitigation tests, and known remaining attack surfaces. This report was produced by the development assistant, **not by an independent penetration tester**. Production/GA remains blocked on live host confinement, external security review, external-effect reconciliation and independent audit witnessing.
