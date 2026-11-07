# CATL v0.5.0 — engineering security review

**Scope:** v0.5 code and documentation, Linux/Python 3.13 local tests. **No external penetration testing or formal assurance.**

## Improvements validated

1. **No-root broker path:** agent-facing and operator-facing UDS endpoints can be created under a dedicated, unprivileged broker UID via group-traversable, owner-controlled socket directories. Kernel `SO_PEERCRED` checks expected UID regardless of the socket's group mode.
2. **External tool service:** a separate unprivileged backend UID serves pinned MCP operations over its own UDS; the broker verifies the backend peer UID; backend verifies broker UID; only a strict MCP method allowlist crosses the channel.
3. **No broker secrets passed to backend:** the backend service is started as a different user and receives a scrubbed process environment. A real multi-user integration test verified the tool UID cannot read the broker's signing key.
4. **Approval integrity:** one-time exact-argument approval remains enforced through an anchored receipt history, with replay denied.
5. **Root-safe startup:** `backend-service` preflights non-root identity, group membership and private socket directory before starting any child, to avoid an accidentally privileged/orphaned tool process.
6. **CI prepared:** standalone repo CI uses read-only GitHub permissions, pinned action revisions, a Linux rootless/graphical job and a Windows/macOS/Linux headless matrix. **GitHub CI not yet verified passing at the point of local packaging.**

## Remaining risks — not solved

- **Windows protected execution is not implemented.** Windows agent/administrator identity segregation and AppContainer/Job Object enforcement require native implementation and Windows security testing. Linux broker intentionally rejects Windows.
- The interface authenticates **OS identity**, not physical human presence; compromised operator sessions can approve actions.
- A broker UID or its HMAC key compromise can forge records and controls. Database-plus-anchor rollback is possible when both protected objects are compromised.
- Peer authentication does not protect against compromise of the approved backend process or tool server; external tool side effects may be irreversible and their outcome is not independently verified.
- No dedicated seccomp/SELinux/AppArmor profile, no cgroup resource guard and no guaranteed network egress isolation shipped in the library. Deployers must configure these controls.
- MCP support is limited to a documented tool subset. No general MCP HTTP transport, remote OAuth, elicitation or sampling certification.
- Backend network access and filesystem capabilities are not bound by CATL itself; restricted UID alone is not a full sandbox.
- Root-only smoke tests use synthetic UIDs and rely on `setpriv`; do not run on hosts with matching real accounts.
- Third-party Python dependency and release build-chain integrity still require independent vulnerability monitoring and reproducible signing.

## Release decision

**Controlled Linux evaluation only.** This release reduces an operational root requirement but is not a Windows deployment, no-backdoor proof or commercial security certification. Independently audit before allowing arbitrary terminal, email, financial or system-administration actions.
