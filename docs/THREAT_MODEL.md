# 🔐 CATL v0.5.0 — threat model

## Protected assets

- Trusted operator's ability to approve/reject actions and suspend tools.
- HMAC signing key, policy bundle, private database and independent receipt checkpoint.
- Restricted backend's credentials and capability set.
- Integrity of tool definitions, arguments, action receipts and verified file output.

## Attacker assumptions

1. **Untrusted model/tool output:** may contain prompt injections or claims of authority. It cannot change reviewed tool pins or mandatory policy when those files are owned by the broker identity.
2. **Compromised agent UID:** may submit arbitrary MCP requests to the agent socket and try to access the operator socket or broker secrets. This is the principal attacker in v0.5 Linux tests.
3. **Local DB modification without HMAC key:** may tamper with rows, replay old signed rows or restore an old database snapshot. The external checkpoint catches DB-only rollback; signed control/approval event history catches tested row-level replay.
4. **Operator account compromised:** can request valid controls and approvals; this is outside the current threat boundary. Kernel UID alone cannot prove human intent.
5. **Broker/kernel compromised:** can access signing key, replace code, rewrite DB+anchor or attack backend. Not covered. No security software can honestly promise zero backdoor possibility under complete host compromise.

## Enforcement vs residual weakness

| Threat | Enforced/observed | Remaining risk |
|---|---|---|
| Agent calls unpinned tools | Deny-by-default, descriptor hash pin, JSON Schema validation | Alternate unmediated tool routes if host allows |
| Agent invokes operator functions | Distinct AF_UNIX endpoint with kernel peer UID check | Operator UID compromise or credential abuse |
| Approval replay | Exact argument binding, one-time SQLite consume and authenticated history | Compromised signing key / broker |
| Old valid control row restored | Compared to most recent signed control-change receipt | Whole DB+checkpoint rollback or broker compromise |
| DB-only snapshot restored | External signed head/count checkpoint | Both DB+anchor restored simultaneously |
| Tail truncated or body edited | Full HMAC chain plus independent anchor | Performance cost O(n); tampered broker/key |
| Untrusted backend reads supervisor secrets | Distinct POSIX backend UID and 0700 private state | Broader host APIs/network/mounts not sandboxed |
| Operator disables audit or verification | Dependent tool calls blocked, not silently allowed | Operator compromise may legitimately change controls |
| Backend times out after external side effect | Audit records uncertain transport outcome | Remote side effects may already have completed |
| Compromised desktop spoofed human click | Not solved | Trusted operator UI/2FA isolation required |

## Required future controls

- Independent OS sandbox profiles for the rootless broker/backend, secure credential provisioning and network egress restrictions.
- Real Windows AppContainer/ACL/named-pipe implementation with tests on Windows 11.
- Remote/hardware monotonic receipt witness, plus tested crash-recovery transaction protocol.
- Remote action idempotency/read-after-write verification and reconciliation.
- Full MCP SDK conformance and dependency provenance, SBOM, signed build attestations and independent penetration testing.

**Deployment verdict:** controlled low-impact security experiments only. Do not market CATL v0.5 as impossible to backdoor, a complete agent sandbox or a certified payment/security appliance.
