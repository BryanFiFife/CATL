# 🔍 CATL v0.6.0rc1 — delta security review

This is a **source review + local adversarial/regression evaluation**, not an independent penetration test.

## Reviewed trust boundaries

- `src/catl/gateway.py`: upstream MCP allowlist and tool dispatch; fixed client-controlled legacy initialization and notification passthrough. Backend initialization now happens on the trusted side only during an authorised catalogue refresh.
- `src/catl/store.py`: authenticated approvals, feature controls, receipts, rate limits. Previously the separate `tool_rate` table was writable without the audit HMAC, enabling quota rewind if DB-write access were obtained. The new limiter counts HMAC-protected receipt events under an independent-anchor-protected transaction. Legacy counters are ignored.
- `src/catl/anchor.py`: independent signed receipt-chain head; database-only truncation/rollback detected. Compromise of key and both audit and checkpoint files remains outside the threat boundary.
- `src/catl/broker.py`: Linux `SO_PEERCRED` separation for agent and operator; the tool backend uses a distinct UID. These checks are not proof of per-human identity or root/kernel compromise resistance.
- `src/catl/policy.py`: added path-component-aware `path_within` for POSIX absolute *lexical* paths; ordinary `starts_with` remains a string-prefix check and should not be used as a filesystem boundary.
- `src/catl/doctor.py`: preflight rejects missing/misowned key, DB and checkpoint rather than recreating them. An existing SQLite state may undergo a compatible schema migration; back up before running on production data.

## Confirmed limitation / unresolved exposure

1. **Windows/macOS:** protected broker IPC is Linux-specific and no equivalent protected process transport has been evaluated.
2. **Agent bypass:** CATL only controls calls routed through it. An unrestricted local agent could call tools or access secrets directly, bypassing CATL. Distinct OS identities and OS-level mandatory access controls are essential.
3. **Backend lateral movement:** a restricted UID is not a network or kernel sandbox. Deploy seccomp/AppArmor/SELinux, systemd, filesystem and egress policies at the host level.
4. **Operator compromise:** a process under the configured trusted operator UID can act as the operator. No FIDO2/passkey or tamper-resistant human-presence enforcement is currently built in.
5. **Audit rollback:** an attacker who replaces the DB **and** the anchor with a coherent older snapshot can defeat local rollback detection. Remote witnessed or hardware monotonic anchors remain unimplemented.
6. **Remote side effects:** tool success replies, signed audit events and local file hashes are not proof that remote payments, messages or API operations finished exactly once.
7. **Scale:** full ledger verification before a write is O(N); a million-receipt production deployment needs measured performance, checkpoint strategy and safe pruning protocol.
8. **Schema complexity:** reviewed JSON schemas may still contain regexes susceptible to pathological inputs. Sandbox/timeout, input limits and schema review remain necessary.
9. **Dependency assurance:** `jsonschema` is pinned, but this release has not obtained independent vulnerability attestations or package signing.
10. **Protocol:** modern MCP supports stateless flows, new metadata and extensibility; this code intentionally only supports a tool subset and legacy downstream service.

## Safe deployment boundary

Use only reviewed, pinned tool schemas and a separate backend UID with no access to broker state, signing key, human operator socket or unrestricted OS credentials. Keep state and the independent anchor in directories restricted to the broker. Require manual approval for irreversible or expensive actions and independently check outcomes in the target system. Do not expose the operator socket over TCP or treat an unisolated demo as secure.

## Acceptance tests

- Signed audit counter events cannot be bypassed by manipulating `tool_rate` rows.
- Tampering with receipt content makes future state changes fail closed.
- Operator controls and consumable approval tokens remain signed and linked to anchored receipts.
- An unauthorised legacy initialize/notification never reaches the backend.
- Path traversal, slash aliasing and sibling-prefix cases are rejected by `path_within`.
- Real rootless broker integration validates four distinct UIDs (separate test).
- Nonroot `catl doctor` validates legitimate state and fails on a missing checkpoint without recreation.
