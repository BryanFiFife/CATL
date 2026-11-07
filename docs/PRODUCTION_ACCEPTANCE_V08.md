# 🛡️ CATL v0.8.0rc1 — production release acceptance record

**Decision: NOT approved for general production deployment.** Evidence-based private Linux release candidate only. Private repository and branch remain unchanged unless explicitly approved for release.

## Implemented and reproducible

- Distinct Linux agent/operator/broker/backend OS UIDs verified by peer credentials, not a universal OS sandbox.
- Default-deny pinned tool definitions, exact-argument human approvals, revocation and bounded rate limits.
- Signed receipt chain, local independent checkpoint, deterministic packaging and rollback refusal in synthetic tests.
- Minimisable operator overlay, tool toggles and fail-closed disabled-feature semantics.
- **New v0.8:** validation of pinned `outputSchema` on `structuredContent`; unknown or `input_required` result variants fail closed as *side effect may have occurred*. Remote `$ref` retrieval is prohibited.
- Unsupported Windows protected broker refuses to launch; portable Windows tests are not protection tests.

## Release-blocking evidence that cannot be manufactured by local tests

| Gate | External acceptance evidence | Status |
|---|---|---|
| Host OS containment | Target hardware systemd+LSM attestations, privilege and egress checks; malicious agent cannot access backend credentials or bypass broker | OPEN |
| Independent penetration review | Signed test report from independent professional, including privilege escalation, local socket hijacking, race, TOCTOU, schema, malicious MCP backend and prompt-injection scenarios | OPEN |
| Operator human authenticity | MFA/hardware-presence evidence independent of compromised agent identity for high-impact approvals | OPEN |
| External action verification | Read-after-write receipts, idempotency and reconciliation for email/API/payment tools | OPEN |
| Supply-chain provenance | Signed artefacts with safely managed signing identity, reproducible tag/commit mapping, and release verification instructions | OPEN |
| Disaster recovery | Production-equivalent key/anchor loss, crash-gap, restore and rollback recovery drills, with preserved evidence | OPEN |
| Full MCP claims | Protocol-version interoperability and conformance against official SDKs (current 2026-07-28) for exactly the transports/features advertised | OPEN |
| Load/retention | Quantified audit append latency and bounded ledger-growth policy for the intended workload | OPEN |

## Private release-candidate scope

Only disposable or reviewed, restricted Linux hosts with low-impact tools. The backend must run under a separate unprivileged identity with no direct access to broker keys, and the operator must be kept separate from the agent account. Local HMAC does not prove integrity after both key and anchor are compromised. Passing CI does **not** eliminate backdoors.

## Independent review package / reproducibility

1. Check the repository commit SHA, unpack the candidate and verify `RELEASE_MANIFEST.json` using `python tools/release_pack.py --verify <zip>`; integrity is not authenticity because checksums are unsigned.
2. Run `python -m unittest discover -s tests`, `python tools/security_sanity.py`, `python tools/recovery_drill.py` and the rootless four-identity integration on a disposable Linux host.
3. Install dedicated OS identities and reviewed unit templates only on a disposable staging host. Run `catl doctor --strict` and `catl host-audit` against live units, document the binary, UID/group, file ACL and network/LSM context.
4. Independently attempt direct backend socket connection, policy/approval/anchor tampering, malicious output schemas, result replay and denial-of-service attacks. Record every observed deviation with the exact commit and reproducible command.
5. Only after externally supported evidence clears every applicable gate should the release owner consider changing from RC to a signed supported release.

*This checklist is an engineering acceptance contract, not a certificate or completed audit.*
