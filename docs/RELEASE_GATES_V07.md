# 🛡️ CATL v0.7.0rc1 — production readiness gates

**Status: PRIVATE Linux security-hardening release candidate. Production general availability is blocked.**

This document is a release acceptance record, not a claim of certification. CATL's protected broker supports Linux only. Windows and macOS have portable/negative tests, **not** a validated protected broker.

| Gate | Latest evidence | Decision |
|---|---|---|
| Unit, adversarial and overlay tests | 220 automated local tests; exact final CI run to be recorded in `CI_EVIDENCE_V07.md` | Verify final GitHub run |
| Four separate Linux identities | Real synthetic UID test of agent/operator/broker/backend | PASS for disposable test host |
| Agent-owned policy integrity | Trusted file UID, parent directory, no-follow FD, 1 MiB max; adversarial test | PASS in tests |
| Operator pause and tool disable | Revokes outstanding approvals, adds signed revocation records, detects signed-row replay | PASS in tests |
| Untrusted backend responses | 512 KiB bound, result shape validation, untrusted `_meta` stripped, ambiguous outcome labelled | PASS in tests |
| MCP 2026-07-28 request subset | Enforces version/client capabilities/client info; tool-only stdio subset | PARTIAL; full HTTP, MRTR and SDK conformance NOT done |
| Live Linux systemd sandbox inspection | `catl host-audit` checks dedicated users, restricted writable roots, no privileges, no IP egress | CODE READY; **NOT attested on real target host** |
| Static systemd unit syntax | `systemd-analyze verify` on rendered evaluation units | PASS static only |
| Rollback/recovery exercise | Disposable rollback restores older database and demands independent anchor mismatch | PASS synthetic; live disaster-recovery rehearsal outstanding |
| Independent audit witness | HMAC-linked SQLite receipts and separate local keyed checkpoint | PARTIAL; key+checkpoint compromise or coordinated rollback not excluded |
| Remote action verification | Local file SHA-256 only; cannot verify external email/payment/API outcomes | NOT READY for external-effect claims |
| Signed release provenance | Deterministic hashes and package build; no hardware-held release key | NOT DONE |
| Independent penetration test | Not performed by independent security team | BLOCKER |
| Live host containment | Agent UID, broker UID, LSM, syscalls, socket ACL, egress, installed systemd units all verified on target host | BLOCKER |
| Windows/macOS protected brokers | Not implemented | NOT SUPPORTED |
| Operator human authenticity | Linux UID is checked; compromised operator identity can still approve | BLOCKER for unattended consequential actions |
| Performance at significant audit sizes | Signed receipt history reverified O(N) per write | Needs scale/retention benchmark before high-volume production |

## Deployment policy

- **Private low-impact Linux evaluation:** allowed on a disposable/controlled host with reviewed OS identities and pinned tools.
- **Limited Linux beta:** require a real target host `catl doctor --strict`, `catl host-audit` and a documented exception for warnings, independent sysadmin review, restricted tool capabilities, supervised recovery procedure, and successful final CI.
- **Public/production GA:** require independent pentest, host containment evaluation, a release signing/attestation process, live recovery rehearsal and fully reviewed action-effect semantics for every advertised use case. If a platform is not secured, do not advertise it as supported.

Passing automated tests cannot prove that a security product is free from backdoors. The model and backend are not trusted parties; the host OS and the operator identity are part of the trusted computing base.
