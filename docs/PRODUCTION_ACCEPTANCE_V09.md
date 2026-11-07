# 🛡️ CATL v0.9.0rc1 — evidence-backed release gate

**Verdict: PRIVATE LINUX RELEASE CANDIDATE, NOT PUBLIC/PRODUCTION-GA.**

## Improvements with developer-controlled tests

- A signed, 128-bit action ID links pre-dispatch intent and terminal status.
- Crash, timeout, malformed reply, backend error or independent postcondition
  failure causes durable quarantine of that tool, across process restarts.
- Tool switches and client RPC cannot clear quarantine. Only operator IPC and
  an explicit documented external read-back reference can reconcile it.
- Older action receipts are conservatively migrated instead of dropped.
- A corrupt audit stream fails closed; CATL no longer compounds the error by
  trying to append to an already invalid ledger before returning denial.
- The desktop overlay lists and reconciles incidents while preserving the
  broker's keyless client architecture.

## Still mandatory before external production launch

| Gate | Evidence needed | Status |
|---|---|---|
| Host isolation | Run production-equivalent Linux host with reviewed systemd, AppArmor/SELinux/LSM, strict ACLs, no unintended egress; attacker-agent cannot bypass broker or read keys | OPEN |
| Independent penetration test | Independent malicious backend/agent review; signed findings and remediation retest | OPEN |
| Independent human identity | MFA/hardware-backed authorisation for high-impact operator actions | OPEN |
| External side effects | Provider-specific read-after-write, idempotency and reconciliation for actual supported high-impact tools | OPEN |
| Audit witness | Off-host signed/witnessed audit checkpoint and recovery/restore exercise | OPEN |
| Supply-chain provenance | Verified build provenance and signed release artifacts | OPEN |
| MCP conformance | Official SDK/integration coverage of *advertised* MCP subset | OPEN |
| Scale | Stable heavy-load ledger, throughput and retention evaluation | OPEN |
| Cross-platform | Windows/macOS **protected** broker not implemented, cannot advertise those platforms | OPEN |

**No implementation, test or self-authored assessment can prove there are no backdoors.**
Do not merge to a production branch or turn the repository public on the strength of CI alone.
