# 🛡️ CATL v0.6.0rc1 — release acceptance gates

**Status: private Linux release candidate; general availability is NOT approved.**

The scope of this candidate is a **local, rootless Linux MCP tool gateway** with distinct agent, operator, broker and backend OS identities. The unisolated `catl run --allow-unsandboxed` mode is for demonstrations only, not production. The Windows and macOS protected brokers are **not** implemented.

| Gate | Result | Evidence / release condition |
|---|---|---|
| A1 — Regression tests | Local PASS | 200 Python unit/regression tests under Linux with Xvfb; rerun on the final archive |
| A2 — Real Linux identity isolation | Local PASS | Four-UID E2E: agent cannot approve, backend cannot read key, one-use consent and audit |
| A3 — Authenticated rate limiting | Local PASS | Rate quotas now derive from HMAC-protected, anchored receipts; a forged legacy counter cannot lift limits |
| A4 — Legacy MCP preinit boundary | Local PASS | No agent-controlled initialize or notification reaches the tool backend |
| A5 — Operational diagnostics | Local PASS | `catl doctor` validates Linux identities, state files, key, checkpoint and policy; never repairs silently |
| A6 — File path scope | Local PASS | `path_within` segment-aware lexical rule avoids sibling-prefix bypass; OS symlink controls still required |
| A7 — Rootless host hardening | NOT ATTESTED | systemd sandbox, SELinux/AppArmor, filesystem ACL and egress must be independently checked on each deployment |
| A8 — Windows/macOS security boundary | FAIL / unavailable | No Windows AppContainer/job/ACL solution or verified macOS identity broker |
| A9 — Cross-platform CI | NOT VERIFIED | Pinned workflow committed; GitHub run results must be confirmed before publication |
| A10 — External action reconciliation | NOT IMPLEMENTED | No independent read-after-write for email, API, payments, refunds or device control |
| A11 — Independent penetration test | NOT PERFORMED | Third-party assessment required for consequential actions |
| A12 — Supply chain / signed provenance | PARTIAL | Per-file SHA-256 source manifest and local wheel install; no Sigstore attestation or signed release |
| A13 — Resource/scale validation | PARTIAL | Receipt checks stream rather than `fetchall`; authenticated ledger checks are still O(N) per operation |
| A14 — MCP interoperability | PARTIAL | 2025-11-25 downstream and restricted 2026-07-28 upstream tool subset; not HTTP/MRTR/full SDK conformance |

## Release policy

- **Private evaluation:** permitted with synthetic or low-impact tools on correctly separated Linux identities.
- **Linux public beta:** require confirmed Linux CI, reproducible installation on a clean Linux VM, documented emergency disarm, OS sandbox attestations and an external peer review of the broker.
- **Production / enterprise GA:** additionally require verified host isolation on advertised platforms, independent pentest, high-impact action verification, recovery exercises, threat-model review and signed provenance.

No finite number of automated tests can prove that software has no backdoors. Never infer host isolation from a GUI toggle or from passing Python tests.
