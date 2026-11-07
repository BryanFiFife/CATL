# 🗺️ CATL implementation status and release gates — 7 November 2026

**Scope:** source on the v0.11.0rc1 Linux hardening candidate. This status audit distinguishes verified developer-controlled features from real production assurance. It does not incorporate the separately delivered local-only Hermes v1.2 evaluation package.

## Completed scoped features

- [x] Deterministic policy + schema pinning.
- [x] Exact argument-bound approvals and replay protection.
- [x] Linux keyless agent shim and UID-bound operator channel.
- [x] HMAC-linked local receipts, separate local checkpoint, database-only rollback detection.
- [x] Minimisable overlay, control toggles, approval queue and incident handling.
- [x] Non-root broker with independently supervised backend, separated UIDs and peer-credential checks.
- [x] Command-bound one-use Ed25519 **software** operator grants; Pause-versus-dispatch ordering tests.

A checked feature is supported by code and internal tests, **not** an independent security certification. A compromised operator signing key, privileged OS account or Hermes bypass remains a risk.

## Open milestones

| Workstream | Implemented portions | Still required |
|---|---|---|
| 🔐 Linux host hardening and human presence | systemd templates, rootless broker identity, operator software signing, doctor/host-audit | Production-equivalent LSM/cgroups/capability/egress validation; hardware-verified human presence |
| 🪟 Windows protected mode | Portable negative/regression tests | AppContainer/restricted-token broker, named-pipe ACLs, real hostile-host tests |
| 🍎 macOS protected mode | Portable policy components | Authenticated peer sockets, macOS sandbox and host tests |
| 🌐 MCP full interoperability | Legacy plus modern tool-only stdio subset | Current full advertised SDK conformance, modern upstream backend, remainder of protocol |
| 🧾 External action correctness | Local file postconditions, uncertain-action quarantine | Remote read-after-write and idempotent reconciliation of real email, API or payment |
| 🏛️ Independent assurance and provenance | Local checkpoint, deterministic hash tooling, evaluation SBOM | Off-host/hardware witness, signed artifacts/attestations, SBOM validation, independent pentest |

## Priority order

1. **P0: Stop bypasses.** Audit Hermes' *effective* tool registry (including auto-loaded native/plugin/MCP tools), not just static YAML. Confine the dedicated Linux agent identity so it cannot reach direct tools, backend, operator socket or secrets.
2. **P0: End-to-end Linux confinement.** Prove kernel UID/ACL and LSM restrictions, no unintended network egress, approved systemd service settings and no privilege escalation under adversarial tests.
3. **P0: Native broker red-team regression.** Signed-approval forgery and replay; races with Pause; side-effect uncertainty; audit rollback; malformed JSON-RPC and denial-of-service.
4. **P1: Consequential-action evidence.** Hardware-backed operator presence; independently witnessed audit checkpoints; verified provider-side effects and idempotency; independent assessor retests.
5. **P2: Interoperability and platform expansion.** MCP conformance and real Windows/macOS protected implementations.

## Release handling

**GitHub Actions are deliberately manual-only** via `workflow_dispatch`. No push, pull-request, scheduled or automated hosted test runs are authorized by this update.

**Important:** existing checked-in `RELEASE_MANIFEST.json` and `SHA256SUMS.txt` are out of date relative to the current source tree. Before distributing a source release, run `python tools/release_pack.py --output /tmp/catl-release-candidate.zip` and `python tools/release_pack.py --verify /tmp/catl-release-candidate.zip` in a trusted isolated build, review the regenerated manifests, and commit them only under manual-CI controls. **Do not treat the currently checked-in manifests as authoritative.** They are not cryptographically signed.

**GA blockers:** live Hermes E2E in a restricted profile, genuine protected host tests, independent pentest, hardware user presence, off-host audit witness, remote external-action verification and signed provenance. Do not promote this candidate to production or public GA.

References: [production acceptance](PRODUCTION_ACCEPTANCE_V09.md), [signed operator model](OPERATOR_SIGNING_V011.md), [Hermes evaluation](HERMES_EVALUATION.md), [security review scope](INDEPENDENT_REVIEW_SCOPE_V08.md).
