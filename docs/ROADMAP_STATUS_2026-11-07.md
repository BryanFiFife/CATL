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
| 🏛️ Independent assurance and provenance | Local checkpoint, deterministic hash tooling, tested software-key release attestations, evaluation SBOM | Off-host/hardware witness, signed artifacts/attestations, SBOM validation, independent pentest |

## Priority order

1. **P0: Stop bypasses.** Audit Hermes' *effective* tool registry (including auto-loaded native/plugin/MCP tools), not just static YAML. Confine the dedicated Linux agent identity so it cannot reach direct tools, backend, operator socket or secrets.
2. **P0: End-to-end Linux confinement.** Prove kernel UID/ACL and LSM restrictions, no unintended network egress, approved systemd service settings and no privilege escalation under adversarial tests.
3. **P0: Native broker red-team regression.** Signed-approval forgery and replay; races with Pause; side-effect uncertainty; audit rollback; malformed JSON-RPC and denial-of-service.
4. **P1: Consequential-action evidence.** Hardware-backed operator presence; independently witnessed audit checkpoints; verified provider-side effects and idempotency; independent assessor retests.
5. **P2: Interoperability and platform expansion.** MCP conformance and real Windows/macOS protected implementations.

## Release handling

**GitHub Actions are deliberately manual-only** via `workflow_dispatch`. No push, pull-request, scheduled or automated hosted test runs are authorized by this update.

**Integrity update:** `RELEASE_MANIFEST.json` and `SHA256SUMS.txt` were refreshed against this tracked source tree. They are **unsigned** and must be regenerated, independently verified and reviewed after every source change. Before distributing a source release, run `python tools/release_pack.py --output /tmp/catl-release-candidate.zip` then `python tools/release_pack.py --verify /tmp/catl-release-candidate.zip` in a trusted isolated build. The updated manifests are not equivalent to a signed release attestation.

**GA blockers:** live Hermes E2E in a restricted profile, genuine protected host tests, independent pentest, hardware user presence, off-host audit witness, remote external-action verification and signed provenance. Do not promote this candidate to production or public GA.

References: [production acceptance](PRODUCTION_ACCEPTANCE_V09.md), [signed operator model](OPERATOR_SIGNING_V011.md), [Hermes evaluation](HERMES_EVALUATION.md), [security review scope](INDEPENDENT_REVIEW_SCOPE_V08.md).

## Signed artifact incremental milestone (7 November 2026)

Added `tools/release_attest.py`, its isolated red-team regression suite and `docs/RELEASE_ATTESTATIONS.md`. An operator-owned **software** Ed25519 key signs the exact ZIP hash and manifest/source-commit claim. The verifier checks the full archive against its internal manifest and an **independently pinned** public key fingerprint. The claimed source commit is an assertion by the signing operator, **not cryptographically proven source-to-artifact correspondence**. No hardware user-presence, independent witness or external pentest is claimed. The combined roadmap milestone remains unchecked.

## v1.4 protected Hermes integration source — 7 November 2026

The private repository now carries `integrations/hermes/` with a documented preflight verifier, root-controlled Python import-tree checks, a fail-closed diagnostic mode, bounded subprocess cleanup and a test subset. Its standalone subset passed **22/22 locally** (including a real four-UID synthetic Linux kernel socket/peer-credential matrix). The separate signed v1.4 integration ZIP passed **141/141** local tests on two clean extractions. **No live Hermes runtime, real CATL broker, production systemd host, or independent security evaluation was exercised in this evidence.** The checked/open boxes remain **7/6**; no combined roadmap milestone is newly completed. GitHub Actions remain manual-only.

## Native broker ingress hardening — 7 November 2026

Added a **per-broker** authenticated-agent request budget (600 attempts per monotonic minute, shared across connections/threads), charged before frame parsing; the trusted operator channel has separate capacity. Grossly oversized/unpinned tool names are rejected before expensive signed audit-binding work. Added native-source regression tests for concurrency, reconnection, malformed frames and operator access, plus a bounded-tool-name regression. A standalone copy of the admission algorithm passed 9 local tests; a deterministic race regression failed before the clock/lock fix and passed after, but the full native CATL tests are **not run in this environment** because the complete private source was not available in its runtime. This is DoS-risk reduction, not a complete denial-of-service guarantee; live host load testing remains OPEN. See [broker admission notes](AGENT_ADMISSION_RATE_LIMIT_V011.md).

## Linux service-profile controls — 7 November 2026

Both CATL systemd evaluation templates now include finite memory/swap limits, startup burst suppression, core-dump denial, keyring/namespace/syscall protections and bounded teardown. Six static regression tests passed locally, as did `systemd-analyze verify` on sanitized templates; offline scoring was 1.6 for each with systemd 257. **No service was installed, and no live LSM/cgroup/network enforcement was tested.** The combined Linux host-hardening milestone remains UNCHECKED. See [service profile evidence](OS_SERVICE_PROFILE_HARDENING_V011.md).
