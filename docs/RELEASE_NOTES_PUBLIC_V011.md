# CATL v0.11.0rc1 — public source evaluation candidate

> **Pre-release, not production-certified.** This source snapshot is provided for inspection and controlled evaluation. Public visibility is not a security certification, and release status does not change licensing terms.

CATL (Caledapt Agent Trust Layer) is a local-first AI agent tool gateway for the Model Context Protocol (MCP). It offers default-deny policies, pinned tool definitions and schemas, human-in-the-loop approvals, a four-identity protected Linux broker architecture, a desktop operator overlay, and local audit and uncertainty handling.

## Scope of this candidate

- **Supported protected runtime evaluated:** Linux rootless broker, separated operator/agent/backend UIDs and authenticated Unix sockets in a disposable Ubuntu VM.
- **Model/tool integration:** bounded legacy and modern MCP tools subset; Hermes integration fixtures and a real Linux shim smoke test are available. Full MCP conformance and hardened production Hermes deployment are not claimed.
- **Security features:** signed **software-key** operator commands; exact-call, one-use approval and replay fences; pause ordering; result validation; optional local file postconditions; uncertain-action quarantine; HMAC-linked receipts and separate local checkpoint.
- **Packaging:** source archive/manifest verification and software-key release signing tools are present. They are not independently certified or hardware-backed.

## Reported verification baseline

Hermes reported the following on 8 November 2026 from an Ubuntu 24.04.5 VM with Python 3.12.3, pinned dependencies and Xvfb:

| Test | Hermes-reported result |
| --- | --- |
| Native unittest discovery | 707 tests, 0 failures, 2 Windows-only skips in root mode |
| Pytest | 679 passed, 28 skipped, 426 subtests |
| Hermes integration unit tests | 22/22 |
| Linux kernel UID/socket isolation matrix | 11/11 |
| Rootless and broker end-to-end tests | PASS in disposable test environment |
| Live four-identity policy smoke | Disarmed/armed/approval-required and socket denial PASS |
| Source ZIP verification | 209-file Git tree reported; 207 indexed source files plus manifest/checksum index |

**Source baseline:** `6ccd65009cfb88dc5d4b4c164d9725a98b4cebe5` on `hardening/v10-backend-containment`. These are developer-run/reported tests, not independent reproduction of the raw VM logs. The committed [acceptance report](../docs/CATL_ACCEPTANCE_RC_2026-11-08.md) refers to an earlier intermediate commit and archive count; do not conflate those historical figures with this snapshot.

## Important limitations

**Do not use as an unrestricted production security boundary.** The following are not accepted for public general availability:

- Production systemd/LSM/egress/cgroup confinement on a hardened target;
- Protected Windows AppContainer and macOS sandbox runtimes;
- Real enrolled FIDO2/WebAuthn hardware presence;
- Independently administered off-host witness and independent external penetration test;
- Real provider-specific email/API/payment readback and idempotent reconciliation;
- Complete supported-SDK/transport MCP conformance;
- Validated current SBOM and independent dependency/licence review.

CATL cannot constrain an agent that still has an unmediated shell, plugin, network path or tool registry outside the broker. Local audit checkpoints cannot defeat an attacker able to roll back both local records. An external side effect is not confirmed merely because a tool returned success.

## Getting started

Read the [README](../README.md), [Linux deployment guide](../docs/DEPLOY_ROOTLESS_LINUX.md), [security policy](../SECURITY.md) and [roadmap](../docs/ROADMAP_STATUS_2026-11-07.md). Use the README's `--allow-unsandboxed` demonstration **only in a disposable environment without production credentials**. Real protected deployments require administrator-provisioned OS identities and independent host review.

## Licensing and publication

The current [`LICENSE`](../LICENSE) grants **private evaluation only**, and does not authorise redistribution, sublicensing or commercial deployment. Public repository visibility, a source ZIP and a zero price do **not** automatically replace that licence. The copyright holder must expressly choose and commit an appropriate public-distribution licence before advertising CATL as open source.

## Release provenance

This document records the **pre-documentation engineering baseline**, not a signed self-referential assertion of the eventual Git commit. GitHub source ZIPs generated from a branch are convenient downloads, but are not substitute signatures or independent provenance. Use CATL's release verification tooling, an independently reviewed source ref and independently pinned public key for any authenticated build.

Security findings should be reported according to [`SECURITY.md`](../SECURITY.md), not as public exploit issues.
