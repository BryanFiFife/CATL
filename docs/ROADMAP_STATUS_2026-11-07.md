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

## Software operator key provisioning hardening — 7 November 2026

Private-key generation and loading explicitly fail closed outside POSIX until Windows ACL handling is implemented. POSIX key provisioning checks the immediate parent directory for owner/mode and symlink trust; private signer rejects hardlinked secrets. **11 isolated key-handler tests passed on Linux** with real Ed25519 signatures, including simulated Windows-deny cases; an additional Windows-native regression is prepared for a real platform test. The full CATL native suite **was not executed** in this environment. The hardware-human-presence, Windows protected execution and external pentest gates remain OPEN. See [key guard evidence](OPERATOR_KEY_GUARD_2026-11-07.md).


## Audit verification snapshot integrity — 7 November 2026

Fixed `src/catl/store.py::State.verify()` to hold the independent anchor lock from receipt scanning through checkpoint comparison. The earlier two-pass implementation could return a stale count/head while authenticating a newer checkpoint after a concurrent append. New source-native regression cases cover a one-pass verification, anchored concurrent append, missing anchor, database errors and unanchored evaluation. **7 isolated method-level tests passed**, including a deterministic old/new reproduction; the new full-native tests are written and syntax-checked but **not executed against the complete private CATL checkout here**. The external witness/independent review milestone remains open. See [evidence](AUDIT_SNAPSHOT_FIX_2026-11-07.md).

## JSON numeric decoding boundary — 7 November 2026

Fixed native `src/catl/crypto.py::strict_loads` so JSON exponent overflow can no longer silently convert to Python infinity, and a nonzero numeric literal underflowing to zero fails closed. The unchanged authenticated module was first verified against Git blob `9ca67f3f2e3f198faf60805463b383a1c75f0f84`. After patching, **13 focused native-module tests passed**, plus **15,000** deterministic numeric inputs (7,786 valid, 3,465 underflow rejected, 3,749 overflow rejected; zero unexpected results). No native `Gateway`, broker, systemd service or Hermes process was executed by this parser-only test. Roadmap remains **7 checked / 6 open**. See [test evidence](JSON_NUMBER_BOUNDARY_V012.md).


## Offline full-native unit-suite acceptance runner — 7 November 2026

Added a fail-closed standalone `tools/offline_native_acceptance.py` runner, plus twelve focused tests using disposable Git fixtures. It verifies a clean local Git commit, optional pinned SHA, tracked file paths, all source SHA-256 values and the checksum index before executing `python -m unittest discover -s tests -p test_*.py -v` with an environment allowlist, bounded timeout and process-group cleanup. It produces structured JSON plus log hash. **12/12 isolated runner tests passed; the complete CATL unit suite itself was NOT run in this container.** Rootless four-UID E2E tests, live Hermes, external effects, real Windows/macOS protected mode and independent assessment remain OPEN. [Execution instructions](OFFLINE_NATIVE_ACCEPTANCE.md).


## Six-gate implementation foundations (7 November 2026)

Added a **separate development branch** with focused implementation slices across all six outstanding workstreams: WebAuthn ES256 assertion verification, Linux process proof, Windows token/named-pipe ACL proof, macOS getpeereid, explicit modern MCP tools-only upstream adapter wired through `--backend-era modern`, crash-conservative remote effect/readback ledger, durable signed witness receipts + a mutual-TLS service, and offline SBOM verification. A standalone local suite passed **107 focused tests, including real localhost mTLS and simulated-provider crash tests**, including key-signature and SQLite restart/concurrency fixtures. This is **NOT** a full CATL native checkout test, actual hardware attestation, Windows/macOS kernel run, real external provider demonstration, independent remote witness deployment or external pentest. For specific limitations, requirements and reproduction see [six-gate implementation report](SIX_GATE_IMPLEMENTATION_2026-11-07.md). **All 6 combined roadmap milestones remain unchecked.** GitHub Actions remain manual-only.


## Live on-host mTLS witness and remote-action crash checks — 7 November 2026

Added bounded TLS 1.3 handshake workers, a finite worker budget (16), HTTP request framing refusal and an exact **SHA-256 DER client certificate pin** to the witness service. The client transport ignores inherited HTTP(S) proxy settings; the service requires explicit `--client-cert-sha256`. A real temporary witness subprocess under another non-root Linux UID accepted the pinned client certificate and rejected a different certificate from the SAME CA, absent client certificates, forged sequences and rollback after restart. A slow plain TCP peer did not block authenticated new clients. The separately tested `RemoteEffectLedger` survived hard child exits before/after simulated provider mutations without duplicate auto-submission, and two independent clients racing an identical action used one mutation. **107 / 107 focused local tests + 5 pytest subtests passed twice; this is NOT a live email/payment integration, independent witness host or full native CATL checkout.** See [witness and remote-effect evidence](WITNESS_RUNTIME_ACCEPTANCE_2026-11-07.md). **All six combined release milestones remain unchecked.**


## Witness pre-TLS source-address admission and release-status checkpoint — 8 November 2026

Added a required exact-IP source allowlist to the witness's TCP accept path, checked before TLS worker allocation. Witness TLS 1.3, CA trust and exact client-certificate fingerprint are independently still required. **115/115 local focused unittest tests and 115/115 pytest tests plus 17 subtests passed**, including clean-extraction; a live non-root test accepted a legitimate signed witness after 24 connections from an unlisted loopback address. **A real remaining DoS condition was also reproduced:** 16 stalled connections originating from the allowed client address exhausted all 16 TLS workers until the five-second handshake window expired. Static systemd template checks: 6/6. Historical v0.5 native tests: 179/179 under Xvfb, which does not validate current PR native broker. The full current private checkout, real Windows/macOS deployments, FIDO2, live providers, off-host witness and external pentest remain **NOT RUN**. An unrelated Hermes v1.4 integration run timed out and is not counted as a pass. See [scoped hardening evidence](WITNESS_SOURCE_IP_ADMISSION_2026-11-08.md) and [release decision table](RELEASE_ACCEPTANCE_STATUS_2026-11-08.md). **Seven scoped milestones checked; six combined milestones still OPEN.** GitHub Actions remains manual-only.


## Complete current-source Linux native regression — 8 November 2026

The full private development ZIP (PR #10, parent `ba5fc502...`) was finally available locally, rather than only separate module fixtures. An initial **479-test** full Linux run found two stale assertions (legacy-only backend method allowlist and package-wide networking prohibition), which have been corrected with narrowly bounded exceptions and additional negative security tests. Real four-UID Linux CATL/MCP/shim integration and broker anchored-audit integration passed. The Hermes verifier's **22-test** standalone suite also passed. Both original stale source-manifest entries were reconciled with actual GitHub blobs. See [full current-source evidence and exclusions](NATIVE_SOURCE_ACCEPTANCE_2026-11-08.md). This validates source-level and disposable Linux integration behaviour, **not** production environment isolation, live Hermes, Windows, macOS, physical FIDO2, off-host witnesses, live payments/email or external assessor clearance. All six combined release milestones remain **unchecked**.


## Successful full native current-development acceptance — 8 November 2026

Following the tested compatibility/security-sanity repairs, the complete uploaded CATL source passed **486 unittest cases: 484 passed, 2 native-Windows skips, 0 failures**, running all five real Tk overlay GUI tests under Xvfb. The independent pytest runner passed **484 tests plus 172 subtests**, with only the same two Windows-only skips. Both current Linux broker integration scripts passed, including rootless four-UID separation, signed operator approvals and real MCP shim, and the Hermes v1.4 evaluation verifier passed **22/22**. Static security scan, CLI compilation and deterministic release file-set verification passed after carefully scoped test/scan corrections. See [acceptance evidence and exclusions](NATIVE_SOURCE_ACCEPTANCE_2026-11-08.md). **This completes the scoped native Linux testing milestone, not the six broad production-release gates.** Hardware-backed signers, installed live Hermes confinement, Windows/macOS sandbox hosts, real provider effects, remote witness and independent pentest remain open.

## 9 November 2026 — live systemd resource preflight hardening

Added a fail-closed effective-property extension to `catl host-audit` for
finite reviewed `MemoryMax`, zero swap, task and core-dump ceilings, absence
of explicit `IPAddressAllow` egress exceptions and nine other runtime
settings. A weakened or unbounded active unit must not pass solely because
its static evaluation template looked safe. Source-native regression fixtures
and 12 focused helper tests were added; the helper's isolated tests passed
locally. **No real systemd service was installed or tested during this edit,
and the complete CATL native suite was not rerun.** This improves an
acceptance prerequisite; **the combined Linux host-hardening milestone remains
OPEN**. See [live systemd gate evidence](LIVE_SYSTEMD_GATES_2026-11-09.md).
