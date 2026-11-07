# CATL six-roadmap implementation — scoped engineering branch

**Status: DEVELOPMENT BRANCH, NOT PRODUCTION READY.** This branch delivers real, testable implementation slices to every open roadmap workstream. The six combined acceptance milestones remain **OPEN** until external proof is collected. Do not present passing local fixtures as completed hardware, Windows, macOS, remote-provider or independent tests.

## What is implemented

| Open workstream | Implemented code | Validated locally | Still required before roadmap checkbox |
| --- | --- | --- | --- |
| Linux confinement and hardware user presence | `hardware_presence.py` verifies ES256 WebAuthn assertions, origin, RP ID, challenge, UP+UV flags, counters; `platform_proofs.py` checks current process's kernel seccomp/no-new-privs/caps and bounded cgroups | Real generated ES256 signatures and fail-closed fixture tests | Secure FIDO2/WebAuthn credential enrolment, command+UID-bound one-use challenge and durable counter in broker, real FIDO2 hardware; production-equivalent systemd/LSM/egress/cgroups and Hermes bypass attempts |
| Windows protected execution | `windows_current_token_proof()` reads real Windows token AppContainer and restriction flags; `windows_named_pipe_acl_proof()` inspects named-pipe DACL with exact SID allowlist, rejecting broader allowed principals | Non-Windows fail-closed tests and code review only | Actual AppContainer/restricted-token process launcher, ACL installer and Windows-host adversarial tests; no such launcher has been built here |
| macOS protected execution | `macos_peer_uid()` uses kernel `getpeereid()` for AF_UNIX; `protected_unix_socket_path()` verifies path ancestry, socket ownership and modes | Simulated macOS UID mismatch; Unix filesystem tests | Signed/App Sandbox helper application with correct entitlements, launchd services, exact socket ownership and tests on an actual Mac |
| MCP modern/legacy interoperability | `ModernToolsBackend` wraps CATL's existing legacy gateway interface and explicitly translates `server/discover` + stateless 2026-07-28 `_meta` tool calls. Broker can opt into it with `--backend-era modern`. | Mock modern upstream tests with fail-closed malformed responses | Official SDK cross-version conformance; HTTP OAuth, resources, prompts, subscriptions, MRTR, server-initiated flows not implemented and must remain disabled |
| Remote-effect correctness | `RemoteEffectLedger` records durable attempted intent **before** calling a provider and never automatically repeats uncertain operations; HMAC-sealed state, POSIX file locking, provider idempotency key, operator readback reconciliation | Fake provider errors/side effects, threaded concurrency, restart and tamper fixtures | Service-specific Gmail/SMTP/API/payments adapters supporting **authoritative** provider readback, integration into CATL's broker/ledger, multiple-process crash drills and real provider tests. Note: SQLite snapshots can still roll back without external anchor. |
| Off-host witness & release assurance | `witness_protocol.py` verifies pinned Ed25519 receipts; durable witness log and mTLS-only witness service are supplied for a **separate host**; `sbom_assurance.py` checks deterministic source hashes and CycloneDX structure | Signatures, fork/rollback detection, fixture state witnessing, SBOM/manifest negatives | Deploy independent witness with separately controlled keys and certificate identities; prove full signed-reproducible release provenance; hardware-backed release keys, third-party SBOM/vulnerability audit and **independent external penetration test** |

## Deployment and security conditions

1. The broker/agent must not share a UID, API token, home, key or unmediated tool entry point. Every local system call available to Hermes requires separate review; the broker cannot sandbox arbitrary native extensions merely by changing MCP metadata.
2. **Do not enable** WebAuthn privilege grants using only the assertion verifier. The operator workflow must generate and atomically consume one-use **command-and-UID-bound** challenges, enrol a hardware-attested public key, and persist signature counters under a trusted checkpoint. No WebAuthn user interface/CTAP stack is delivered here.
3. Modern MCP bridging is **tools-only**. Unsafe MRTR `input_required` is rejected rather than triggering a second call; do not claim full modern SDK conformance.
4. External effects require a provider that can look up exactly the intended operation by stable idempotency key and return a canonical payload. A valid HTTP 200 or SMTP acceptance is **not** confirmed external completion. Never auto-resend after timeout; require trusted operator reconciliation after an authoritative readback. Do not use the example adapter as a payment SDK.
5. The witness host must be genuinely independent of CATL and use mTLS, separate Ed25519 private key, protected database and off-host backups. A second process in the same container does **not** constitute independent witnessing. The witness can notarise the hash it receives; it cannot prove the actual ledger content or reality of external side effects on its own.
6. The SBOM tool does not query a live vulnerability database, review licence obligations or assert a reproducible build. It provides only file-hash/format checks.
7. No GitHub Actions were invoked by this work. CI workflow remains `workflow_dispatch` only.

## Commands

```bash
# Isolated development tests (requires cryptography; other CATL deps unchanged):
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py' -v

# Once integrated into a trusted, clean *full* CATL checkout:
python tools/offline_native_acceptance.py --repo . --expected-commit "$(git rev-parse HEAD)" --out /tmp/catl-offline-acceptance

# Modern backend selection, only after catalogue pins, systemd and actual
# modern backend are configured; command skeleton only:
catl broker ... --backend-era modern ...
```

## Official source alignment

- MCP protocol revision `2026-07-28` is stateless; every request carries `_meta` and `server/discover` replaces `initialize`. The 2025-11-25 era uses `initialize`; consult the MCP Python/TypeScript SDK v2 version-negotiation references.
- WebAuthn authenticators sign authenticatorData + SHA256(clientDataJSON); user present and verified flags are separate (W3C WebAuthn L3/L4).
- Windows AppContainer profiles and restricted-token rules require Windows kernel APIs and an audited named-pipe DACL (Microsoft Learn).
- macOS sandbox enforcement requires an App Sandbox-entitled, signed app/helper and is verified on-device (Apple Developer).

## Exit criteria to actually tick six boxes

**None satisfied from this Linux container alone.** Require signed third-party/host-specific evidence for: (1) live Linux Hermes+CATL under four UIDs with FIDO2 and kernel egress barriers, (2) Windows launcher+pipe adversarial results, (3) real macOS sandbox peer-auth E2E, (4) MCP SDK transport/era conformance including explicitly supported methods, (5) actual provider read-after-write and crash/restart payment/email test, (6) independent off-host witness, signed reproducible release, independently reviewed SBOM and third-party pentest. Keep all six checkboxes unchecked until all corresponding obligations are demonstrated.
