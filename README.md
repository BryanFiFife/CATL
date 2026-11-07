<div align="center">

# 🛡️⚡ CALEDAPT AGENT TRUST LAYER
### Your AI can act. **CATL enforces what it may execute.**

**Local-first · Harness-independent · Default-deny · Human-controlled**

![Release](https://img.shields.io/badge/release-v0.11.0rc1-7c3aed?style=for-the-badge)
![Tests](https://img.shields.io/badge/CI-security_matrix_passing-16a34a?style=for-the-badge)
![Broker](https://img.shields.io/badge/Linux_broker-rootless_UID_auth-087f8c?style=for-the-badge)
![MCP](https://img.shields.io/badge/MCP-tool_subset-2563eb?style=for-the-badge)
![Security](https://img.shields.io/badge/default-DENY-dc2626?style=for-the-badge)
[![CI](https://github.com/BryanFiFife/CATL/actions/workflows/ci.yml/badge.svg?branch=release%2Fv0.11.0-rc1)](https://github.com/BryanFiFife/CATL/actions/workflows/ci.yml)

![Python](https://img.shields.io/badge/Python-3.11%2B-3776ab?logo=python&logoColor=white)
![Offline](https://img.shields.io/badge/offline-first-0f766e)
![License](https://img.shields.io/badge/license-private_evaluation-64748b)

🇬🇧 Built by **[Caledapt](https://caledapt.com)** · *Make AI useful. Not mysterious.*

**🔒 Private evaluation · 🔐 Signed operator authority · 🧪 Linux-only · 🚫 Not independently certified**

</div>

---

## 🚨 Why CATL exists

Giving an agent a tool does **not** mean it should have permanent authority to use it. CATL sits between an MCP-capable agent and a reviewed downstream tool server. It checks tool definitions, schemas, policy, operator controls, one-time consent and optional observed file postconditions. It records the decision and actual outcome rather than trusting the model to certify itself.

> **Retrieval isn't permission. Intelligence isn't authority. An approval isn't a blank cheque.**

CATL is **not** another agent harness or LLM. A protected Linux broker can now keep keys, policy and approval records away from the agent **and** operate without root, communicating with a separately supervised backend UID.

```mermaid
flowchart TD
  A[🤖 Agent / harness under restricted UID] -->|AF_UNIX agent socket| G[🛡️ CATL trusted broker]
  O[🖥️ Minimisable operator overlay under different UID] -->|AF_UNIX operator socket| G
  G --> P{🔒 Pinned definition + policy + schema + controls}
  P -->|Denied| D[⛔ Block and receipt]
  P -->|Needs consent| H[✋ One-time human decision]
  H -->|Rejected or expired| D
  H -->|Approved exact call| X[🔗 Protected AF_UNIX backend socket]
  P -->|Allowed| X
  X --> B[⚙️ Separately supervised backend UID]
  B --> V[🔍 Optional observed file postcondition]
  V --> R[🧾 HMAC-linked SQLite receipt + independent checkpoint]
  R --> S[✅ Result / ⚠️ uncertain / ❌ failure]
```

## 🔐 New in v0.11: Signed authority, safer Pause, cryptographic replay fence

A protected Linux broker now **requires a reviewed Ed25519 operator public key** unless the administrator explicitly opts into **unsafe UID-only evaluation**. Re-enabling tools, granting approvals and clearing incident quarantine require a fresh 192-bit, 30-second, single-use challenge signed over the exact command and Linux operator UID. The broker never reads the operator private key. The desktop overlay and CLI support software signing keys for evaluation; this does **not** certify a human was physically present or prevent malware stealing an operator-held software key.

A red-team regression also reproduced a v0.10 **Pause/dispatch race**. Operator control writes and signed dispatch intents now have a definite ordering; after Pause has returned success no new dispatch intent can be approved under the old state. A tool with a prior recorded intent remains potentially in flight and might still produce external effects. The operator overlay remains responsive during backend execution.

> 🛑 **Live protected service:** no `--operator-public-key` means startup is refused unless `--allow-uid-only-operator` is explicitly specified. Never rely on that unsafe switch for production.

🧭 **Hermes Agent evaluation:** [Isolated Linux integration, stdio smoke checks and operator control runbook](docs/HERMES_EVALUATION.md).

📘 [Operator signing and trust boundary](docs/OPERATOR_SIGNING_V011.md) · [Internal red-team reproduction](docs/RED_TEAM_ASSESSMENT_V011.md) · [Release notes](docs/RELEASE_NOTES_V011.md)

## 🧪 Release candidate: v0.11.0rc1

**Candidate status: not yet general availability.** Windows protected process isolation,
independent pen testing, full Windows protected execution, full modern MCP conformance and remote
side-effect verification remain unpassed release gates. See
[release gates](docs/PRODUCTION_ACCEPTANCE_V09.md) and [security review](docs/SECURITY_AUDIT_V07.md).

**Previously in v0.7:** hardened policy file ownership, immediate approval revocation when the operator disables a safety feature, and fail-closed validation of untrusted tool replies. The current 2026 MCP `_meta` envelope is checked for the supported stdio subset. `catl host-audit` provides read-only checks of the live Linux systemd service profile; a separate recovery drill proves that database-only rollback is rejected in a disposable environment. [Full notes](docs/RELEASE_NOTES_V07.md).

## 🔐 Previously in v0.8: Pinned output-contract firewall

CATL now rejects ambiguous MCP result kinds (including `input_required`) as **uncertain, not completed**. If a pinned tool definition declares `outputSchema`, the downstream server's `structuredContent` must match that locally validated JSON Schema before the caller receives a success. Remote `$ref` loading is refused. The original tool's potential side effect is recorded, and CATL **does not automatically retry** a call whose result was unverified.

This is a narrower, testable guarantee—not proof that the external system actually changed correctly or that prompt injection can never occur. See [the v0.8 acceptance checklist](docs/PRODUCTION_ACCEPTANCE_V08.md).

## 🚨 New in v0.9: Durable incident quarantine — no blind replay

CATL now records a **unique action ID before dispatch**. If a backend crashes, times out,
returns an error or invalid data, or fails independent file verification, CATL places
that tool into an **audit-backed quarantine**. Restarting CATL, re-enabling the ordinary
tool switch or changing the arguments **does not clear this quarantine**. Unexpected
shutdown after the intent receipt but before a terminal result is likewise treated
as an unresolved action. Earlier, uncorrelated legacy receipts are conservatively
migrated; old uncertain results can require explicit reconciliation.

The minimisable operator panel now shows **⚠️ Uncertain Actions**. An operator can
clear an incident *only* through the separate protected operator channel, providing
an external read-back or incident-ticket reference (e.g., `ticket:payment-reviewed-023`)
and an explicit confirmation. That reference is a **human attestation**, not proof
CATL obtained from the external service. The agent cannot clear incidents through
the MCP tool channel. Resolving an incident **does not replay** its original action.

**Important:** successful responses without an independent postcondition remain
**backend-reported**, not proven external success. A real production deployment
must still add tool-specific read-after-write verification and independently tested
OS confinement. See [incident runbook](docs/INCIDENT_RECOVERY_V09.md) and
[release gates](docs/PRODUCTION_ACCEPTANCE_V09.md).

## 🧨 New in v0.10: Adversarial broker flood hardening

An internal red-team regression reproduced **two denial-of-service weaknesses in
v0.9**: an agent could occupy the shared thread budget and obstruct the human
operator socket; an untrusted backend could fill its bounded event queue and
permanently block its reader thread. CATL now reserves separate, non-borrowable
agent/operator connection budgets and uses nonblocking queue overflow detection.
A flood of malformed backend frames likewise trips a bounded fault rather than
continuing indefinitely.

The output firewall now rejects unknown MCP content types and high-risk active
resource-link schemes; ordinary HTTPS links are still untrusted and **must not
be automatically fetched**. Pinned output schemas may represent any JSON value,
including arrays, as required by MCP.

These are *internal attack tests*, **not an independent penetration test**.
An agent that compromises the operator UID, kernel, host policy or broker
signing key may still bypass this release. The broker remains **Linux-only**.
See [red-team reproduction and limitations](docs/RED_TEAM_ASSESSMENT_V010.md) and [10/10 scoped GitHub CI evidence](docs/CI_EVIDENCE_V010.md).

## ✨ What's in v0.11.0rc1?

| Capability | Evidence / limits |
|---|---|
| 🛡️ Default-deny, per-tool enable/disable and pinning | Regression tested |
| ✋ One-time, exact-argument human approvals | Tested against replay and modified rows |
| 🧬 Independent JSON Schema validation | External schema references refused |
| 🛑 Minimisable always-on-top operator overlay | Graphical tests on virtual Linux display |
| 🔐 Distinct Linux agent and operator sockets | Kernel `SO_PEERCRED` validates both configured UIDs |
| 🗝️ Keyless agent shim and broker-controlled desktop client | Agent cannot request operator operations through its MCP socket |
| 🚨 **New: crash-persistent uncertain-action quarantine** | No automatic retry; only protected operator acknowledgement clears it |
| 🧾 Independent audit checkpoint | Detects DB-only rollback/truncation; deliberately fails closed after crash gaps |
| 🧷 Signed control/approval-row replay fences | Control and consumed-approval receipt history checked |
| 🐧 **New: non-root broker and separately supervised tool backend** | Real four-UID test with separate IPC groups and peer UID enforcement |
| 🧑‍💻 Restricted backend identity and scrubbed environment | Test backend couldn't access broker's protected signing key |
| 🔎 File SHA-256 output verification | Local files only; external business outcomes not verified |
| 🧯 Rate limits, bounded payloads, no shell subprocesses | Included; not a full resource sandbox |
| 🔌 MCP 2025 legacy + 2026-07-28 **tool-only** subset | Full protocol conformance, HTTP and MRTR are not supported |

**What is *not* promised:** no-backdoor guarantee, Windows AppContainer enforcement, independent penetration-test certification, remote payment/email verification, arbitrary network egress blocking or a complete MCP implementation. The protected broker currently supports **Linux only**, and its deployment needs distinct OS users and protected directories.

## 🧭 Before deploying on Linux

`catl doctor` checks policy/state/key/anchor configuration; `catl host-audit` reads **actual active systemd units** and fails if restrictions are missing. Neither can prove the kernel or operator account is uncompromised. Example units are in `packaging/systemd/` and must be adapted, installed and verified on a real host. The `tools/recovery_drill.py` script deliberately damages only synthetic temporary state and must reject an old database when the checkpoint has advanced.

```bash
catl host-audit --broker-unit catl-broker.service --backend-unit catl-backend.service
python tools/recovery_drill.py
```

Never arm high-impact external-effect tools solely because these checks pass. An independent outcomes verifier and host review are still required.

## 🖥️ Minimise it. Control it. Inspect every tool.

![Tested CATL desktop overlay](docs/assets/control-overlay.png)

*Actual v0.9 desktop screenshot with **synthetic demonstration state**, showing a quarantined tool. The protected overlay communicates over the operator socket without opening the broker signing key.*

The panel allows users to **pause/resume execution, enable or disable approvals, verification and audit pathways, toggle each pinned tool, bulk-toggle tools, approve or reject precise actions, and inspect/reconcile quarantined actions**. Disabling verification, approvals or audit never creates an unsafe bypass: dependent calls stop instead. The window can minimise to the taskbar or collapse to a compact view.

**Secure deployment:** `catl overlay --operator-socket /run/catl/operator.sock`. The GUI must run as the *trusted operator OS identity*, not as the agent. The legacy direct-state interface remains for explicitly flagged **demonstrations only**.

## 🧪 Fast demonstration (NOT an isolated installation)

```bash
python -m pip install -e .
python examples/make_policy.py
PYTHONPATH=src python -m unittest discover -s tests -q

# Non-isolated demo only, explicitly acknowledged:
PYTHONPATH=src python -m catl run \
  --config examples/policy.json \
  --state-dir "$HOME/.catl-demo" \
  --allow-unsandboxed -- python examples/mock_server.py
```

Running this waits for MCP JSON-RPC input from your harness. It does not start a chat app. The demo mode intentionally **does not** claim security against a same-user compromised agent.

### 🔐 Quick start: signed operator evaluation (Linux)

```bash
# As the trusted operator (in a protected directory you own):
catl operator-keygen --private-key "$HOME/.config/catl/operator.pem" \
  --public-key "$HOME/.config/catl/operator-public.hex"

# A trusted admin places ONLY operator-public.hex into a broker-owned config path.
# When starting the protected broker add:
#     --operator-public-key /etc/catl/operator-public.hex

catl operator --operator-socket /run/catl-operator/operator.sock \
  --signing-key "$HOME/.config/catl/operator.pem" feature gateway_enabled on
catl overlay --operator-socket /run/catl-operator/operator.sock \
  --signing-key "$HOME/.config/catl/operator.pem"
```

**Software-key support is for evaluation, not hardware-backed human verification.** See [operator setup](docs/OPERATOR_SIGNING_V011.md) for installation/permission requirements.

## 🐧 Rootless Linux security: four isolated identities

1. **🛡️ Broker UID:** stores pinned policies, protected key, SQLite approvals and receipt checkpoint; runs as a normal unprivileged service identity.
2. **🤖 Agent UID:** can submit *only* MCP tool requests over its group-traversable agent socket. Kernel peer credentials verify the exact UID, not just the group.
3. **👤 Operator UID:** controls the overlay and approvals over a different operator-only socket. Agent requests never reach the operator API.
4. **⚙️ Tool backend UID:** runs independently under a third protected Unix socket, with a different unprivileged identity. Both ends verify the peer UID. CATL cannot launch an untrusted tool as the broker's own user in protected mode.

No service needs root **during normal operation**. A trusted administrator still provisions accounts, groups, directories and OS service restrictions. The rootless design was tested using four distinct synthetic UIDs and three separate socket groups in a disposable Linux test environment.

**🔧 [Read the rootless deployment guide](docs/DEPLOY_ROOTLESS_LINUX.md).** This includes the startup sequence and required ownership/modes. Misconfigured group access or shared OS identities defeat the intended separation. A restricted UID is not a complete sandbox.

### 🔁 How approval works

`tools/call` on a sensitive tool → `human_approval_required` → operator verifies the arguments in the protected overlay → one-use decision stored and anchored → the agent retries the **same** arguments → a receipt records dispatch and outcome. Any subsequent replay is refused unless separately approved again.

A control change updates the anchored audit history. Restoring an old *validly signed* control row or used approval row no longer silently restores authority.

### 🧷 Why the anchor matters

HMAC alone can authenticate individual receipts but cannot reveal a missing *tail* if both the database and its previous checkpoint are under attacker's control. CATL keeps a second signed head record outside the database directory and requires it to match the verified receipt chain. **A database-only rollback is denied.** If the anchor is deleted, modified, or out of sync after a crash, execution **fails closed** and requires trusted investigation; it does not auto-reset the checkpoint.

This **does not protect** against a broker-account compromise, copying back *both* database and anchor, compromised signing key, kernel compromise, or editing backend and harness outside CATL. A remotely witnessed or hardware-backed monotonic anchor remains future work.

## 🛠️ Test it yourself

```bash
python -m pip install -e .
python -m compileall -q src tests examples
# Desktop test if Xvfb exists (Linux):
xvfb-run -a env PYTHONPATH=src python -m unittest discover -s tests -q
# On a disposable Linux root test environment only (uses synthetic test UIDs):
PYTHONPATH=src python tests/integration_rootless_e2e.py
```

**v0.11 local evidence:** 278 automated tests passed across two bounded batches on Linux / Python 3.13.5, including 49 GUI and adversarial checks under Xvfb. The real four-UID (broker, operator, agent, backend) Linux signed-approval integration also passed, with unsigned-request denial, approval replay protection, audit validity and signing-key access denial. Fresh ZIP and GitHub remote CI evidence are recorded separately when available. Windows checks are **portability/fail-closed only**, not protected broker tests. No independent penetration test or hardware-held human verification has been performed.

🧪 [v0.6.0rc1 audit](docs/SECURITY_AUDIT_V06.md) · 🐧 [Rootless deployment](docs/DEPLOY_ROOTLESS_LINUX.md) · 🗒️ [Release notes](docs/CHANGES_V06.md) · 🔐 [Responsible disclosure](SECURITY.md)

## 🪟 Windows and macOS

- **Windows:** the existing unisolated demonstration can be run intentionally, but the v0.6.0rc1 *protected broker* is **not supported**. Before consequential deployment it needs tested AppContainer/restricted-token isolation, secured named-pipe/ACL operator channels, Job Objects, and anti-UI-spoofing controls. Microsoft documents AppContainer as an OS-enforced security boundary.
- **macOS:** direct demo and general policy components can be evaluated, but the current kernel-credential broker transport is Linux-only. macOS identity-pinned transport and sandbox verification remain open work.

Windows references: [Microsoft AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation), [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

## 🌍 Built for eventual interoperability

CATL is designed to complement rather than replace [AgentInterdict](https://github.com/BryanFiFife/AgentInterdict), [MandateLease](https://github.com/BryanFiFife/MandateLease), [EvidenceClock](https://github.com/BryanFiFife/EvidenceClock) and [Assentia](https://github.com/BryanFiFife/Assentia). The named integrations remain a **roadmap**, not installed adapters.

## 🗺️ Roadmap

**Status: private Linux v0.11 release candidate, not production GA.** `[x]` means the scoped implementation and internal tests exist; it does not imply independent security certification. Combined milestones stay unchecked until **all** requirements are met. See [roadmap status and release gates](docs/ROADMAP_STATUS_2026-11-07.md).


- [x] ✅ Deterministic policy + schema pinning
- [x] ✅ Human approval with replay protection
- [x] ✅ Keyless Linux agent shim and UID-authenticated operator channel
- [x] ✅ Signed audit checkpoints, database-only rollback detection
- [x] ✅ Desktop overlay with functional toggles and approval queue
- [x] ✅ Dedicated non-root broker with independent backend and kernel UID-bound sockets
- [x] 🔐 One-use signed operator grants and Pause/dispatch ordering tests (software key only)
- [ ] 🔐 Hardware-backed user-presence signing and production-verified Linux service isolation (systemd/LSM, capabilities, cgroups and egress restrictions). **PARTIAL:** templates and audit code exist; real protected-host proof remains open.
- [ ] 🪟 Windows AppContainer/restricted-token + named-pipe ACL deployment, real Windows security results
- [ ] 🍎 macOS sandbox and peer-authenticated UNIX socket support
- [ ] 🌐 Full MCP current/legacy interoperability, modern upstream backend and SDK conformance. **PARTIAL:** a tool-only stdio subset is supported.
- [ ] 🧾 Remote API/email/payment read-after-write and idempotent reconciliation. **PARTIAL:** local postconditions and uncertain-action quarantine exist; provider-side read-back does not.
- [ ] 🏛️ Remote/hardware-backed audit anchors, signed reproducible releases, SBOM review and external penetration tests. **PARTIAL:** local keyed checkpoint, deterministic hashes, tested **software** Ed25519 artifact attestations and evaluation SBOM exist; independent witness, hardware-backed provenance and external pentest do not.

### 🔏 Signed release verification (software-key evaluation)

CATL now includes [a detached Ed25519 release attester](docs/RELEASE_ATTESTATIONS.md) with adversarial ZIP/file-set tests and independently pinned public-key fingerprints. **This is not a hardware-backed signature, signed build provenance or independent security certification.** The combined release-assurance roadmap milestone remains open.

### 🧪 Hermes trusted-runtime preflight (v1.4 private evaluation)

[The reviewed Hermes integration module and regression subset](integrations/hermes/README.md) now check root-controlled verifier/import code, a root-owned Python environment, fail-closed runtime tool inventory and kernel UID/socket ACL primitives. The standalone integration subset passed **22 local tests**; the separate downloadable v1.4 lab integration bundle passed **141 local tests**. **Neither result is a live CATL broker + Hermes integration test or proof of production containment.** Native Hermes-tool bypasses and the real protected Linux host remain **OPEN** release gates.

### 🧱 Global authenticated-agent admission guard

The Linux broker now limits agent-channel **request attempts across reconnects and threads** (600 per monotonic 60-second window), before JSON parsing and expensive ledger work. Grossly oversized tool names are rejected before they can enter audit-binding calculations. This is an in-memory availability guard, **not** a durable business-action quota or a substitute for cgroups/OS confinement. See [native ingress hardening](docs/AGENT_ADMISSION_RATE_LIMIT_V011.md). The production Linux host security gate remains open.

### 🐧 Restricted Linux service templates (static verification)

[Broker and backend systemd examples](packaging/systemd/) now include finite memory/swap/task limits, crash-loop limits, core-dump suppression and additional namespace/syscall restrictions. Both pass offline syntax verification; **live host containment remains unverified**. [Evidence and deployment cautions](docs/OS_SERVICE_PROFILE_HARDENING_V011.md).

### 🔐 Protected operator private-key provisioning

The software Ed25519 operator signer now fails closed for **private-key use and generation on unsupported non-POSIX hosts**. Linux/Unix provisioning rejects untrusted writable/symlink parent directories; private signing keys with multiple hard links are refused. Read-only public-key verification remains available. [Key handling test scope](docs/OPERATOR_KEY_GUARD_2026-11-07.md). **This does not implement Windows ACLs, hardware-backed signing or operator presence.**

### 🧾 Atomic audit verification snapshot (native-source repair)

`State.verify()` now performs one receipt-chain scan **under the independent anchor lock**, then authenticates exactly that head before returning the result. This prevents a stale reported count/head from being paired with successful verification of a newer checkpoint and removes a duplicate O(N) scan. [Tests and limitations](docs/AUDIT_SNAPSHOT_FIX_2026-11-07.md). The native full-suite and off-host witness release gates remain **OPEN**.

### 🔢 Fail-closed JSON numeric decoding

CATL's native JSON decoder now rejects exponent overflow (`1e999`) and nonzero decimal underflow (`1e-9999`) before those tokens can influence agent commands, policies or operator data. [Exact regression evidence](docs/JSON_NUMBER_BOUNDARY_V012.md): 13 native-module tests passed; 15,000 deterministic numeric inputs exercised. **This is not a full native integration test or a completed roadmap gate.**

### 🧪 Local-only native acceptance runner (manual, no hosted CI)

[`tools/offline_native_acceptance.py`](tools/offline_native_acceptance.py) verifies the tracked Git source file list, SHA-256 manifest and checksum index **before running the full `test_*.py` unit suite offline**. It refuses a dirty or mismatched checkout, bounds hangs, and writes `acceptance.json` plus `native-unittest.log` outside the source tree. **12 isolated runner regression tests passed.** The full private CATL suite was **not** executed in this development environment. [Read the offline acceptance instructions](docs/OFFLINE_NATIVE_ACCEPTANCE.md).

### 🔧 Six outstanding roadmap workstreams — development implementation

A [separate six-workstream implementation report](docs/SIX_GATE_IMPLEMENTATION_2026-11-07.md) covers new WebAuthn assertion verification, Linux/Windows/macOS isolation proofs, explicit **modern MCP upstream tools-only mode** (`catl broker --backend-era modern`), crash-conservative provider idempotency/readback, independently signed witness receipts, an mTLS witness-service scaffold and offline SBOM validation.

**96 focused local tests passed. This is not full platform or live service evidence.** The six combined roadmap milestones below remain **unchecked**, including FIDO2 hardware, real AppContainer/macOS sandbox, SDK conformance, live provider readback, remote witness deployment and independent penetration testing. No running services or Hermes installation were changed.

## 🩺 Broker preflight (Linux)

Run as the *broker* OS account **after** initial state and external checkpoint
provisioning, and before arming any tools:

```bash
catl doctor --config /etc/catl/policy.json \
  --state-dir /var/lib/catl/state \
  --anchor-path /var/lib/catl-anchor/head.json \
  --agent-uid 10021 --operator-uid 10022 --backend-uid 10023
```

Replace example UIDs with the actual distinct host accounts. Output is JSON with
explicit failures and warnings. The `--strict` flag additionally treats unverified
host-isolation assurances as blockers. This diagnostic cannot prove the host is
secure; it never repairs or recreates a missing key or checkpoint.

## ⚖️ Security and licensing

**Private evaluation license.** See [LICENSE](LICENSE). No telemetry, external login requirement, automatic update service or outbound reporting endpoint has been added to this release. Review all dependencies and backend tools before using real data.

Security reports: see [SECURITY.md](SECURITY.md). This is an actively developed engineering prototype, **not a guarantee that an attacker cannot insert a backdoor**.

---
<div align="center">

**🛡️ Protect the action. 🔍 Verify the outcome. 🧾 Keep the evidence.**

**[Caledapt](https://caledapt.com) · Perth, Scotland 🇬🇧**

</div>
