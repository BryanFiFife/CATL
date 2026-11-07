# 🧨 CATL v0.11 internal security assessment

**Author:** Internal development assessment, NOT an independent penetration test.
**Scope:** v0.10 → v0.11 broker/operator authorization, TOCTOU, authentication replay, key permissions, private Linux four-UID integration.

## Finding CATL-011-01: Pause/dispatch control race

**Previous impact:** an operator disabling `gateway_enabled` could receive a success response while an agent tool call, having passed the previous final check, was paused immediately before acquiring a rate permit and recording a dispatch intent. That action could subsequently record an intent and execute **after** Pause had reported success. This was a real timing-dependent control-plane consistency defect in v0.10.

**Reproducer:** `tests/test_pause_race_v011.py::test_pause_cannot_return_before_existing_dispatch_intent` fails against v0.10 code and passes after remediation. The actor does not need network credentials; the attack requires concurrent agent/operator requests.

**Repair:** `Gateway.dispatch_gate` now serialises the final control recheck, signed rate permit and signed dispatch intent against the protected broker's operator control mutations. If Pause completes first, the following dispatch is refused; if the signed intent completes first, Pause cannot claim to retroactively undo a potentially in-flight side effect. The lock is released **before** the untrusted backend runs, preserving operator responsiveness during backend delays.

**Residual:** POSIX state modified outside the broker by someone holding the broker account or audit key can bypass this in-process lock. A tool already carrying a signed intent may still act after the human clicks Pause, and must be handled by quarantine/reconciliation. Do not market Pause as guaranteed physical cancellation.

## Finding CATL-011-02: Same-UID unsigned privilege grants

**Previous impact:** v0.10 operator socket trusts Linux peer UID. Any process that can run as that same UID can arm CATL, approve a sensitive action or clear quarantine, even without interactive human review. An attacker already occupying that account could exploit this.

**Repair:** v0.11 protected broker requires a pinned Ed25519 **public key** by default; software operator client supplies independent command-bound, one-use challenges. The agent and backend do not receive that private key. Existing unsafe legacy UID-only operation requires an explicitly named override.

**Tests:** forged key, altered command, wrong peer UID, expired/nonexistent/replayed nonce, unsigned same-UID grant, signing-key symlink/permissions, and four-UID kernel peer credential test.

**Residual:** local software signing keys can still be exfiltrated if operator session compromised; hardware-held user-verified signatures are NOT implemented. The signed command may be issued automatically by malware possessing the private key. The broker's own integrity, off-host audit witness and independent security testing remain prerequisites for GA.

## Supply-chain review

During implementation, the originally selected `cryptography==46.0.4` dependency was identified as affected by published security advisories and was **not shipped**. v0.11 pins `cryptography==50.0.2`, for which current public vulnerability listings do not report a direct vulnerability at the time of review. Automated GitHub `pip-audit` will be a release gate. This is a point-in-time assessment, not a guarantee of future security.

## Production verdict

**Private Linux security release candidate only**. The reviewer still needs a production-equivalent real host, independent malicious-agent and operator-account testing, physical user verification, genuine provider-side readback, off-host anchor and signed provenance. Do not make this repo public or promote a release on the basis of the internal report.
