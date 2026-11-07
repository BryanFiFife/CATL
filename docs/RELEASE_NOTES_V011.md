# 🔐 CATL v0.11.0rc1 — signed operator authority and emergency-pause ordering

Private Linux release candidate (not GA).

- **Safer default:** production-style protected `catl broker` refuses to start unless a trusted operator Ed25519 verification key is configured. The old UID-only path requires `--allow-uid-only-operator` (unsafe legacy evaluation).
- **Nonce-bound signing:** enabling tools/features, approving exact sensitive calls and reconciling uncertain actions require single-use Ed25519 signatures when secured. Deny/pause remains operable without the signer.
- **Broker does not hold operator private key:** software signer used by CLI or minimisable desktop overlay; no WebAuthn, HSM or physical presence claim.
- **TOCTOU fix:** protected operator Pause and signed dispatch intent now have a linear ordering, with no lock held during untrusted backend execution.
- **Supply-chain patch:** pin cryptography 50.0.2 (originally evaluated 46.0.4 was known vulnerable); expand dependency scanner inventory.
- **Version consistency:** derive MCP-reported server version from the package version.
- **Regression evidence:** new deterministic concurrency, replay, expiry, tampering, key permission and live socket tests; 278 local tests and rootless four-UID signed integration passed; fresh ZIP/CI evidence recorded separately.

See `docs/OPERATOR_SIGNING_V011.md` and `docs/RED_TEAM_ASSESSMENT_V011.md` for design and boundaries.

- **Client signing-oracle hardening:** before signing any broker-supplied challenge, the operator client reconstructs the exact canonical message from the intended command and kernel operator UID; refuses altered command bytes and unsupported signature schemes.
