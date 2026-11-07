# 🔐 CATL v0.11 — signed operator decisions

**Status:** private Linux evaluation, not an independently tested WebAuthn/FIDO2 or hardware-human-presence implementation.

## Why

The Linux broker's `SO_PEERCRED` verifies that the caller has the configured operator UID. That is necessary, but not sufficient when another process could run under the same account. v0.11 adds command-bound Ed25519 **one-use challenges** for capability-increasing decisions. The broker holds only a **trusted public verification key**, never the private signing key. An operator process cannot acquire authority simply by connecting to the operator socket.

The following require signatures: enabling a global feature, enabling a tool (or all tools), approving a pending request and clearing an uncertain-action quarantine. Denying/rejecting actions, disabling a feature/tool and read-only status remain possible without the signing key, so emergency **Pause** works when the signer is unavailable. A compromised operator account can still cause a denial of service; this mechanism is not a replacement for OS separation.

## Evaluation setup — use a disposable deployment first

Provision a keypair from a **trusted operator account**. Do not generate inside the broker service, agent process or repository:

```bash
catl operator-keygen --private-key "$HOME/.config/catl/operator-private.pem" \
  --public-key "$HOME/.config/catl/operator-public.hex"
```

The provisioner exclusively creates new files and refuses to overwrite keys; private mode is `0600`. Ensure the destination directory already exists and is owned/protected by the operator. Transfer **only the public key** via a trusted administrator to an immutable, root/broker-owned directory (e.g. `/etc/catl/operator-public.hex`, not writable by the agent, tool backend or operator). Keep the private key in a separate operator security domain. Never commit either private keys or actual production public-key fingerprints in a demo repository.

The protected broker now **refuses to start** without `--operator-public-key` unless an administrator explicitly uses the `--allow-uid-only-operator` **unsafe evaluation** compatibility override.

```bash
catl broker ... --operator-public-key /etc/catl/operator-public.hex ...
catl operator --operator-socket /run/catl-operator/operator.sock \
  --signing-key "$HOME/.config/catl/operator-private.pem" feature gateway_enabled on
catl overlay --operator-socket /run/catl-operator/operator.sock \
  --signing-key "$HOME/.config/catl/operator-private.pem"
```

A protected command first requests a short-lived (30-second) unpredictable 192-bit challenge. The signing client signs a canonical payload bound to the exact command, challenge and kernel-observed operator UID. The broker validates its fixed public key, consumes the challenge **even for a bad signature**, and only then performs the action. A replayed, changed, expired or cross-UID request is rejected. A broker restart discards outstanding challenges. No private key is exposed to the broker over its socket.

## Threat model and limitations

- **Not hardware-backed human presence.** The provided software signer loads a private key into the operator process; malware with access to that key or process can sign commands. An HSM/FIDO2 authenticator with UV/UP and a trusted confirmation UI is a separate production acceptance gate.
- No browser/WebAuthn ceremony, remote approval service, telemetry or TCP listener has been added.
- Physical display of approval arguments must be independently trusted; signing an ID in a compromised UI is not proof a human reviewed the original action.
- The broker/host admin or a compromised kernel can still bypass this layer; no claim of cryptographic resistance to a compromised broker account.
- Key rotation is **not automatic**; requires an audited, disarmed service change, out-of-band key validation and protected restart. Do not replace a verification key silently while armed.
- The policy, executable, environment and public verification key must live on trusted administrator-controlled read-only paths. A public key is not confidential, but must be integrity-protected.
- A correct Ed25519 signature authorizes a broker command; it **does not** establish the external outcome of an email, API call or payment.

## Security tests

- Forged signature, wrong key, altered command, cross-UID signature, expired nonce and replay are rejected.
- Challenge allocation is bounded to 32 concurrent outstanding requests.
- Same-operator-UID unsigned grant is rejected in a real Linux Unix-socket test.
- Real four-UID Linux subprocess integration performs signed arming and approval, preserves audit and denies backend access to broker signing keys.
- The `Pause` race test proves no dispatch intent can appear **after** a completed pause when both commands go through the protected broker. Existing in-flight side effects are not automatically canceled.
