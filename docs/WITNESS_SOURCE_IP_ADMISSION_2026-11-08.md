# Witness peer-address admission hardening — 8 November 2026

## Change and threat model

Before this change, any TCP source could hold one of the 16 mTLS handshake/HTTP worker slots, even though only a client carrying an exact pinned certificate could submit a witness head. Sixteen idle unauthenticated clients from an accessible source denied a subsequent legitimate signed submission until handshake timeouts freed capacity. The finite worker pool prevented unbounded threads but **not** short-term denial of service.

`tools/witness_service.py` now requires `--allow-client-ip <exact IP>` (repeatable, maximum 32). The accepted address list is validated at startup. Source IPs are checked from the kernel socket peer tuple **before** allocating a TLS worker or parsing client-controlled HTTP/TLS bytes. Missing allowlists, CIDR entries, multicast/unspecified values, invalid addresses and IPv4 reserved/broadcast addresses fail closed. IPv4/IPv6 exact addresses are supported. The pre-existing TLS 1.3 client CA and **exact DER client certificate fingerprint** remain independently mandatory. Invalid peers receive no application-level data or trusted status.

Example for a separately operated witness, after network firewall policy has also been configured:

```bash
python tools/witness_service.py \
  --database /secure/witness/heads.db --signing-key /secure/witness/signing.pem \
  --tls-cert /secure/witness/server.pem --tls-key /secure/witness/server.key \
  --client-ca /secure/witness/client-ca.pem \
  --client-cert-sha256 <reviewed-64-character-lowercase-hex> \
  --allow-client-ip <reviewed-broker-source-ip> \
  --listen <dedicated-listen-ip> --port 9443
```

**Deployment caveats:** IP pinning is not equivalent to authenticating a broker. NAT, VPNs, proxies and changed egress addresses can alter the peer address; do not use `X-Forwarded-For` as an authentication source. Deploy host/network firewall allowlists and connection-rate limits *ahead* of the Python service. A malicious host sharing an allowed source IP can still consume all 16 workers. The source filter is deliberately not represented as a complete DoS fix.

## Local execution results

Ran on a disposable Linux host with Python 3.13.5, `cryptography` 46.0.4, and genuine TLS 1.3 using ephemeral test certificates. No persistent witness or Hermes/CATL deployment was altered.

- Updated current six-workstream **evaluation subset**: **115/115 pytest tests plus 17 pytest subtests passed**, and separately **115/115 unittest tests passed**. Native `python -m compileall` succeeded.
- Live separate-UID witness: **24 connections sourced from disallowed 127.0.0.2** did not prevent a correctly pinned 127.0.0.1 witness client from submitting a signed head; authorised request completed in approximately **8.68 ms** (local observation, not a latency guarantee).
- Remaining availability limitation reproduced: **16 stalled peers from allowed 127.0.0.1** rejected a legitimate concurrent submission; the request succeeded after the 5-second TLS handshake timeouts released worker slots.
- Historical CATL v0.5 native baseline: **179/179 tests passed** under Xvfb on this host; this is **not** current PR #10 source. Historical native integration tests are separate and do not certify the current branch.
- systemd service-profile static checks: **6/6 passed**; no live protected systemd host was started.
- A separate Hermes integration unittest run exceeded the execution window at one test. It is explicitly **INCOMPLETE**, not reported as a passing suite.

## Release acceptance

This closes the **source-IP pre-worker admission subtask only**. It does **not** close any of CATL's six combined roadmap milestones. **Full native CATL checkout regression, current broker/Hermes runtime, real Windows AppContainer, macOS signed sandbox, FIDO2 hardware authorisation, provider write/readback, external penetration testing, remote witness administration and end-to-end provenance remain unverified.**

The authenticated private GitHub connector permits inspection of source files, but direct network clone of the private repository fails in this container; the binary PNG asset cannot be fetched through the text-only connector. The local evaluation subset is not a complete copy of the pinned 167-file PR tree. Do not mark full functional or production acceptance as passed based on these tests.
