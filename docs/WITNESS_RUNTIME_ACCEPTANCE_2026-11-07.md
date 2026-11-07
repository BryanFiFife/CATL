# CATL witness and remote-effect runtime acceptance — 7 November 2026

**Scope: development security improvement, not production acceptance.** All new tests run in a disposable Linux container. They use locally generated test CA/certificates and fake provider operations. The signing-key material is temporary, never packaged or published. No CATL broker or Hermes process was installed or started.

## Hardened witness server

The `tools/witness_service.py` service now:

- Terminates TLS setup after a **five-second handshake timeout**, with a maximum of **16 concurrent TLS/HTTP workers**. TLS handshakes run inside those workers rather than the main accept loop, avoiding indefinite accept-loop head-of-line blocking from a plain TCP client that never begins TLS.
- Requires **TLS 1.3**, server certificates signed by a pinned CA from the client's point of view, and a trusted TLS client certificate. **The exact authorised CATL client certificate is additionally pinned by its SHA-256 DER certificate fingerprint** using required `--client-cert-sha256`, not merely by CA membership.
- Restricts each worker's request read to 10 seconds. Uses HTTP/1.0 responses without persistent keep-alive; ignores operator-untrusted proxy environment variables in the client transport.
- Rejects ambiguous framing (`Transfer-Encoding` or duplicate `Content-Length`), unsupported methods, excessive headers, incorrect content type and oversized bodies before reading or processing a witness head.
- Signs and durably stores monotonic ledger heads; refuses old heads and equal-sequence forks across process restarts. The witness signing key stays only within the server's non-root account.

### Runtime tests, actual Linux kernel and TLS

`tests/test_witness_mtls_e2e.py` starts a real server process under a **different non-root Linux user** from the caller, generates a disposable test CA, runs TLS 1.3 and validates:

- successful client certificate authentication and separately pinned Ed25519 response verification;
- no-client-certificate refusal;
- **different client certificate from the SAME CA is refused** (`403`);
- wrong server hostname is refused by TLS hostname verification;
- rollback and same-sequence fork rejection after a server process restart;
- `Transfer-Encoding`/duplicate `Content-Length` requests refused;
- malformed method and oversized body refused;
- HTTP(S) proxy environmental variables cannot divert the trusted witness request;
- an idle unauthenticated plain TCP connection cannot block the accept loop.

The full isolated six-workstream suite passed **107 / 107** tests plus **5 pytest subtests**, twice in succession (`pytest_run1.log`, `pytest_run2.log`). `python -m compileall -q src tests tools` passed.

### Remote action crash/restart tests

`tests/test_remote_effects_process_crash.py` uses the existing `RemoteEffectLedger` and launches separate OS processes sharing a real SQLite-backed HMAC intent ledger. It verifies:

- hard process exit **before mutation** leaves the action uncertain and prevents an automatic resend;
- hard exit **after an attempted mutation** cannot auto-repeat; authoritative readback via a separately executed reconciliation confirms the observed action;
- two independent processes racing the same action id produce only one mock mutation.

These are **fake local providers**; they neither send real email nor move funds. No provider SDK is integrated into the protected broker and no independent witness host was used. Thus the related combined release milestones are still OPEN.

## Installation and security requirements

- Run this witness service on an **independently operated host**, with its own protected disk, key hierarchy, backups, telemetry and owner. Never copy the signing key to the CATL broker.
- Provision a dedicated TLS server key, dedicated client CA, dedicated CATL broker client certificate and its **lowercase SHA-256 fingerprint of DER encoding**. Pass `--client-cert-sha256 <64 lowercase hex>` on the server; keep private keys unreadable by all other users.
- Restrict inbound network traffic to the broker address, and enforce external rate limits and OS cgroup limits. The 16-worker budget is a bounded-resource measure, not a complete defence against a sustained handshake flood.
- Use a durable filesystem with independent snapshots and clock monitoring. The witness receipt is evidence of a submitted ledger hash, **not** verification of the underlying database receipts or a real-world payment.
- Monitor certificate renewal and explicitly review/pin the replacement certificate before rotating. Server startup intentionally fails when the client pin is omitted or invalid.
- Before GA, demonstrate real CATL State-to-witness integration, certificate rotation, remote network failure/recovery, signed release provenance and **independent external penetration testing**.

## Reproduction

On a disposable Linux host with Python 3.13 and `cryptography` installed, from this development package:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py' -v
PYTHONPATH=src pytest -q --disable-warnings
```

The real mTLS test requires root solely to create a **test-only separate non-root process**. It skips on other platforms. It does not modify systemd or touch real accounts beyond running `nobody` as a temporary child. The user-facing release gates remain **7 checked / 6 open** pending actual acceptance evidence.
