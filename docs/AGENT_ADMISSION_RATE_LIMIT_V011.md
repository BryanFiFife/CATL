# CATL native broker agent-channel admission hardening

**Status:** scoped source hardening; not a production certification. Protects availability of the *operator control channel* when a compromised, kernel-UID-authenticated **agent** repeatedly reconnects to the agent socket.

## Finding

The original broker limited each agent connection to 64 messages and reserved operator connection slots, but had no process-wide request admission limit. A malicious agent could reconnect indefinitely and request expensive HMAC-ledger and tool-catalogue checks. The gateway also accepted arbitrarily long tool-name strings into its audit-binding path.

## Repair

- A shared `AgentRequestBudget` limits agent-channel requests to **600 per monotonic 60-second window** across threads and reopened sockets.
- Credits are spent **before** parsing incoming JSON, including malformed agent frames and empty connections. On exhaustion, the broker emits `agent_request_budget_exceeded` and closes that connection.
- The operator UID/socket does **not** consume the agent budget. Distinct, non-borrowable connection slots remain in place.
- The gateway rejects tool names longer than **128 Unicode code points** before any policy, binding, backend call or signed audit work. This matches the trusted policy's existing 128-character limit.

## Tests

`tests/test_native_agent_budget_v011.py`: admission exhaustion, 2,000 concurrent contenders, window reset, invalid inputs, reconnection non-bypass, malformed-frame charging, and operator independence, executed against the real `catl.broker` when the native test suite runs.

`tests/test_gateway_input_budget_v011.py`: reject malformed and 129/700,000-character tool names without requiring a live `Gateway.state` or backend.

A separately copied reference implementation was checked locally with **9 passing tests**. Its deterministic out-of-order-clock regression **failed on the pre-fix algorithm** (2 admissions under a limit of 1) and passed after moving the monotonic read inside the mutex. **Do not count these as successful native CATL runs.** The new tests must be exercised on a trusted clone with `PYTHONPATH=src python -m unittest discover -s tests -v` before a release candidate can be promoted. GitHub Actions stay manual-only.

## Limitations

This is best-effort in-memory admission, not signed durable rate accounting; broker restart resets the window. The agent can exhaust its own request budget, and native OS scheduling, disk, network, cgroups, process trees, kernel and operator identities remain part of the threat model. Full production-equivalent load and denial-of-service tests remain open. Normal operation above 600 agent requests/minute will be deliberately throttled; capacity must be validated on the intended target before adoption.

No protected Windows or macOS broker is implied.
