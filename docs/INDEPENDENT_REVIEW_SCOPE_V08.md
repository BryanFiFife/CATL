# 🔬 CATL v0.8 independent security review request

**Scope of engagement:** Linux-protected broker, operator panel, audit key/checkpoint, independently supervised tools, modern/legacy MCP stdio subset. CATL's developer-authored tests are evidence for review, not independent assurance.

## Adversarial objectives

1. Compromise a low-trust agent UID and attempt to read the policy signing key, approval store and operator socket; attempt to invoke the backend directly without the broker.
2. Attempt to bypass kernel peer-UID pinning, socket parent protections, Unix permissions, environment scrubbing and systemd confinement using race conditions, symlink swaps or inherited descriptors.
3. Replay, truncate, reorder, roll back or forge controls, approvals, rate permits, receipts or the independent checkpoint, including crash between database commit and checkpoint update.
4. Coerce the backend into returning forged JSON-RPC IDs, duplicate JSON keys, deeply nested structures, resource-exhausting payloads, unknown `resultType`, `input_required`, forged metadata and output-schema mismatches.
5. Attempt prompt/tool-output instruction injection via successful text results and structuredContent; test whether client harnesses incorrectly treat backend statements as CATL authority.
6. Simulate approval occurring concurrently with pause, tool disable, process termination and external side effects; measure any dispatch already in progress and user-visible outcomes.
7. Fuzz catalogues, pagination, schemas, subscriptions, modern request `_meta`, legacy handshakes and malformed newline-delimited frames.
8. Simulate operator identity compromise; document the limits of UID-based approval, recommend a concrete independent presence/identity control for high-impact actions.
9. Attempt outbound network access, unauthorized filesystem writes, local process execution and sibling-UID credential theft on the actual deployed systemd/LSM profile.
10. Check package integrity, dependency and update path, source/release provenance, incident triage and reproducible build from the pinned Git commit.

## Acceptance evidence

- Signed report by an independent reviewer with scope, methods, limitations, severity, reproducible PoCs and remediation retest results.
- Host configuration: OS/kernel, systemd unit properties, sandbox/LSM, user/group memberships, socket ownership, trusted mount points, disabled network paths, application version and commit.
- Results explicitly identify whether a side effect was attempted/observed and whether it could be stopped, rolled back or reconciled.
- High/Critical defects remediated and independently retested; Medium defects risk-accepted explicitly or remediated before GA.

**No blanket “no backdoors possible” certification is requested or scientifically defensible.** The claim should be limited to an independently examined threat model and tested constraints.
