# 🔬 CATL v0.7.0rc1 — engineering security review

Date: 2026-11-07 · Scope: local Linux rootless trust boundary · **Internal engineering review only, not a third-party penetration test.**

## Addressed in this candidate

1. **High — policy file ownership was not verified.** A file readable by the broker but owned by the agent could be replaced between launches while remaining mode `0644`. The load path now requires trusted owner and parent directory, rejects symlinks, reads through an `O_NOFOLLOW` file descriptor, and limits file size to 1 MiB. Tests cover untrusted directory and UID scenarios. Host still must protect parent ancestors and mount namespace.
2. **High — pause did not revoke already-approved actions.** Disabling the gateway, approvals, audit, verification or any pinned tool now invalidates pending/approved requests in the same signed transaction. A row-level replay of an old, otherwise correctly HMAC-signed approval is blocked by the authenticated revocation receipt.
3. **Medium/high — tool replies could be misreported as successful.** Untrusted results now require a JSON serialisation check, a hard 512 KiB limit, a well-formed tool result and a constrained content list. Untrusted backend `_meta` is removed, and upstream protocol errors are normalised. Invalid or oversized responses after a possible effect produce an explicit uncertain-outcome error and receipt, never successful verification.
4. **Medium — incomplete modern MCP client metadata accepted.** The restricted 2026-07-28 stdio adapter now requires and bounds all three `_meta` elements: version, capabilities, and client info. MCP identity fields are never treated as OS authority.
5. **Operational — non-attestable host profiles.** Added a read-only systemd live-unit property audit and hardened example units with stricter kernel/device/egress flags. The test container does not use systemd as PID1, so it correctly returns an unsuccessful host audit. Static `systemd-analyze verify` does not prove runtime sandboxing.
6. **Operational — recovery evidence.** Added a disposable database-rollback drill, preserving the independent anchor, to demonstrate the intended fail-closed recovery semantics.

## High-priority residual risks

- **Host compromise / same-UID bypass:** If untrusted agents share operator or broker credentials, the broker may be bypassed. OS identity alone does not authenticate a human.
- **Unreviewed tools:** CATL cannot infer whether a tool advertised as `read` changes remote state. `catl doctor` warns when permitted tools lack independent postconditions, but policy signing and security classification remain deployment responsibilities.
- **Remote effects:** File digests do not establish mail delivery, cloud API action success, payment outcomes, or exactly-once execution. Timeouts must be considered uncertain until reconciled.
- **Signing and rollback:** Local HMAC keys plus a separate checkpoint cannot resist theft of that key or coordinated rollback of the database and checkpoint. A hardware or independent monotonic witness is needed for higher assurance.
- **Long-lived service:** The full receipt chain is verified at each anchored mutation. This is an intentional integrity-over-performance trade-off; large ledgers may degrade or become a denial-of-service vector.
- **Privilege sandbox:** systemd templating, POSIX UID separation and local tests are not substitute for an LSM/namespace/network attack simulation on the actual installed host.
- **Windows/macOS:** Protected subprocess broker has not been designed, implemented or independently validated on these platforms.
- **Supply chain:** This ZIP carries deterministic SHA-256 manifests but no cryptographically signed release identity. GitHub private attestations may require Enterprise entitlements; do not claim them unless produced and verified.

## Release recommendation

**Do not release as a production security guarantee.** Permit evaluation only with restricted synthetic/low-impact tools and reviewed Linux identities. Complete the production gates in `RELEASE_GATES_V07.md` and obtain independent verification before the public launch.
