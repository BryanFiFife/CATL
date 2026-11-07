# 🧨 CATL v0.10.0rc1 — Internal adversarial security assessment

**Date:** 7 November 2026  
**Type:** Source-assisted, developer-operated adversarial assessment (NOT independent penetration testing)  
**Authorisation/scope:** The locally mounted CATL v0.9.0rc1 source and disposable Unix sockets/processes. No third-party service, customer infrastructure or credentials were targeted.  
**Disposition:** Security release candidate for controlled *Linux* evaluation only; no public/production certification.

## Method and evidence

We inspected the broker IPC queues, backend reader, MCP result boundary, state/audit machinery, deployment CI and existing regression suite. We deliberately attacked local agent/operator resource isolation and malicious-backend message handling. Reproduction used Linux test identities and deliberately untrusted fixture processes. The baseline test script is archived in the test logs, and the new regression tests in `tests/test_redteam_dos_v010.py` and `tests/test_redteam_reply_v010.py` remain executable.

### Confirmed weaknesses and remediations

| ID | Severity* | Exploit on v0.9 | Remediation in v0.10 | Verification |
|---|---|---|---|---|
| CATL-RT-01 | **High (availability)** | Agent opens idle connections up to shared 16-thread ceiling. A separate operator's `status` request receives no successful reply, making emergency controls inaccessible. | Separate non-borrowable 8-agent and 8-operator connection permits; admission is nonblocking, each permit released in `finally`. Bound agent requests per session to 64. | Reproduced **FAIL on v0.9**, **PASS on v0.10** using real Linux `SO_PEERCRED` UIDs. |
| CATL-RT-02 | **Medium (availability)** | Flood of unsolicited JSON-RPC notifications fills a 512-item queue. Reader blocks in `Queue.put` and does not terminate on timeout or shutdown. | `put_nowait`, explicit overflow event, bounded failure, nonblocking EOF sentinel and backend termination; uncertain call is not presented as success. | Reproduced **FAIL on v0.9**, **PASS on v0.10** with bounded in-memory malicious backend stream. |
| CATL-RT-03 | **Medium (availability)** | Endless malformed backend frames are ignored without any cumulative failure threshold, enabling an avoidable CPU consumption loop. | 32-invalid-frame limit; fail closed instead of spinning indefinitely. | Adversarial synthetic malformed stream test. |
| CATL-RT-04 | **Medium (result-boundary)** | An untrusted backend could supply unknown MCP content types, active `javascript:`, `data:`, `file:`, loopback/private `https:` resource links, and extra metadata fields. | Explicit known content types, HTTPS non-local resource links only, no automatic URL fetching, and forwarding only reviewed MCP response fields; reject complete results containing continuation fields. | Schema/type/metadata/URI injection tests. |
| CATL-RT-05 | **Medium (supply chain, when public)** | GitHub's privileged (sudo) Linux identity CI job would execute code from external fork pull requests. | Restrict privileged identity job to `push` or **same-repository PRs**. Fork contributions still receive unprivileged checks. | Static CI guard regression; full GitHub execution still required. |
| CATL-RT-06 | **Compatibility** | Pinned `outputSchema` allowed arrays/scalars under MCP but CATL rejected them before schema validation. | Validate any JSON instance and let the pinned schema decide. | Array-positive, wrong-type-negative regression. |

*Severity is internal engineering prioritisation, not an independently assigned CVSS score.

**Baseline evidence:** The v0.9 copy failed the hostile-backend queue/thread tests and the actual cross-UID agent-saturation/operator-availability test (`FAILED (failures=3)`). The new candidate passes the same cases. The v0.9 baseline is not modified.

## Attack boundaries that remain unverified

1. **Physical human authentication.** `SO_PEERCRED` establishes the connecting Linux UID, not that a person is present. Malware running as the configured operator UID may request approvals. For high-impact actions an independent hardware-backed approval factor remains required.
2. **OS privilege and kernel compromise.** Root, compromised systemd/LSM policy, or an agent given direct tool credentials can bypass CATL. Tests do not prove a production host has correctly removed those capabilities.
3. **External business outcomes.** A backend-reported success is not proof that a payment, email or API operation succeeded. v0.9 incident quarantine limits blind retry, but requires real provider-specific read-back and idempotency before high-impact use.
4. **Audit witness.** HMAC + separate local checkpoint detect DB-only rollback, not compromise of both the protected key and checkpoint or total-host restore. Off-host witness and recovery drills remain mandatory.
5. **Prompt injection via ordinary text.** Sanitizing fields does not make backend text trustworthy. The agent and operator must treat model-visible content as data, never as new policy or authorization.
6. **Resource-link resolution.** CATL itself never follows HTTPS resource links; a downstream host can still resolve an innocuous public hostname to an internal address. CATL cannot enforce network isolation in a separate consumer.
7. **Filesystem symlink/TOCTOU.** Lexical `path_within` alone does not confine arbitrary backend file operations; only separately enforced filesystem sandbox permissions can provide that boundary.
8. **Full MCP conformance.** CATL intentionally supports a limited legacy/2026 tools subset. Full protocol, MRTR, HTTP, OAuth, subscriptions and SDK compatibility are not established.
9. **High-volume performance and denial of service.** Ledger verification can become expensive as receipts grow; CPU/memory/disk and host cgroup exhaustion remain open production attack surfaces. Limits in CATL are defence in depth, not a resource quota.
10. **Independent review.** No external tester has validated these findings, the fixes or deployment as a whole.

## Reproduction commands

```bash
# From an installed Linux test environment; separate-UID test requires root.
PYTHONPATH=src python -m unittest discover -s tests -p 'test_redteam_reply_v010.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_redteam_dos_v010.py' -v
# CI additionally runs the root-only operator-flood test from a readable /tmp stage.
PYTHONPATH=src xvfb-run -a python -m unittest discover -s tests -q
python tools/incident_drill.py
python tools/recovery_drill.py
```

The tests do **not** authorize testing unrelated networks, external services or deployment hosts. Do not substitute this report for an independent security assessment.

## Release decision

**Internal code vulnerabilities reproduced and fixed, subject to continued CI verification.** Production/general availability remains **BLOCKED** on the acceptance criteria in `docs/PRODUCTION_ACCEPTANCE_V09.md` and [GitHub issue #5](https://github.com/BryanFiFife/CATL/issues/5). The repository and release candidate must remain private pending approval.

### Referenced specifications and secure CI guidance

- [MCP 2026-07-28 tools specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)
- [GitHub: compromised runners](https://docs.github.com/en/actions/concepts/security/compromised-runners)
- [OWASP GitHub Actions Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html)
