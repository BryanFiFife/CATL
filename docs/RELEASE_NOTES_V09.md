# 🛡️ CATL 0.9.0rc1 — uncertainty containment

**Private, Linux-scoped engineering release candidate. NOT public production GA.**

## Security and usability changes

- Persistent, signed per-action intent IDs, with quarantine after uncertain
  tool execution, including crash between intent and result.
- Conservative reconciliation of older action receipts without IDs.
- Human/operator-reconciled actions require an authenticated local operator
  socket (or explicit unsafe demo state mode), confirmation and incident ticket.
- Normal tool switches and agent-supplied MCP JSON-RPC cannot lift quarantine.
- A corrupted audit chain returns a fail-closed protocol error rather than
  cascading into an attempted impossible audit append.
- Scrollable, minimisable operator panel now keeps the incident and approval
  controls accessible at 465×800 window size.
- CI includes an isolated synthetic incident/restart/reconciliation drill.
- New incident response runbook, acceptance checklist and engineering audit.
- New **real GUI screenshot** with synthetic example action data.

## Local reproducibility

- 249/249 tests passed, Linux/Python 3.13/Xvfb.
- Linux four-identity broker/agent/operator/backend integration passed.
- Static sanity scan and both disposable recovery drills passed.
- Python wheel built with installed build backend; dependencies must still be
  verified by clean-network GitHub package-smoke job.

## Still open before public/production

External hostile-agent host test, independent penetration testing, hardware or
independently authenticated operator approval, signed artifact provenance,
witnessed audit, actual email/payment/API provider read-back and official MCP
interop remain outstanding. No test proves a completely backdoor-proof system.
