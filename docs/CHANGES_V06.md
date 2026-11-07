# 🚀 CATL v0.6.0rc1 — hardening change log

- 🔐 **Authenticated tool throttling:** rate-limit permits are signed events, not rewritable SQLite counters. Older `tool_rate` entries are deliberately ignored.
- 🧾 **Streamed HMAC verification:** verify receipts without loading the entire history into memory; full-history verification still has linear runtime.
- 🚫 **No client-directed backend handshake:** the legacy MCP `initialize` exchange is answered locally, and agent notifications cannot directly reach the backend. Broker-generated upstream initialization remains trusted.
- 🧭 **Path-component containment:** `path_within` policy condition for absolute POSIX paths (lexical rule only).
- 🩺 **`catl doctor`:** static/Linux broker preflight for identity separation, policy, key, checkpoint and control integrity, with JSON results and nonzero failure exit codes.
- 🧪 **Expanded adversarial regression coverage:** ledger tampering, counter replay, pathname confusion, bootstrap behaviour, missing anchor and impersonation boundaries.
- 🧩 **Version metadata corrected:** modern MCP `serverInfo` now reports the candidate's version.
- 🏗️ **Packaging/CI:** wheel build, archive integrity manifest, cross-platform test workflow retained; no unverified CI claims.

**Compatibility notice:** The release increases authenticated ledger records on allowed calls, so existing test-count assumptions and audit dashboards must be updated. It does not change the persisted schema and can read v0.5 receipts. A backup and full checkpoint verification are required before trying it with existing state. There is no automatic downgrade or anchor repair.

**Release status:** private evaluation candidate, not general availability or production security certification.
