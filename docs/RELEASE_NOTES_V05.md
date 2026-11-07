# 🚀 v0.5.0 — standalone repository + rootless broker

**2026-11-07 | private engineering release**

- 🐧 Rootless Linux broker behind UID-bound AF_UNIX sockets.
- 🧰 Separately supervised restricted-UID tool backend service; dual-sided `SO_PEERCRED` peer verification.
- 🔑 Agent, operator, tool backend and broker no longer need the broker to execute as root.
- 🪪 Protected controls and one-time approvals retained from v0.4.
- 🔒 Startup preflight rejects privileged tool service launches and wrong IPC-group configuration before child execution.
- 🧪 Expanded static/unit/security tests, plus a separate four-UID real integration exercise.
- 🖥️ Existing tested minimisable overlay retained.
- 📦 Standalone root-level Python packaging and GitHub Actions workflows.

**Still not implemented:** secure Windows AppContainer broker, strong human reauthentication, remote business outcome verification, external security certification and complete MCP specification conformance.
