# 🧪 CATL v0.6.0rc1 — scoped GitHub Actions evidence

The first successful full matrix was observed on **7 November 2026**.

- **Repository:** `BryanFiFife/CATL` (private at verification)
- **Branch:** `release/v0.6.0-rc1` (draft PR #1)
- **Tested commit:** `62547af399a4c4191a949616ff7431eb5d236015`
- **Workflow:** [GitHub Actions run 42327737185](https://github.com/BryanFiFife/CATL/actions/runs/42327737185) — **completed / success**

| Job | Result | What it does **not** establish |
|---|---|---|
| Ubuntu Python 3.11 regression | PASS | Independent penetration-test certification |
| Ubuntu Python 3.13 regression | PASS | Kernel MAC/LSM sandbox conformance |
| macOS Python 3.11 regression | PASS | macOS protected broker support (Linux-only tests skip) |
| macOS Python 3.13 regression | PASS | macOS protected broker support (Linux-only tests skip) |
| Windows Python 3.11 portable smoke | PASS | Windows protected broker; Windows backend security |
| Windows Python 3.13 portable smoke | PASS | Windows protected broker; Windows backend security |
| Linux graphical + separate-UID identity E2E | PASS | Real customer host hardening or external pen-test |
| Package build + clean network dependency install | PASS | Cryptographic artifact-signing provenance |

The Windows job intentionally checks only portable policy code, static safety and explicit fail-closed behaviour for unsupported protected execution. It **does not** claim that CATL can safely protect a Windows-local agent. The backend identity test uses synthetic UIDs on a GitHub Linux runner; production service accounts and host confinement must be separately reviewed.

The release remains a **private, Linux-scoped evaluation release candidate**, not commercial or public general availability. See [release gates](RELEASE_GATES_V06.md) and [security audit](SECURITY_AUDIT_V06.md).
