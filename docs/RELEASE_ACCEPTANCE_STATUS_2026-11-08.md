# CATL release-acceptance status — 8 November 2026

**Decision: NOT RELEASE-READY.** This record is deliberately narrower than the statement that all software components are secure, functional or deployable. No production GA tag or release should be created.

| Requirement | Evidence | Status |
|---|---|---|
| Current PR focused six-workstream package | 115 pytest tests, 17 subtests, 115 unittest tests on disposable Linux | **PASS — partial package only** |
| Source-IP witness pre-worker rejection | 24 disallowed-source sockets; real signed mTLS submission accepted | **PASS — scoped control** |
| Flood from allowed witness source | 16 held TLS workers refused legitimate client until timeout | **OPEN — observed risk** |
| Historical native CATL v0.5 suite | 179 tests passed with Xvfb | **PASS — different historical revision** |
| Current CATL full pinned private source/unit/integration suite | Exact current 167-file checkout unavailable in runtime | **NOT RUN** |
| Live four-UID CATL broker/Hermes deployment | No current branch deployment available | **NOT RUN** |
| Protected systemd/cgroup/LSM + firewall/egress | Static templates tested; no production-equivalent host | **NOT RUN** |
| Windows restricted-token/AppContainer/pipe ACL runtime | No Windows target host or VM | **NOT RUN** |
| macOS sandbox/getpeereid runtime | No macOS host | **NOT RUN** |
| FIDO2 physical user-presence device | No enrolled authenticator | **NOT RUN** |
| Full modern/legacy MCP SDK conformance | Tools-only subset fixtures | **OPEN** |
| Live email/API/payment idempotency | Fake-provider crash/readback fixtures only | **NOT RUN** |
| Independent off-host audit witness and external pentest | On-host signed mTLS fixture only | **NOT RUN** |
| Reproducible signed provenance/SBOM vulnerability review | Manifest source hashes present, no independent release attestation | **OPEN** |

**Policy:** Do not merge the draft PR or mark the six combined roadmap milestones complete on the strength of scoped fixture tests. The root-level release-readiness statement in the README must remain accurate, even if an individual source hardening subtask is completed.
